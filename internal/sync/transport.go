// Package sync is the anti-entropy engine: version vector exchange, delta
// computation, push-on-write, and periodic pull.
//
// # Why there is no consensus here
//
// Nothing in this package votes, elects, or waits for a quorum. That absence is what
// makes joining and leaving free (plan §5.4, §11.2): a node that appears starts
// exchanging vectors, and a node that vanishes is simply a peer nobody heard from.
// Adding Raft "for correctness" would buy nothing — records are append-only, so there
// is no conflicting write to order — and would cost exactly the property the system
// exists for.
//
// # Convergence
//
// Version vectors form a lattice under Merge, which is commutative, associative and
// idempotent. So any order of pairwise exchanges converges to the same state, and a
// duplicate delivery is a no-op. That is the whole correctness argument, and it is why
// the tests can shuffle the exchange order and still assert an exact final state.
package sync

import (
	"context"
	"errors"
	"time"

	"github.com/coryforsythe/memmesh/internal/record"
	"github.com/coryforsythe/memmesh/internal/wire"
)

// Transport layers. The names are what memctl members prints in its TRANSPORT column.
const (
	// TransportMemory is the in-process transport used by tests. Two-node and N-node
	// tests run entirely in memory with no network (plan §0.4), which is what makes
	// a convergence failure a bug rather than a flake.
	TransportMemory = "memory"
	// TransportDirect is a direct tailnet connection.
	TransportDirect = "direct"
	// TransportDERP is a relayed tailnet connection.
	TransportDERP = "derp"
)

// Errors returned by transports.
var (
	// ErrNoSuchPeer reports a peer the transport cannot reach.
	ErrNoSuchPeer = errors.New("sync: no such peer")
	// ErrTransportClosed reports use after Close.
	ErrTransportClosed = errors.New("sync: transport closed")
)

// Peer is a node the transport can see.
//
// Being listed here means enrolled — visible with the node tag — not participating.
// Whether records from a peer have actually arrived is a question only the version
// vectors can answer, and keeping the two apart is what makes the divergence between
// them visible (plan §8.2).
type Peer struct {
	// Node is the peer's node id, as the discovery layer reports it.
	Node record.NodeID
	// Address is how to reach it, for display and dialling.
	Address string
	// Transport is direct or DERP, when the discovery layer knows.
	Transport string
	// Online is what discovery last reported.
	Online bool
}

// Session is one bidirectional frame stream with a peer.
//
// Implementations need not be safe for concurrent use; the engine owns a session for
// the duration of an exchange.
type Session interface {
	// Peer returns the peer's node id, which may be empty until Hello has been
	// exchanged.
	Peer() record.NodeID
	// SetPeer records the identity learned from a Hello.
	SetPeer(record.NodeID)
	// Send writes one frame.
	Send(*wire.Frame) error
	// Receive reads one frame, blocking until one arrives or the session ends.
	Receive() (*wire.Frame, error)
	// Transport describes the path: memory, direct or DERP.
	Transport() string
	// RemoteAddr describes the peer's address, for display.
	RemoteAddr() string
	// Close ends the session.
	Close() error
}

// Transport moves frames between nodes.
//
// It is an interface because the tests need an in-process implementation and the real
// deployment needs a tailnet one, and because the tailnet specifics — LocalAPI
// discovery, DERP fallback — have no business leaking into the protocol.
type Transport interface {
	// Dial opens a session to a peer.
	Dial(ctx context.Context, peer record.NodeID) (Session, error)
	// Accept returns the next inbound session, blocking until one arrives, the
	// context is cancelled, or the transport closes.
	Accept(ctx context.Context) (Session, error)
	// Peers returns the currently discovered peers.
	Peers() ([]Peer, error)
	// Discovery describes how peers are found, and why the list is empty when it is.
	// "No peers" and "cannot ask" are different answers and must not look the same.
	Discovery() string
	// Close releases the transport.
	Close() error
}

// DefaultPullInterval is the base period between anti-entropy pulls.
//
// Push-on-write handles latency; this handles correctness. A peer that was asleep when
// a record was pushed catches up here, which is why the interval can be relaxed rather
// than aggressive (plan §5.1.4).
const DefaultPullInterval = 45 * time.Second

// DefaultPullJitter is the random spread applied to each pull.
//
// Jitter matters more than it looks: without it, N nodes that started together stay in
// lockstep and every pull round becomes a synchronised thundering herd.
const DefaultPullJitter = 15 * time.Second

// DefaultPushFanout is how many peers a fresh write is pushed to immediately.
//
// k=3 rather than all peers, because push is a latency optimisation and pull is the
// correctness mechanism. Pushing to everyone would make write cost scale with mesh
// size for a guarantee anti-entropy already provides.
const DefaultPushFanout = 3

// DefaultBatchLimit caps how many records one exchange transfers per space.
//
// Bounded batches are what make a large backfill resumable: a receiver that applies a
// partial batch advances its high-water mark to the last record it stored and asks
// again from there, so an interruption costs one batch rather than the whole transfer.
const DefaultBatchLimit = 256

// DefaultMaxRoundsPerSpace caps how many batches one exchange pulls for a single space.
//
// Sixty-four batches of 256 records is ~16k records per space per exchange, which closes
// a realistic gap in one round while still ending the session in bounded time. A node
// returning after three weeks takes several rounds, and that is the intended behaviour:
// it keeps one very stale peer from monopolising an exchange slot.
const DefaultMaxRoundsPerSpace = 64
