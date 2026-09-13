package sync

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sort"
	stdsync "sync"
	"time"

	"github.com/coryforsythe/memmesh/internal/admin"
	"github.com/coryforsythe/memmesh/internal/clock"
	"github.com/coryforsythe/memmesh/internal/daemon"
	"github.com/coryforsythe/memmesh/internal/hlc"
	"github.com/coryforsythe/memmesh/internal/node"
	"github.com/coryforsythe/memmesh/internal/record"
	"github.com/coryforsythe/memmesh/internal/wire"
)

// Config configures an Engine.
type Config struct {
	// Node is the local node.
	Node *node.Node
	// Transport moves frames. Required.
	Transport Transport
	// Signer signs outbound frames. This authenticates the hop; records keep their
	// own author signatures, which are the only thing that survives relaying.
	Signer *record.Signer
	// Clock is the time source, injected so tests are deterministic.
	Clock clock.Clock
	// Rand is the randomness source for pull jitter and push peer selection.
	// Injected for the same reason: a convergence test that flakes is a failed test,
	// not a retry (plan §0.5).
	Rand *rand.Rand

	// PullInterval and PullJitter set the anti-entropy cadence.
	PullInterval time.Duration
	PullJitter   time.Duration
	// PushFanout is how many peers a fresh write is pushed to.
	PushFanout int
	// BatchLimit caps records per space per batch.
	BatchLimit int
	// MaxRoundsPerSpace caps how many batches one exchange will pull for a single
	// space before returning.
	//
	// It bounds how long one peer can hold a session while closing a large gap, so a
	// node with several peers gives each of them a turn instead of spending an entire
	// round backfilling from the first one. A capped exchange is not a failed one: the
	// remaining records come on the next round, because the high-water mark advanced.
	MaxRoundsPerSpace int
}

// Engine runs anti-entropy for one node.
//
// An Engine is safe for concurrent use.
type Engine struct {
	cfg  Config
	node *node.Node

	mu       stdsync.RWMutex
	peers    map[record.NodeID]*peerState
	outbound []*pending
	lastSync *admin.SyncEvent
	closed   bool
}

// peerState is what this node has learned about a peer.
//
// Every field is a memory of a past exchange, never a live reading. memctl reports it
// with an age attached rather than presenting it as current (plan §8).
type peerState struct {
	node        record.NodeID
	enrolled    bool
	address     string
	transport   string
	software    string
	embedModel  string
	lastContact time.Time
	clockSkewMS int64
	vectors     map[record.SpaceID]record.VersionVector
	agentKeys   map[string]bool
	asOf        time.Time
}

// pending is a record waiting to be pushed.
type pending struct {
	space record.SpaceID
	entry *wire.SealedRecord
}

// New builds an Engine and registers it as the node's write hook.
func New(cfg Config) (*Engine, error) {
	if cfg.Node == nil {
		return nil, errors.New("sync: Node is required")
	}
	if cfg.Transport == nil {
		return nil, errors.New("sync: Transport is required")
	}
	if cfg.Signer == nil {
		return nil, errors.New("sync: Signer is required")
	}
	if cfg.Clock == nil {
		cfg.Clock = clock.System{}
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.New(rand.NewSource(int64(cfg.Clock.NowMillis())))
	}
	if cfg.PullInterval <= 0 {
		cfg.PullInterval = DefaultPullInterval
	}
	if cfg.PullJitter < 0 {
		cfg.PullJitter = DefaultPullJitter
	}
	if cfg.PushFanout <= 0 {
		cfg.PushFanout = DefaultPushFanout
	}
	if cfg.BatchLimit <= 0 {
		cfg.BatchLimit = DefaultBatchLimit
	}
	if cfg.MaxRoundsPerSpace <= 0 {
		cfg.MaxRoundsPerSpace = DefaultMaxRoundsPerSpace
	}

	e := &Engine{cfg: cfg, node: cfg.Node, peers: make(map[record.NodeID]*peerState)}
	cfg.Node.SetWriteHook(e.enqueue)
	return e, nil
}

// enqueue records a locally written record for pushing.
//
// It never blocks and never fails. The network is not in the write path (plan §5.5), so
// a full queue or an unreachable peer must not be able to make a write fail — the
// record is already durable on disk, and anti-entropy will deliver it eventually
// whatever happens here.
func (e *Engine) enqueue(space record.SpaceID, entry *wire.SealedRecord) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return
	}
	e.outbound = append(e.outbound, &pending{space: space, entry: entry})
}

// Run serves inbound sessions and drives the pull loop until the context is cancelled.
func (e *Engine) Run(ctx context.Context) error {
	var wg stdsync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		e.serveLoop(ctx)
	}()
	go func() {
		defer wg.Done()
		e.pullLoop(ctx)
	}()
	wg.Wait()
	return ctx.Err()
}

func (e *Engine) serveLoop(ctx context.Context) {
	for {
		session, err := e.cfg.Transport.Accept(ctx)
		if err != nil {
			return
		}
		go func() {
			defer session.Close()
			if err := e.respond(session); err != nil {
				// A failed exchange with one peer is that peer's problem. The next
				// pull round tries again, which is the entire recovery story.
				_ = err
			}
		}()
	}
}

// pullLoop runs anti-entropy on a jittered interval.
//
// Jitter is applied per tick rather than once at startup, so nodes that begin together
// drift apart instead of colliding on every round forever.
func (e *Engine) pullLoop(ctx context.Context) {
	for {
		wait := e.cfg.PullInterval
		if e.cfg.PullJitter > 0 {
			wait += time.Duration(e.cfg.Rand.Int63n(int64(e.cfg.PullJitter)))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		_, _ = e.SyncNow("", "")
	}
}

// PushNow delivers the queued writes to a few random subscribed peers.
//
// Push is a latency optimisation, not a correctness mechanism: a push that fails is
// dropped and the record is delivered by the next pull instead. That is why the fanout
// can be small and why nothing here retries.
func (e *Engine) PushNow(ctx context.Context) (int, error) {
	e.mu.Lock()
	queued := e.outbound
	e.outbound = nil
	e.mu.Unlock()
	if len(queued) == 0 {
		return 0, nil
	}

	peers, err := e.cfg.Transport.Peers()
	if err != nil {
		// Re-queue: discovery being unavailable is not the records' fault.
		e.requeue(queued)
		return 0, err
	}
	online := make([]Peer, 0, len(peers))
	for _, p := range peers {
		if p.Online {
			online = append(online, p)
		}
	}
	if len(online) == 0 {
		e.requeue(queued)
		return 0, nil
	}

	// Group by space, so one frame per space per peer carries everything queued.
	bySpace := make(map[record.SpaceID][]*wire.SealedRecord)
	for _, p := range queued {
		bySpace[p.space] = append(bySpace[p.space], p.entry)
	}

	targets := e.pickPeers(online, e.cfg.PushFanout)
	pushed := 0
	for _, peer := range targets {
		session, err := e.cfg.Transport.Dial(ctx, peer.Node)
		if err != nil {
			continue
		}
		if err := e.pushTo(session, bySpace); err == nil {
			pushed++
		}
		session.Close()
	}
	return pushed, nil
}

func (e *Engine) requeue(queued []*pending) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.outbound = append(queued, e.outbound...)
}

// pickPeers chooses up to k peers at random, using the injected RNG so a test can
// reproduce the selection exactly.
func (e *Engine) pickPeers(peers []Peer, k int) []Peer {
	if len(peers) <= k {
		return peers
	}
	shuffled := append([]Peer(nil), peers...)
	e.cfg.Rand.Shuffle(len(shuffled), func(i, j int) {
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	})
	return shuffled[:k]
}

func (e *Engine) pushTo(session Session, bySpace map[record.SpaceID][]*wire.SealedRecord) error {
	if _, err := e.handshake(session, true); err != nil {
		return err
	}
	spaces := make([]record.SpaceID, 0, len(bySpace))
	for space := range bySpace {
		spaces = append(spaces, space)
	}
	sort.Slice(spaces, func(i, j int) bool { return spaces[i] < spaces[j] })

	for _, space := range spaces {
		bundle, err := wire.EncodeBundle(bySpace[space])
		if err != nil {
			return err
		}
		frame, err := wire.NewBundleFrame(wire.MsgRecords, wire.Version, space, bundle, e.cfg.Signer)
		if err != nil {
			return err
		}
		if err := session.Send(frame); err != nil {
			return err
		}
	}
	return nil
}

// SyncNow forces an anti-entropy round, optionally limited to one peer and one space.
func (e *Engine) SyncNow(only record.NodeID, space record.SpaceID) (*admin.Sync, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	peers, err := e.cfg.Transport.Peers()
	if err != nil {
		return nil, fmt.Errorf("sync: discover peers: %w", err)
	}
	out := &admin.Sync{Errors: make(map[string]string)}

	// Flush pending pushes first: a forced sync should deliver local writes as well
	// as collect remote ones, which is what an operator typing `memctl sync` means.
	if _, err := e.PushNow(ctx); err != nil {
		out.Errors["push"] = err.Error()
	}

	for _, peer := range peers {
		if only != "" && peer.Node != only {
			continue
		}
		if !peer.Online {
			out.Errors[string(peer.Node)] = "offline"
			continue
		}
		out.Attempted = append(out.Attempted, peer.Node)
		event, err := e.exchangeWith(ctx, peer, space)
		if err != nil {
			out.Errors[string(peer.Node)] = err.Error()
			continue
		}
		out.Events = append(out.Events, *event)
	}
	if len(out.Errors) == 0 {
		out.Errors = nil
	}
	if only != "" && len(out.Attempted) == 0 {
		return out, fmt.Errorf("%w: %s", ErrNoSuchPeer, only)
	}
	return out, nil
}

// exchangeWith runs one pull against a peer.
//
// # An exchange pulls; it does not offer
//
// The initiator asks for what it is missing and stops. It does not push its own records
// at the peer, and the reason is worth stating because the alternative looks tempting:
//
//   - Every node pulls from every peer on its own anti-entropy round, so records travel
//     in both directions across a pair without either side needing to offer. Convergence
//     comes from both nodes pulling, not from one round being bidirectional.
//   - A request/response shape means every transfer is asked for. An offer step would
//     have the initiator writing frames the peer never requested, on a session the
//     initiator is about to close, which is a lost-frame race dressed up as an
//     optimisation.
//   - Fresh writes do not wait for the next pull: push-on-write delivers them
//     immediately (plan §5.1.3). Push covers latency, pull covers correctness, and
//     neither needs to do the other's job.
//
// The one cost is a node that can dial out but not accept: it would give up records only
// through push. On a tailnet every node is dialable, so that case does not arise here.
func (e *Engine) exchangeWith(ctx context.Context, peer Peer, onlySpace record.SpaceID) (*admin.SyncEvent, error) {
	session, err := e.cfg.Transport.Dial(ctx, peer.Node)
	if err != nil {
		return nil, err
	}
	defer session.Close()

	peerHello, err := e.handshake(session, true)
	if err != nil {
		return nil, err
	}

	// Exchange vectors. Ours goes first because we opened the connection; theirs
	// tells us what to ask for.
	if err := e.sendVectors(session, onlySpace); err != nil {
		return nil, err
	}
	theirVectors, err := e.expectVectors(session)
	if err != nil {
		return nil, err
	}
	e.rememberVectors(peer.Node, theirVectors)

	received := 0

	// Ask for what we are missing, one space at a time, so a failure on one space
	// does not abandon the others.
	for _, space := range e.commonSpaces(theirVectors, onlySpace) {
		got, err := e.pullSpace(session, space, theirVectors[space])
		if err != nil {
			return nil, err
		}
		received += got
	}

	event := &admin.SyncEvent{
		Peer:     peer.Node,
		At:       e.cfg.Clock.Now(),
		Received: received,
	}
	e.recordExchange(peer, peerHello, session, event)
	return event, nil
}

// respond handles an inbound session: the mirror of exchangeWith.
func (e *Engine) respond(session Session) error {
	peerHello, err := e.handshake(session, false)
	if err != nil {
		return err
	}
	// Deliberately no address or transport label. An inbound connection's remote
	// address is the peer's ephemeral source port, not the port it listens on, and the
	// receiving end cannot tell a direct path from a relayed one. Recording either
	// would overwrite what discovery knows with something less true.
	peer := Peer{Node: peerHello.Node, Online: true}
	event := &admin.SyncEvent{Peer: peerHello.Node, At: e.cfg.Clock.Now()}

	for {
		frame, err := session.Receive()
		if err != nil {
			// End of session. Record what happened before returning, so even a
			// push-only exchange shows up in status.
			e.recordExchange(peer, peerHello, session, event)
			return nil
		}
		switch frame.Type {
		case wire.MsgVectors:
			theirs, err := wire.DecodeVectors(frame.Payload)
			if err != nil {
				return err
			}
			e.rememberVectors(peerHello.Node, theirs.Vectors)
			if err := e.sendVectors(session, ""); err != nil {
				return err
			}

		case wire.MsgWant:
			want, err := wire.DecodeWant(frame.Payload)
			if err != nil {
				return err
			}
			n, err := e.serveRanges(session, frame.Space, want)
			if err != nil {
				return err
			}
			event.Sent += n

		case wire.MsgRecords:
			n, err := e.acceptBundle(frame)
			if err != nil {
				return err
			}
			event.Received += n

		case wire.MsgPing:
			live, err := wire.DecodeLiveness(frame.Payload)
			if err != nil {
				return err
			}
			pong := &wire.Liveness{
				Nonce:      live.Nonce,
				WallMillis: e.cfg.Clock.NowMillis(),
				HLC:        e.node.Stamps().Peek(),
			}
			reply, err := wire.NewControlFrame(wire.MsgPong, frame.Version, pong.Encode(), e.cfg.Signer)
			if err != nil {
				return err
			}
			if err := session.Send(reply); err != nil {
				return err
			}

		case wire.MsgPong, wire.MsgError:
			// Nothing to do on the responding side.

		default:
			payload := (&wire.ErrorPayload{
				Code:    wire.ErrCodeMalformed,
				Message: fmt.Sprintf("unexpected %s on an inbound session", frame.Type),
			}).Encode()
			reply, err := wire.NewControlFrame(wire.MsgError, frame.Version, payload, e.cfg.Signer)
			if err != nil {
				return err
			}
			if err := session.Send(reply); err != nil {
				return err
			}
		}
	}
}

// handshake exchanges Hello and HelloAck and returns the peer's half.
//
// The initiator sends Hello and reads HelloAck; the responder does the reverse. Version
// negotiation happens here and fails the session rather than guessing: a peer with no
// version in common is a peer to refuse.
func (e *Engine) handshake(session Session, initiator bool) (*wire.Hello, error) {
	mine := e.hello()

	send := func() error {
		typ := wire.MsgHello
		if !initiator {
			typ = wire.MsgHelloAck
		}
		frame, err := wire.NewControlFrame(typ, wire.Version, mine.Encode(), e.cfg.Signer)
		if err != nil {
			return err
		}
		return session.Send(frame)
	}
	recv := func() (*wire.Hello, error) {
		frame, err := session.Receive()
		if err != nil {
			return nil, err
		}
		wantType := wire.MsgHelloAck
		if !initiator {
			wantType = wire.MsgHello
		}
		if frame.Type != wantType {
			return nil, fmt.Errorf("%w: expected %s, got %s", wire.ErrMalformed, wantType, frame.Type)
		}
		return wire.DecodeHello(frame.Payload)
	}

	var peerHello *wire.Hello
	var err error
	if initiator {
		if err = send(); err != nil {
			return nil, err
		}
		if peerHello, err = recv(); err != nil {
			return nil, err
		}
	} else {
		if peerHello, err = recv(); err != nil {
			return nil, err
		}
		if err = send(); err != nil {
			return nil, err
		}
	}

	if _, err := wire.Negotiate(peerHello.Versions); err != nil {
		return nil, err
	}
	session.SetPeer(peerHello.Node)
	return peerHello, nil
}

func (e *Engine) hello() *wire.Hello {
	return &wire.Hello{
		Versions:   wire.SupportedVersions(),
		Node:       e.node.ID(),
		Software:   node.Software,
		WallMillis: e.cfg.Clock.NowMillis(),
		Spaces:     e.node.SpaceIDs(),
		Relaying:   e.node.Relaying(),
		EmbedModel: e.node.Embedder().ModelID(),
	}
}

func (e *Engine) sendVectors(session Session, onlySpace record.SpaceID) error {
	vectors := e.node.Vectors()
	if onlySpace != "" {
		filtered := make(map[record.SpaceID]record.VersionVector, 1)
		if vv, ok := vectors[onlySpace]; ok {
			filtered[onlySpace] = vv
		}
		vectors = filtered
	}
	payload := (&wire.Vectors{Vectors: vectors}).Encode()
	frame, err := wire.NewControlFrame(wire.MsgVectors, wire.Version, payload, e.cfg.Signer)
	if err != nil {
		return err
	}
	return session.Send(frame)
}

func (e *Engine) expectVectors(session Session) (map[record.SpaceID]record.VersionVector, error) {
	frame, err := session.Receive()
	if err != nil {
		return nil, err
	}
	if frame.Type == wire.MsgError {
		payload, decodeErr := wire.DecodeError(frame.Payload)
		if decodeErr != nil {
			return nil, decodeErr
		}
		return nil, fmt.Errorf("peer refused: %s (%s)", payload.Message, payload.Code)
	}
	if frame.Type != wire.MsgVectors {
		return nil, fmt.Errorf("%w: expected vectors, got %s", wire.ErrMalformed, frame.Type)
	}
	v, err := wire.DecodeVectors(frame.Payload)
	if err != nil {
		return nil, err
	}
	return v.Vectors, nil
}

// commonSpaces lists the spaces both sides hold, which is the only set worth syncing.
// Partial participation is the normal case, so a space the peer does not carry is not a
// problem to report (plan §3.1).
func (e *Engine) commonSpaces(theirs map[record.SpaceID]record.VersionVector, onlySpace record.SpaceID) []record.SpaceID {
	mine := e.node.Vectors()
	var out []record.SpaceID
	for space := range theirs {
		if onlySpace != "" && space != onlySpace {
			continue
		}
		if _, ok := mine[space]; ok {
			out = append(out, space)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// pullSpace asks for the ranges this node is missing in one space, and applies what
// comes back.
//
// The loop continues while the peer keeps returning a full batch, so a large gap closes
// over several bounded transfers rather than one unbounded one. Each applied batch
// advances the local high-water mark, which is what makes an interruption cost a batch
// instead of the whole backfill.
func (e *Engine) pullSpace(session Session, space record.SpaceID, theirs record.VersionVector) (int, error) {
	total := 0
	for round := 0; round < e.cfg.MaxRoundsPerSpace; round++ {
		local, ok := e.node.Store().Get(space)
		if !ok {
			return total, nil
		}
		missing := local.Vector().MissingFrom(theirs)
		if len(missing) == 0 {
			return total, nil
		}

		want := &wire.Want{Ranges: missing, Limit: uint32(e.cfg.BatchLimit)}
		frame, err := wire.NewMetaFrame(wire.MsgWant, wire.Version, space, 0, want.Encode(), e.cfg.Signer)
		if err != nil {
			return total, err
		}
		if err := session.Send(frame); err != nil {
			return total, err
		}

		reply, err := session.Receive()
		if err != nil {
			return total, err
		}
		switch reply.Type {
		case wire.MsgRecords:
			n, err := e.acceptBundle(reply)
			if err != nil {
				return total, err
			}
			total += n
			if n == 0 {
				// The peer has nothing more for us even though our vector says
				// otherwise. That happens when it holds the high-water record but
				// not the ones below it, and looping again would spin.
				return total, nil
			}
		case wire.MsgError:
			payload, decodeErr := wire.DecodeError(reply.Payload)
			if decodeErr != nil {
				return total, decodeErr
			}
			// A peer that cannot serve a space is a normal answer, not a failure:
			// it may relay the space without a key, or not carry it at all.
			if payload.Code == wire.ErrCodeNoSpace || payload.Code == wire.ErrCodeNoKey {
				return total, nil
			}
			return total, fmt.Errorf("peer refused %s: %s (%s)", space, payload.Message, payload.Code)
		default:
			return total, fmt.Errorf("%w: expected records, got %s", wire.ErrMalformed, reply.Type)
		}
	}
	return total, nil
}

// serveRanges sends the records a peer asked for.
//
// A relay serves this path with no key at all: the ranges are defined over the record
// id and authoring node, both of which live in the plaintext envelope, and the sealed
// blobs are forwarded byte for byte (docs/decisions/0006).
func (e *Engine) serveRanges(session Session, space record.SpaceID, want *wire.Want) (int, error) {
	local, ok := e.node.Store().Get(space)
	if !ok {
		payload := (&wire.ErrorPayload{
			Code:    wire.ErrCodeNoSpace,
			Message: fmt.Sprintf("this node does not carry %s", space),
		}).Encode()
		frame, err := wire.NewControlFrame(wire.MsgError, wire.Version, payload, e.cfg.Signer)
		if err != nil {
			return 0, err
		}
		return 0, session.Send(frame)
	}

	limit := int(want.Limit)
	if limit <= 0 || limit > e.cfg.BatchLimit {
		limit = e.cfg.BatchLimit
	}

	var entries []*wire.SealedRecord
	for _, authorNode := range sortedNodeKeys(want.Ranges) {
		if len(entries) >= limit {
			break
		}
		batch, err := local.Log().Range(authorNode, want.Ranges[authorNode], limit-len(entries))
		if err != nil {
			return 0, err
		}
		entries = append(entries, batch...)
	}

	bundle, err := wire.EncodeBundle(entries)
	if err != nil {
		return 0, err
	}
	frame, err := wire.NewBundleFrame(wire.MsgRecords, wire.Version, space, bundle, e.cfg.Signer)
	if err != nil {
		return 0, err
	}
	if err := session.Send(frame); err != nil {
		return 0, err
	}
	return len(entries), nil
}

// acceptBundle stores the records in a bundle frame.
func (e *Engine) acceptBundle(frame *wire.Frame) (int, error) {
	entries, err := wire.DecodeBundle(frame.Space, frame.Payload)
	if err != nil {
		return 0, err
	}
	if len(entries) == 0 {
		return 0, nil
	}
	written, err := e.node.Accept(frame.Space, entries...)
	if err != nil {
		if errors.Is(err, node.ErrNoSuchSpace) {
			// A peer offered a space this node neither holds nor relays. Declining
			// is correct: relaying is opt-in (docs/decisions/0003).
			return 0, nil
		}
		return written, err
	}
	return written, nil
}

// rememberVectors stores a peer's sync state for the members view and the lag numbers.
func (e *Engine) rememberVectors(peer record.NodeID, vectors map[record.SpaceID]record.VersionVector) {
	if peer == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	state := e.peerLocked(peer)
	state.vectors = make(map[record.SpaceID]record.VersionVector, len(vectors))
	for space, vv := range vectors {
		state.vectors[space] = vv.Clone()
	}
	state.asOf = e.cfg.Clock.Now()
}

// recordExchange folds what an exchange revealed into the peer's state.
func (e *Engine) recordExchange(peer Peer, peerHello *wire.Hello, session Session, event *admin.SyncEvent) {
	if peerHello == nil || peerHello.Node == "" {
		return
	}
	now := e.cfg.Clock.Now()

	e.mu.Lock()
	state := e.peerLocked(peerHello.Node)
	state.enrolled = true
	state.software = peerHello.Software
	state.embedModel = peerHello.EmbedModel
	state.lastContact = now
	state.asOf = now
	// Address and path label come from discovery, which knows the port a peer listens
	// on and whether the path is relayed. A session knows neither reliably, so it only
	// contributes when it was the dialling side.
	if peer.Address != "" {
		state.address = peer.Address
		state.transport = peer.Transport
	} else if session != nil && session.Transport() != "" {
		state.transport = session.Transport()
		state.address = session.RemoteAddr()
	}
	// Skew is measured against the local physical clock at the moment the peer's
	// reading arrived. Positive means the peer is ahead.
	state.clockSkewMS = hlc.Skew(hlc.HLC{Wall: peerHello.WallMillis}, e.cfg.Clock.NowMillis())

	if event != nil {
		e.lastSync = &admin.SyncEvent{
			Peer:     event.Peer,
			At:       event.At,
			Sent:     event.Sent,
			Received: event.Received,
		}
	}
	e.mu.Unlock()
}

// peerLocked returns a peer's state, creating it. Caller holds the write lock.
func (e *Engine) peerLocked(peer record.NodeID) *peerState {
	state, ok := e.peers[peer]
	if !ok {
		state = &peerState{node: peer, agentKeys: make(map[string]bool)}
		e.peers[peer] = state
	}
	return state
}

// Peers implements daemon.Syncer.
func (e *Engine) Peers() []daemon.PeerState {
	discovered, _ := e.cfg.Transport.Peers()
	online := make(map[record.NodeID]Peer, len(discovered))
	for _, p := range discovered {
		online[p.Node] = p
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	seen := make(map[record.NodeID]bool, len(e.peers)+len(online))
	for id := range e.peers {
		seen[id] = true
	}
	for id := range online {
		seen[id] = true
	}

	ids := make([]record.NodeID, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })

	out := make([]daemon.PeerState, 0, len(ids))
	for _, id := range ids {
		ps := daemon.PeerState{Node: id}
		if p, ok := online[id]; ok {
			ps.Enrolled = true
			ps.Address = p.Address
			ps.Transport = p.Transport
		}
		if state, ok := e.peers[id]; ok {
			ps.Software = state.software
			ps.EmbedModel = state.embedModel
			ps.LastContact = state.lastContact
			ps.ClockSkewMS = state.clockSkewMS
			ps.AsOf = state.asOf
			if state.address != "" {
				ps.Address = state.address
				ps.Transport = state.transport
			}
			ps.PeerVectors = make(map[record.SpaceID]record.VersionVector, len(state.vectors))
			for space, vv := range state.vectors {
				ps.PeerVectors[space] = vv.Clone()
			}
			for key := range state.agentKeys {
				ps.AgentKeys = append(ps.AgentKeys, key)
			}
			sort.Strings(ps.AgentKeys)
		}
		out = append(out, ps)
	}
	return out
}

// OutboundQueue implements daemon.Syncer.
func (e *Engine) OutboundQueue() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.outbound)
}

// LastSync implements daemon.Syncer.
func (e *Engine) LastSync() *admin.SyncEvent {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.lastSync == nil {
		return nil
	}
	out := *e.lastSync
	out.AgeSec = int64(e.cfg.Clock.Now().Sub(out.At).Seconds())
	return &out
}

// Discovery implements daemon.Syncer.
func (e *Engine) Discovery() string { return e.cfg.Transport.Discovery() }

// Close stops accepting work. It does not close the transport; whoever built it owns
// it.
func (e *Engine) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed = true
	e.outbound = nil
	return nil
}

func sortedNodeKeys[V any](m map[record.NodeID]V) []record.NodeID {
	out := make([]record.NodeID, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
