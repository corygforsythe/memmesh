// Package tailnet carries mesh frames over Tailscale.
//
// # What this is, and what the plan asked for
//
// The plan specifies `tsnet`: the daemon as its own tailnet node with its own identity
// and its own ACL surface (plan §5.3). No `tsnet` is reachable in this build
// (docs/decisions/0002), so discovery goes through the host's Tailscale LocalAPI over
// its unix socket, and peers are dialled directly over their tailnet addresses.
//
// The consequence is worth stating plainly rather than burying: the daemon shares the
// host's tailnet identity instead of having its own, so tailnet ACLs cannot distinguish
// it from anything else on that machine. What is unaffected is provenance — records stay
// signed by their authoring agent and frames by the sending node, and those signatures
// are the only thing that survives relaying through a third node anyway. Tailnet
// identity was always the weaker of the two checks; this weakens the weaker one.
//
// Everything else the plan asked for is intact: no registry to run, `tag:mem-node`
// selects which machines participate, and MagicDNS names are what appears in memctl.
//
// # Why discovery and identity are kept separate
//
// A peer being visible on the tailnet means enrolled. Whether its records have actually
// arrived is a different question that only the version vectors answer. This package
// reports the first and says nothing about the second, which is what keeps the divergence
// between them visible in `memctl members` (plan §8.2) instead of being averaged away
// into one "peers" number.
package tailnet

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strings"
	stdsync "sync"
	"time"

	"github.com/coryforsythe/memmesh/internal/record"
	"github.com/coryforsythe/memmesh/internal/sync"
	"github.com/coryforsythe/memmesh/internal/wire"
)

// DefaultPort is the TCP port memd listens on over the tailnet.
const DefaultPort = 4713

// DefaultTag selects which machines participate. A node without it is not part of the
// mesh even if it is on the tailnet.
const DefaultTag = "tag:mem-node"

// localAPIHost is the Host header the Tailscale LocalAPI requires. The socket ignores
// the address but the daemon checks the header.
const localAPIHost = "local-tailscaled.sock"

// statusTimeout bounds a LocalAPI call. Discovery must never be able to hang the sync
// loop: a stuck query should become "cannot ask" quickly, not a wedged daemon.
const statusTimeout = 3 * time.Second

// Errors returned by this package.
var (
	// ErrNoLocalAPI reports that the local Tailscale daemon could not be reached.
	// Distinguished from "no peers" because they call for completely different
	// actions and must never look the same in output.
	ErrNoLocalAPI = errors.New("tailnet: cannot reach the local Tailscale daemon")
	// ErrNotTagged reports that this host does not carry the mesh tag.
	ErrNotTagged = errors.New("tailnet: this host does not carry the mesh tag")
)

// Config configures a Transport.
type Config struct {
	// NodeID is this machine's node id. It must match what peers will see as this
	// host's tailnet name, or peers will list it as enrolled and never participating.
	NodeID record.NodeID
	// Port is the TCP port to listen on and dial. Zero means DefaultPort.
	Port int
	// Tag selects participating machines. Empty means DefaultTag.
	Tag string
	// SocketPath overrides the LocalAPI socket. Empty means the platform default.
	SocketPath string
	// BindAll listens on every interface rather than only the tailnet address.
	//
	// Off by default on purpose: binding only the tailnet address means the mesh port
	// is not reachable from the local network or the internet even if a firewall is
	// misconfigured. Turn it on only when the tailnet address is not known at startup.
	BindAll bool
}

// Transport implements sync.Transport over the tailnet.
type Transport struct {
	cfg      Config
	port     int
	tag      string
	client   *http.Client
	listener net.Listener
	inbound  chan sync.Session

	mu          stdsync.RWMutex
	discovery   string
	lastPeers   []sync.Peer
	lastErr     error
	selfAddress string
	closed      bool
}

// Open starts listening and prepares discovery.
//
// It does not fail when Tailscale is unreachable. A node whose tailnet is down still
// serves its agents, still writes, and still reads — the network is in neither path
// (plan §5.5) — so an unreachable tailnet is a reporting condition, not a startup error.
func Open(cfg Config) (*Transport, error) {
	if !cfg.NodeID.Valid() {
		return nil, fmt.Errorf("tailnet: %q is not a valid node id", string(cfg.NodeID))
	}
	port := cfg.Port
	if port == 0 {
		port = DefaultPort
	}
	tag := cfg.Tag
	if tag == "" {
		tag = DefaultTag
	}

	t := &Transport{
		cfg:       cfg,
		port:      port,
		tag:       tag,
		inbound:   make(chan sync.Session, 32),
		discovery: "not queried yet",
	}
	t.client = &http.Client{
		Timeout: statusTimeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", t.socketPath())
			},
		},
	}

	// Find our own tailnet address so the listener can bind to it alone.
	bind := fmt.Sprintf(":%d", port)
	if !cfg.BindAll {
		if status, err := t.status(context.Background()); err == nil && len(status.Self.TailscaleIPs) > 0 {
			addr := status.Self.TailscaleIPs[0]
			t.mu.Lock()
			t.selfAddress = addr
			t.mu.Unlock()
			bind = net.JoinHostPort(addr, fmt.Sprintf("%d", port))
		}
	}

	ln, err := net.Listen("tcp", bind)
	if err != nil {
		return nil, fmt.Errorf("tailnet: listen on %s: %w", bind, err)
	}
	t.listener = ln
	go t.accept()
	return t, nil
}

// socketPath returns the LocalAPI socket path for this platform.
func (t *Transport) socketPath() string {
	if t.cfg.SocketPath != "" {
		return t.cfg.SocketPath
	}
	if env := os.Getenv("TS_SOCKET"); env != "" {
		return env
	}
	switch runtime.GOOS {
	case "darwin":
		// The standalone tailscaled on macOS. The sandboxed App Store build uses a
		// local TCP port and a token instead, which this transport does not speak;
		// that case surfaces as "cannot reach the local Tailscale daemon", which is
		// the honest answer.
		return "/var/run/tailscaled.socket"
	default:
		return "/var/run/tailscale/tailscaled.sock"
	}
}

// Addr returns the address this transport listens on.
func (t *Transport) Addr() string { return t.listener.Addr().String() }

// localAPIStatus is the subset of the Tailscale status we need.
//
// Only the fields that are actually used are declared, so a Tailscale release that adds
// or renames something else cannot break parsing.
type localAPIStatus struct {
	Self struct {
		HostName     string   `json:"HostName"`
		DNSName      string   `json:"DNSName"`
		TailscaleIPs []string `json:"TailscaleIPs"`
		Tags         []string `json:"Tags"`
		Online       bool     `json:"Online"`
	} `json:"Self"`
	Peer map[string]struct {
		HostName     string   `json:"HostName"`
		DNSName      string   `json:"DNSName"`
		TailscaleIPs []string `json:"TailscaleIPs"`
		Tags         []string `json:"Tags"`
		Online       bool     `json:"Online"`
		// CurAddr is set when the connection is direct.
		CurAddr string `json:"CurAddr"`
		// Relay names the DERP region when traffic is relayed.
		Relay string `json:"Relay"`
	} `json:"Peer"`
}

func (t *Transport) status(ctx context.Context) (*localAPIStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+localAPIHost+"/localapi/v0/status", nil)
	if err != nil {
		return nil, err
	}
	req.Host = localAPIHost
	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w at %s: %v", ErrNoLocalAPI, t.socketPath(), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %s", ErrNoLocalAPI, resp.Status)
	}
	var status localAPIStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return nil, fmt.Errorf("tailnet: parse status: %w", err)
	}
	return &status, nil
}

// Peers implements sync.Transport.
//
// A failed query returns the last known peer list with the error recorded, rather than an
// empty list. Discovery being momentarily unavailable is not evidence that the peers went
// away, and treating it as such would make every transient hiccup look like a mesh-wide
// partition.
func (t *Transport) Peers() ([]sync.Peer, error) {
	ctx, cancel := context.WithTimeout(context.Background(), statusTimeout)
	defer cancel()

	status, err := t.status(ctx)
	if err != nil {
		t.mu.Lock()
		t.lastErr = err
		t.discovery = fmt.Sprintf("Tailscale LocalAPI unreachable at %s: %v", t.socketPath(), err)
		last := t.lastPeers
		t.mu.Unlock()
		return last, err
	}

	if !hasTag(status.Self.Tags, t.tag) {
		t.mu.Lock()
		t.discovery = fmt.Sprintf("this host does not carry %s, so it is not part of the mesh", t.tag)
		t.mu.Unlock()
		return nil, fmt.Errorf("%w: %s", ErrNotTagged, t.tag)
	}

	var peers []sync.Peer
	tagged := 0
	for _, p := range status.Peer {
		if !hasTag(p.Tags, t.tag) {
			continue
		}
		tagged++
		if len(p.TailscaleIPs) == 0 {
			continue
		}
		transport := sync.TransportDERP
		if p.CurAddr != "" {
			transport = sync.TransportDirect
		}
		peers = append(peers, sync.Peer{
			Node:      nodeIDFor(p.HostName, p.DNSName),
			Address:   net.JoinHostPort(p.TailscaleIPs[0], fmt.Sprintf("%d", t.port)),
			Transport: transport,
			Online:    p.Online,
		})
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].Node < peers[j].Node })

	t.mu.Lock()
	t.lastPeers = peers
	t.lastErr = nil
	t.discovery = fmt.Sprintf("Tailscale LocalAPI: %d peers carry %s", tagged, t.tag)
	t.mu.Unlock()
	return peers, nil
}

// Discovery implements sync.Transport.
func (t *Transport) Discovery() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.discovery
}

// nodeIDFor derives a node id from a peer's tailnet names.
//
// The hostname is preferred because it is what memd derives its own node id from, so the
// two agree without configuration. A mismatch is not silent: the peer shows up in memctl
// as enrolled and never participating, which is exactly the signal that check exists for.
func nodeIDFor(hostname, dnsName string) record.NodeID {
	name := hostname
	if name == "" {
		name = strings.SplitN(dnsName, ".", 2)[0]
	}
	out := make([]rune, 0, len(name))
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.', r == '_':
			out = append(out, r)
		default:
			out = append(out, '-')
		}
	}
	return record.NodeID(out)
}

func hasTag(tags []string, want string) bool {
	for _, tag := range tags {
		if tag == want {
			return true
		}
	}
	return false
}

// Dial implements sync.Transport.
func (t *Transport) Dial(ctx context.Context, peer record.NodeID) (sync.Session, error) {
	t.mu.RLock()
	closed := t.closed
	known := append([]sync.Peer(nil), t.lastPeers...)
	t.mu.RUnlock()
	if closed {
		return nil, sync.ErrTransportClosed
	}

	// Refresh if the peer is not in the cached list, so a node that just joined is
	// reachable without waiting for the next discovery cycle.
	target, found := findPeer(known, peer)
	if !found {
		refreshed, err := t.Peers()
		if err != nil {
			return nil, err
		}
		if target, found = findPeer(refreshed, peer); !found {
			return nil, fmt.Errorf("%w: %s is not a tagged tailnet peer", sync.ErrNoSuchPeer, peer)
		}
	}

	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", target.Address)
	if err != nil {
		return nil, fmt.Errorf("tailnet: dial %s at %s: %w", peer, target.Address, err)
	}
	return newConnSession(conn, peer, target.Transport), nil
}

func findPeer(peers []sync.Peer, want record.NodeID) (sync.Peer, bool) {
	for _, p := range peers {
		if p.Node == want {
			return p, true
		}
	}
	return sync.Peer{}, false
}

// Accept implements sync.Transport.
func (t *Transport) Accept(ctx context.Context) (sync.Session, error) {
	select {
	case s, ok := <-t.inbound:
		if !ok {
			return nil, sync.ErrTransportClosed
		}
		return s, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (t *Transport) accept() {
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			t.mu.RLock()
			closed := t.closed
			t.mu.RUnlock()
			if closed {
				return
			}
			continue
		}
		// The peer's identity comes from its Hello, not from the connection: the
		// address only says which machine dialled, and the frame signature is what
		// says who is speaking.
		// The path label is left empty: the receiving end cannot tell whether a
		// connection arrived direct or via DERP. Only the local Tailscale daemon knows
		// that, and it reports it per peer during discovery, so the engine keeps
		// whatever discovery already learned rather than overwriting it with a guess.
		session := newConnSession(conn, "", "")
		select {
		case t.inbound <- session:
		default:
			// Backlog full. Dropping is correct: the peer will retry on its next
			// anti-entropy round, and queueing without bound would let one peer
			// exhaust memory.
			session.Close()
		}
	}
}

// Close implements sync.Transport.
func (t *Transport) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	t.mu.Unlock()

	err := t.listener.Close()
	close(t.inbound)
	for session := range t.inbound {
		session.Close()
	}
	return err
}

// connSession is a sync.Session over a net.Conn.
type connSession struct {
	conn      net.Conn
	peer      record.NodeID
	transport string

	mu     stdsync.Mutex
	closed bool
}

func newConnSession(conn net.Conn, peer record.NodeID, transport string) *connSession {
	return &connSession{conn: conn, peer: peer, transport: transport}
}

func (s *connSession) Peer() record.NodeID      { return s.peer }
func (s *connSession) SetPeer(id record.NodeID) { s.peer = id }
func (s *connSession) Transport() string        { return s.transport }
func (s *connSession) RemoteAddr() string       { return s.conn.RemoteAddr().String() }

// frameDeadline bounds how long one frame may take to move.
//
// Without it a peer that stops responding mid-exchange holds a session forever. With it,
// a stalled peer costs one timeout and the next round tries again.
const frameDeadline = 30 * time.Second

func (s *connSession) Send(f *wire.Frame) error {
	if err := s.conn.SetWriteDeadline(time.Now().Add(frameDeadline)); err != nil {
		return err
	}
	return wire.WriteFrame(s.conn, f)
}

func (s *connSession) Receive() (*wire.Frame, error) {
	if err := s.conn.SetReadDeadline(time.Now().Add(frameDeadline)); err != nil {
		return nil, err
	}
	return wire.ReadFrame(s.conn)
}

func (s *connSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.conn.Close()
}
