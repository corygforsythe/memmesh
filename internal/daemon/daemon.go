// Package daemon assembles a running memd: the node, the admin socket, the MCP
// listener, and the health checks.
//
// # Why the MCP server is on a socket rather than stdio in-process
//
// The daemon owns the log files, and two processes cannot both own them. Agents want
// MCP over stdio, so `memd mcp` is a thin stdio-to-socket bridge and the real MCP
// server lives here, next to the store. That keeps exactly one writer per space while
// letting any number of agents attach (plan §7).
package daemon

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/coryforsythe/memmesh/internal/admin"
	"github.com/coryforsythe/memmesh/internal/crypto"
	"github.com/coryforsythe/memmesh/internal/hlc"
	"github.com/coryforsythe/memmesh/internal/mcp"
	"github.com/coryforsythe/memmesh/internal/node"
	"github.com/coryforsythe/memmesh/internal/record"
	"github.com/coryforsythe/memmesh/internal/wire"
)

// MCPSocketName is the socket agents reach the MCP server on.
const MCPSocketName = "memd-mcp.sock"

// Syncer is the sync engine's surface as the daemon needs it.
//
// It is an interface so a node with no transport configured still runs, reports
// honestly, and serves agents. A single machine with no peers is a supported
// deployment, not a degraded one.
type Syncer interface {
	// Peers returns what this node knows about its peers.
	Peers() []PeerState
	// OutboundQueue returns how many records are waiting to be pushed.
	OutboundQueue() int
	// LastSync returns the most recent successful exchange, or nil.
	LastSync() *admin.SyncEvent
	// SyncNow forces anti-entropy, optionally with one peer and one space.
	SyncNow(peer record.NodeID, space record.SpaceID) (*admin.Sync, error)
	// Discovery describes how peers were found, including why the list is empty.
	Discovery() string
}

// PeerState is what the daemon needs to know about one peer.
//
// Every field is what this node last learned, never a live reading: memctl does not
// touch the network (plan §8), so staleness is the normal condition and AsOf is how a
// caller judges it.
type PeerState struct {
	Node        record.NodeID
	Enrolled    bool
	Address     string
	Transport   string
	Software    string
	EmbedModel  string
	LastContact time.Time
	ClockSkewMS int64
	PeerVectors map[record.SpaceID]record.VersionVector
	AgentKeys   []string
	AsOf        time.Time
}

// Daemon is a running memd.
type Daemon struct {
	node    *node.Node
	started time.Time

	adminSrv *admin.Server
	mcpSrv   *mcp.Server
	mcpLn    net.Listener

	mu     sync.RWMutex
	syncer Syncer
	closed bool
}

// Config configures a Daemon.
type Config struct {
	// Node is the already-opened node.
	Node *node.Node
	// Dir is where the sockets live, normally the data directory.
	Dir string
}

// Start brings up the admin socket and the MCP listener.
func Start(cfg Config) (*Daemon, error) {
	if cfg.Node == nil {
		return nil, errors.New("daemon: Node is required")
	}
	d := &Daemon{node: cfg.Node, started: cfg.Node.Clock().Now()}

	d.mcpSrv = mcp.NewServer("memmesh", node.Software)
	mcp.Attach(d.mcpSrv, cfg.Node)

	adminSrv, err := admin.Listen(cfg.Dir, d)
	if err != nil {
		return nil, err
	}
	d.adminSrv = adminSrv

	mcpPath := filepath.Join(cfg.Dir, MCPSocketName)
	if err := removeStaleSocket(mcpPath); err != nil {
		adminSrv.Close()
		return nil, err
	}
	ln, err := net.Listen("unix", mcpPath)
	if err != nil {
		adminSrv.Close()
		return nil, fmt.Errorf("daemon: listen on the mcp socket: %w", err)
	}
	if err := os.Chmod(mcpPath, 0o600); err != nil {
		ln.Close()
		adminSrv.Close()
		return nil, fmt.Errorf("daemon: chmod the mcp socket: %w", err)
	}
	d.mcpLn = ln
	go d.acceptMCP()

	return d, nil
}

func removeStaleSocket(path string) error {
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	if conn, err := net.Dial("unix", path); err == nil {
		conn.Close()
		return fmt.Errorf("daemon: something is already listening on %s", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("daemon: remove stale socket %s: %w", path, err)
	}
	return nil
}

func (d *Daemon) acceptMCP() {
	for {
		conn, err := d.mcpLn.Accept()
		if err != nil {
			d.mu.RLock()
			closed := d.closed
			d.mu.RUnlock()
			if closed {
				return
			}
			continue
		}
		go func() {
			defer conn.Close()
			// One MCP session per connection. A failing session is that agent's
			// problem, not the daemon's.
			_ = d.mcpSrv.Serve(conn, conn)
		}()
	}
}

// SetSyncer attaches a sync engine. Safe to call before or after Start.
func (d *Daemon) SetSyncer(s Syncer) {
	d.mu.Lock()
	d.syncer = s
	d.mu.Unlock()
}

// Node returns the daemon's node.
func (d *Daemon) Node() *node.Node { return d.node }

// MCPSocket returns the path agents connect to.
func (d *Daemon) MCPSocket() string { return d.mcpLn.Addr().String() }

// AdminSocket returns the path memctl connects to.
func (d *Daemon) AdminSocket() string { return d.adminSrv.Path() }

// Handle implements admin.Handler.
func (d *Daemon) Handle(req admin.Request) admin.Response {
	switch req.Command {
	case admin.CmdStatus:
		return admin.Response{OK: true, Status: d.status()}
	case admin.CmdSpaces:
		return admin.Response{OK: true, Spaces: d.spaces(req.Space)}
	case admin.CmdMembers:
		return admin.Response{OK: true, Members: d.members()}
	case admin.CmdHealth:
		return admin.Response{OK: true, Health: d.health(req.Check)}
	case admin.CmdKeys:
		return admin.Response{OK: true, Keys: d.keys()}
	case admin.CmdSync:
		s := d.currentSyncer()
		if s == nil {
			return admin.Response{Error: "no transport is configured on this node, so there is nothing to sync with"}
		}
		result, err := s.SyncNow(req.Peer, req.Space)
		if err != nil {
			return admin.Response{Error: err.Error()}
		}
		return admin.Response{OK: true, Sync: result}
	default:
		return admin.Response{Error: fmt.Sprintf("unknown command %q", req.Command)}
	}
}

func (d *Daemon) currentSyncer() Syncer {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.syncer
}

func (d *Daemon) status() *admin.Status {
	n := d.node
	readable := n.ReadableSpaces()
	relayed := n.RelayedSpaces()

	var records int
	var bytes int64
	for _, s := range n.Store().Stats() {
		records += s.Records
		bytes += s.Bytes
	}

	st := &admin.Status{
		Node:               n.ID(),
		Software:           node.Software,
		WireVersion:        wire.Version,
		Protocol:           admin.Protocol,
		UptimeSec:          int64(n.Clock().Now().Sub(d.started).Seconds()),
		Agents:             d.agentInfo(),
		SpacesReadable:     len(readable),
		SpacesRelayed:      len(relayed),
		SpacesTotal:        len(readable) + len(relayed),
		Relaying:           n.Relaying(),
		Records:            records,
		Bytes:              bytes,
		IndexResidentBytes: n.IndexResidentBytes(),
		RAMBudgetBytes:     n.RAMBudgetBytes(),
		IndexedRecords:     n.IndexedRecords(),
		EmbedModel:         n.Embedder().ModelID(),
		Warm:               n.Warm(),
		Recipient:          n.Recipient().String(),
	}
	if s := d.currentSyncer(); s != nil {
		st.OutboundQueue = s.OutboundQueue()
		st.LastSync = s.LastSync()
	}
	return st
}

// agentInfo pairs each named agent key with how many records it has authored.
func (d *Daemon) agentInfo() []admin.AgentInfo {
	counts := d.node.AgentCounts()
	var out []admin.AgentInfo
	for _, name := range d.node.Agents() {
		info := admin.AgentInfo{Name: name}
		// The signer is reachable only through the node, so re-derive the id by
		// asking for the builder's identity.
		if id, ok := d.node.AgentIDFor(name); ok {
			info.AgentID = id.String()
			info.Fingerprint = id.Fingerprint()
			info.Records = counts[id]
		}
		out = append(out, info)
	}
	return out
}

func (d *Daemon) spaces(only record.SpaceID) *admin.Spaces {
	out := &admin.Spaces{}
	for _, info := range d.node.ListSpaces() {
		if only != "" && info.Space != only {
			continue
		}
		out.Spaces = append(out.Spaces, admin.SpaceRow{
			Space:         info.Space,
			Class:         info.Class,
			Readable:      info.Readable,
			Policy:        info.Policy,
			Epoch:         info.Epoch,
			Records:       info.Records,
			Bytes:         info.Bytes,
			Indexed:       info.Indexed,
			ByKind:        info.ByKind,
			Undecryptable: info.Undecryptable,
		})
	}
	// Fill in the per-space participating-node counts, which only the store knows.
	stats := make(map[record.SpaceID]int)
	for _, s := range d.node.Store().Stats() {
		stats[s.Space] = s.Nodes
	}
	for i := range out.Spaces {
		out.Spaces[i].Nodes = stats[out.Spaces[i].Space]
	}
	return out
}

// members builds the peer listing, with the two populations kept distinct.
//
// Enrolled means visible on the tailnet with the node tag. Participating means records
// from that node have actually arrived. A peer that is enrolled but not participating
// is the failure worth catching, and it is invisible if the two are merged into one
// "peers" list (plan §8.2).
func (d *Daemon) members() *admin.Members {
	out := &admin.Members{Discovery: "no transport configured"}
	local := d.node.Vectors()

	// Every node appearing in any of our version vectors is participating, whether
	// or not the tailnet currently shows it.
	participating := make(map[record.NodeID]bool)
	for _, vv := range local {
		for peer := range vv {
			if peer != d.node.ID() {
				participating[peer] = true
			}
		}
	}

	states := make(map[record.NodeID]PeerState)
	if s := d.currentSyncer(); s != nil {
		out.Discovery = s.Discovery()
		for _, ps := range s.Peers() {
			states[ps.Node] = ps
		}
	}

	seen := make(map[record.NodeID]bool)
	for peer := range participating {
		seen[peer] = true
	}
	for peer := range states {
		seen[peer] = true
	}

	peers := make([]record.NodeID, 0, len(seen))
	for peer := range seen {
		peers = append(peers, peer)
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i] < peers[j] })

	now := d.node.Clock().Now()
	for _, peer := range peers {
		state, hasState := states[peer]
		row := admin.PeerRow{
			Node:              peer,
			Enrolled:          hasState && state.Enrolled,
			Participating:     participating[peer],
			Address:           state.Address,
			Transport:         state.Transport,
			Software:          state.Software,
			EmbedModel:        state.EmbedModel,
			ClockSkewMS:       state.ClockSkewMS,
			AgentKeys:         state.AgentKeys,
			LastContactAgeSec: -1,
		}
		if !state.LastContact.IsZero() {
			row.LastContactAgeSec = int64(now.Sub(state.LastContact).Seconds())
		}
		if !state.AsOf.IsZero() {
			row.AsOfAgeSec = int64(now.Sub(state.AsOf).Seconds())
		}
		row.LagBehind, row.LagAhead, row.SharedSpaces, row.KeyEpochs = lagAgainst(local, state.PeerVectors, peer)

		if row.Enrolled {
			out.Enrolled++
		}
		if row.Participating {
			out.Participating++
		}
		out.Peers = append(out.Peers, row)
		if row.Enrolled && !row.Participating {
			out.Notes = append(out.Notes, fmt.Sprintf(
				"%s is on the tailnet but has never appeared in a version vector: it is reachable and not syncing", peer))
		}
	}
	return out
}

// lagAgainst computes bidirectional lag between the local vectors and a peer's.
//
// Counting is by high-water gap rather than by exact record count, because that is
// what a version vector can tell you without a round trip. It is an estimate and the
// direction is what matters: lag in one direction only looks like a healthy sync right
// up until you notice it never completes.
func lagAgainst(
	local, peerVectors map[record.SpaceID]record.VersionVector,
	peer record.NodeID,
) (behind, ahead int, shared []record.SpaceID, epochs map[string]uint32) {
	for space, mine := range local {
		theirs, ok := peerVectors[space]
		if !ok {
			continue
		}
		shared = append(shared, space)
		for _, node := range theirs.Nodes() {
			if !mine.Covers(node, theirs.Get(node)) {
				behind++
			}
		}
		for _, node := range mine.Nodes() {
			if !theirs.Covers(node, mine.Get(node)) {
				ahead++
			}
		}
	}
	sort.Slice(shared, func(i, j int) bool { return shared[i] < shared[j] })
	return behind, ahead, shared, epochs
}

func (d *Daemon) keys() *admin.Keys {
	recipient := d.node.Recipient()
	out := &admin.Keys{
		Recipient:            recipient.String(),
		RecipientFingerprint: recipient.Fingerprint(),
		Agents:               d.agentInfo(),
	}
	ring := d.node.Keyring()
	for _, info := range d.node.ListSpaces() {
		row := admin.SpaceKeyRow{Space: info.Space, Readable: info.Readable}
		if info.Readable {
			if current, err := ring.CurrentEpoch(string(info.Space)); err == nil {
				row.Current = current
				for epoch := uint32(0); epoch <= current; epoch++ {
					if _, err := ring.Key(string(info.Space), epoch); err == nil {
						row.Epochs = append(row.Epochs, epoch)
					}
				}
			}
		}
		out.SpaceKeys = append(out.SpaceKeys, row)
	}
	return out
}

// ShareSpace wraps a space key to a recipient, for handing to a new member.
func (d *Daemon) ShareSpace(space record.SpaceID, to string) (*crypto.WrappedKey, error) {
	pub, err := crypto.ParseRecipientPublic(to)
	if err != nil {
		return nil, err
	}
	return d.node.ShareSpace(space, pub)
}

// Stamps exposes the node's HLC, so the sync engine and the skew check read the same
// clock the records were stamped from.
func (d *Daemon) Stamps() *hlc.Timestamper { return d.node.Stamps() }

// Close stops the sockets. It does not close the node: whoever opened it owns it.
func (d *Daemon) Close() error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return nil
	}
	d.closed = true
	d.mu.Unlock()

	var firstErr error
	if d.mcpLn != nil {
		if err := d.mcpLn.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		_ = os.Remove(d.mcpLn.Addr().String())
	}
	if d.adminSrv != nil {
		if err := d.adminSrv.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// BridgeMCP copies a local stdio stream to the daemon's MCP socket.
//
// This is what `memd mcp` runs, and what an agent's config points at. The bridge is
// deliberately dumb: it does not parse MCP, so it cannot corrupt or reinterpret a
// message, and it needs no version agreement with the daemon.
func BridgeMCP(dir string, in interface {
	Read([]byte) (int, error)
}, out interface {
	Write([]byte) (int, error)
}) error {
	path := filepath.Join(dir, MCPSocketName)
	conn, err := net.Dial("unix", path)
	if err != nil {
		return fmt.Errorf("memd: no daemon is listening at %s: %w", path, err)
	}
	defer conn.Close()

	errs := make(chan error, 2)
	go func() { errs <- copyStream(conn, in) }()
	go func() { errs <- copyStream(out, conn) }()
	// The first side to finish ends the session: either the agent hung up or the
	// daemon did, and in both cases there is nothing left to bridge.
	return <-errs
}

func copyStream(dst interface{ Write([]byte) (int, error) }, src interface {
	Read([]byte) (int, error)
}) error {
	buf := make([]byte, 64<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if err != nil {
			return nil
		}
	}
}
