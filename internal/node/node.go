// Package node wires the durable store, the vector index, the embedder and the key
// material into one object the MCP server, the admin socket and the sync engine all
// share.
//
// It is where the offline guarantee is actually delivered: every operation here
// reads local disk and the local index, and writes commit locally and queue
// outbound. The network is in neither path (plan §5.5), so nothing a caller does
// here can fail because a peer is unreachable.
package node

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/coryforsythe/memmesh/internal/clock"
	"github.com/coryforsythe/memmesh/internal/crypto"
	"github.com/coryforsythe/memmesh/internal/embed"
	"github.com/coryforsythe/memmesh/internal/hlc"
	"github.com/coryforsythe/memmesh/internal/index"
	"github.com/coryforsythe/memmesh/internal/record"
	"github.com/coryforsythe/memmesh/internal/store"
	"github.com/coryforsythe/memmesh/internal/ulid"
	"github.com/coryforsythe/memmesh/internal/wire"
)

// ErrClosed reports use of a node that has been closed.
//
// It exists because shutdown is genuinely concurrent: the sync engine's inbound loop can
// still be mid-exchange when the node closes, and a peer's records arriving one
// microsecond too late should be a refusal rather than a panic.
var ErrClosed = errors.New("node: closed")

// Software is the build identifier reported to peers and in memctl status.
const Software = "memd/0.1.0-m3"

// DefaultRAMBudgetMB is the default cap the index footprint is reported against.
const DefaultRAMBudgetMB = 512

// Config configures a Node.
type Config struct {
	// Root is the data directory. Everything the node owns lives under it.
	Root string
	// ID is this machine's node identifier. Version vectors are keyed by it, so
	// it must be stable across restarts.
	ID record.NodeID
	// AuthorModel is recorded on records for audit. Never used to filter.
	AuthorModel string
	// Clock is the time source. Injected so tests are deterministic.
	Clock clock.Clock
	// Entropy is the randomness source. Injected for the same reason.
	Entropy io.Reader
	// RAMBudgetMB is the budget the index footprint is reported against. It is a
	// reporting target, not an enforced limit: evicting vectors to hit a number
	// would degrade recall silently, which is the failure mode this system works
	// hardest to avoid.
	RAMBudgetMB int
	// Relay opts this node in to carrying spaces it holds no key for. Off by
	// default (docs/decisions/0003).
	Relay bool
	// Embedder overrides the local embedder. Nil means the default.
	Embedder embed.Embedder
}

// Node is one machine's memory mesh participation.
//
// A Node is safe for concurrent use.
type Node struct {
	cfg      Config
	keys     *keystore
	ids      *ulid.Monotonic
	stamps   *hlc.Timestamper
	store    *store.Manager
	embedder embed.Embedder

	mu        sync.RWMutex
	indexes   map[record.SpaceID]*index.Quantized
	builders  map[string]*record.Builder
	writeHook WriteHook
	warm      bool
	closed    bool
}

// Open starts a node, replaying whatever is already on disk.
func Open(cfg Config) (*Node, error) {
	if cfg.Root == "" {
		return nil, errors.New("node: Root is required")
	}
	if !cfg.ID.Valid() {
		return nil, fmt.Errorf("node: %q is not a valid node id", string(cfg.ID))
	}
	if cfg.Clock == nil {
		cfg.Clock = clock.System{}
	}
	if cfg.RAMBudgetMB <= 0 {
		cfg.RAMBudgetMB = DefaultRAMBudgetMB
	}
	if cfg.Embedder == nil {
		cfg.Embedder = embed.NewHashed()
	}
	if err := os.MkdirAll(cfg.Root, 0o700); err != nil {
		return nil, fmt.Errorf("node: create root: %w", err)
	}

	keys, err := openKeystore(cfg.Root, cfg.Entropy)
	if err != nil {
		return nil, err
	}
	n := &Node{
		cfg:      cfg,
		keys:     keys,
		stamps:   hlc.New(cfg.Clock),
		embedder: cfg.Embedder,
		indexes:  make(map[record.SpaceID]*index.Quantized),
		builders: make(map[string]*record.Builder),
	}
	n.ids = ulid.NewMonotonic(cfg.Clock, cfg.Entropy)

	mgr, err := store.NewManager(n.spacesRoot(), keys.ring, cfg.Entropy)
	if err != nil {
		return nil, err
	}
	n.store = mgr

	// Seed the id generator past anything already published by this node. Without
	// this, a wall clock that moved backwards during downtime could mint an id
	// below one peers have already seen, and they would never ask for the record
	// again (docs/decisions/0001).
	if err := n.seedIDs(); err != nil {
		mgr.Close()
		return nil, err
	}
	if err := n.warmIndexes(); err != nil {
		mgr.Close()
		return nil, err
	}
	return n, nil
}

func (n *Node) spacesRoot() string { return filepath.Join(n.cfg.Root, "spaces") }
func (n *Node) indexRoot() string  { return filepath.Join(n.cfg.Root, "index") }

// seedIDs advances the ULID generator past the highest id this node has authored,
// across every space.
func (n *Node) seedIDs() error {
	if highest := n.store.MaxLocalID(n.cfg.ID); !highest.IsZero() {
		n.ids.Seed(highest)
	}
	return nil
}

// warmIndexes opens or rebuilds the vector index for every readable space.
//
// Warming reads persisted vectors where the model still matches, and re-embeds from
// the log where it does not. The second path is what makes changing the local
// embedding model a supported operation rather than a silent recall regression.
func (n *Node) warmIndexes() error {
	for _, id := range n.store.Spaces() {
		if _, err := n.indexFor(id); err != nil {
			return err
		}
	}
	n.mu.Lock()
	n.warm = true
	n.mu.Unlock()
	return nil
}

// indexFor returns the index for a readable space, opening and populating it on
// first use. It returns nil, nil for a relayed space: there is nothing to index, and
// that is the point.
func (n *Node) indexFor(id record.SpaceID) (*index.Quantized, error) {
	space, ok := n.store.Get(id)
	if !ok {
		return nil, fmt.Errorf("node: space %s is not open", id)
	}
	if !space.Readable() {
		return nil, nil
	}

	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return nil, ErrClosed
	}
	if idx, ok := n.indexes[id]; ok {
		n.mu.Unlock()
		return idx, nil
	}
	n.mu.Unlock()

	idx, err := index.Open(index.Config{
		Dir:     filepath.Join(n.indexRoot(), id.Filename()),
		Dims:    n.embedder.Dims(),
		ModelID: n.embedder.ModelID(),
	})
	if err != nil {
		return nil, err
	}

	// Fill in anything the persisted index is missing. After a model change the
	// index is empty and this re-embeds the whole space; in the normal case it is
	// a no-op for every record.
	cat := space.Catalog()
	for _, recID := range space.Log().All() {
		if idx.Has(recID) {
			continue
		}
		if _, ok := cat.Get(recID); !ok {
			// Held but undecryptable — an epoch this node never received a key
			// for. It stays unindexed, which is correct: a node can only index
			// what it can decrypt.
			continue
		}
		r, err := space.Record(recID)
		if err != nil {
			continue
		}
		if err := n.indexRecord(idx, r); err != nil {
			idx.Close()
			return nil, err
		}
	}

	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		idx.Close()
		return nil, ErrClosed
	}
	if existing, ok := n.indexes[id]; ok {
		// Another caller opened it while this one was populating. Keep theirs and
		// discard this one rather than leaking two handles on the same files.
		n.mu.Unlock()
		idx.Close()
		return existing, nil
	}
	n.indexes[id] = idx
	n.mu.Unlock()
	return idx, nil
}

// indexRecord embeds and indexes one record.
//
// Tombstones and conflict records are skipped: they carry no claim of their own, and
// indexing them would put noise into every search result. Retractions are indexed,
// because the text of a correction is often exactly what someone is searching for.
func (n *Node) indexRecord(idx *index.Quantized, r *record.Record) error {
	switch r.Kind {
	case record.KindTombstone, record.KindConflict:
		return nil
	}
	text := embed.Text(r.Body, r.Tags)
	vec, err := n.embedder.Embed(text)
	if err != nil {
		if errors.Is(err, embed.ErrEmpty) {
			// An artifact_ref whose body is a bare hash has nothing to embed. It
			// stays reachable by id and by tag; it is just not a vector search hit.
			return nil
		}
		return fmt.Errorf("node: embed %s: %w", r.ID, err)
	}
	return idx.Add(r.ID, vec)
}

// ID returns this node's identifier.
func (n *Node) ID() record.NodeID { return n.cfg.ID }

// Store returns the space manager.
func (n *Node) Store() *store.Manager { return n.store }

// Keyring returns the node's space keyring.
func (n *Node) Keyring() *crypto.Keyring { return n.keys.ring }

// Recipient returns this node's X25519 identity: the address space keys are wrapped
// to when someone shares a space with it.
func (n *Node) Recipient() crypto.RecipientPublic { return n.keys.recipient.Public() }

// Embedder returns the local embedder.
func (n *Node) Embedder() embed.Embedder { return n.embedder }

// Stamps returns the node's HLC, so the sync engine can fold in peer timestamps.
func (n *Node) Stamps() *hlc.Timestamper { return n.stamps }

// Clock returns the node's time source.
func (n *Node) Clock() clock.Clock { return n.cfg.Clock }

// Relaying reports whether this node carries spaces it cannot read.
func (n *Node) Relaying() bool { return n.cfg.Relay }

// Warm reports whether index warm-up has finished. memctl status distinguishes warm
// from replaying because a cold node answers recall badly rather than not at all,
// and that is worth knowing before trusting an empty result.
func (n *Node) Warm() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.warm
}

// WriteHook is called after a record is durably written locally.
//
// It is how the sync engine learns about a fresh write without the node importing the
// sync package. The hook must not block and must not be able to fail the write: the
// record is already on disk, the network is not in the write path (plan §5.5), and
// anti-entropy will deliver it whatever the hook does.
type WriteHook func(record.SpaceID, *wire.SealedRecord)

// SetWriteHook installs the write hook. Passing nil removes it.
func (n *Node) SetWriteHook(hook WriteHook) {
	n.mu.Lock()
	n.writeHook = hook
	n.mu.Unlock()
}

func (n *Node) notifyWrite(space record.SpaceID, entry *wire.SealedRecord) {
	n.mu.RLock()
	hook := n.writeHook
	n.mu.RUnlock()
	if hook != nil {
		hook(space, entry)
	}
}

// FrameSigner returns the agent key this node signs wire frames with.
//
// Frames are signed by the sending node; records stay signed by their authoring agent.
// The two answer different questions — "who sent me this" versus "who wrote it" — and
// only the second survives relaying through a third node (plan §5.3), so they get
// different keys as well as different signature domains.
func (n *Node) FrameSigner() (*record.Signer, error) {
	return n.keys.agent(frameAgentName)
}

// frameAgentName is the reserved agent name used for frame signing. It is a normal
// agent key so that a peer can attribute frames, but it never authors records.
const frameAgentName = "node"

// Agents lists the agent names this node holds keys for.
func (n *Node) Agents() []string { return n.keys.agentNames() }

// AgentIDFor returns a named agent's public identity, without creating it.
func (n *Node) AgentIDFor(name string) (record.AgentID, bool) {
	n.keys.mu.Lock()
	defer n.keys.mu.Unlock()
	signer, ok := n.keys.agents[name]
	if !ok {
		return record.AgentID{}, false
	}
	return signer.AgentID(), true
}

// builderFor returns the record builder for an agent, creating its key on first use.
//
// Each agent gets its own builder because a Builder is not safe for concurrent use
// and because the agent identity is baked into it. They all share the node's single
// id generator and HLC, which is what keeps per-node id monotonicity intact no
// matter how many agents write at once.
func (n *Node) builderFor(agent string) (*record.Builder, error) {
	n.mu.RLock()
	b, ok := n.builders[agent]
	n.mu.RUnlock()
	if ok {
		return b, nil
	}
	signer, err := n.keys.agent(agent)
	if err != nil {
		return nil, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if b, ok := n.builders[agent]; ok {
		return b, nil
	}
	b, err = record.NewBuilder(record.BuilderConfig{
		Node:        n.cfg.ID,
		Signer:      signer,
		IDs:         n.ids,
		Stamps:      n.stamps,
		AuthorModel: n.cfg.AuthorModel,
		EmbedModel:  n.embedder.ModelID(),
	})
	if err != nil {
		return nil, err
	}
	n.builders[agent] = b
	return b, nil
}

// CreateSpace creates a space this node owns, generating its content key.
//
// There is no registry and no coordination: creating a space is generating a key and
// a directory. Sharing it with someone else is wrapping that key to their recipient
// identity, which is a separate, later, and equally uncoordinated act.
func (n *Node) CreateSpace(id record.SpaceID) error {
	if err := id.Validate(); err != nil {
		return err
	}
	if n.keys.ring.Readable(string(id)) {
		if _, err := n.store.Open(id); err != nil {
			return err
		}
		return nil
	}
	if _, _, err := n.keys.ring.Rotate(string(id), n.cfg.Entropy); err != nil {
		return err
	}
	if err := n.keys.saveKeyring(); err != nil {
		return err
	}
	if _, err := n.store.Open(id); err != nil {
		return err
	}
	_, err := n.indexFor(id)
	return err
}

// JoinSpace installs a wrapped content key and makes the space readable.
//
// If the records were already on disk from relaying, this makes them searchable with
// no network traffic at all: the bytes were always there, only the key was missing.
func (n *Node) JoinSpace(w *crypto.WrappedKey) error {
	if err := n.keys.ring.InstallWrapped(n.keys.recipient, w); err != nil {
		return err
	}
	if err := n.keys.saveKeyring(); err != nil {
		return err
	}
	id := record.SpaceID(w.Space)
	if _, err := n.store.Open(id); err != nil {
		return err
	}
	if err := n.store.Reindex(id); err != nil {
		return err
	}
	_, err := n.indexFor(id)
	return err
}

// ShareSpace wraps a space's current content key to a recipient, so it can be handed
// to another member out of band.
func (n *Node) ShareSpace(id record.SpaceID, to crypto.RecipientPublic) (*crypto.WrappedKey, error) {
	epoch, err := n.keys.ring.CurrentEpoch(string(id))
	if err != nil {
		return nil, err
	}
	key, err := n.keys.ring.Key(string(id), epoch)
	if err != nil {
		return nil, err
	}
	return crypto.Wrap(string(id), epoch, key, to, n.cfg.Entropy)
}

// RotateSpace rotates a space into a new epoch, which is how a member is removed.
//
// Revocation is forward-only: the departing member keeps whatever they already
// synced. Everyone who stays needs the new epoch key wrapped to them, which is what
// the returned epoch is for.
func (n *Node) RotateSpace(id record.SpaceID) (uint32, error) {
	epoch, _, err := n.keys.ring.Rotate(string(id), n.cfg.Entropy)
	if err != nil {
		return 0, err
	}
	if err := n.keys.saveKeyring(); err != nil {
		return 0, err
	}
	return epoch, nil
}

// SubscribeRelay opens a space this node holds no key for, so it can store and
// gossip it. Only meaningful when relaying is enabled.
func (n *Node) SubscribeRelay(id record.SpaceID) error {
	if !n.cfg.Relay {
		return fmt.Errorf("node: relaying is off on this node; enable it to carry %s", id)
	}
	if err := id.Validate(); err != nil {
		return err
	}
	_, err := n.store.Open(id)
	return err
}

// SpaceIDs lists every space this node holds, readable or relayed.
func (n *Node) SpaceIDs() []record.SpaceID { return n.store.Spaces() }

// ReadableSpaces lists the spaces this node can decrypt, sorted.
func (n *Node) ReadableSpaces() []record.SpaceID {
	var out []record.SpaceID
	for _, id := range n.store.Spaces() {
		if s, ok := n.store.Get(id); ok && s.Readable() {
			out = append(out, id)
		}
	}
	return out
}

// RelayedSpaces lists the spaces this node carries without a key, sorted.
func (n *Node) RelayedSpaces() []record.SpaceID {
	var out []record.SpaceID
	for _, id := range n.store.Spaces() {
		if s, ok := n.store.Get(id); ok && !s.Readable() {
			out = append(out, id)
		}
	}
	return out
}

// IndexResidentBytes totals the index footprint across spaces.
func (n *Node) IndexResidentBytes() int64 {
	n.mu.RLock()
	defer n.mu.RUnlock()
	var total int64
	for _, idx := range n.indexes {
		total += idx.ResidentBytes()
	}
	return total
}

// IndexedRecords totals how many records are in the vector indexes.
func (n *Node) IndexedRecords() int {
	n.mu.RLock()
	defer n.mu.RUnlock()
	total := 0
	for _, idx := range n.indexes {
		total += idx.Len()
	}
	return total
}

// RAMBudgetBytes returns the configured budget in bytes.
func (n *Node) RAMBudgetBytes() int64 { return int64(n.cfg.RAMBudgetMB) << 20 }

// EmbedModelCounts totals the embedding model ids seen across readable spaces.
//
// More than one entry means this node holds records embedded by a model it no longer
// runs, which is the local half of the embed-model-match health check.
func (n *Node) EmbedModelCounts() map[string]int {
	out := make(map[string]int)
	for _, id := range n.ReadableSpaces() {
		s, ok := n.store.Get(id)
		if !ok {
			continue
		}
		for model, count := range s.Catalog().EmbedModels() {
			out[model] += count
		}
	}
	return out
}

// AgentCounts totals records per authoring agent across readable spaces.
func (n *Node) AgentCounts() map[record.AgentID]int {
	out := make(map[record.AgentID]int)
	for _, id := range n.ReadableSpaces() {
		s, ok := n.store.Get(id)
		if !ok {
			continue
		}
		for agent, count := range s.Catalog().Agents() {
			out[agent] += count
		}
	}
	return out
}

// Vectors returns every space's version vector: this node's full sync state.
func (n *Node) Vectors() map[record.SpaceID]record.VersionVector { return n.store.Vectors() }

// SortedSpaces is a small helper for callers rendering space lists.
func SortedSpaces(ids []record.SpaceID) []record.SpaceID {
	out := append([]record.SpaceID(nil), ids...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Close releases the node's resources.
func (n *Node) Close() error {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return nil
	}
	n.closed = true
	// The map stays in place rather than being nil-ed. A concurrent reader that
	// slipped past the closed check would otherwise write to a nil map and panic,
	// and shutdown racing an in-flight exchange is normal, not exceptional.
	indexes := make(map[record.SpaceID]*index.Quantized, len(n.indexes))
	for id, idx := range n.indexes {
		indexes[id] = idx
	}
	n.writeHook = nil
	n.mu.Unlock()

	var firstErr error
	for _, idx := range indexes {
		if err := idx.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if err := n.store.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}
