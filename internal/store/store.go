package store

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/coryforsythe/memmesh/internal/crypto"
	"github.com/coryforsythe/memmesh/internal/record"
	"github.com/coryforsythe/memmesh/internal/ulid"
	"github.com/coryforsythe/memmesh/internal/wire"
)

// Keys is what a store needs from a keyring: the wire layer's provider, plus the
// ability to ask whether a space is readable at all.
type Keys interface {
	wire.KeyProvider
	// Readable reports whether this node holds any key for the space.
	Readable(space string) bool
	// MarkRelaying records that this node carries a space it cannot read.
	MarkRelaying(space string)
}

// ErrRelayed reports an operation that requires decryption on a space this node
// only relays. It is a normal answer, not a fault: a node can only index what it
// can decrypt (plan §3.3).
var ErrRelayed = errors.New("store: space is relayed on this node and cannot be read")

// Space is one space's durable log plus, when this node holds the key, the
// decrypted catalog derived from it.
//
// The two-part structure is the encryption boundary made structural. Every
// operation that needs plaintext goes through the catalog, and the catalog does not
// exist for a relayed space, so there is no path by which a node could index or
// search something it cannot read.
type Space struct {
	log     *Log
	keys    Keys
	entropy io.Reader

	mu            sync.RWMutex
	catalog       *Catalog
	undecryptable int
}

// OpenSpace opens a space's log and, if the key is held, builds its catalog by
// replaying and decrypting the log.
func OpenSpace(root string, id record.SpaceID, keys Keys, entropy io.Reader) (*Space, error) {
	log, err := OpenLog(root, id)
	if err != nil {
		return nil, err
	}
	s := &Space{log: log, keys: keys, entropy: entropy}
	if keys.Readable(string(id)) {
		if err := s.buildCatalog(); err != nil {
			log.Close()
			return nil, err
		}
	} else {
		keys.MarkRelaying(string(id))
	}
	return s, nil
}

// buildCatalog replays the log, decrypting every record. This is the warm-on-boot
// path, and its cost is why status distinguishes warm from replaying.
func (s *Space) buildCatalog() error {
	cat := NewCatalog()
	var undecryptable int
	err := s.log.Replay(func(entry *wire.SealedRecord) error {
		r, err := wire.OpenRecord(s.keys, entry)
		if err != nil {
			// A record sealed under an epoch whose key this node never received is
			// a real possibility: a member added mid-history holds only the epochs
			// wrapped to them. Count it and move on rather than refusing to open
			// the space, which would make one unreadable record deny access to
			// everything else.
			if errors.Is(err, crypto.ErrNoKey) || errors.Is(err, crypto.ErrOpen) {
				undecryptable++
				return nil
			}
			return err
		}
		cat.Add(r, entry.Len())
		return nil
	})
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.catalog = cat
	s.undecryptable = undecryptable
	s.mu.Unlock()
	return nil
}

// ID returns the space's identifier.
func (s *Space) ID() record.SpaceID { return s.log.Space() }

// Readable reports whether this node can decrypt the space.
func (s *Space) Readable() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.catalog != nil
}

// Catalog returns the decrypted view, or nil for a relayed space.
func (s *Space) Catalog() *Catalog {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.catalog
}

// Log returns the durable log, which exists for readable and relayed spaces alike.
func (s *Space) Log() *Log { return s.log }

// Undecryptable returns how many stored records this node holds but cannot open,
// typically because they predate the epoch it was given a key for.
func (s *Space) Undecryptable() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.undecryptable
}

// Write seals a record, appends it, and folds it into the catalog.
//
// Writes commit locally and never touch the network. That is the offline guarantee
// in one sentence: the network is not in the write path, so a write cannot fail
// because a peer is unreachable (plan §5.5).
func (s *Space) Write(r *record.Record) (*wire.SealedRecord, error) {
	if !s.Readable() {
		return nil, fmt.Errorf("%w: cannot write to %s", ErrRelayed, s.ID())
	}
	if r.Space != s.ID() {
		return nil, fmt.Errorf("store: record is for %s, this space is %s", r.Space, s.ID())
	}
	sealed, err := wire.SealRecord(s.keys, r, wire.TransformNone, s.entropy)
	if err != nil {
		return nil, err
	}
	n, err := s.log.Append(sealed)
	if err != nil {
		return nil, err
	}
	if n > 0 {
		s.mu.RLock()
		cat := s.catalog
		s.mu.RUnlock()
		cat.Add(r, sealed.Len())
	}
	return sealed, nil
}

// Accept stores records received from a peer and returns how many were new.
//
// For a readable space each record is decrypted and verified before it is stored,
// so an unverifiable record never reaches the log. For a relayed space the bytes are
// stored as received — there is no key to check them with, and the frame signature
// from the sending peer is the only assurance available (plan §3.3).
func (s *Space) Accept(entries ...*wire.SealedRecord) (int, error) {
	s.mu.RLock()
	cat := s.catalog
	s.mu.RUnlock()

	if cat == nil {
		return s.log.Append(entries...)
	}

	// Decrypt and verify first, then append. Doing it in this order means a batch
	// containing one bad record does not leave the log holding the good half of it
	// with no indication anything was rejected.
	opened := make([]*record.Record, 0, len(entries))
	keep := make([]*wire.SealedRecord, 0, len(entries))
	for _, entry := range entries {
		if s.log.Has(entry.ID) {
			continue
		}
		r, err := wire.OpenRecord(s.keys, entry)
		if err != nil {
			return 0, fmt.Errorf("store: reject record %s from %s: %w", entry.ID, entry.AuthorNode, err)
		}
		opened = append(opened, r)
		keep = append(keep, entry)
	}
	n, err := s.log.Append(keep...)
	if err != nil {
		return n, err
	}
	for i, r := range opened {
		cat.Add(r, keep[i].Len())
	}
	return n, nil
}

// Record returns a decrypted record by id.
func (s *Space) Record(id ulid.ULID) (*record.Record, error) {
	if !s.Readable() {
		return nil, fmt.Errorf("%w: cannot read %s from %s", ErrRelayed, id, s.ID())
	}
	entry, err := s.log.Get(id)
	if err != nil {
		return nil, err
	}
	return wire.OpenRecord(s.keys, entry)
}

// Vector returns the space's version vector.
func (s *Space) Vector() record.VersionVector { return s.log.Vector() }

// Close releases the space's files.
func (s *Space) Close() error { return s.log.Close() }

// Stats summarises a space for memctl. For a relayed space, everything that would
// require decryption is left zero and Readable is false — counts and bytes only,
// never a body, never a tag, never a decrypted title (plan §8).
type Stats struct {
	Space         record.SpaceID    `json:"space"`
	Readable      bool              `json:"readable"`
	Records       int               `json:"records"`
	Bytes         int64             `json:"bytes"`
	Segments      int               `json:"segments"`
	Nodes         int               `json:"participating_nodes"`
	Epoch         uint32            `json:"epoch,omitempty"`
	Policy        string            `json:"conflict_policy"`
	ByKind        map[string]int    `json:"by_kind,omitempty"`
	EmbedModels   map[string]int    `json:"embed_models,omitempty"`
	Undecryptable int               `json:"undecryptable,omitempty"`
	TruncatedTail bool              `json:"truncated_tail,omitempty"`
	Pending       int               `json:"pending_supersessions,omitempty"`
	Vector        map[string]string `json:"vector,omitempty"`
}

// Stats collects the space's summary.
func (s *Space) Stats() Stats {
	vec := s.log.Vector()
	out := Stats{
		Space:         s.ID(),
		Readable:      s.Readable(),
		Records:       s.log.Count(),
		Bytes:         s.log.Bytes(),
		Segments:      s.log.Segments(),
		Nodes:         len(vec),
		Policy:        string(record.PolicyFor(s.ID())),
		TruncatedTail: s.log.TruncatedTail(),
		Vector:        make(map[string]string, len(vec)),
	}
	for node, id := range vec {
		out.Vector[string(node)] = id.String()
	}
	if cat := s.Catalog(); cat != nil {
		out.ByKind = make(map[string]int)
		for kind, n := range cat.CountsByKind() {
			out.ByKind[string(kind)] = n
		}
		out.EmbedModels = cat.EmbedModels()
		out.Undecryptable = s.Undecryptable()
		out.Pending = len(cat.PendingSupersessions())
		if epoch, err := s.keys.CurrentEpoch(string(s.ID())); err == nil {
			out.Epoch = epoch
		}
	}
	return out
}

// Manager owns every space this node holds, readable or relayed.
//
// It is the object the daemon hands to the MCP server, the sync engine and the
// admin socket, so all three see the same set of spaces and the same
// readable-versus-relayed answer.
//
// A Manager is safe for concurrent use.
type Manager struct {
	root    string
	keys    Keys
	entropy io.Reader

	mu     sync.RWMutex
	spaces map[record.SpaceID]*Space
	closed bool
}

// NewManager opens the spaces already present under root.
//
// Spaces are discovered from the filesystem rather than from configuration, so a
// node that was given a key and then restarted picks up what it already holds
// without being told about it again.
func NewManager(root string, keys Keys, entropy io.Reader) (*Manager, error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("store: create root: %w", err)
	}
	m := &Manager{root: root, keys: keys, entropy: entropy, spaces: make(map[record.SpaceID]*Space)}

	present, err := DiscoverSpaces(root)
	if err != nil {
		return nil, err
	}
	for _, id := range present {
		if _, err := m.Open(id); err != nil {
			m.Close()
			return nil, err
		}
	}
	return m, nil
}

// DiscoverSpaces lists the spaces with a directory under root.
func DiscoverSpaces(root string) ([]record.SpaceID, error) {
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: read root: %w", err)
	}
	var out []record.SpaceID
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id, err := spaceFromFilename(e.Name())
		if err != nil {
			// An unrecognised directory is not this package's business to delete or
			// to fail on; skip it and let the operator notice.
			continue
		}
		if _, err := os.Stat(filepath.Join(root, e.Name(), manifestName)); err != nil {
			continue
		}
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// spaceFromFilename reverses SpaceID.Filename.
func spaceFromFilename(name string) (record.SpaceID, error) {
	for i := 0; i+1 < len(name); i++ {
		if name[i] == '_' && name[i+1] == '_' {
			id := record.SpaceID(name[:i] + "/" + name[i+2:])
			if err := id.Validate(); err != nil {
				return "", err
			}
			return id, nil
		}
	}
	return "", fmt.Errorf("store: %q is not a space directory name", name)
}

// Open returns the space, opening it if this is the first reference.
func (m *Manager) Open(id record.SpaceID) (*Space, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, ErrClosed
	}
	if s, ok := m.spaces[id]; ok {
		return s, nil
	}
	s, err := OpenSpace(m.root, id, m.keys, m.entropy)
	if err != nil {
		return nil, err
	}
	m.spaces[id] = s
	return s, nil
}

// Get returns an already-open space.
func (m *Manager) Get(id record.SpaceID) (*Space, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.spaces[id]
	return s, ok
}

// Spaces lists the open spaces, sorted.
func (m *Manager) Spaces() []record.SpaceID {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]record.SpaceID, 0, len(m.spaces))
	for id := range m.spaces {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Vectors returns every open space's version vector: the full sync handshake
// payload for this node.
func (m *Manager) Vectors() map[record.SpaceID]record.VersionVector {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[record.SpaceID]record.VersionVector, len(m.spaces))
	for id, s := range m.spaces {
		out[id] = s.Vector()
	}
	return out
}

// Reindex rebuilds a space's catalog from its log.
//
// Called after a key arrives for a space that was being relayed: the records were
// already on disk, and gaining the key turns them from opaque bytes into a readable
// corpus without any network traffic at all.
func (m *Manager) Reindex(id record.SpaceID) error {
	s, ok := m.Get(id)
	if !ok {
		return fmt.Errorf("store: space %s is not open", id)
	}
	if !m.keys.Readable(string(id)) {
		return fmt.Errorf("%w: %s", ErrRelayed, id)
	}
	return s.buildCatalog()
}

// MaxLocalID returns the highest record id authored by node across every open
// space.
//
// The daemon seeds its ULID generator with this on boot so that a wall clock which
// moved backwards during downtime cannot produce an id below one already published
// (docs/decisions/0001).
func (m *Manager) MaxLocalID(node record.NodeID) ulid.ULID {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var max ulid.ULID
	for _, s := range m.spaces {
		if id := s.log.MaxLocalID(node); id.Compare(max) > 0 {
			max = id
		}
	}
	return max
}

// Stats collects every open space's summary, sorted by space id.
func (m *Manager) Stats() []Stats {
	out := make([]Stats, 0)
	for _, id := range m.Spaces() {
		if s, ok := m.Get(id); ok {
			out = append(out, s.Stats())
		}
	}
	return out
}

// Close closes every open space.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	var firstErr error
	for _, s := range m.spaces {
		if err := s.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
