package store

import (
	"sort"
	"sync"

	"github.com/coryforsythe/memmesh/internal/hlc"
	"github.com/coryforsythe/memmesh/internal/record"
	"github.com/coryforsythe/memmesh/internal/ulid"
)

// Meta is the decrypted, queryable metadata for one record.
//
// Bodies are deliberately absent. They are the bulk of a corpus and are read from
// the log on demand, so the catalog's footprint scales with record count rather
// than with content size — which is what lets the working set fit in RAM at
// realistic corpus sizes.
type Meta struct {
	ID          ulid.ULID
	AuthorNode  record.NodeID
	AuthorAgent record.AgentID
	AuthorModel string
	HLC         hlc.HLC
	Epoch       uint32
	Kind        record.Kind
	Evidence    record.Evidence
	EmbedModel  string
	Tags        []string
	Supersedes  []ulid.ULID
	Refs        []ulid.ULID
	CausalCtx   record.VersionVector
	// Bytes is the record's sealed size on disk.
	Bytes int
}

// Catalog is the decrypted view of a readable space: which records exist, what
// kind they are, and which have been superseded.
//
// It exists only for spaces this node holds a key for. A relayed space has a Log
// and no Catalog, and that asymmetry is the whole of "a node can only index what it
// can decrypt" (plan §3.3) — there is no code path that could accidentally index a
// space whose key is absent, because there is nothing to build the catalog from.
//
// A Catalog is entirely in-memory and rebuildable from the log, per plan §11.6.
// Nothing here is persisted, so it can never disagree with the log.
//
// A Catalog is safe for concurrent use.
type Catalog struct {
	mu sync.RWMutex

	metas map[ulid.ULID]*Meta
	// supersededBy maps a record to the records that superseded it. A record can
	// be superseded more than once — two nodes can independently correct the same
	// claim — so this is a list, not a single id.
	supersededBy map[ulid.ULID][]ulid.ULID
	// referencedBy is the reverse of Meta.Refs, so "what links to this" is a
	// lookup rather than a scan.
	referencedBy map[ulid.ULID][]ulid.ULID
	// byKind indexes live records by kind, which is what makes "promote recent
	// episodes" and "all facts near this one" cheap for the distiller.
	byKind map[record.Kind][]ulid.ULID
	// byTag indexes live records by tag.
	byTag map[string][]ulid.ULID
	// pending holds supersession edges whose target has not arrived yet. Records
	// arrive out of order all the time — a correction can be delivered before the
	// claim it corrects — so the edge has to be remembered until the other half
	// shows up.
	pending map[ulid.ULID][]ulid.ULID
}

// NewCatalog returns an empty catalog.
func NewCatalog() *Catalog {
	return &Catalog{
		metas:        make(map[ulid.ULID]*Meta),
		supersededBy: make(map[ulid.ULID][]ulid.ULID),
		referencedBy: make(map[ulid.ULID][]ulid.ULID),
		byKind:       make(map[record.Kind][]ulid.ULID),
		byTag:        make(map[string][]ulid.ULID),
		pending:      make(map[ulid.ULID][]ulid.ULID),
	}
}

// Add folds a decrypted record into the catalog. It is idempotent.
func (c *Catalog) Add(r *record.Record, sealedBytes int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, seen := c.metas[r.ID]; seen {
		return
	}

	m := &Meta{
		ID:          r.ID,
		AuthorNode:  r.AuthorNode,
		AuthorAgent: r.AuthorAgent,
		AuthorModel: r.AuthorModel,
		HLC:         r.HLC,
		Epoch:       r.Epoch,
		Kind:        r.Kind,
		Evidence:    r.Evidence,
		EmbedModel:  r.EmbedModel,
		Bytes:       sealedBytes,
	}
	if len(r.Tags) > 0 {
		m.Tags = append([]string(nil), r.Tags...)
	}
	if len(r.Supersedes) > 0 {
		m.Supersedes = append([]ulid.ULID(nil), r.Supersedes...)
	}
	if len(r.Refs) > 0 {
		m.Refs = append([]ulid.ULID(nil), r.Refs...)
	}
	m.CausalCtx = r.CausalCtx.Clone()
	c.metas[r.ID] = m

	for _, target := range m.Supersedes {
		c.supersededBy[target] = appendUnique(c.supersededBy[target], r.ID)
		if _, present := c.metas[target]; !present {
			// The target has not arrived. Remember the edge so that when it does,
			// it is marked superseded rather than surfacing as live.
			c.pending[target] = appendUnique(c.pending[target], r.ID)
		}
	}
	for _, target := range m.Refs {
		c.referencedBy[target] = appendUnique(c.referencedBy[target], r.ID)
	}

	// Resolve any edges that were waiting for this record.
	if waiting, ok := c.pending[r.ID]; ok {
		for _, by := range waiting {
			c.supersededBy[r.ID] = appendUnique(c.supersededBy[r.ID], by)
		}
		delete(c.pending, r.ID)
	}

	c.byKind[m.Kind] = append(c.byKind[m.Kind], r.ID)
	for _, tag := range m.Tags {
		c.byTag[tag] = append(c.byTag[tag], r.ID)
	}
}

// Get returns a record's metadata.
func (c *Catalog) Get(id ulid.ULID) (*Meta, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	m, ok := c.metas[id]
	return m, ok
}

// Count returns how many records the catalog holds.
func (c *Catalog) Count() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.metas)
}

// Superseded reports whether a record has been replaced, and by what.
//
// A superseded record is not deleted. It stays in the log, stays verifiable, and
// stays reachable by id — which is the point of append-only storage. What
// supersession changes is whether it is *live*: whether recall surfaces it by
// default.
func (c *Catalog) Superseded(id ulid.ULID) ([]ulid.ULID, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	by, ok := c.supersededBy[id]
	if !ok || len(by) == 0 {
		return nil, false
	}
	return append([]ulid.ULID(nil), by...), true
}

// ReferencedBy returns the records that point at this one through their refs.
func (c *Catalog) ReferencedBy(id ulid.ULID) []ulid.ULID {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]ulid.ULID(nil), c.referencedBy[id]...)
}

// Live reports whether a record is current: present, and not superseded.
func (c *Catalog) Live(id ulid.ULID) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if _, ok := c.metas[id]; !ok {
		return false
	}
	return len(c.supersededBy[id]) == 0
}

// LiveByKind returns the live records of a kind, newest first by HLC.
func (c *Catalog) LiveByKind(kind record.Kind, limit int) []*Meta {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.collect(c.byKind[kind], limit)
}

// LiveByTag returns the live records carrying a tag, newest first by HLC.
func (c *Catalog) LiveByTag(tag string, limit int) []*Meta {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.collect(c.byTag[tag], limit)
}

// collect filters out superseded ids and orders the rest newest first. Caller holds
// at least a read lock.
func (c *Catalog) collect(ids []ulid.ULID, limit int) []*Meta {
	out := make([]*Meta, 0, len(ids))
	for _, id := range ids {
		if len(c.supersededBy[id]) > 0 {
			continue
		}
		if m, ok := c.metas[id]; ok {
			out = append(out, m)
		}
	}
	sortMetasNewestFirst(out)
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// Tombstoned reports whether a record was superseded specifically by a tombstone,
// as opposed to by a retraction or a corrected claim.
//
// The distinction is what `forget` versus `retract` buys: a tombstone means "this
// should not be here", a retraction means "this was wrong, and here is why"
// (plan §6.6). A caller deciding whether to show a superseded record at all wants
// to know which it was.
func (c *Catalog) Tombstoned(id ulid.ULID) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, by := range c.supersededBy[id] {
		if m, ok := c.metas[by]; ok && m.Kind == record.KindTombstone {
			return true
		}
	}
	return false
}

// Retractions returns the retraction records that superseded this one, so the
// correction can be shown alongside the claim it corrects.
func (c *Catalog) Retractions(id ulid.ULID) []*Meta {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out []*Meta
	for _, by := range c.supersededBy[id] {
		if m, ok := c.metas[by]; ok && m.Kind == record.KindRetraction {
			out = append(out, m)
		}
	}
	sortMetasNewestFirst(out)
	return out
}

// Conflicts returns the conflict records that name this record as one of their
// sides.
func (c *Catalog) Conflicts(id ulid.ULID) []*Meta {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out []*Meta
	for _, by := range c.referencedBy[id] {
		if m, ok := c.metas[by]; ok && m.Kind == record.KindConflict {
			out = append(out, m)
		}
	}
	sortMetasNewestFirst(out)
	return out
}

// PendingSupersessions returns targets that have been superseded by a record this
// node holds, but whose own record has not arrived yet.
//
// A non-empty result is normal in a mesh where a correction can outrun the claim it
// corrects; a result that stays non-empty is a sign of a hole worth reconciling.
func (c *Catalog) PendingSupersessions() []ulid.ULID {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]ulid.ULID, 0, len(c.pending))
	for id := range c.pending {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Compare(out[j]) < 0 })
	return out
}

// CountsByKind returns how many live records exist of each kind, for memctl stats.
func (c *Catalog) CountsByKind() map[record.Kind]int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[record.Kind]int, len(c.byKind))
	for kind, ids := range c.byKind {
		n := 0
		for _, id := range ids {
			if len(c.supersededBy[id]) == 0 {
				n++
			}
		}
		out[kind] = n
	}
	return out
}

// EmbedModels returns the set of embedding model ids seen on records in this space,
// with counts.
//
// This is the data behind the embed-model-match health check. A mismatch across
// peers degrades recall silently rather than erroring, so the only way it becomes
// visible is by someone counting (plan §4.3, §8.4).
func (c *Catalog) EmbedModels() map[string]int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[string]int)
	for _, m := range c.metas {
		out[m.EmbedModel]++
	}
	return out
}

// Agents returns the authoring agents seen in this space, with counts, for the
// agent-keys column of memctl members.
func (c *Catalog) Agents() map[record.AgentID]int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make(map[record.AgentID]int)
	for _, m := range c.metas {
		out[m.AuthorAgent]++
	}
	return out
}

func sortMetasNewestFirst(ms []*Meta) {
	sort.Slice(ms, func(i, j int) bool {
		if c := ms[i].HLC.Compare(ms[j].HLC); c != 0 {
			return c > 0
		}
		// HLC ties are possible across nodes; break on id so the order is total
		// and stable rather than dependent on map iteration.
		return ms[i].ID.Compare(ms[j].ID) > 0
	})
}

func appendUnique(list []ulid.ULID, id ulid.ULID) []ulid.ULID {
	for _, existing := range list {
		if existing == id {
			return list
		}
	}
	return append(list, id)
}
