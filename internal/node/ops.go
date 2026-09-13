package node

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/coryforsythe/memmesh/internal/hlc"
	"github.com/coryforsythe/memmesh/internal/record"
	"github.com/coryforsythe/memmesh/internal/store"
	"github.com/coryforsythe/memmesh/internal/ulid"
	"github.com/coryforsythe/memmesh/internal/wire"
)

// This file implements the five operations that are the whole agent-facing surface:
// remember, recall, forget, link and list_spaces (plan §7). The MCP server is a thin
// translation layer over them, and so is anything else that ever talks to a node.

// DefaultRecallLimit is how many hits recall returns when the caller does not say.
const DefaultRecallLimit = 8

// MaxSiblings caps how many contradictory records are returned alongside a hit.
//
// Beyond the cap the conflict is queued for adjudication rather than the response
// growing without bound (plan §6.2). An agent handed twelve mutually contradictory
// claims is not better informed than one handed four and told there are more.
const MaxSiblings = 4

// Errors returned by the operations.
var (
	// ErrNoSuchSpace reports a space this node does not hold.
	ErrNoSuchSpace = errors.New("node: no such space")
	// ErrEmptyBody reports a write with nothing in it.
	ErrEmptyBody = errors.New("node: record body is empty")
)

// RememberRequest is a write.
type RememberRequest struct {
	// Agent names the writing agent. Its keypair is created on first use.
	Agent string `json:"agent"`
	// Space is where the record goes.
	Space record.SpaceID `json:"space"`
	// Kind defaults to episode, which is what agents should write most of: a
	// description of what happened, for the distiller to promote later.
	Kind record.Kind `json:"kind,omitempty"`
	// Body is the content.
	Body string `json:"body"`
	// Tags are how an agent says what this is about in words the body may not use.
	Tags []string `json:"tags,omitempty"`
	// Evidence defaults to asserted. Claim observed only with real backing.
	Evidence record.Evidence `json:"evidence,omitempty"`
	// Supersedes replaces existing records with this one.
	Supersedes []ulid.ULID `json:"supersedes,omitempty"`
	// Refs relates this record to others without replacing them.
	Refs []ulid.ULID `json:"refs,omitempty"`
}

// RememberResult is what a write produced.
type RememberResult struct {
	ID          ulid.ULID       `json:"id"`
	Space       record.SpaceID  `json:"space"`
	Kind        record.Kind     `json:"kind"`
	Evidence    record.Evidence `json:"evidence"`
	AuthorAgent string          `json:"author_agent"`
	HLC         hlc.HLC         `json:"hlc"`
	Epoch       uint32          `json:"epoch"`
	SealedBytes int             `json:"sealed_bytes"`
	// Superseded lists what this record replaced, echoed back so a caller can see
	// the write did what it meant to.
	Superseded []ulid.ULID `json:"superseded,omitempty"`
}

// Remember writes a record.
//
// The record's causal context is the space's current version vector: what this node
// had seen at write time. That is what later lets a reader tell a considered
// disagreement from a blind write, and it costs nothing to capture here while it is
// still knowable (plan §2.1).
func (n *Node) Remember(req RememberRequest) (*RememberResult, error) {
	space, err := n.readableSpace(req.Space)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.Body) == "" && len(req.Supersedes) == 0 {
		return nil, ErrEmptyBody
	}
	kind := req.Kind
	if kind == "" {
		kind = record.KindEpisode
	}
	builder, err := n.builderFor(agentOrDefault(req.Agent))
	if err != nil {
		return nil, err
	}
	epoch, err := n.keys.ring.CurrentEpoch(string(req.Space))
	if err != nil {
		return nil, err
	}

	r, err := builder.Build(record.Draft{
		Space:      req.Space,
		Kind:       kind,
		Body:       []byte(req.Body),
		Tags:       req.Tags,
		Supersedes: req.Supersedes,
		Refs:       req.Refs,
		Evidence:   req.Evidence,
		CausalCtx:  space.Vector(),
		Epoch:      epoch,
	})
	if err != nil {
		return nil, err
	}

	sealed, err := space.Write(r)
	if err != nil {
		return nil, err
	}
	if err := n.indexWritten(req.Space, r); err != nil {
		return nil, err
	}
	n.notifyWrite(req.Space, sealed)

	return &RememberResult{
		ID:          r.ID,
		Space:       r.Space,
		Kind:        r.Kind,
		Evidence:    r.Evidence,
		AuthorAgent: r.AuthorAgent.String(),
		HLC:         r.HLC,
		Epoch:       r.Epoch,
		SealedBytes: sealed.Len(),
		Superseded:  r.Supersedes,
	}, nil
}

// indexWritten embeds a newly written record.
//
// Superseded records deliberately stay in the index. Supersession is filtered at query
// time, in buildHit, and having exactly one mechanism for it is what makes
// include_superseded work: a caller reconstructing what a space used to say needs the
// old claims to still be findable by content, not merely by id. Evicting their vectors
// would be a second, redundant filter that silently disabled that.
//
// The cost is that the index holds vectors for claims nobody will see by default. In a
// memory system that is the right trade: records are superseded far more often than
// they are numerous, and the alternative loses a feature to save a few kilobytes.
func (n *Node) indexWritten(spaceID record.SpaceID, r *record.Record) error {
	idx, err := n.indexFor(spaceID)
	if err != nil || idx == nil {
		return err
	}
	return n.indexRecord(idx, r)
}

// RecallRequest is a search.
type RecallRequest struct {
	// Query is the text to search for. Required.
	Query string `json:"query"`
	// Spaces limits the search. Empty means every readable space.
	Spaces []record.SpaceID `json:"spaces,omitempty"`
	// Limit caps the hits returned.
	Limit int `json:"limit,omitempty"`
	// Kinds filters by record kind. Empty means every kind.
	Kinds []record.Kind `json:"kinds,omitempty"`
	// Tags requires a hit to carry all of these tags.
	Tags []string `json:"tags,omitempty"`
	// IncludeSuperseded surfaces records that have been replaced. Off by default,
	// and worth turning on when reconstructing what a space used to say.
	IncludeSuperseded bool `json:"include_superseded,omitempty"`
	// MinScore drops hits below a similarity threshold.
	MinScore float32 `json:"min_score,omitempty"`
}

// Provenance is who wrote a record and how well backed it is.
//
// Every hit carries it, because the consumer is a language model weighing
// contradictory evidence, and it cannot weigh what it cannot see (plan §6.2).
type Provenance struct {
	AuthorAgent string          `json:"author_agent"`
	AuthorNode  string          `json:"author_node"`
	AuthorModel string          `json:"author_model,omitempty"`
	Evidence    record.Evidence `json:"evidence"`
	HLC         hlc.HLC         `json:"hlc"`
	Epoch       uint32          `json:"epoch"`
}

// Hit is one recall result.
type Hit struct {
	ID    ulid.ULID      `json:"id"`
	Space record.SpaceID `json:"space"`
	Kind  record.Kind    `json:"kind"`
	Body  string         `json:"body"`
	Tags  []string       `json:"tags,omitempty"`
	Score float32        `json:"score"`

	Provenance Provenance `json:"provenance"`

	// Superseded reports that this record has been replaced.
	Superseded bool `json:"superseded,omitempty"`
	// SupersededBy names what replaced it.
	SupersededBy []ulid.ULID `json:"superseded_by,omitempty"`
	// Retractions carries the text of any retraction that replaced this record,
	// so the correction travels with the claim rather than being something the
	// caller has to go and look for.
	Retractions []string `json:"retractions,omitempty"`

	// Siblings are records that contradict this one and are equally current.
	Siblings []Sibling `json:"siblings,omitempty"`
	// MoreSiblings reports how many contradictory records were left out at the
	// sibling cap. A non-zero value means this claim needs adjudication, not more
	// reading.
	MoreSiblings int `json:"more_siblings,omitempty"`
	// Refs relates this record to others.
	Refs []ulid.ULID `json:"refs,omitempty"`
}

// Sibling is a contradictory record returned alongside a hit.
type Sibling struct {
	ID         ulid.ULID   `json:"id"`
	Kind       record.Kind `json:"kind"`
	Body       string      `json:"body"`
	Provenance Provenance  `json:"provenance"`
	// SawThisClaim reports whether the sibling's author had already seen the hit
	// when they wrote their contradicting version.
	//
	// This is the distinction HLC cannot make and causal context can: true means a
	// considered disagreement, false means the author wrote blind. They deserve
	// different treatment, and an agent handed both without being told which is
	// which will treat them the same (plan §2.1).
	SawThisClaim bool `json:"saw_this_claim"`
	// ConflictRecord is the record that linked the two, for adjudication.
	ConflictRecord ulid.ULID `json:"conflict_record"`
}

// RecallResult is a search response.
type RecallResult struct {
	Query string `json:"query"`
	// Searched lists the spaces actually searched.
	Searched []record.SpaceID `json:"searched"`
	// Skipped lists spaces that were asked for but could not be searched, with
	// the reason. A relayed space appears here rather than silently returning
	// nothing, because "no results" and "cannot look" are very different answers.
	Skipped map[record.SpaceID]string `json:"skipped,omitempty"`
	Hits    []Hit                     `json:"hits"`
	// EmbedModel is the model the query was embedded with. If a hit was embedded
	// under a different one, similarity is not comparable, and this is how a
	// caller can tell.
	EmbedModel string `json:"embed_model"`
	// Warnings surface conditions that degrade results without failing, which is
	// the whole category of problem this system is most exposed to.
	Warnings []string `json:"warnings,omitempty"`
}

// Recall searches the readable spaces.
//
// Contradictory records are returned side by side, never resolved down to one. The
// consumer is a language model that can weigh contradictory evidence, which is an
// unusually good fit for multi-value returns — but only if it is told that is what it
// is looking at, which is why every sibling carries full provenance and an explicit
// note about whether its author had seen the claim they contradict.
func (n *Node) Recall(req RecallRequest) (*RecallResult, error) {
	if strings.TrimSpace(req.Query) == "" {
		return nil, fmt.Errorf("node: recall needs a query")
	}
	limit := req.Limit
	if limit <= 0 {
		limit = DefaultRecallLimit
	}

	queryVec, err := n.embedder.Embed(req.Query)
	if err != nil {
		return nil, fmt.Errorf("node: embed query: %w", err)
	}

	out := &RecallResult{
		Query:      req.Query,
		EmbedModel: n.embedder.ModelID(),
		Skipped:    make(map[record.SpaceID]string),
	}

	targets := req.Spaces
	if len(targets) == 0 {
		targets = n.store.Spaces()
	}
	kindFilter := kindSet(req.Kinds)

	for _, id := range SortedSpaces(targets) {
		space, ok := n.store.Get(id)
		if !ok {
			out.Skipped[id] = "not held on this node"
			continue
		}
		if !space.Readable() {
			out.Skipped[id] = "relayed on this node; no key to search with"
			continue
		}
		idx, err := n.indexFor(id)
		if err != nil {
			return nil, err
		}
		if idx == nil {
			out.Skipped[id] = "not indexed"
			continue
		}
		out.Searched = append(out.Searched, id)

		// Ask the index for more than the caller wants, because filtering by kind,
		// tag and supersession happens after the vector search and will discard
		// some of what comes back.
		matches, err := idx.Search(queryVec, limit*4+MaxSiblings)
		if err != nil {
			return nil, err
		}
		cat := space.Catalog()
		for _, m := range matches {
			if m.Score < req.MinScore {
				continue
			}
			hit, ok := n.buildHit(space, cat, id, m.ID, m.Score, req, kindFilter)
			if !ok {
				continue
			}
			out.Hits = append(out.Hits, *hit)
		}
	}

	sort.SliceStable(out.Hits, func(i, j int) bool {
		if out.Hits[i].Score != out.Hits[j].Score {
			return out.Hits[i].Score > out.Hits[j].Score
		}
		return out.Hits[i].ID.Compare(out.Hits[j].ID) < 0
	})
	if len(out.Hits) > limit {
		out.Hits = out.Hits[:limit]
	}
	if len(out.Skipped) == 0 {
		out.Skipped = nil
	}
	out.Warnings = n.recallWarnings(out)
	return out, nil
}

// buildHit assembles one result, applying the post-search filters. It reports false
// when the record should not be returned at all.
func (n *Node) buildHit(
	space *store.Space,
	cat *store.Catalog,
	spaceID record.SpaceID,
	id ulid.ULID,
	score float32,
	req RecallRequest,
	kinds map[record.Kind]bool,
) (*Hit, bool) {
	meta, ok := cat.Get(id)
	if !ok {
		return nil, false
	}
	if len(kinds) > 0 && !kinds[meta.Kind] {
		return nil, false
	}
	if !hasAllTags(meta.Tags, req.Tags) {
		return nil, false
	}
	supersededBy, superseded := cat.Superseded(id)
	if superseded && !req.IncludeSuperseded {
		return nil, false
	}

	r, err := space.Record(id)
	if err != nil {
		return nil, false
	}

	hit := &Hit{
		ID:           id,
		Space:        spaceID,
		Kind:         meta.Kind,
		Body:         string(r.Body),
		Tags:         meta.Tags,
		Score:        score,
		Provenance:   provenanceOf(meta),
		Superseded:   superseded,
		SupersededBy: supersededBy,
		Refs:         meta.Refs,
	}
	for _, ret := range cat.Retractions(id) {
		if rr, err := space.Record(ret.ID); err == nil {
			hit.Retractions = append(hit.Retractions, string(rr.Body))
		}
	}
	hit.Siblings, hit.MoreSiblings = n.siblingsOf(space, cat, r)
	return hit, true
}

// siblingsOf collects the records that contradict r, via the conflict records that
// link them.
//
// Conflict records are the only source here. A record is not a sibling because it is
// merely similar — similarity is what the search already measured — but because
// something explicitly recorded that the two disagree.
func (n *Node) siblingsOf(space *store.Space, cat *store.Catalog, r *record.Record) ([]Sibling, int) {
	if !r.Kind.Claims() {
		return nil, 0
	}
	var out []Sibling
	seen := map[ulid.ULID]bool{r.ID: true}
	total := 0

	for _, conflict := range cat.Conflicts(r.ID) {
		for _, other := range conflict.Refs {
			if seen[other] {
				continue
			}
			seen[other] = true
			otherMeta, ok := cat.Get(other)
			if !ok {
				continue
			}
			// A side that has since been superseded is no longer a live
			// disagreement; the supersession already settled it.
			if _, superseded := cat.Superseded(other); superseded {
				continue
			}
			total++
			if len(out) >= MaxSiblings {
				continue
			}
			otherRec, err := space.Record(other)
			if err != nil {
				continue
			}
			out = append(out, Sibling{
				ID:             other,
				Kind:           otherMeta.Kind,
				Body:           string(otherRec.Body),
				Provenance:     provenanceOf(otherMeta),
				SawThisClaim:   otherRec.SawRecord(r),
				ConflictRecord: conflict.ID,
			})
		}
	}
	return out, total - len(out)
}

// recallWarnings reports conditions that make results worse without making them
// fail. Silent degradation is the failure mode this design is most exposed to, so
// the response says so out loud.
func (n *Node) recallWarnings(res *RecallResult) []string {
	var warnings []string
	if !n.Warm() {
		warnings = append(warnings, "index is still warming; results may be incomplete")
	}
	models := n.EmbedModelCounts()
	if len(models) > 1 {
		var others []string
		for model := range models {
			if model != n.embedder.ModelID() {
				others = append(others, model)
			}
		}
		sort.Strings(others)
		warnings = append(warnings, fmt.Sprintf(
			"this node holds records embedded by %s; similarity against those is not comparable to the query",
			strings.Join(others, ", ")))
	}
	for _, hit := range res.Hits {
		if hit.MoreSiblings > 0 {
			warnings = append(warnings, fmt.Sprintf(
				"record %s has %d further contradictory siblings beyond the cap; it needs adjudication, not more reading",
				hit.ID, hit.MoreSiblings))
			break
		}
	}
	return warnings
}

// ForgetRequest removes a record.
type ForgetRequest struct {
	Agent string         `json:"agent"`
	Space record.SpaceID `json:"space"`
	ID    ulid.ULID      `json:"id"`
	// Reason, when given, produces a retraction instead of a tombstone: the claim
	// stops surfacing but the correction stays auditable. Prefer it — deleting a
	// claim loses the information that someone believed it and why that changed
	// (plan §6.6).
	Reason string `json:"reason,omitempty"`
}

// ForgetResult is what a removal produced.
type ForgetResult struct {
	// Record is the tombstone or retraction that was written. Forgetting is a
	// write, never a deletion: nothing is ever removed from the log.
	Record ulid.ULID   `json:"record"`
	Kind   record.Kind `json:"kind"`
	Target ulid.ULID   `json:"target"`
}

// Forget supersedes a record with a tombstone or a retraction.
//
// Neither deletes anything. The original stays in the log, stays verifiable, and
// stays reachable by id; what changes is that recall stops surfacing it. That is a
// property of append-only storage, not an oversight, and it is worth being explicit
// about with anyone who expects "forget" to mean erasure.
func (n *Node) Forget(req ForgetRequest) (*ForgetResult, error) {
	space, err := n.readableSpace(req.Space)
	if err != nil {
		return nil, err
	}
	if _, ok := space.Catalog().Get(req.ID); !ok {
		return nil, fmt.Errorf("node: %s is not in %s on this node", req.ID, req.Space)
	}
	builder, err := n.builderFor(agentOrDefault(req.Agent))
	if err != nil {
		return nil, err
	}
	epoch, err := n.keys.ring.CurrentEpoch(string(req.Space))
	if err != nil {
		return nil, err
	}

	var r *record.Record
	if strings.TrimSpace(req.Reason) != "" {
		r, err = builder.Retract(req.Space, epoch, req.Reason, space.Vector(), req.ID)
	} else {
		r, err = builder.Tombstone(req.Space, epoch, space.Vector(), req.ID)
	}
	if err != nil {
		return nil, err
	}
	sealed, err := space.Write(r)
	if err != nil {
		return nil, err
	}
	if err := n.indexWritten(req.Space, r); err != nil {
		return nil, err
	}
	n.notifyWrite(req.Space, sealed)
	return &ForgetResult{Record: r.ID, Kind: r.Kind, Target: req.ID}, nil
}

// LinkRequest relates records to each other.
type LinkRequest struct {
	Agent string         `json:"agent"`
	Space record.SpaceID `json:"space"`
	IDs   []ulid.ULID    `json:"ids"`
	Note  string         `json:"note,omitempty"`
}

// LinkResult is what a link produced.
type LinkResult struct {
	Record ulid.ULID   `json:"record"`
	Linked []ulid.ULID `json:"linked"`
}

// Link records that some memories belong together, without replacing any of them.
func (n *Node) Link(req LinkRequest) (*LinkResult, error) {
	space, err := n.readableSpace(req.Space)
	if err != nil {
		return nil, err
	}
	if len(req.IDs) < 2 {
		return nil, fmt.Errorf("node: a link needs at least two records, got %d", len(req.IDs))
	}
	for _, id := range req.IDs {
		if _, ok := space.Catalog().Get(id); !ok {
			return nil, fmt.Errorf("node: %s is not in %s on this node", id, req.Space)
		}
	}
	builder, err := n.builderFor(agentOrDefault(req.Agent))
	if err != nil {
		return nil, err
	}
	epoch, err := n.keys.ring.CurrentEpoch(string(req.Space))
	if err != nil {
		return nil, err
	}
	note := req.Note
	if strings.TrimSpace(note) == "" {
		note = "related records"
	}
	r, err := builder.Link(req.Space, epoch, note, space.Vector(), req.IDs...)
	if err != nil {
		return nil, err
	}
	sealed, err := space.Write(r)
	if err != nil {
		return nil, err
	}
	if err := n.indexWritten(req.Space, r); err != nil {
		return nil, err
	}
	n.notifyWrite(req.Space, sealed)
	return &LinkResult{Record: r.ID, Linked: r.Refs}, nil
}

// SpaceInfo describes one space to a caller.
//
// For a relayed space everything past Records and Bytes is left empty: counts and
// bytes only, never a body, never a tag, never a decrypted title (plan §8).
type SpaceInfo struct {
	Space    record.SpaceID `json:"space"`
	Class    string         `json:"class"`
	Readable bool           `json:"readable"`
	Policy   string         `json:"conflict_policy"`
	Records  int            `json:"records"`
	Bytes    int64          `json:"bytes"`
	Epoch    uint32         `json:"epoch,omitempty"`
	ByKind   map[string]int `json:"by_kind,omitempty"`
	Indexed  int            `json:"indexed,omitempty"`
	// Undecryptable counts records held but sealed under an epoch this node has no
	// key for, which happens to a member added part way through a space's life.
	Undecryptable int `json:"undecryptable,omitempty"`
}

// ListSpaces describes every space this node holds.
func (n *Node) ListSpaces() []SpaceInfo {
	out := make([]SpaceInfo, 0, len(n.store.Spaces()))
	for _, id := range n.store.Spaces() {
		space, ok := n.store.Get(id)
		if !ok {
			continue
		}
		stats := space.Stats()
		info := SpaceInfo{
			Space:    id,
			Class:    string(id.Class()),
			Readable: stats.Readable,
			Policy:   stats.Policy,
			Records:  stats.Records,
			Bytes:    stats.Bytes,
		}
		if stats.Readable {
			info.Epoch = stats.Epoch
			info.ByKind = stats.ByKind
			info.Undecryptable = stats.Undecryptable
			n.mu.RLock()
			if idx, ok := n.indexes[id]; ok {
				info.Indexed = idx.Len()
			}
			n.mu.RUnlock()
		}
		out = append(out, info)
	}
	return out
}

// Get returns one record in full, by space and id. Not one of the five tools, but
// the operation every one of them needs when a caller wants to follow a reference.
func (n *Node) Get(spaceID record.SpaceID, id ulid.ULID) (*Hit, error) {
	space, err := n.readableSpace(spaceID)
	if err != nil {
		return nil, err
	}
	cat := space.Catalog()
	hit, ok := n.buildHit(space, cat, spaceID, id, 1, RecallRequest{IncludeSuperseded: true}, nil)
	if !ok {
		return nil, fmt.Errorf("node: %s is not in %s on this node", id, spaceID)
	}
	return hit, nil
}

// Accept hands records received from a peer to the right space, indexing what it can
// read. It is the sync engine's write path.
func (n *Node) Accept(spaceID record.SpaceID, entries ...*wire.SealedRecord) (int, error) {
	n.mu.RLock()
	closed := n.closed
	n.mu.RUnlock()
	if closed {
		return 0, ErrClosed
	}
	space, ok := n.store.Get(spaceID)
	if !ok {
		if !n.cfg.Relay {
			return 0, fmt.Errorf("%w: %s", ErrNoSuchSpace, spaceID)
		}
		// Relaying is on, so a space offered by a peer is one this node is willing
		// to carry even with no key for it.
		var err error
		space, err = n.store.Open(spaceID)
		if err != nil {
			return 0, err
		}
	}

	written, err := space.Accept(entries...)
	if err != nil {
		return written, err
	}
	if written == 0 || !space.Readable() {
		return written, nil
	}

	// Fold the new records' HLC readings into the local clock, or this node's own
	// later writes would not order after them.
	idx, err := n.indexFor(spaceID)
	if err != nil {
		return written, err
	}
	for _, entry := range entries {
		r, err := space.Record(entry.ID)
		if err != nil {
			continue
		}
		n.stamps.Observe(r.HLC)
		if idx != nil {
			if err := n.indexRecord(idx, r); err != nil {
				return written, err
			}
		}
	}
	return written, nil
}

func (n *Node) readableSpace(id record.SpaceID) (*store.Space, error) {
	n.mu.RLock()
	closed := n.closed
	n.mu.RUnlock()
	if closed {
		return nil, ErrClosed
	}
	space, ok := n.store.Get(id)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNoSuchSpace, id)
	}
	if !space.Readable() {
		return nil, fmt.Errorf("%w: %s", store.ErrRelayed, id)
	}
	return space, nil
}

func provenanceOf(m *store.Meta) Provenance {
	return Provenance{
		AuthorAgent: m.AuthorAgent.String(),
		AuthorNode:  string(m.AuthorNode),
		AuthorModel: m.AuthorModel,
		Evidence:    m.Evidence,
		HLC:         m.HLC,
		Epoch:       m.Epoch,
	}
}

func kindSet(kinds []record.Kind) map[record.Kind]bool {
	if len(kinds) == 0 {
		return nil
	}
	out := make(map[record.Kind]bool, len(kinds))
	for _, k := range kinds {
		out[k] = true
	}
	return out
}

func hasAllTags(have, want []string) bool {
	if len(want) == 0 {
		return true
	}
	set := make(map[string]bool, len(have))
	for _, t := range have {
		set[t] = true
	}
	for _, t := range want {
		if !set[t] {
			return false
		}
	}
	return true
}

// agentOrDefault names the agent a request came from, falling back to a shared
// default.
//
// The fallback exists so a client that has not been configured with an identity
// still works, but it is deliberately named: records written by "default" are
// visibly unattributed rather than borrowing someone else's key.
func agentOrDefault(name string) string {
	if strings.TrimSpace(name) == "" {
		return "default"
	}
	return name
}
