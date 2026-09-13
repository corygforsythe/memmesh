package record

import (
	"fmt"

	"github.com/coryforsythe/memmesh/internal/hlc"
	"github.com/coryforsythe/memmesh/internal/ulid"
)

// IDSource issues record IDs. The daemon owns exactly one per node, shared by
// every agent on that machine, because version vectors are keyed by node and
// depend on that node's IDs being strictly increasing.
type IDSource interface {
	Next() (ulid.ULID, error)
}

// Builder assembles and signs records for one agent on one node.
//
// It exists so that the fields an author must not get wrong — node, agent, HLC
// advancement, causal context, embed model — are supplied once at construction
// rather than at every call site. A Builder is not safe for concurrent use; give
// each agent its own.
type Builder struct {
	node       NodeID
	signer     *Signer
	ids        IDSource
	stamps     *hlc.Timestamper
	model      string
	embedModel string
}

// BuilderConfig configures a Builder.
type BuilderConfig struct {
	// Node is the machine this agent runs on.
	Node NodeID
	// Signer is the agent keypair.
	Signer *Signer
	// IDs is the node-wide record ID source.
	IDs IDSource
	// Stamps is the node-wide HLC.
	Stamps *hlc.Timestamper
	// AuthorModel is recorded for audit only.
	AuthorModel string
	// EmbedModel is the local embedding model ID, pinned onto every record.
	EmbedModel string
}

// NewBuilder validates the configuration and returns a Builder.
func NewBuilder(cfg BuilderConfig) (*Builder, error) {
	if !cfg.Node.Valid() {
		return nil, fmt.Errorf("record: builder node %q is not a valid node id", string(cfg.Node))
	}
	if cfg.Signer == nil {
		return nil, fmt.Errorf("record: builder requires a signer")
	}
	if cfg.IDs == nil {
		return nil, fmt.Errorf("record: builder requires an id source")
	}
	if cfg.Stamps == nil {
		return nil, fmt.Errorf("record: builder requires an hlc timestamper")
	}
	return &Builder{
		node:       cfg.Node,
		signer:     cfg.Signer,
		ids:        cfg.IDs,
		stamps:     cfg.Stamps,
		model:      cfg.AuthorModel,
		embedModel: cfg.EmbedModel,
	}, nil
}

// AgentID returns the identity this Builder signs with.
func (b *Builder) AgentID() AgentID { return b.signer.AgentID() }

// Node returns the machine this Builder writes as.
func (b *Builder) Node() NodeID { return b.node }

// Draft is the caller-supplied half of a record: the content, without any of the
// identity, ordering or provenance machinery.
type Draft struct {
	Space      SpaceID
	Kind       Kind
	Body       []byte
	Tags       []string
	Supersedes []ulid.ULID
	// Refs relates this record to others without replacing them.
	Refs     []ulid.ULID
	Evidence Evidence
	// CausalCtx is what the author had seen. Pass the store's current version
	// vector for the space; an empty one is honest only for a genuinely blind
	// write.
	CausalCtx VersionVector
	// Epoch is the key epoch in force for the space.
	Epoch uint32
}

// Build stamps, normalizes and signs a draft.
//
// Evidence defaults to asserted rather than observed: an agent that does not say
// what backs a claim has, by definition, not shown its backing, and defaulting
// the other way would quietly inflate the rank of every unsourced write.
func (b *Builder) Build(d Draft) (*Record, error) {
	id, err := b.ids.Next()
	if err != nil {
		return nil, fmt.Errorf("record: allocate id: %w", err)
	}
	if d.Evidence == "" {
		d.Evidence = EvidenceAsserted
	}
	r := &Record{
		ID:          id,
		Space:       d.Space,
		AuthorNode:  b.node,
		AuthorAgent: b.signer.AgentID(),
		AuthorModel: b.model,
		HLC:         b.stamps.Now(),
		Epoch:       d.Epoch,
		Kind:        d.Kind,
		Body:        d.Body,
		Tags:        d.Tags,
		Supersedes:  d.Supersedes,
		Refs:        d.Refs,
		CausalCtx:   d.CausalCtx.Clone(),
		Evidence:    d.Evidence,
		EmbedModel:  b.embedModel,
	}
	if err := b.signer.Sign(r); err != nil {
		return nil, err
	}
	return r, nil
}

// Tombstone builds a record that removes others without preserving why.
func (b *Builder) Tombstone(space SpaceID, epoch uint32, ctx VersionVector, targets ...ulid.ULID) (*Record, error) {
	return b.Build(Draft{
		Space:      space,
		Kind:       KindTombstone,
		Supersedes: targets,
		Evidence:   EvidenceAsserted,
		CausalCtx:  ctx,
		Epoch:      epoch,
	})
}

// Retract builds a record that supersedes others while preserving the
// correction. Prefer it over Tombstone whenever the reason matters — which is
// most of the time, since deleting a claim loses the information that someone
// believed it and why that changed (plan §6.6).
func (b *Builder) Retract(space SpaceID, epoch uint32, reason string, ctx VersionVector, targets ...ulid.ULID) (*Record, error) {
	if reason == "" {
		return nil, fmt.Errorf("record: a retraction requires a reason; use Tombstone if there is none")
	}
	return b.Build(Draft{
		Space:      space,
		Kind:       KindRetraction,
		Body:       []byte(reason),
		Supersedes: targets,
		Evidence:   EvidenceAsserted,
		CausalCtx:  ctx,
		Epoch:      epoch,
	})
}

// Link relates records to each other without asserting anything about them and
// without replacing any of them. This is what the link MCP tool writes.
func (b *Builder) Link(space SpaceID, epoch uint32, note string, ctx VersionVector, targets ...ulid.ULID) (*Record, error) {
	if len(targets) < 2 {
		return nil, fmt.Errorf("record: a link needs at least two targets, got %d", len(targets))
	}
	return b.Build(Draft{
		Space:     space,
		Kind:      KindEpisode,
		Body:      []byte(note),
		Refs:      targets,
		Evidence:  EvidenceAsserted,
		CausalCtx: ctx,
		Epoch:     epoch,
	})
}

// Conflict links two or more contradictory records. It carries no claim of its
// own: the records it names are the whole content, and neither side is
// superseded, because siblings are both kept and both returned (plan §6.2).
//
// Written by the distiller's contradiction pass, never to pick a winner.
func (b *Builder) Conflict(space SpaceID, epoch uint32, note string, ctx VersionVector, sides ...ulid.ULID) (*Record, error) {
	if len(sides) < 2 {
		return nil, fmt.Errorf("record: a conflict needs at least two sides, got %d", len(sides))
	}
	return b.Build(Draft{
		Space:     space,
		Kind:      KindConflict,
		Body:      []byte(note),
		Refs:      sides,
		Evidence:  EvidenceDerived,
		CausalCtx: ctx,
		Epoch:     epoch,
	})
}
