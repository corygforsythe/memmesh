package record

import (
	"sort"
	"strings"

	"github.com/coryforsythe/memmesh/internal/ulid"
)

// VersionVector maps each authoring node to the highest record ID from that
// node the holder has seen, within one space.
//
// Using the record ID as the high-water mark rather than a separate sequence
// number works because a node's ULIDs are strictly increasing: the daemon owns
// one monotonic generator shared by every agent on the machine, and it is
// re-seeded from the store on boot so a backwards wall clock cannot produce a
// regression across restarts. The consequence is that "everything I have not
// seen from node N" is a single range scan, and the vector is the whole sync
// handshake payload (plan §5.1).
//
// A VersionVector serves two distinct jobs, and confusing them is a bug:
//
//   - As a node's sync state, it answers "what should you send me".
//   - As a record's causal_ctx, it answers "what had the author seen when they
//     wrote this", which is what separates disagreement from ignorance
//     (plan §2.1). HLC cannot make that distinction.
//
// The nil VersionVector is valid and empty. Methods that mutate take a pointer
// receiver and are not safe for concurrent use; copy with Clone at ownership
// boundaries.
type VersionVector map[NodeID]ulid.ULID

// NewVersionVector returns an empty vector ready for writing.
func NewVersionVector() VersionVector { return make(VersionVector) }

// Get returns the high-water ID for a node, or the zero ULID if the node is
// absent.
func (v VersionVector) Get(node NodeID) ulid.ULID { return v[node] }

// Observe raises the high-water mark for node to id if id is greater, and
// reports whether the vector changed. It never lowers a mark, so out-of-order
// delivery cannot make a node forget what it already has.
func (v VersionVector) Observe(node NodeID, id ulid.ULID) bool {
	cur, ok := v[node]
	if ok && cur.Compare(id) >= 0 {
		return false
	}
	v[node] = id
	return true
}

// Covers reports whether the vector already accounts for a record with this ID
// from this node.
//
// Used two ways: to skip a record during sync, and to ask of a record's
// causal_ctx "had this author seen that claim?".
func (v VersionVector) Covers(node NodeID, id ulid.ULID) bool {
	cur, ok := v[node]
	return ok && cur.Compare(id) >= 0
}

// Clone returns an independent copy.
func (v VersionVector) Clone() VersionVector {
	if v == nil {
		return nil
	}
	out := make(VersionVector, len(v))
	for k, val := range v {
		out[k] = val
	}
	return out
}

// Merge folds other into v, keeping the higher mark for each node, and reports
// whether v changed. This is the join of the lattice: merging is commutative,
// associative and idempotent, which is what makes anti-entropy converge
// regardless of the order peers are contacted in.
func (v VersionVector) Merge(other VersionVector) bool {
	changed := false
	for node, id := range other {
		if v.Observe(node, id) {
			changed = true
		}
	}
	return changed
}

// Nodes returns the nodes present in the vector, sorted. Sorted order is
// required by the canonical encoding, so this is the only accessor the encoder
// uses.
func (v VersionVector) Nodes() []NodeID {
	out := make([]NodeID, 0, len(v))
	for node := range v {
		out = append(out, node)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Equal reports whether two vectors hold identical marks.
func (v VersionVector) Equal(other VersionVector) bool {
	if len(v) != len(other) {
		return false
	}
	for node, id := range v {
		o, ok := other[node]
		if !ok || o != id {
			return false
		}
	}
	return true
}

// Dominates reports whether v accounts for everything other accounts for.
//
// If neither vector dominates the other, the two holders are concurrent: each
// has something the other lacks. That is the normal state of a healthy mesh, not
// an error.
func (v VersionVector) Dominates(other VersionVector) bool {
	for node, id := range other {
		if !v.Covers(node, id) {
			return false
		}
	}
	return true
}

// Concurrent reports whether neither vector dominates the other.
func Concurrent(a, b VersionVector) bool {
	return !a.Dominates(b) && !b.Dominates(a)
}

// MissingFrom lists, for each node in other, the high-water mark v needs to be
// brought up to — that is, the ranges v is behind on. Nodes where v is already
// current are omitted, so an empty result means v needs nothing from other.
//
// This is the delta request a sync handshake sends: cost scales with what is
// missing, not with corpus size.
func (v VersionVector) MissingFrom(other VersionVector) map[NodeID]Range {
	var out map[NodeID]Range
	for node, theirs := range other {
		mine := v[node]
		if mine.Compare(theirs) >= 0 {
			continue
		}
		if out == nil {
			out = make(map[NodeID]Range)
		}
		out[node] = Range{After: mine, Through: theirs}
	}
	return out
}

// Range is a half-open interval of record IDs from one node: everything with an
// ID strictly greater than After, up to and including Through.
type Range struct {
	// After is exclusive. The zero ULID means "from the beginning".
	After ulid.ULID `json:"after"`
	// Through is inclusive.
	Through ulid.ULID `json:"through"`
}

// Contains reports whether id falls inside the range.
func (r Range) Contains(id ulid.ULID) bool {
	return id.Compare(r.After) > 0 && id.Compare(r.Through) <= 0
}

// String renders the vector deterministically, for logs and CLI output.
func (v VersionVector) String() string {
	if len(v) == 0 {
		return "{}"
	}
	var b strings.Builder
	b.WriteByte('{')
	for i, node := range v.Nodes() {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(string(node))
		b.WriteByte(':')
		b.WriteString(v[node].String())
	}
	b.WriteByte('}')
	return b.String()
}
