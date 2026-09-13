package record

import (
	"errors"
	"fmt"
)

// Kind classifies what a record is. Retrieval quality depends on this
// separation: agents write mostly Episode, and a background distiller promotes
// episodes into Fact and Procedure (plan §2.2).
type Kind string

// The record kinds.
const (
	// KindEpisode is what happened. Agents write these freely.
	KindEpisode Kind = "episode"
	// KindFact is a durable claim. Written by the distiller, or by an agent
	// explicitly.
	KindFact Kind = "fact"
	// KindProcedure is how we do X here.
	KindProcedure Kind = "procedure"
	// KindArtifactRef points at a blob by content hash; the body holds the hash.
	KindArtifactRef Kind = "artifact_ref"
	// KindTombstone supersedes a record: "this should not be here".
	KindTombstone Kind = "tombstone"
	// KindRetraction supersedes a record while preserving the correction:
	// "this was wrong, because X". Distinct from a tombstone on purpose —
	// deleting a claim loses the information that someone believed it and why
	// that changed (plan §6.6).
	KindRetraction Kind = "retraction"
	// KindConflict links two contradictory records and carries no claim of its
	// own. Emitted by the distiller's contradiction pass.
	KindConflict Kind = "conflict"
)

// ErrBadKind reports an unrecognised kind.
var ErrBadKind = errors.New("record: unrecognised kind")

// Valid reports whether k is one of the defined kinds.
func (k Kind) Valid() bool {
	switch k {
	case KindEpisode, KindFact, KindProcedure, KindArtifactRef,
		KindTombstone, KindRetraction, KindConflict:
		return true
	}
	return false
}

// Supersedable reports whether this kind exists in order to supersede other
// records, and therefore requires a non-empty Supersedes list.
func (k Kind) Supersedable() bool {
	return k == KindTombstone || k == KindRetraction
}

// Claims reports whether the kind asserts something that can be contradicted.
// Only claiming kinds go through contradiction detection.
func (k Kind) Claims() bool {
	return k == KindFact || k == KindProcedure
}

// Evidence ranks how a claim is backed. It outranks recency in conflict
// resolution (plan §2.3, §6.5): a claim with an episode chain behind it beats an
// unsupported assertion regardless of age.
type Evidence string

// The evidence levels, weakest last.
const (
	// EvidenceObserved is backed by a transcript, command output or file
	// content the author actually saw.
	EvidenceObserved Evidence = "observed"
	// EvidenceAsserted is an agent's claim with no attached backing.
	EvidenceAsserted Evidence = "asserted"
	// EvidenceDerived is distiller output: a conclusion drawn from other
	// records.
	EvidenceDerived Evidence = "derived"
)

// ErrBadEvidence reports an unrecognised evidence level.
var ErrBadEvidence = errors.New("record: unrecognised evidence level")

// Valid reports whether e is one of the defined levels.
func (e Evidence) Valid() bool {
	switch e {
	case EvidenceObserved, EvidenceAsserted, EvidenceDerived:
		return true
	}
	return false
}

// Rank returns the resolution weight of the evidence level: higher wins.
//
// This is the first key in evidence-weighted resolution; HLC is only the
// tiebreak below it. An unrecognised level ranks lowest rather than erroring,
// so a record written by a future version never silently wins a comparison.
func (e Evidence) Rank() int {
	switch e {
	case EvidenceObserved:
		return 3
	case EvidenceAsserted:
		return 2
	case EvidenceDerived:
		return 1
	default:
		return 0
	}
}

// ConflictPolicy is how a space handles two records that assert contradictory
// things. Structural convergence is solved by append-only records; this is only
// about semantic disagreement (plan §6).
type ConflictPolicy string

// The conflict policies.
const (
	// PolicyLWW keeps the latest write by HLC and does not detect
	// contradictions. Acceptable for agent/* private spaces only.
	PolicyLWW ConflictPolicy = "lww"
	// PolicySiblingsAuto keeps contradictory records side by side, runs
	// contradiction detection, and may auto-resolve on evidence weight.
	PolicySiblingsAuto ConflictPolicy = "siblings-auto"
	// PolicySiblingsManual keeps contradictory records side by side and never
	// auto-resolves: every conflict queues for adjudication.
	PolicySiblingsManual ConflictPolicy = "siblings-manual"
)

// PolicyFor returns the conflict policy for a space, derived from its class
// (plan §6.8).
//
// The hard rule this encodes: shared spaces never auto-resolve. If user A's
// agent and user B's agent contradict each other, the system surfaces the
// conflict and stops, because choosing a winner across a trust boundary is a
// policy decision the software has no standing to make.
func PolicyFor(space SpaceID) ConflictPolicy {
	switch space.Class() {
	case ClassAgent:
		return PolicyLWW
	case ClassUser:
		return PolicySiblingsAuto
	case ClassShared:
		return PolicySiblingsManual
	default:
		// An unclassifiable space gets the most conservative policy rather than
		// the most convenient one.
		return PolicySiblingsManual
	}
}

// AutoResolves reports whether the policy permits the daemon to pick a winner
// without a human.
func (p ConflictPolicy) AutoResolves() bool {
	return p == PolicyLWW || p == PolicySiblingsAuto
}

// KeepsSiblings reports whether contradictory records are both retained and
// both returned by recall.
func (p ConflictPolicy) KeepsSiblings() bool {
	return p == PolicySiblingsAuto || p == PolicySiblingsManual
}

// String implements fmt.Stringer.
func (p ConflictPolicy) String() string { return string(p) }

// validateKind is the shared validation used by Record.Validate.
func validateKind(k Kind) error {
	if !k.Valid() {
		return fmt.Errorf("%w: %q", ErrBadKind, string(k))
	}
	return nil
}

func validateEvidence(e Evidence) error {
	if !e.Valid() {
		return fmt.Errorf("%w: %q", ErrBadEvidence, string(e))
	}
	return nil
}
