// Package hlc implements the hybrid logical clock stamped on every record.
//
// An HLC is a millisecond wall reading paired with a logical counter. It keeps
// two properties the mesh depends on:
//
//   - Timestamps never go backwards for a single node, even if its wall clock
//     does, so a node's own writes always order correctly.
//   - Receiving a record from a peer advances the local clock past it, so
//     causally-later writes carry strictly larger stamps across nodes.
//
// What an HLC does not give you is causality. It cannot distinguish "B saw A's
// claim and disagreed" from "B never saw it and wrote blind" — that is what the
// record's causal_ctx version vector is for (plan §2.1). Treat HLC as a total
// order for tiebreaking, never as evidence of what an author knew.
//
// HLC is also why clock skew is a first-class health check (plan §8.4): under
// drift the tiebreak degrades quietly rather than failing loudly.
package hlc

import (
	"fmt"
	"sync"
)

// Clock is the millisecond time source a Timestamper reads. It matches
// ulid.Clock so one injected fake can drive both packages.
type Clock interface {
	// NowMillis returns Unix milliseconds.
	NowMillis() uint64
}

// ClockFunc adapts a function to Clock.
type ClockFunc func() uint64

// NowMillis implements Clock.
func (f ClockFunc) NowMillis() uint64 { return f() }

// HLC is a hybrid logical clock reading: a wall-clock millisecond plus a
// logical counter that breaks ties inside a millisecond.
//
// The zero value is the earliest possible timestamp and is a valid sentinel.
type HLC struct {
	// Wall is Unix milliseconds, possibly ahead of the local physical clock
	// after observing a peer.
	Wall uint64 `json:"wall"`
	// Counter increments for events that share a Wall value.
	Counter uint32 `json:"counter"`
}

// Compare orders two timestamps, returning -1, 0 or +1.
//
// Equality is possible across nodes: two nodes can independently produce the
// same (Wall, Counter). Callers that need a strict total order must break the
// remaining tie on something globally unique, such as the record ID.
func (t HLC) Compare(other HLC) int {
	switch {
	case t.Wall < other.Wall:
		return -1
	case t.Wall > other.Wall:
		return 1
	case t.Counter < other.Counter:
		return -1
	case t.Counter > other.Counter:
		return 1
	default:
		return 0
	}
}

// Before reports whether t strictly precedes other.
func (t HLC) Before(other HLC) bool { return t.Compare(other) < 0 }

// After reports whether t strictly follows other.
func (t HLC) After(other HLC) bool { return t.Compare(other) > 0 }

// IsZero reports whether t is the zero timestamp.
func (t HLC) IsZero() bool { return t.Wall == 0 && t.Counter == 0 }

// String renders the timestamp as wall.counter.
func (t HLC) String() string { return fmt.Sprintf("%d.%d", t.Wall, t.Counter) }

// Max returns the later of two timestamps.
func Max(a, b HLC) HLC {
	if a.Compare(b) >= 0 {
		return a
	}
	return b
}

// Timestamper issues HLC readings for one node.
//
// A Timestamper is safe for concurrent use. Every record write goes through
// Now, and every received record goes through Observe; skipping the latter is
// how a mesh silently loses its cross-node ordering guarantee.
type Timestamper struct {
	clock Clock

	mu   sync.Mutex
	last HLC
}

// New returns a Timestamper reading physical time from clock.
func New(clock Clock) *Timestamper {
	return &Timestamper{clock: clock}
}

// Now returns the timestamp for a local event.
func (ts *Timestamper) Now() HLC {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.advance(HLC{})
}

// Observe folds a timestamp received from a peer into the local clock and
// returns the resulting local reading. Call it for every inbound record.
func (ts *Timestamper) Observe(remote HLC) HLC {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.advance(remote)
}

// Peek returns the current reading without advancing the clock.
func (ts *Timestamper) Peek() HLC {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.last
}

// advance implements the standard HLC update rule. remote may be the zero
// timestamp, which reduces it to the local-event case.
func (ts *Timestamper) advance(remote HLC) HLC {
	physical := ts.clock.NowMillis()
	prev := ts.last

	switch {
	case physical > prev.Wall && physical > remote.Wall:
		// The physical clock has genuinely moved on; the counter can reset.
		ts.last = HLC{Wall: physical, Counter: 0}
	case remote.Wall > prev.Wall:
		// The peer is ahead. Adopt its wall reading and step past its counter.
		ts.last = HLC{Wall: remote.Wall, Counter: remote.Counter + 1}
	case prev.Wall > remote.Wall:
		// We are ahead of both the peer and our own physical clock.
		ts.last = HLC{Wall: prev.Wall, Counter: prev.Counter + 1}
	default:
		// Same wall reading on both sides.
		c := prev.Counter
		if remote.Counter > c {
			c = remote.Counter
		}
		ts.last = HLC{Wall: prev.Wall, Counter: c + 1}
	}
	return ts.last
}

// Skew returns how far a peer's timestamp is ahead of the given local physical
// millisecond reading, in milliseconds. A negative result means the peer is
// behind. Both directions matter: drift in either one degrades tiebreaking.
//
// This is the primitive behind the clock-skew health check. It deliberately
// ignores the logical counter, because a counter running ahead is normal
// catch-up behaviour and not evidence of a misconfigured clock.
func Skew(peer HLC, localPhysicalMS uint64) int64 {
	return int64(peer.Wall) - int64(localPhysicalMS)
}
