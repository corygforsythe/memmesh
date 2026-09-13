package ulid

import (
	"crypto/rand"
	"errors"
	"io"
	"sync"
)

// Clock is the millisecond time source a Monotonic generator reads.
//
// It is an interface rather than a func value so that test clocks can also
// expose stepping helpers, and so a single fake can be shared with the hlc
// package (plan §0.5: determinism is injected, never global).
type Clock interface {
	// NowMillis returns Unix milliseconds.
	NowMillis() uint64
}

// ClockFunc adapts a function to Clock.
type ClockFunc func() uint64

// NowMillis implements Clock.
func (f ClockFunc) NowMillis() uint64 { return f() }

// ErrEntropyExhausted reports that too many ULIDs were requested inside a
// single millisecond for the 80-bit entropy field to be incremented further.
// Reaching it means ~1.2e24 IDs in one millisecond, so in practice it signals a
// clock that is going backwards rather than real load.
var ErrEntropyExhausted = errors.New("ulid: monotonic entropy exhausted within the millisecond")

// Monotonic generates ULIDs that strictly increase for a single author, even
// when several are created inside the same millisecond or when the wall clock
// steps backwards.
//
// Strict local monotonicity is what lets the store treat record IDs as an
// append-only sequence per author: a later write from the same agent always
// sorts after an earlier one, so log order and ID order never disagree.
//
// A Monotonic is safe for concurrent use.
type Monotonic struct {
	clock   Clock
	entropy io.Reader

	mu     sync.Mutex
	lastMS uint64
	last   ULID
	seeded bool
}

// NewMonotonic returns a generator reading time from clock and randomness from
// entropy. A nil entropy source means crypto/rand.
func NewMonotonic(clock Clock, entropy io.Reader) *Monotonic {
	if entropy == nil {
		entropy = rand.Reader
	}
	return &Monotonic{clock: clock, entropy: entropy}
}

// Next returns the next ULID for this author.
//
// Within a fresh millisecond the entropy is drawn from the injected source.
// Within a repeated millisecond, or one that has gone backwards, the previous
// ULID's entropy is incremented instead, which keeps the result both unique and
// strictly greater than its predecessor.
func (m *Monotonic) Next() (ULID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	ms := m.clock.NowMillis()
	if ms > MaxTime {
		return Zero, ErrBadTime
	}

	// A clock that moved backwards must not produce a descending ID. Pin to the
	// last observed millisecond and take the increment path; the timestamp is
	// then slightly ahead of the local clock, which is exactly the compromise
	// HLC makes for the same reason.
	if m.seeded && ms <= m.lastMS {
		next, err := increment(m.last)
		if err != nil {
			return Zero, err
		}
		m.last = next
		return next, nil
	}

	u, err := New(ms, m.entropy)
	if err != nil {
		return Zero, err
	}
	m.lastMS = ms
	m.last = u
	m.seeded = true
	return u, nil
}

// Seed advances the generator so that every subsequent Next returns a ULID
// strictly greater than u.
//
// This exists for one specific hazard. The generator's state is in memory, so a
// restart loses it; if the wall clock moved backwards while the process was down,
// a fresh generator could mint an id below one this node has already published,
// and a peer whose version vector has passed that mark would never ask for the
// record again. Seeding from the store's high-water mark on boot closes that hole
// (docs/decisions/0001).
//
// Seeding never moves the generator backwards: a u below the current state is
// ignored.
func (m *Monotonic) Seed(u ULID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seeded && m.last.Compare(u) >= 0 {
		return
	}
	m.last = u
	m.lastMS = u.Time()
	m.seeded = true
}

// MustNext is Next that panics on failure. For tests only.
func (m *Monotonic) MustNext() ULID {
	u, err := m.Next()
	if err != nil {
		panic(err)
	}
	return u
}

// increment adds one to the 80-bit entropy field, keeping the timestamp fixed.
func increment(u ULID) (ULID, error) {
	out := u
	for i := Size - 1; i >= 6; i-- {
		out[i]++
		if out[i] != 0 {
			return out, nil
		}
	}
	return Zero, ErrEntropyExhausted
}
