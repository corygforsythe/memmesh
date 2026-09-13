// Package clock provides the time sources injected throughout the mesh.
//
// Every component that needs the time takes a Clock rather than calling
// time.Now. A convergence test that flakes is a failed test, not a retry
// (plan §0.5), and that is only achievable if time is a parameter.
package clock

import (
	"sync/atomic"
	"time"
)

// Clock is a millisecond time source. It satisfies ulid.Clock and hlc.Clock.
type Clock interface {
	// NowMillis returns Unix milliseconds.
	NowMillis() uint64
	// Now returns the same instant as a time.Time, for display and durations.
	Now() time.Time
}

// System is the real wall clock.
type System struct{}

// NowMillis implements Clock.
func (System) NowMillis() uint64 { return uint64(time.Now().UnixMilli()) }

// Now implements Clock.
func (System) Now() time.Time { return time.Now() }

// Fake is a manually driven clock for tests.
//
// It is safe for concurrent use, so it can drive several in-process nodes in a
// two-node or N-node harness without the harness needing its own locking.
type Fake struct {
	ms atomic.Uint64
}

// NewFake returns a Fake positioned at the given Unix millisecond.
func NewFake(startMS uint64) *Fake {
	f := &Fake{}
	f.ms.Store(startMS)
	return f
}

// NowMillis implements Clock.
func (f *Fake) NowMillis() uint64 { return f.ms.Load() }

// Now implements Clock.
func (f *Fake) Now() time.Time { return time.UnixMilli(int64(f.ms.Load())) }

// Advance moves the clock forward by d milliseconds and returns the new reading.
func (f *Fake) Advance(d uint64) uint64 { return f.ms.Add(d) }

// Set moves the clock to an absolute reading. Values lower than the current one
// are allowed on purpose: a clock stepping backwards is a case the HLC and the
// monotonic ULID generator both have to survive.
func (f *Fake) Set(ms uint64) { f.ms.Store(ms) }

// Offset returns a view of f shifted by delta milliseconds, for simulating a
// peer whose clock is skewed relative to this node.
func (f *Fake) Offset(delta int64) Clock { return offsetClock{base: f, delta: delta} }

type offsetClock struct {
	base  Clock
	delta int64
}

func (o offsetClock) NowMillis() uint64 {
	v := int64(o.base.NowMillis()) + o.delta
	if v < 0 {
		return 0
	}
	return uint64(v)
}

func (o offsetClock) Now() time.Time { return time.UnixMilli(int64(o.NowMillis())) }
