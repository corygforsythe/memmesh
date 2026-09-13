package hlc

import (
	"sync"
	"testing"
)

type fakeClock struct{ ms uint64 }

func (c *fakeClock) NowMillis() uint64 { return c.ms }

func TestCompare(t *testing.T) {
	tests := []struct {
		name string
		a, b HLC
		want int
	}{
		{"equal zero", HLC{}, HLC{}, 0},
		{"wall dominates", HLC{Wall: 1, Counter: 99}, HLC{Wall: 2, Counter: 0}, -1},
		{"counter breaks wall tie", HLC{Wall: 5, Counter: 1}, HLC{Wall: 5, Counter: 2}, -1},
		{"identical", HLC{Wall: 5, Counter: 2}, HLC{Wall: 5, Counter: 2}, 0},
		{"greater", HLC{Wall: 9, Counter: 0}, HLC{Wall: 5, Counter: 100}, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.a.Compare(tc.b); got != tc.want {
				t.Errorf("Compare = %d, want %d", got, tc.want)
			}
			if got := tc.b.Compare(tc.a); got != -tc.want {
				t.Errorf("reverse Compare = %d, want %d", got, -tc.want)
			}
			if tc.want < 0 && !tc.a.Before(tc.b) {
				t.Error("Before disagrees with Compare")
			}
			if tc.want > 0 && !tc.a.After(tc.b) {
				t.Error("After disagrees with Compare")
			}
		})
	}
}

func TestMaxAndZero(t *testing.T) {
	a := HLC{Wall: 4, Counter: 7}
	b := HLC{Wall: 4, Counter: 8}
	if Max(a, b) != b || Max(b, a) != b {
		t.Error("Max did not pick the later timestamp")
	}
	if !(HLC{}).IsZero() || a.IsZero() {
		t.Error("IsZero misreports")
	}
	if got := a.String(); got != "4.7" {
		t.Errorf("String = %q, want %q", got, "4.7")
	}
}

func TestNowAdvancesWithPhysicalClock(t *testing.T) {
	c := &fakeClock{ms: 100}
	ts := New(c)

	first := ts.Now()
	if first != (HLC{Wall: 100, Counter: 0}) {
		t.Fatalf("first = %s, want 100.0", first)
	}

	c.ms = 200
	second := ts.Now()
	if second != (HLC{Wall: 200, Counter: 0}) {
		t.Fatalf("second = %s, want 200.0 (counter should reset on a fresh millisecond)", second)
	}
	if ts.Peek() != second {
		t.Error("Peek did not return the last reading")
	}
}

func TestNowUsesCounterWithinAMillisecond(t *testing.T) {
	c := &fakeClock{ms: 100}
	ts := New(c)

	prev := ts.Now()
	for i := 1; i <= 5; i++ {
		next := ts.Now()
		if next.Wall != 100 {
			t.Fatalf("wall drifted to %d", next.Wall)
		}
		if next.Counter != uint32(i) {
			t.Fatalf("counter = %d, want %d", next.Counter, i)
		}
		if !prev.Before(next) {
			t.Fatalf("%s did not precede %s", prev, next)
		}
		prev = next
	}
}

func TestNowNeverGoesBackwardsWhenTheClockDoes(t *testing.T) {
	c := &fakeClock{ms: 1000}
	ts := New(c)
	first := ts.Now()

	c.ms = 400 // the wall clock steps backwards
	second := ts.Now()

	if !first.Before(second) {
		t.Fatalf("%s did not precede %s", first, second)
	}
	if second.Wall != 1000 {
		t.Errorf("wall = %d, want the pinned 1000", second.Wall)
	}
	if second.Counter != 1 {
		t.Errorf("counter = %d, want 1", second.Counter)
	}
}

func TestObserveAdoptsAPeerThatIsAhead(t *testing.T) {
	c := &fakeClock{ms: 100}
	ts := New(c)
	ts.Now()

	remote := HLC{Wall: 5000, Counter: 3}
	got := ts.Observe(remote)

	if !remote.Before(got) {
		t.Fatalf("local reading %s does not exceed the observed %s", got, remote)
	}
	if got != (HLC{Wall: 5000, Counter: 4}) {
		t.Fatalf("got %s, want 5000.4", got)
	}

	// A subsequent local write must still exceed the adopted reading, even
	// though the physical clock is far behind it.
	next := ts.Now()
	if !got.Before(next) {
		t.Fatalf("local write %s did not exceed adopted %s", next, got)
	}
}

func TestObserveIgnoresAPeerThatIsBehind(t *testing.T) {
	c := &fakeClock{ms: 9000}
	ts := New(c)
	local := ts.Now()

	got := ts.Observe(HLC{Wall: 10, Counter: 0})
	if got.Wall != 9000 {
		t.Errorf("wall = %d, want 9000", got.Wall)
	}
	if !local.Before(got) {
		t.Errorf("%s did not precede %s", local, got)
	}
}

func TestObserveOnEqualWallTakesTheHigherCounter(t *testing.T) {
	c := &fakeClock{ms: 100}
	ts := New(c)
	ts.Now() // 100.0

	got := ts.Observe(HLC{Wall: 100, Counter: 7})
	if got != (HLC{Wall: 100, Counter: 8}) {
		t.Fatalf("got %s, want 100.8", got)
	}
}

// TestHappensBeforeIsPreserved is the property the whole mesh leans on: if A's
// record is delivered to B before B writes, B's stamp must exceed A's.
func TestHappensBeforeIsPreserved(t *testing.T) {
	aClock := &fakeClock{ms: 1000}
	bClock := &fakeClock{ms: 20} // B's clock is badly behind
	a, b := New(aClock), New(bClock)

	aStamp := a.Now()
	b.Observe(aStamp)
	bStamp := b.Now()

	if !aStamp.Before(bStamp) {
		t.Fatalf("causality lost: A wrote %s, B then wrote %s", aStamp, bStamp)
	}

	// And back the other way.
	a.Observe(bStamp)
	aStamp2 := a.Now()
	if !bStamp.Before(aStamp2) {
		t.Fatalf("causality lost on the return path: B wrote %s, A then wrote %s", bStamp, aStamp2)
	}
}

func TestTimestamperIsConcurrencySafe(t *testing.T) {
	c := &fakeClock{ms: 42}
	ts := New(c)

	const goroutines, each = 8, 250
	var wg sync.WaitGroup
	out := make(chan HLC, goroutines*each)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < each; j++ {
				out <- ts.Now()
			}
		}()
	}
	wg.Wait()
	close(out)

	seen := make(map[HLC]bool, goroutines*each)
	for h := range out {
		if seen[h] {
			t.Fatalf("duplicate timestamp %s under concurrency", h)
		}
		seen[h] = true
	}
	if len(seen) != goroutines*each {
		t.Fatalf("got %d distinct stamps, want %d", len(seen), goroutines*each)
	}
}

func TestSkew(t *testing.T) {
	tests := []struct {
		name  string
		peer  HLC
		local uint64
		want  int64
	}{
		{"in step", HLC{Wall: 1000}, 1000, 0},
		{"peer ahead", HLC{Wall: 1500}, 1000, 500},
		{"peer behind", HLC{Wall: 400}, 1000, -600},
		{"counter is ignored", HLC{Wall: 1000, Counter: 9999}, 1000, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Skew(tc.peer, tc.local); got != tc.want {
				t.Errorf("Skew = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestClockFuncAdapter(t *testing.T) {
	ts := New(ClockFunc(func() uint64 { return 77 }))
	if got := ts.Now(); got.Wall != 77 {
		t.Errorf("wall = %d, want 77", got.Wall)
	}
}
