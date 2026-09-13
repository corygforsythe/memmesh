package record

import (
	"math/rand"
	"testing"

	"github.com/coryforsythe/memmesh/internal/ulid"
)

func id(n int) ulid.ULID {
	u, err := ulid.New(uint64(n), fixedBytes(byte(n)))
	if err != nil {
		panic(err)
	}
	return u
}

type fixedBytes byte

func (f fixedBytes) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(f)
	}
	return len(p), nil
}

func TestObserveOnlyRaises(t *testing.T) {
	v := NewVersionVector()

	if !v.Observe("alpha", id(5)) {
		t.Error("first Observe reported no change")
	}
	if v.Observe("alpha", id(3)) {
		t.Error("Observe with a lower id reported a change")
	}
	if got := v.Get("alpha"); got != id(5) {
		t.Errorf("mark = %s, want %s: Observe must never lower a mark", got, id(5))
	}
	if v.Observe("alpha", id(5)) {
		t.Error("Observe with an equal id reported a change")
	}
	if !v.Observe("alpha", id(9)) {
		t.Error("Observe with a higher id reported no change")
	}
	if got := v.Get("beta"); !got.IsZero() {
		t.Error("Get on an absent node did not return the zero id")
	}
}

func TestCovers(t *testing.T) {
	v := VersionVector{"alpha": id(5)}
	tests := []struct {
		name string
		node NodeID
		in   ulid.ULID
		want bool
	}{
		{"below the mark", "alpha", id(3), true},
		{"at the mark", "alpha", id(5), true},
		{"above the mark", "alpha", id(7), false},
		{"unknown node", "beta", id(1), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := v.Covers(tc.node, tc.in); got != tc.want {
				t.Errorf("Covers = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMergeIsAJoin(t *testing.T) {
	a := VersionVector{"alpha": id(5), "beta": id(2)}
	b := VersionVector{"beta": id(9), "gamma": id(1)}

	// Commutative: merging in either direction gives the same result.
	ab := a.Clone()
	ab.Merge(b)
	ba := b.Clone()
	ba.Merge(a)
	if !ab.Equal(ba) {
		t.Fatalf("merge is not commutative: %s vs %s", ab, ba)
	}

	want := VersionVector{"alpha": id(5), "beta": id(9), "gamma": id(1)}
	if !ab.Equal(want) {
		t.Fatalf("merge = %s, want %s", ab, want)
	}

	// Idempotent: merging again changes nothing.
	if ab.Merge(b) {
		t.Error("re-merging reported a change")
	}

	// Associative, checked against a random third vector.
	c := VersionVector{"alpha": id(7), "delta": id(4)}
	left := a.Clone()
	left.Merge(b)
	left.Merge(c)
	right := b.Clone()
	right.Merge(c)
	combined := a.Clone()
	combined.Merge(right)
	if !left.Equal(combined) {
		t.Fatalf("merge is not associative: %s vs %s", left, combined)
	}
}

func TestDominatesAndConcurrent(t *testing.T) {
	ahead := VersionVector{"alpha": id(9), "beta": id(4)}
	behind := VersionVector{"alpha": id(5)}
	sideways := VersionVector{"gamma": id(1)}

	if !ahead.Dominates(behind) {
		t.Error("the larger vector does not dominate the smaller")
	}
	if behind.Dominates(ahead) {
		t.Error("the smaller vector dominates the larger")
	}
	if Concurrent(ahead, behind) {
		t.Error("a dominating pair was reported as concurrent")
	}
	if !Concurrent(ahead, sideways) {
		t.Error("two vectors each holding something the other lacks are concurrent")
	}
	if !ahead.Dominates(nil) {
		t.Error("every vector dominates the empty one")
	}
	if !VersionVector(nil).Dominates(nil) {
		t.Error("the empty vector does not dominate itself")
	}
}

func TestMissingFromDescribesTheDelta(t *testing.T) {
	mine := VersionVector{"alpha": id(5), "beta": id(9)}
	theirs := VersionVector{"alpha": id(11), "beta": id(9), "gamma": id(3)}

	got := mine.MissingFrom(theirs)
	if len(got) != 2 {
		t.Fatalf("got %d ranges, want 2 (beta is already current): %v", len(got), got)
	}
	if r, ok := got["alpha"]; !ok || r.After != id(5) || r.Through != id(11) {
		t.Errorf("alpha range = %+v", r)
	}
	if r, ok := got["gamma"]; !ok || !r.After.IsZero() || r.Through != id(3) {
		t.Errorf("gamma range = %+v, want After=zero meaning 'from the beginning'", r)
	}
	if _, ok := got["beta"]; ok {
		t.Error("a node we are already current on appeared in the delta")
	}

	if got := theirs.MissingFrom(mine); got != nil {
		t.Errorf("a dominating vector needs nothing, got %v", got)
	}
}

func TestRangeContains(t *testing.T) {
	r := Range{After: id(5), Through: id(9)}
	tests := []struct {
		in   ulid.ULID
		want bool
	}{
		{id(4), false},
		{id(5), false}, // After is exclusive
		{id(6), true},
		{id(9), true}, // Through is inclusive
		{id(10), false},
	}
	for _, tc := range tests {
		if got := r.Contains(tc.in); got != tc.want {
			t.Errorf("Contains(%s) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestNodesIsSorted(t *testing.T) {
	// Sorted order is required by the canonical encoding; a map iteration leak
	// here would make signatures non-reproducible.
	rng := rand.New(rand.NewSource(3))
	v := NewVersionVector()
	names := []NodeID{"delta", "alpha", "charlie", "bravo", "echo"}
	for _, n := range names {
		v.Observe(n, id(rng.Intn(100)+1))
	}
	for attempt := 0; attempt < 20; attempt++ {
		got := v.Nodes()
		for i := 1; i < len(got); i++ {
			if got[i-1] >= got[i] {
				t.Fatalf("Nodes() is not ascending: %v", got)
			}
		}
	}
}

func TestCloneIsIndependent(t *testing.T) {
	orig := VersionVector{"alpha": id(5)}
	cp := orig.Clone()
	cp.Observe("alpha", id(9))
	cp.Observe("beta", id(1))
	if orig.Get("alpha") != id(5) {
		t.Error("mutating the clone changed the original")
	}
	if _, ok := orig["beta"]; ok {
		t.Error("adding to the clone added to the original")
	}
	if VersionVector(nil).Clone() != nil {
		t.Error("cloning nil should stay nil")
	}
}

func TestStringIsDeterministic(t *testing.T) {
	v := VersionVector{"beta": id(2), "alpha": id(1)}
	first := v.String()
	for i := 0; i < 20; i++ {
		if v.String() != first {
			t.Fatal("String is not deterministic")
		}
	}
	if VersionVector(nil).String() != "{}" {
		t.Error("the empty vector should render as {}")
	}
}
