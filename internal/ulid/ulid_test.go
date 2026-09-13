package ulid

import (
	"bytes"
	"errors"
	"math/rand"
	"sort"
	"strings"
	"testing"
)

// zeroEntropy yields a deterministic, repeating entropy stream.
type fixedEntropy byte

func (f fixedEntropy) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(f)
	}
	return len(p), nil
}

type stepClock struct{ ms uint64 }

func (c *stepClock) NowMillis() uint64 { return c.ms }

func TestNewCarriesTimeAndEntropy(t *testing.T) {
	tests := []struct {
		name string
		ms   uint64
	}{
		{"zero", 0},
		{"epoch plus one", 1},
		{"realistic", 1_757_700_000_000},
		{"max", MaxTime},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u, err := New(tc.ms, fixedEntropy(0xab))
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if got := u.Time(); got != tc.ms {
				t.Errorf("Time() = %d, want %d", got, tc.ms)
			}
			if want := bytes.Repeat([]byte{0xab}, 10); !bytes.Equal(u.Entropy(), want) {
				t.Errorf("Entropy() = %x, want %x", u.Entropy(), want)
			}
		})
	}
}

func TestNewRejectsOverflowingTime(t *testing.T) {
	if _, err := New(MaxTime+1, fixedEntropy(0)); !errors.Is(err, ErrBadTime) {
		t.Fatalf("err = %v, want ErrBadTime", err)
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 2000; i++ {
		var u ULID
		for j := range u {
			u[j] = byte(rng.Intn(256))
		}
		s := u.String()
		if len(s) != EncodedSize {
			t.Fatalf("String() length = %d, want %d", len(s), EncodedSize)
		}
		back, err := Parse(s)
		if err != nil {
			t.Fatalf("Parse(%q): %v", s, err)
		}
		if back != u {
			t.Fatalf("round trip: got %x want %x (via %q)", back, u, s)
		}
	}
}

func TestStringKnownValues(t *testing.T) {
	tests := []struct {
		name string
		in   ULID
		want string
	}{
		{"zero", Zero, strings.Repeat("0", 26)},
		{
			// 26 base32 characters hold 130 bits, so the leading character
			// carries only 3 significant bits and tops out at 7.
			name: "all ones",
			in:   ULID{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			want: "7" + strings.Repeat("Z", 25),
		},
		{
			name: "least significant bit only",
			in:   ULID{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
			want: strings.Repeat("0", 25) + "1",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.in.String(); got != tc.want {
				t.Errorf("String() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseRejectsBadInput(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"too short", strings.Repeat("0", 25)},
		{"too long", strings.Repeat("0", 27)},
		{"excluded letter U", strings.Repeat("0", 25) + "U"},
		{"non alphanumeric", strings.Repeat("0", 25) + "-"},
		{"leading char overflows", "8" + strings.Repeat("0", 25)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse(tc.in); !errors.Is(err, ErrBadEncoding) {
				t.Errorf("Parse(%q) err = %v, want ErrBadEncoding", tc.in, err)
			}
		})
	}
}

func TestParseIsCaseInsensitiveAndHandlesAliases(t *testing.T) {
	u, err := New(1_757_700_000_000, fixedEntropy(0x5c))
	if err != nil {
		t.Fatal(err)
	}
	upper := u.String()
	lower, err := Parse(strings.ToLower(upper))
	if err != nil {
		t.Fatalf("Parse lowercase: %v", err)
	}
	if lower != u {
		t.Errorf("lowercase parse mismatch")
	}

	// Crockford treats O as 0 and I/L as 1.
	aliased := strings.Repeat("O", 25) + "I"
	want := strings.Repeat("0", 25) + "1"
	got, err := Parse(aliased)
	if err != nil {
		t.Fatalf("Parse aliased: %v", err)
	}
	if got != MustParse(want) {
		t.Errorf("alias parse = %x, want %x", got, MustParse(want))
	}
}

func TestCompareIsByteOrderAndTimeOrder(t *testing.T) {
	a, _ := New(1000, fixedEntropy(0x00))
	b, _ := New(1000, fixedEntropy(0x01))
	c, _ := New(1001, fixedEntropy(0x00))

	if a.Compare(b) != -1 {
		t.Errorf("a.Compare(b) = %d, want -1", a.Compare(b))
	}
	if c.Compare(a) != 1 {
		t.Errorf("c.Compare(a) = %d, want 1", c.Compare(a))
	}
	if a.Compare(a) != 0 {
		t.Errorf("a.Compare(a) = %d, want 0", a.Compare(a))
	}
	if !Zero.IsZero() || a.IsZero() {
		t.Errorf("IsZero misreports")
	}
}

func TestLexicographicOrderMatchesByteOrder(t *testing.T) {
	// The encoding must preserve order, or the store cannot use string IDs as a
	// sortable key in the Merkle prefix tree later on.
	rng := rand.New(rand.NewSource(11))
	ids := make([]ULID, 500)
	for i := range ids {
		u, err := New(uint64(rng.Intn(1<<20)), fixedEntropy(byte(rng.Intn(256))))
		if err != nil {
			t.Fatal(err)
		}
		ids[i] = u
	}
	byBytes := append([]ULID(nil), ids...)
	sort.Slice(byBytes, func(i, j int) bool { return byBytes[i].Compare(byBytes[j]) < 0 })

	strs := make([]string, len(ids))
	for i, u := range ids {
		strs[i] = u.String()
	}
	sort.Strings(strs)

	for i := range strs {
		if strs[i] != byBytes[i].String() {
			t.Fatalf("order diverges at %d: string sort %q, byte sort %q", i, strs[i], byBytes[i].String())
		}
	}
}

func TestMonotonicStrictlyIncreasesWithinAMillisecond(t *testing.T) {
	c := &stepClock{ms: 5000}
	g := NewMonotonic(c, fixedEntropy(0x00))

	prev := g.MustNext()
	for i := 0; i < 1000; i++ {
		next := g.MustNext()
		if next.Compare(prev) <= 0 {
			t.Fatalf("iteration %d: %s did not exceed %s", i, next, prev)
		}
		if next.Time() != 5000 {
			t.Fatalf("iteration %d: timestamp drifted to %d", i, next.Time())
		}
		prev = next
	}
}

func TestMonotonicSurvivesClockGoingBackwards(t *testing.T) {
	c := &stepClock{ms: 5000}
	g := NewMonotonic(c, fixedEntropy(0x00))

	first := g.MustNext()
	c.ms = 4000 // NTP step backwards
	second := g.MustNext()

	if second.Compare(first) <= 0 {
		t.Fatalf("%s did not exceed %s after the clock stepped back", second, first)
	}
	if second.Time() != 5000 {
		t.Errorf("timestamp = %d, want the pinned 5000", second.Time())
	}

	c.ms = 6000
	third := g.MustNext()
	if third.Compare(second) <= 0 {
		t.Fatalf("%s did not exceed %s once the clock recovered", third, second)
	}
	if third.Time() != 6000 {
		t.Errorf("timestamp = %d, want 6000", third.Time())
	}
}

func TestMonotonicReportsEntropyExhaustion(t *testing.T) {
	c := &stepClock{ms: 1}
	g := NewMonotonic(c, fixedEntropy(0xff))

	// The first call seeds all-ones entropy; the second must overflow.
	if _, err := g.Next(); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Next(); !errors.Is(err, ErrEntropyExhausted) {
		t.Fatalf("err = %v, want ErrEntropyExhausted", err)
	}
}

func TestMonotonicIsConcurrencySafe(t *testing.T) {
	c := &stepClock{ms: 9000}
	g := NewMonotonic(c, fixedEntropy(0x10))

	const goroutines, each = 8, 200
	out := make(chan ULID, goroutines*each)
	done := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		go func() {
			for j := 0; j < each; j++ {
				out <- g.MustNext()
			}
			done <- struct{}{}
		}()
	}
	for i := 0; i < goroutines; i++ {
		<-done
	}
	close(out)

	seen := make(map[ULID]bool, goroutines*each)
	for u := range out {
		if seen[u] {
			t.Fatalf("duplicate ULID %s under concurrency", u)
		}
		seen[u] = true
	}
	if len(seen) != goroutines*each {
		t.Fatalf("got %d ids, want %d", len(seen), goroutines*each)
	}
}

func TestTextMarshalling(t *testing.T) {
	u, _ := New(1_757_700_000_123, fixedEntropy(0x42))
	b, err := u.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	var back ULID
	if err := back.UnmarshalText(b); err != nil {
		t.Fatal(err)
	}
	if back != u {
		t.Errorf("text round trip mismatch")
	}
	if err := back.UnmarshalText([]byte("nope")); err == nil {
		t.Error("UnmarshalText accepted invalid input")
	}
}
