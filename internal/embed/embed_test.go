package embed

import (
	"errors"
	"math"
	"strings"
	"testing"
)

func TestTokenize(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"simple", "parse_ts assumes UTC", []string{"parse_ts", "assumes", "utc"}},
		{"punctuation separates", "flake: timezone-assumption!", []string{"flake", "timezone", "assumption"}},
		{"single letters dropped", "a b crew", []string{"crew"}},
		{"digits kept", "go 1.24 error 500", []string{"go", "1", "24", "error", "500"}},
		{"unicode letters", "héllo wörld", []string{"héllo", "wörld"}},
		{"empty", "", nil},
		{"only punctuation", "!!! ??? ...", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Tokenize(tc.in)
			if strings.Join(got, "|") != strings.Join(tc.want, "|") {
				t.Errorf("Tokenize(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestEmbedIsDeterministic(t *testing.T) {
	h := NewHashed()
	text := "crewmate 3 found the flake was a timezone assumption in parse_ts"

	first, err := h.Embed(text)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, err := h.Embed(text)
		if err != nil {
			t.Fatal(err)
		}
		for j := range first {
			if first[j] != again[j] {
				t.Fatalf("Embed is not deterministic at component %d", j)
			}
		}
	}
	if len(first) != DefaultDims {
		t.Errorf("vector length = %d, want %d", len(first), DefaultDims)
	}
	if h.Dims() != DefaultDims {
		t.Errorf("Dims = %d", h.Dims())
	}
	if h.ModelID() == "" {
		t.Error("ModelID is empty")
	}
}

func TestEmbedProducesUnitVectors(t *testing.T) {
	h := NewHashed()
	for _, text := range []string{
		"short",
		"parse_ts assumes UTC input",
		strings.Repeat("a longer document with plenty of repeated words ", 50),
		"1 2 3 4 5",
	} {
		v, err := h.Embed(text)
		if err != nil {
			t.Fatalf("%q: %v", text, err)
		}
		var sum float64
		for _, c := range v {
			sum += float64(c) * float64(c)
		}
		if math.Abs(sum-1) > 1e-5 {
			t.Errorf("%q: squared norm = %f, want 1", text, sum)
		}
	}
}

func TestEmbedRejectsTextWithNoTokens(t *testing.T) {
	h := NewHashed()
	for _, text := range []string{"", "   ", "!!!", "a"} {
		if _, err := h.Embed(text); !errors.Is(err, ErrEmpty) {
			t.Errorf("Embed(%q) err = %v, want ErrEmpty", text, err)
		}
	}
}

// TestSimilarTextIsCloser is the property that makes recall work at all: text about
// the same thing must score higher against each other than against unrelated text.
func TestSimilarTextIsCloser(t *testing.T) {
	h := NewHashed()
	must := func(s string) []float32 {
		v, err := h.Embed(s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}

	query := must("the flake in parse_ts was a timezone assumption")
	related := must("parse_ts assumed the timestamp was a timezone-naive local time")
	unrelated := must("the deploy pipeline needs a signing key for the release build")

	simRelated := Cosine(query, related)
	simUnrelated := Cosine(query, unrelated)
	if simRelated <= simUnrelated {
		t.Errorf("related text scored %f, unrelated scored %f; retrieval would be no better than chance",
			simRelated, simUnrelated)
	}
	if self := Cosine(query, query); math.Abs(float64(self)-1) > 1e-5 {
		t.Errorf("self-similarity = %f, want 1", self)
	}
}

// TestBigramsSeparateContradictoryClaims is why bigrams are in the feature set:
// the two claims the conflict machinery exists to distinguish share most of their
// unigrams.
func TestBigramsSeparateContradictoryClaims(t *testing.T) {
	h := NewHashed()
	utc, err := h.Embed("parse_ts assumes UTC input")
	if err != nil {
		t.Fatal(err)
	}
	local, err := h.Embed("parse_ts assumes local time input")
	if err != nil {
		t.Fatal(err)
	}

	sim := Cosine(utc, local)
	// They should be similar — they are about the same function — but clearly
	// distinguishable, not effectively identical.
	if sim > 0.95 {
		t.Errorf("two contradictory claims scored %f; they are nearly indistinguishable", sim)
	}
	if sim < 0.1 {
		t.Errorf("two claims about the same function scored only %f; they should still be related", sim)
	}
}

func TestSublinearTermFrequency(t *testing.T) {
	h := NewHashed()
	once, err := h.Embed("timezone assumption in the parser")
	if err != nil {
		t.Fatal(err)
	}
	// Repeating one word many times must not dominate the vector to the point that
	// the record stops resembling its own single-mention form.
	repeated, err := h.Embed("timezone timezone timezone timezone timezone timezone timezone timezone assumption in the parser")
	if err != nil {
		t.Fatal(err)
	}
	if sim := Cosine(once, repeated); sim < 0.5 {
		t.Errorf("repeating one term dropped similarity to %f; the weighting is not sublinear enough", sim)
	}
}

func TestCosineHandlesMismatchedLengths(t *testing.T) {
	if got := Cosine([]float32{1, 0}, []float32{1, 0, 0}); got != 0 {
		t.Errorf("Cosine with mismatched lengths = %f, want 0", got)
	}
}

func TestNormalizeRejectsTheZeroVector(t *testing.T) {
	v := make([]float32, 4)
	if err := Normalize(v); !errors.Is(err, ErrEmpty) {
		t.Errorf("err = %v, want ErrEmpty", err)
	}
}

func TestTextIncludesTags(t *testing.T) {
	got := Text([]byte("the flake was a timezone assumption"), []string{"parse_ts", "flake"})
	for _, want := range []string{"timezone", "parse_ts", "flake"} {
		if !strings.Contains(got, want) {
			t.Errorf("Text() lost %q: %q", want, got)
		}
	}
	if got := Text([]byte("body only"), nil); got != "body only" {
		t.Errorf("Text with no tags = %q", got)
	}
}

// TestTagsMakeRecordsFindable checks the reason tags are embedded alongside the
// body: an agent's tag is often the word a searcher will use, even when the body
// never says it.
func TestTagsMakeRecordsFindable(t *testing.T) {
	h := NewHashed()
	withTag, err := h.Embed(Text([]byte("the flake was a timezone assumption"), []string{"parse_ts"}))
	if err != nil {
		t.Fatal(err)
	}
	withoutTag, err := h.Embed("the flake was a timezone assumption")
	if err != nil {
		t.Fatal(err)
	}
	query, err := h.Embed("parse_ts")
	if err != nil {
		t.Fatal(err)
	}

	if Cosine(query, withTag) <= Cosine(query, withoutTag) {
		t.Error("tagging a record did not make it more findable by that tag")
	}
}

func TestHashFeatureUsesTheFullDimensionRange(t *testing.T) {
	// A hash that clusters into a few buckets would make every vector look alike.
	const dims = 384
	seen := make(map[uint32]bool)
	signs := map[float64]int{1: 0, -1: 0}
	for i := 0; i < 5000; i++ {
		bucket, sign := hashFeature(string(rune('a'+i%26))+string(rune('a'+i/26%26))+string(rune('0'+i%10)), dims)
		if bucket >= dims {
			t.Fatalf("bucket %d is out of range", bucket)
		}
		seen[bucket] = true
		signs[sign]++
	}
	if len(seen) < dims*9/10 {
		t.Errorf("only %d of %d buckets were used", len(seen), dims)
	}
	// Signs should be roughly balanced, which is what makes collisions cancel.
	ratio := float64(signs[1]) / float64(signs[1]+signs[-1])
	if ratio < 0.4 || ratio > 0.6 {
		t.Errorf("sign balance = %.2f, want near 0.5", ratio)
	}
}
