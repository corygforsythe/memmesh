// Package embed turns record text into vectors, locally.
//
// Embeddings are never synced. Text ships between nodes and every node embeds
// what it receives (plan §4.3). That choice is nearly free — every node already
// needs a local embedder to ingest anything while offline, so the capability is
// not additional — and it removes a whole class of version-skew bugs, because no
// node ever has to interpret a vector produced by a model it does not have.
//
// The cost is that a model mismatch between peers degrades recall silently
// instead of erroring. Nothing breaks; searches just quietly get worse. That is
// precisely why the model ID is pinned onto every record and why matching it
// across peers is a first-class health check rather than a footnote.
//
// # What is implemented here
//
// The plan calls for a local ONNX model. No ONNX runtime is reachable in this
// build (docs/decisions/0002), so this package ships a hashed bag-of-words
// embedder behind the Embedder interface. It is a real lexical embedder — hashed
// unigram and bigram features, sublinear term frequency, L2 normalized — not a
// placeholder that returns noise: it retrieves on shared vocabulary and phrasing,
// which covers a useful fraction of what recall is asked for. What it cannot do is
// match paraphrases with no shared words.
//
// Swapping in a real model is an Embedder implementation and a new model ID. The
// ID change is the migration: records keep the ID they were embedded under, so a
// node can tell exactly which of its vectors are stale and re-embed those.
package embed

import (
	"errors"
	"fmt"
	"hash/fnv"
	"math"
	"strings"
	"unicode"
)

// Embedder produces a vector for a piece of text.
//
// Implementations must be deterministic: the same text and the same model ID must
// always produce the same vector, on every platform. Search results that depend on
// the order records happened to arrive are not reproducible, and a convergence
// test over them could not be written.
type Embedder interface {
	// ModelID identifies the model, and is pinned onto every record embedded with
	// it. Changing behaviour without changing this ID is a bug: it makes stale
	// vectors indistinguishable from current ones.
	ModelID() string
	// Dims is the vector length.
	Dims() int
	// Embed returns an L2-normalized vector for the text. The returned slice is
	// owned by the caller.
	Embed(text string) ([]float32, error)
}

// ErrEmpty reports text with no usable tokens. A record whose body is punctuation
// or whitespace has nothing to embed, and returning a zero vector would make it
// spuriously similar to every other empty one.
var ErrEmpty = errors.New("embed: text has no tokens")

// DefaultDims is the vector length. 384 matches the plan's sizing math: 384-dim
// f32 is ~1.5 KB per record, so 100k records is ~150 MB resident as f32 and ~38 MB
// once int8-quantized (plan §4.2).
const DefaultDims = 384

// hashModelID is the pinned identifier for the hashed embedder.
//
// The version suffix covers the tokenizer, the feature set, the weighting and the
// dimension count. Any change to any of those is a new ID.
const hashModelID = "memmesh-hashembed-v1-384"

// Hashed is a hashing bag-of-words embedder.
//
// Features are hashed directly into the vector rather than held in a vocabulary,
// which is what makes it usable with no training corpus and no shared state
// between nodes: two nodes with the same model ID produce identical vectors for
// identical text without ever having agreed on a word list.
//
// A Hashed is safe for concurrent use; it holds no mutable state.
type Hashed struct {
	dims int
}

// NewHashed returns the default hashed embedder.
func NewHashed() *Hashed { return &Hashed{dims: DefaultDims} }

// ModelID implements Embedder.
func (h *Hashed) ModelID() string { return hashModelID }

// Dims implements Embedder.
func (h *Hashed) Dims() int { return h.dims }

// Embed implements Embedder.
//
// The pipeline is: tokenize, take unigrams and adjacent bigrams, hash each into a
// bucket with a sign, weight by sublinear term frequency, then L2 normalize.
//
// Bigrams matter more than they look: "assumes UTC" and "assumes local" share the
// unigram "assumes", and without bigrams the two claims that the whole conflict
// machinery exists to tell apart would sit closer together than they should.
//
// Sublinear term frequency (1 + log tf) rather than raw counts stops a record that
// repeats one word twenty times from being dominated by it.
func (h *Hashed) Embed(text string) ([]float32, error) {
	tokens := Tokenize(text)
	if len(tokens) == 0 {
		return nil, ErrEmpty
	}

	// Accumulate raw counts per bucket, keeping the sign separate from the count
	// so sublinear weighting applies to magnitude only.
	counts := make(map[uint32]float64, len(tokens)*2)
	signs := make(map[uint32]float64, len(tokens)*2)

	add := func(feature string) {
		bucket, sign := hashFeature(feature, uint32(h.dims))
		counts[bucket]++
		signs[bucket] = sign
	}
	for i, tok := range tokens {
		add(tok)
		if i+1 < len(tokens) {
			add(tokens[i] + "\x00" + tokens[i+1])
		}
	}

	vec := make([]float32, h.dims)
	for bucket, count := range counts {
		weight := (1 + math.Log(count)) * signs[bucket]
		vec[bucket] = float32(weight)
	}
	if err := Normalize(vec); err != nil {
		return nil, err
	}
	return vec, nil
}

// hashFeature maps a feature string to a bucket and a sign.
//
// The sign is taken from a bit of the same hash. Signed hashing makes collisions
// cancel on average instead of always reinforcing, which keeps unrelated features
// from accumulating spurious similarity — the standard hashing-trick correction.
func hashFeature(feature string, dims uint32) (uint32, float64) {
	h := fnv.New64a()
	_, _ = h.Write([]byte(feature))
	sum := h.Sum64()
	bucket := uint32(sum % uint64(dims))
	sign := 1.0
	if sum&(1<<63) != 0 {
		sign = -1.0
	}
	return bucket, sign
}

// Tokenize lowercases and splits text into word tokens.
//
// It is deliberately simple and deliberately frozen: the tokenizer is part of the
// model ID, so changing it changes which records are comparable. Unicode letters
// and digits form tokens; everything else separates them.
func Tokenize(text string) []string {
	if len(text) == 0 {
		return nil
	}
	fields := strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsNumber(r) && r != '_'
	})
	out := fields[:0]
	for _, f := range fields {
		// Single characters carry almost no signal and inflate the feature count;
		// digits are kept because version numbers and error codes are often the
		// most distinctive thing in a record.
		if len(f) > 1 || isNumeric(f) {
			out = append(out, f)
		}
	}
	return out
}

func isNumeric(s string) bool {
	for _, r := range s {
		if !unicode.IsNumber(r) {
			return false
		}
	}
	return len(s) > 0
}

// Normalize scales a vector to unit length in place.
//
// Every vector in the system is unit length, which is what lets cosine similarity
// be computed as a plain dot product and lets int8 quantization use one fixed scale
// instead of a per-vector one.
func Normalize(vec []float32) error {
	var sum float64
	for _, v := range vec {
		sum += float64(v) * float64(v)
	}
	if sum == 0 {
		return fmt.Errorf("%w: vector is all zeroes", ErrEmpty)
	}
	inv := float32(1 / math.Sqrt(sum))
	for i := range vec {
		vec[i] *= inv
	}
	return nil
}

// Cosine returns the cosine similarity of two unit vectors, which for unit vectors
// is their dot product. It does not check normalization; callers in this tree only
// ever hold normalized vectors.
func Cosine(a, b []float32) float32 {
	if len(a) != len(b) {
		return 0
	}
	var sum float32
	for i := range a {
		sum += a[i] * b[i]
	}
	return sum
}

// Text extracts the embeddable text for a record: its body, with tags appended.
//
// Tags are included because they are how an agent says what a record is about in
// words the body may never use. A record tagged "parse_ts" whose body says "the
// flake was a timezone assumption" should be findable by either.
func Text(body []byte, tags []string) string {
	if len(tags) == 0 {
		return string(body)
	}
	var b strings.Builder
	b.Grow(len(body) + len(tags)*12)
	b.Write(body)
	for _, tag := range tags {
		b.WriteByte(' ')
		b.WriteString(tag)
	}
	return b.String()
}
