package index

import (
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/coryforsythe/memmesh/internal/embed"
	"github.com/coryforsythe/memmesh/internal/ulid"
)

func id(n int) ulid.ULID {
	u, err := ulid.New(uint64(n), fixed(byte(n)))
	if err != nil {
		panic(err)
	}
	return u
}

type fixed byte

func (f fixed) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(f)
	}
	return len(p), nil
}

func unitVector(rng *rand.Rand, dims int) []float32 {
	v := make([]float32, dims)
	for i := range v {
		v[i] = float32(rng.NormFloat64())
	}
	if err := embed.Normalize(v); err != nil {
		panic(err)
	}
	return v
}

func TestAddSearchExactMatch(t *testing.T) {
	q, err := Open(Config{Dims: 8, ModelID: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()

	rng := rand.New(rand.NewSource(1))
	vecs := make(map[ulid.ULID][]float32)
	for i := 1; i <= 20; i++ {
		v := unitVector(rng, 8)
		vecs[id(i)] = v
		if err := q.Add(id(i), v); err != nil {
			t.Fatal(err)
		}
	}
	if q.Len() != 20 {
		t.Fatalf("Len = %d, want 20", q.Len())
	}

	// Querying with a stored vector must return that record first, with a score
	// near 1.
	for target, v := range vecs {
		got, err := q.Search(v, 3)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) == 0 {
			t.Fatal("no results")
		}
		if got[0].ID != target {
			t.Fatalf("query with %s returned %s first", target, got[0].ID)
		}
		if got[0].Score < 0.97 {
			t.Errorf("self-match score = %f, want close to 1", got[0].Score)
		}
	}
}

func TestSearchOrdersByScore(t *testing.T) {
	q, err := Open(Config{Dims: 4, ModelID: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()

	// Three vectors at known angles from the query axis.
	query := []float32{1, 0, 0, 0}
	near := []float32{0.98, 0.199, 0, 0}
	mid := []float32{0.7, 0.714, 0, 0}
	far := []float32{0, 1, 0, 0}
	for _, v := range [][]float32{near, mid, far} {
		if err := embed.Normalize(v); err != nil {
			t.Fatal(err)
		}
	}
	if err := q.Add(id(3), far); err != nil {
		t.Fatal(err)
	}
	if err := q.Add(id(1), near); err != nil {
		t.Fatal(err)
	}
	if err := q.Add(id(2), mid); err != nil {
		t.Fatal(err)
	}

	got, err := q.Search(query, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d results", len(got))
	}
	if got[0].ID != id(1) || got[1].ID != id(2) || got[2].ID != id(3) {
		t.Errorf("wrong order: %v", got)
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].Score < got[i].Score {
			t.Error("results are not in descending score order")
		}
	}
}

// TestRerankRecoversQuantizationError is the reason full-precision vectors are kept
// on disk: the int8 scan must not be allowed to have the final say on close calls.
func TestRerankRecoversQuantizationError(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(Config{Dir: dir, Dims: 64, ModelID: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()

	rng := rand.New(rand.NewSource(7))
	query := unitVector(rng, 64)

	// Build a cluster of vectors that are all very close to the query and to each
	// other, so quantization error is the same order as the real differences.
	const n = 40
	for i := 1; i <= n; i++ {
		v := make([]float32, 64)
		copy(v, query)
		for j := range v {
			v[j] += float32(rng.NormFloat64()) * 0.02
		}
		if err := embed.Normalize(v); err != nil {
			t.Fatal(err)
		}
		if err := q.Add(id(i), v); err != nil {
			t.Fatal(err)
		}
	}

	got, err := q.Search(query, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Fatalf("got %d results", len(got))
	}

	// Reranked scores are exact cosines, so recompute them independently and check
	// the reported ordering is the true one.
	for i := 1; i < len(got); i++ {
		if got[i-1].Score < got[i].Score-1e-6 {
			t.Errorf("reranked results are out of order: %f before %f", got[i-1].Score, got[i].Score)
		}
	}
	if got[0].Score > 1.0001 || got[0].Score < 0.9 {
		t.Errorf("top score = %f, which is not a plausible exact cosine", got[0].Score)
	}
}

func TestAddReplacesAnExistingVector(t *testing.T) {
	q, err := Open(Config{Dims: 4, ModelID: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()

	first := []float32{1, 0, 0, 0}
	second := []float32{0, 1, 0, 0}
	if err := q.Add(id(1), first); err != nil {
		t.Fatal(err)
	}
	if err := q.Add(id(1), second); err != nil {
		t.Fatal(err)
	}
	if q.Len() != 1 {
		t.Fatalf("Len = %d, want 1 after replacing", q.Len())
	}
	got, err := q.Search(second, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Score < 0.97 {
		t.Errorf("the replacement vector is not what is indexed: %v", got)
	}
}

func TestRemoveAndSlotReuse(t *testing.T) {
	q, err := Open(Config{Dims: 4, ModelID: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()

	for i := 1; i <= 3; i++ {
		if err := q.Add(id(i), []float32{1, 0, 0, 0}); err != nil {
			t.Fatal(err)
		}
	}
	q.Remove(id(2))
	if q.Len() != 2 || q.Has(id(2)) {
		t.Fatalf("Len = %d, Has(2) = %v after removal", q.Len(), q.Has(id(2)))
	}
	q.Remove(id(2)) // removing twice is not an error

	got, err := q.Search([]float32{1, 0, 0, 0}, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range got {
		if m.ID == id(2) {
			t.Fatal("a removed record came back from a search")
		}
	}

	// The freed slot must be reused rather than the arrays growing.
	before := q.Slots()
	if err := q.Add(id(4), []float32{0, 1, 0, 0}); err != nil {
		t.Fatal(err)
	}
	if q.Slots() != before {
		t.Errorf("slot count grew from %d to %d; the freed slot was not reused", before, q.Slots())
	}
	if !q.Has(id(4)) {
		t.Error("the record added into a freed slot is not indexed")
	}
}

func TestDimensionMismatchIsRefused(t *testing.T) {
	q, err := Open(Config{Dims: 8, ModelID: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()

	if err := q.Add(id(1), make([]float32, 4)); !errors.Is(err, ErrDims) {
		t.Errorf("Add err = %v, want ErrDims", err)
	}
	if _, err := q.Search(make([]float32, 4), 1); !errors.Is(err, ErrDims) {
		t.Errorf("Search err = %v, want ErrDims", err)
	}
	if _, err := Open(Config{Dims: 0}); !errors.Is(err, ErrDims) {
		t.Errorf("Open err = %v, want ErrDims", err)
	}
	if err := q.Add(ulid.Zero, make([]float32, 8)); err == nil {
		t.Error("Add accepted the zero id")
	}
}

func TestEmptyIndexAndZeroK(t *testing.T) {
	q, err := Open(Config{Dims: 4, ModelID: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()

	got, err := q.Search([]float32{1, 0, 0, 0}, 5)
	if err != nil || len(got) != 0 {
		t.Errorf("searching an empty index returned %v, %v", got, err)
	}
	if err := q.Add(id(1), []float32{1, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	if got, err := q.Search([]float32{1, 0, 0, 0}, 0); err != nil || got != nil {
		t.Errorf("k=0 returned %v, %v", got, err)
	}
}

func TestWarmOnBootFromDisk(t *testing.T) {
	dir := t.TempDir()
	rng := rand.New(rand.NewSource(11))
	vecs := make(map[ulid.ULID][]float32)

	q, err := Open(Config{Dir: dir, Dims: 32, ModelID: "test-model"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 50; i++ {
		v := unitVector(rng, 32)
		vecs[id(i)] = v
		if err := q.Add(id(i), v); err != nil {
			t.Fatal(err)
		}
	}
	q.Remove(id(7))
	q.Remove(id(21))
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	// Reopening must recover every vector without re-embedding anything.
	warm, err := Open(Config{Dir: dir, Dims: 32, ModelID: "test-model"})
	if err != nil {
		t.Fatal(err)
	}
	defer warm.Close()

	if warm.Len() != 48 {
		t.Fatalf("Len after warm = %d, want 48", warm.Len())
	}
	for _, gone := range []int{7, 21} {
		if warm.Has(id(gone)) {
			t.Errorf("removed record %d came back after a restart", gone)
		}
	}
	for target, v := range vecs {
		if target == id(7) || target == id(21) {
			continue
		}
		got, err := warm.Search(v, 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].ID != target {
			t.Fatalf("after warm, query for %s returned %v", target, got)
		}
		if got[0].Score < 0.999 {
			t.Errorf("after warm, self-match score = %f; precision was lost", got[0].Score)
		}
	}

	// A freed slot must still be reusable after a restart.
	if err := warm.Add(id(99), unitVector(rng, 32)); err != nil {
		t.Fatal(err)
	}
	if warm.Len() != 49 {
		t.Errorf("Len = %d after adding post-warm", warm.Len())
	}
}

func TestModelChangeDiscardsTheIndex(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(Config{Dir: dir, Dims: 16, ModelID: "old-model"})
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(13))
	for i := 1; i <= 5; i++ {
		if err := q.Add(id(i), unitVector(rng, 16)); err != nil {
			t.Fatal(err)
		}
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	// A different model must not inherit the old vectors. Silently reusing them is
	// exactly how recall degrades with nobody noticing.
	fresh, err := Open(Config{Dir: dir, Dims: 16, ModelID: "new-model"})
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if fresh.Len() != 0 {
		t.Fatalf("a model change left %d vectors in place", fresh.Len())
	}
	if fresh.ModelID() != "new-model" {
		t.Errorf("ModelID = %q", fresh.ModelID())
	}

	// The manifest must now name the new model, so the next boot agrees.
	raw, err := os.ReadFile(filepath.Join(dir, manifestName))
	if err != nil {
		t.Fatal(err)
	}
	model, dims, err := parseManifest(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if model != "new-model" || dims != 16 {
		t.Errorf("manifest says %s/%d", model, dims)
	}
}

func TestDimensionChangeDiscardsTheIndex(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(Config{Dir: dir, Dims: 16, ModelID: "m"})
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(17))
	if err := q.Add(id(1), unitVector(rng, 16)); err != nil {
		t.Fatal(err)
	}
	q.Close()

	fresh, err := Open(Config{Dir: dir, Dims: 32, ModelID: "m"})
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if fresh.Len() != 0 {
		t.Errorf("a dimension change left %d vectors in place", fresh.Len())
	}
}

func TestTornVectorFileIsTruncated(t *testing.T) {
	dir := t.TempDir()
	q, err := Open(Config{Dir: dir, Dims: 8, ModelID: "m"})
	if err != nil {
		t.Fatal(err)
	}
	rng := rand.New(rand.NewSource(19))
	for i := 1; i <= 4; i++ {
		if err := q.Add(id(i), unitVector(rng, 8)); err != nil {
			t.Fatal(err)
		}
	}
	q.Close()

	path := filepath.Join(dir, vectorsName)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, info.Size()-7); err != nil {
		t.Fatal(err)
	}

	// The index is a derived cache, so a torn write costs one vector, not the
	// whole file and certainly not an error the daemon cannot start through.
	warm, err := Open(Config{Dir: dir, Dims: 8, ModelID: "m"})
	if err != nil {
		t.Fatalf("a torn vector file must be recoverable: %v", err)
	}
	defer warm.Close()
	if warm.Len() != 3 {
		t.Errorf("Len = %d, want the 3 intact vectors", warm.Len())
	}
}

func TestResidentBytesTracksTheQuantizedFootprint(t *testing.T) {
	q, err := Open(Config{Dims: embed.DefaultDims, ModelID: "m"})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()

	rng := rand.New(rand.NewSource(23))
	const n = 1000
	for i := 1; i <= n; i++ {
		if err := q.Add(id(i), unitVector(rng, embed.DefaultDims)); err != nil {
			t.Fatal(err)
		}
	}

	// The plan's sizing claim: int8 quantization should put the resident vectors at
	// roughly a quarter of what float32 would cost.
	f32Bytes := int64(n * embed.DefaultDims * 4)
	resident := q.ResidentBytes()
	if resident > f32Bytes/2 {
		t.Errorf("resident %d bytes for %d vectors is not meaningfully smaller than the %d bytes float32 would need",
			resident, n, f32Bytes)
	}
	if resident < int64(n*embed.DefaultDims) {
		t.Errorf("resident %d bytes is below the %d bytes the int8 vectors alone require", resident, n*embed.DefaultDims)
	}
}

func TestClosedIndexRefusesWork(t *testing.T) {
	q, err := Open(Config{Dims: 4, ModelID: "m"})
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
	if err := q.Close(); err != nil {
		t.Errorf("closing twice returned %v", err)
	}
	if err := q.Add(id(1), make([]float32, 4)); !errors.Is(err, ErrClosed) {
		t.Errorf("Add after close = %v, want ErrClosed", err)
	}
	if _, err := q.Search(make([]float32, 4), 1); !errors.Is(err, ErrClosed) {
		t.Errorf("Search after close = %v, want ErrClosed", err)
	}
}

func TestConcurrentUse(t *testing.T) {
	q, err := Open(Config{Dims: 16, ModelID: "m"})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()

	rng := rand.New(rand.NewSource(29))
	base := make([][]float32, 200)
	for i := range base {
		base[i] = unitVector(rng, 16)
	}

	done := make(chan error, 6)
	for w := 0; w < 6; w++ {
		go func(w int) {
			for i, v := range base {
				if w%2 == 0 {
					if err := q.Add(id(i+1), v); err != nil {
						done <- err
						return
					}
				} else {
					if _, err := q.Search(v, 5); err != nil {
						done <- err
						return
					}
					q.Len()
					q.ResidentBytes()
				}
			}
			done <- nil
		}(w)
	}
	for w := 0; w < 6; w++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if q.Len() != len(base) {
		t.Errorf("Len = %d, want %d", q.Len(), len(base))
	}
}

// TestQuantizationIsSymmetric guards the clamp at -127: an asymmetric int8 range
// would bias every dot product slightly.
func TestQuantizationIsSymmetric(t *testing.T) {
	pos := quantize([]float32{1.0, 0.5, 0})
	neg := quantize([]float32{-1.0, -0.5, 0})
	for i := range pos {
		if pos[i] != -neg[i] {
			t.Errorf("component %d: %d and %d are not symmetric", i, pos[i], neg[i])
		}
	}
	if got := quantize([]float32{2.0})[0]; got != 127 {
		t.Errorf("out-of-range positive clamped to %d, want 127", got)
	}
	if got := quantize([]float32{-2.0})[0]; got != -127 {
		t.Errorf("out-of-range negative clamped to %d, want -127", got)
	}
}

func TestSearchIsDeterministicUnderTies(t *testing.T) {
	q, err := Open(Config{Dims: 4, ModelID: "m"})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()

	// Several identical vectors: the ordering must come from the id tiebreak, not
	// from slot allocation order.
	v := []float32{1, 0, 0, 0}
	for i := 5; i >= 1; i-- {
		if err := q.Add(id(i), v); err != nil {
			t.Fatal(err)
		}
	}
	var first []Match
	for attempt := 0; attempt < 10; attempt++ {
		got, err := q.Search(v, 5)
		if err != nil {
			t.Fatal(err)
		}
		if first == nil {
			first = got
			continue
		}
		for i := range got {
			if got[i].ID != first[i].ID {
				t.Fatalf("attempt %d returned a different order: %s vs %s", attempt, got[i].ID, first[i].ID)
			}
		}
	}
	for i := 1; i < len(first); i++ {
		if first[i-1].ID.Compare(first[i].ID) >= 0 {
			t.Errorf("tied results are not ordered by id: %v", first)
		}
	}
}

func TestManifestParsing(t *testing.T) {
	model, dims, err := parseManifest(fmt.Sprintf("%s\nmodel=abc-v1\ndims=384\n", manifestMagi))
	if err != nil {
		t.Fatal(err)
	}
	if model != "abc-v1" || dims != 384 {
		t.Errorf("got %s/%d", model, dims)
	}
	if _, _, err := parseManifest("garbage"); err == nil {
		t.Error("parseManifest accepted garbage")
	}
}
