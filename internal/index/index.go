// Package index is the vector search layer: int8-quantized vectors resident in
// memory, full-precision vectors on disk for reranking.
//
// # The sizing that makes this work
//
// 384-dimensional float32 is about 1.5 KB per record, so 100k records would be
// ~150 MB resident. Quantized to int8 the same corpus is ~38 MB, with the float32
// copies left on disk and read back only for the handful of candidates a search
// actually needs to rank precisely (plan §4.2). That split is what makes "the
// working set lives in RAM" true at realistic corpus sizes rather than aspirational.
//
// # What is implemented here
//
// The plan specifies usearch, mmap'd. No usearch binding is reachable in this build
// (docs/decisions/0002), so this is a brute-force scan over the quantized vectors,
// behind the Index interface. That is a real tradeoff and worth being plain about:
// an approximate index is sublinear in corpus size and this is not. At 100k records
// a scan over 38 MB of int8 is a few tens of milliseconds, which is fine; at ten
// million it is not, and that is the point at which the interface needs its other
// implementation.
//
// Float32 vectors are read from disk with ReadAt rather than mmap, because mmap
// needs platform-specific syscalls and the read path goes through the same page
// cache either way. Swapping in mmap changes no caller.
package index

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/coryforsythe/memmesh/internal/ulid"
)

// Match is one search result.
type Match struct {
	// ID is the matching record.
	ID ulid.ULID `json:"id"`
	// Score is cosine similarity in [-1, 1]. Higher is closer.
	Score float32 `json:"score"`
}

// Index is a vector store supporting nearest-neighbour search.
//
// It is an interface so that the quantized scan here can be replaced by a real
// approximate index without touching the store, the MCP server, or the distiller's
// contradiction pass.
type Index interface {
	// Add stores a vector for a record. Adding the same id twice replaces the
	// vector.
	Add(id ulid.ULID, vec []float32) error
	// Remove drops a record's vector. Removing an absent id is not an error.
	Remove(id ulid.ULID)
	// Search returns up to k nearest records to the query vector, best first.
	Search(query []float32, k int) ([]Match, error)
	// Len returns how many vectors are held.
	Len() int
	// Dims returns the vector length.
	Dims() int
	// ResidentBytes estimates the in-memory footprint, for the RAM line in
	// memctl status.
	ResidentBytes() int64
	// Close releases resources.
	Close() error
}

// Errors returned by this package.
var (
	// ErrDims reports a vector of the wrong length.
	ErrDims = errors.New("index: wrong vector dimension")
	// ErrModelMismatch reports a persisted index built by a different embedding
	// model. Not a failure: it is the signal to re-embed, which is exactly what
	// happens when a node's local model changes (plan §4.3).
	ErrModelMismatch = errors.New("index: persisted index was built by a different model")
	// ErrCorruptIndex reports an unusable index file. The index is a derived
	// cache, so the response is always to rebuild rather than to fail.
	ErrCorruptIndex = errors.New("index: persisted index is unusable")
	// ErrClosed reports use after Close.
	ErrClosed = errors.New("index: closed")
)

// quantScale maps the [-1, 1] range of a unit vector's components onto int8.
//
// One fixed scale rather than a per-vector one is possible only because every
// vector in this system is L2-normalized. That saves storing a scale factor per
// record and makes the quantized dot product a plain integer sum.
const quantScale = 127.0

// oversample is how many extra candidates the quantized scan collects before
// reranking with full precision.
//
// Quantization perturbs scores slightly, which can reorder near-ties and can push
// the true best match just outside a tight top-k. Collecting 4x candidates and
// reranking them makes that essentially unobservable, at the cost of a few extra
// float32 reads.
const oversample = 4

// minCandidates floors the candidate pool so a small k still reranks a useful
// number of records.
const minCandidates = 32

// Quantized is the default Index: int8 vectors in memory, float32 on disk.
//
// A Quantized is safe for concurrent use.
type Quantized struct {
	dims    int
	modelID string
	dir     string

	mu sync.RWMutex

	// quant holds every vector's int8 form, concatenated. Slot i occupies
	// [i*dims, (i+1)*dims).
	quant []int8
	// ids maps slot to record id. A freed slot holds the zero ULID.
	ids []ulid.ULID
	// slots maps record id to slot.
	slots map[ulid.ULID]int
	// free lists reusable slots, so churn does not grow the arrays without bound.
	free []int

	// vectors is the float32 backing file, one vector per slot at slot*dims*4.
	vectors *os.File
	closed  bool
}

// Config configures a Quantized index.
type Config struct {
	// Dir is where the float32 backing file and manifest live. Empty means
	// memory-only, which is what tests and the contradiction pass use.
	Dir string
	// Dims is the vector length.
	Dims int
	// ModelID pins which embedding model built the index. A persisted index whose
	// model differs is discarded rather than trusted.
	ModelID string
}

const (
	vectorsName  = "vectors.f32"
	manifestName = "index.manifest"
	manifestMagi = "memmesh-index v1"
)

// Open creates or reopens a quantized index.
//
// Reopening reads the float32 file back and requantizes it, which is the warm-on-
// boot path: it avoids re-embedding every record, and it is a sequential read of a
// file the page cache will mostly already hold. If the manifest names a different
// model or dimension, the files are discarded and the caller is told to re-embed —
// silently reusing vectors from another model is how recall degrades without anyone
// noticing.
func Open(cfg Config) (*Quantized, error) {
	if cfg.Dims <= 0 {
		return nil, fmt.Errorf("%w: dims must be positive, got %d", ErrDims, cfg.Dims)
	}
	q := &Quantized{
		dims:    cfg.Dims,
		modelID: cfg.ModelID,
		dir:     cfg.Dir,
		slots:   make(map[ulid.ULID]int),
	}
	if cfg.Dir == "" {
		return q, nil
	}
	if err := os.MkdirAll(cfg.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("index: create dir: %w", err)
	}
	if err := q.checkManifest(); err != nil {
		// Discard a mismatched or unreadable index and start clean. The vectors are
		// derived from the log, so nothing is lost that cannot be rebuilt.
		q.discard()
		if !errors.Is(err, ErrModelMismatch) && !errors.Is(err, ErrCorruptIndex) {
			return nil, err
		}
		if err := q.writeManifest(); err != nil {
			return nil, err
		}
	}
	f, err := os.OpenFile(filepath.Join(cfg.Dir, vectorsName), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("index: open vectors: %w", err)
	}
	q.vectors = f
	if err := q.warm(); err != nil {
		f.Close()
		return nil, err
	}
	return q, nil
}

func (q *Quantized) manifestPath() string { return filepath.Join(q.dir, manifestName) }

func (q *Quantized) writeManifest() error {
	body := fmt.Sprintf("%s\nmodel=%s\ndims=%d\n", manifestMagi, q.modelID, q.dims)
	return os.WriteFile(q.manifestPath(), []byte(body), 0o600)
}

func (q *Quantized) checkManifest() error {
	raw, err := os.ReadFile(q.manifestPath())
	if os.IsNotExist(err) {
		return q.writeManifest()
	}
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCorruptIndex, err)
	}
	model, dims, err := parseManifest(string(raw))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCorruptIndex, err)
	}
	if model != q.modelID || dims != q.dims {
		return fmt.Errorf("%w: on disk %s/%d, this node uses %s/%d",
			ErrModelMismatch, model, dims, q.modelID, q.dims)
	}
	return nil
}

func parseManifest(body string) (string, int, error) {
	var model string
	var dims int
	for _, line := range splitLines(body) {
		switch {
		case len(line) > 6 && line[:6] == "model=":
			model = line[6:]
		case len(line) > 5 && line[:5] == "dims=":
			if _, err := fmt.Sscanf(line[5:], "%d", &dims); err != nil {
				return "", 0, err
			}
		}
	}
	if dims == 0 {
		return "", 0, errors.New("no dims in manifest")
	}
	return model, dims, nil
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// discard removes the persisted index files.
func (q *Quantized) discard() {
	if q.dir == "" {
		return
	}
	_ = os.Remove(filepath.Join(q.dir, vectorsName))
	_ = os.Remove(q.manifestPath())
}

// warm reads the float32 file and rebuilds the quantized array and slot map.
//
// Slots whose id is zero are holes left by Remove and are added to the free list
// rather than being compacted away, so warming is a single sequential pass with no
// rewriting.
func (q *Quantized) warm() error {
	info, err := q.vectors.Stat()
	if err != nil {
		return fmt.Errorf("index: stat vectors: %w", err)
	}
	slotBytes := int64(slotSize(q.dims))
	if info.Size()%slotBytes != 0 {
		// A torn write at the tail: drop the partial slot.
		if err := q.vectors.Truncate(info.Size() - info.Size()%slotBytes); err != nil {
			return fmt.Errorf("index: truncate partial slot: %w", err)
		}
		info, err = q.vectors.Stat()
		if err != nil {
			return fmt.Errorf("index: stat vectors: %w", err)
		}
	}
	n := int(info.Size() / slotBytes)
	q.quant = make([]int8, 0, n*q.dims)
	q.ids = make([]ulid.ULID, 0, n)

	buf := make([]byte, slotBytes)
	for slot := 0; slot < n; slot++ {
		if _, err := q.vectors.ReadAt(buf, int64(slot)*slotBytes); err != nil {
			return fmt.Errorf("index: read slot %d: %w", slot, err)
		}
		var id ulid.ULID
		copy(id[:], buf[:ulid.Size])
		q.ids = append(q.ids, id)
		if id.IsZero() {
			q.free = append(q.free, slot)
			q.quant = append(q.quant, make([]int8, q.dims)...)
			continue
		}
		q.slots[id] = slot
		vec := decodeVector(buf[ulid.Size:], q.dims)
		q.quant = append(q.quant, quantize(vec)...)
	}
	return nil
}

// slotSize is the on-disk footprint of one slot: the record id followed by the
// float32 vector. Storing the id alongside the vector is what makes the file
// self-describing, so warming needs no separate id list to stay in step with.
func slotSize(dims int) int { return ulid.Size + dims*4 }

func encodeVector(dst []byte, id ulid.ULID, vec []float32) {
	copy(dst[:ulid.Size], id[:])
	for i, v := range vec {
		binary.LittleEndian.PutUint32(dst[ulid.Size+i*4:], math.Float32bits(v))
	}
}

func decodeVector(src []byte, dims int) []float32 {
	out := make([]float32, dims)
	for i := 0; i < dims; i++ {
		out[i] = math.Float32frombits(binary.LittleEndian.Uint32(src[i*4:]))
	}
	return out
}

func quantize(vec []float32) []int8 {
	out := make([]int8, len(vec))
	for i, v := range vec {
		scaled := float64(v) * quantScale
		switch {
		case scaled > 127:
			scaled = 127
		case scaled < -127:
			// Clamp at -127 rather than -128 so the scale is symmetric; an
			// asymmetric range would bias every dot product slightly negative.
			scaled = -127
		}
		out[i] = int8(math.Round(scaled))
	}
	return out
}

// Dims implements Index.
func (q *Quantized) Dims() int { return q.dims }

// ModelID returns the embedding model this index was built with.
func (q *Quantized) ModelID() string { return q.modelID }

// Len implements Index.
func (q *Quantized) Len() int {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return len(q.slots)
}

// ResidentBytes implements Index.
func (q *Quantized) ResidentBytes() int64 {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return int64(len(q.quant)) + int64(len(q.ids)*ulid.Size) + int64(len(q.slots)*(ulid.Size+8))
}

// Add implements Index.
func (q *Quantized) Add(id ulid.ULID, vec []float32) error {
	if len(vec) != q.dims {
		return fmt.Errorf("%w: got %d, want %d", ErrDims, len(vec), q.dims)
	}
	if id.IsZero() {
		return fmt.Errorf("index: cannot add the zero id")
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return ErrClosed
	}

	slot, existing := q.slots[id]
	if !existing {
		if n := len(q.free); n > 0 {
			slot = q.free[n-1]
			q.free = q.free[:n-1]
		} else {
			slot = len(q.ids)
			q.ids = append(q.ids, id)
			q.quant = append(q.quant, make([]int8, q.dims)...)
		}
		q.slots[id] = slot
		q.ids[slot] = id
	}

	copy(q.quant[slot*q.dims:(slot+1)*q.dims], quantize(vec))
	return q.persist(slot, id, vec)
}

// persist writes one slot's id and float32 vector to disk.
func (q *Quantized) persist(slot int, id ulid.ULID, vec []float32) error {
	if q.vectors == nil {
		return nil
	}
	buf := make([]byte, slotSize(q.dims))
	encodeVector(buf, id, vec)
	if _, err := q.vectors.WriteAt(buf, int64(slot)*int64(slotSize(q.dims))); err != nil {
		return fmt.Errorf("index: write slot %d: %w", slot, err)
	}
	return nil
}

// Remove implements Index.
//
// The slot is zeroed and freed rather than compacted out, because compaction would
// move every later slot and invalidate the whole file. A memory system deletes
// rarely — records are superseded, not removed — so holes are cheap and reuse is
// enough.
func (q *Quantized) Remove(id ulid.ULID) {
	q.mu.Lock()
	defer q.mu.Unlock()
	slot, ok := q.slots[id]
	if !ok {
		return
	}
	delete(q.slots, id)
	q.ids[slot] = ulid.ULID{}
	for i := slot * q.dims; i < (slot+1)*q.dims; i++ {
		q.quant[i] = 0
	}
	q.free = append(q.free, slot)
	_ = q.persist(slot, ulid.ULID{}, make([]float32, q.dims))
}

// Slots returns how many slots the index has allocated, including freed ones.
//
// Together with Len it says how much of the resident footprint is holes: a Slots
// well above Len means churn has fragmented the arrays.
func (q *Quantized) Slots() int {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return len(q.ids)
}

// Has reports whether a record is indexed.
func (q *Quantized) Has(id ulid.ULID) bool {
	q.mu.RLock()
	defer q.mu.RUnlock()
	_, ok := q.slots[id]
	return ok
}

// Search implements Index.
//
// Two passes: an integer scan over the quantized vectors to pick candidates, then a
// float32 rerank of those candidates read back from disk. The scan is what keeps the
// hot path inside the resident footprint; the rerank is what stops quantization
// error from reordering close results.
func (q *Quantized) Search(query []float32, k int) ([]Match, error) {
	if len(query) != q.dims {
		return nil, fmt.Errorf("%w: query has %d, index has %d", ErrDims, len(query), q.dims)
	}
	if k <= 0 {
		return nil, nil
	}
	q.mu.RLock()
	defer q.mu.RUnlock()
	if q.closed {
		return nil, ErrClosed
	}
	if len(q.slots) == 0 {
		return nil, nil
	}

	qq := quantize(query)
	candidateCount := k * oversample
	if candidateCount < minCandidates {
		candidateCount = minCandidates
	}

	candidates := make([]Match, 0, len(q.ids))
	for slot, id := range q.ids {
		if id.IsZero() {
			continue
		}
		var dot int32
		row := q.quant[slot*q.dims : (slot+1)*q.dims]
		for i, v := range row {
			dot += int32(v) * int32(qq[i])
		}
		candidates = append(candidates, Match{
			ID: id,
			// Both operands were scaled by quantScale, so undo it twice.
			Score: float32(float64(dot) / (quantScale * quantScale)),
		})
	}

	sortMatches(candidates)
	if len(candidates) > candidateCount {
		candidates = candidates[:candidateCount]
	}

	// Rerank with full precision. Without a backing file there is nothing more
	// precise to read, so the quantized scores stand.
	if q.vectors != nil {
		buf := make([]byte, slotSize(q.dims))
		for i := range candidates {
			slot, ok := q.slots[candidates[i].ID]
			if !ok {
				continue
			}
			if _, err := q.vectors.ReadAt(buf, int64(slot)*int64(slotSize(q.dims))); err != nil {
				return nil, fmt.Errorf("index: rerank read slot %d: %w", slot, err)
			}
			exact := decodeVector(buf[ulid.Size:], q.dims)
			var dot float32
			for j := range exact {
				dot += exact[j] * query[j]
			}
			candidates[i].Score = dot
		}
		sortMatches(candidates)
	}

	if len(candidates) > k {
		candidates = candidates[:k]
	}
	return candidates, nil
}

// sortMatches orders by descending score, breaking ties on id so the order is total
// and reproducible rather than dependent on slot allocation.
func sortMatches(ms []Match) {
	sort.Slice(ms, func(i, j int) bool {
		if ms[i].Score != ms[j].Score {
			return ms[i].Score > ms[j].Score
		}
		return ms[i].ID.Compare(ms[j].ID) < 0
	})
}

// Sync flushes the backing file.
func (q *Quantized) Sync() error {
	q.mu.RLock()
	defer q.mu.RUnlock()
	if q.vectors == nil {
		return nil
	}
	return q.vectors.Sync()
}

// Close implements Index.
func (q *Quantized) Close() error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return nil
	}
	q.closed = true
	if q.vectors == nil {
		return nil
	}
	if err := q.vectors.Sync(); err != nil {
		q.vectors.Close()
		return err
	}
	return q.vectors.Close()
}
