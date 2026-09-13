// Package store is the durable layer: one append-only log per space, plus the
// derived in-memory catalog that resolves supersession.
//
// Disk is truth. RAM is a cache that can always be rebuilt from the log
// (plan §11.6), and this package is where that is literally true: the log is the
// only authoritative state, and every other structure in the process — the
// version vector, the catalog, the vector index — is reconstructed by replaying
// it.
//
// # Why a log rather than SQLite
//
// The plan specifies SQLite in WAL mode, one database per space. No SQLite driver
// is reachable in this build (docs/decisions/0002), so the durable layer is a
// segmented append-only log with the same per-space file boundary, which keeps
// subscription, key rotation and eviction as file operations rather than query
// predicates. Store is an interface; a SQLite backend is a new implementation and
// no caller changes.
//
// The fit is close because records are append-only anyway. There are no updates to
// apply, no rows to rewrite, and no transactions spanning spaces — which is most of
// what a database would have been doing.
package store

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/coryforsythe/memmesh/internal/record"
	"github.com/coryforsythe/memmesh/internal/ulid"
	"github.com/coryforsythe/memmesh/internal/wire"
)

// Log file layout, per space directory:
//
//	<root>/<space>/
//	    manifest            one line of metadata; identifies the space and format
//	    000001.seg          segment files, rolled at SegmentTargetBytes
//	    000002.seg
//
// Each segment is a sequence of entries:
//
//	u32 BE  length of the entry payload
//	u32 BE  CRC32C of the entry payload
//	bytes   entry payload: wire.SealedRecord.MarshalEnvelope()
//
// The CRC is what makes a torn tail recoverable rather than fatal. A process killed
// mid-append leaves a partial entry; replay stops at the first entry that does not
// checksum, truncates there, and carries on. That is the whole crash story, and it
// works because nothing is ever rewritten: a truncated tail can only ever lose the
// write that was in flight.

const (
	// SegmentTargetBytes is the size at which a segment is rolled. Segments exist
	// so that eviction and backup can work on whole files, and so replay can
	// report progress.
	SegmentTargetBytes = 64 << 20

	// entryHeaderSize is the length and CRC prefix on each entry.
	entryHeaderSize = 8

	// maxEntryBytes bounds what replay will allocate for one entry, so a corrupt
	// length field cannot exhaust memory.
	maxEntryBytes = 8 << 20

	// manifestName is the per-space metadata file.
	manifestName = "manifest"

	// logFormatVersion is the segment entry framing version.
	logFormatVersion = 1
)

var crcTable = crc32.MakeTable(crc32.Castagnoli)

// segmentTargetForTest is the roll threshold actually used. It exists as a
// variable so tests can shrink it and exercise segment boundaries without writing
// 64 MiB of records; production always uses SegmentTargetBytes.
var segmentTargetForTest = SegmentTargetBytes

// Errors returned by the log.
var (
	// ErrClosed reports use of a closed log.
	ErrClosed = errors.New("store: log is closed")
	// ErrCorrupt reports damage a replay could not recover from. A torn tail is
	// not corruption and does not produce this; only damage in the middle of a
	// segment does.
	ErrCorrupt = errors.New("store: log is corrupt")
	// ErrNotFound reports a record this node does not hold.
	ErrNotFound = errors.New("store: record not found")
	// ErrSpaceMismatch reports a directory whose manifest names a different space.
	ErrSpaceMismatch = errors.New("store: manifest names a different space")
)

// entryLoc is where one record's bytes live on disk.
type entryLoc struct {
	segment int
	offset  int64
	length  int
}

// Log is the append-only record log for one space.
//
// It works identically whether or not this node holds the space key: everything it
// does is defined over the plaintext envelope (record ID, authoring node, epoch),
// which is exactly why a relay can carry a space it cannot read
// (docs/decisions/0006).
//
// A Log is safe for concurrent use.
type Log struct {
	space record.SpaceID
	dir   string

	mu       sync.RWMutex
	closed   bool
	segments []*segment
	active   *segment

	// index maps record id to its location. Rebuilt on open by replaying.
	index map[ulid.ULID]entryLoc
	// byNode lists each authoring node's record ids in ascending order, which is
	// what makes a range request a binary search rather than a scan.
	byNode map[record.NodeID][]ulid.ULID
	// vector is the derived high-water mark per authoring node.
	vector record.VersionVector

	bytes int64
	// truncatedTail records whether opening recovered from an interrupted write,
	// so status can report it rather than hiding it.
	truncatedTail bool
}

type segment struct {
	num  int
	path string
	file *os.File
	size int64
}

// OpenLog opens or creates the log for a space under root.
//
// Opening replays every segment to rebuild the index and version vector. That is
// the cost of holding no separate durable index, and it buys the guarantee that the
// in-memory state can never disagree with the log — there is no second source of
// truth to fall out of step.
func OpenLog(root string, space record.SpaceID) (*Log, error) {
	if err := space.Validate(); err != nil {
		return nil, err
	}
	dir := filepath.Join(root, space.Filename())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("store: create space dir: %w", err)
	}
	l := &Log{
		space:  space,
		dir:    dir,
		index:  make(map[ulid.ULID]entryLoc),
		byNode: make(map[record.NodeID][]ulid.ULID),
		vector: record.NewVersionVector(),
	}
	if err := l.writeManifest(); err != nil {
		return nil, err
	}
	if err := l.openSegments(); err != nil {
		return nil, err
	}
	if err := l.replay(); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// Space returns the space this log holds.
func (l *Log) Space() record.SpaceID { return l.space }

// Dir returns the space's directory, for status output and eviction.
func (l *Log) Dir() string { return l.dir }

func (l *Log) writeManifest() error {
	path := filepath.Join(l.dir, manifestName)
	want := fmt.Sprintf("memmesh-log v%d space=%s\n", logFormatVersion, l.space)
	existing, err := os.ReadFile(path)
	switch {
	case err == nil:
		if string(existing) != want {
			return fmt.Errorf("%w: %s holds %q, expected %q", ErrSpaceMismatch, path, existing, want)
		}
		return nil
	case os.IsNotExist(err):
		return os.WriteFile(path, []byte(want), 0o600)
	default:
		return fmt.Errorf("store: read manifest: %w", err)
	}
}

func (l *Log) openSegments() error {
	names, err := filepath.Glob(filepath.Join(l.dir, "*.seg"))
	if err != nil {
		return fmt.Errorf("store: list segments: %w", err)
	}
	sort.Strings(names)
	for _, name := range names {
		var num int
		if _, err := fmt.Sscanf(filepath.Base(name), "%06d.seg", &num); err != nil {
			return fmt.Errorf("%w: unexpected file %s", ErrCorrupt, name)
		}
		f, err := os.OpenFile(name, os.O_RDWR, 0o600)
		if err != nil {
			return fmt.Errorf("store: open segment: %w", err)
		}
		info, err := f.Stat()
		if err != nil {
			f.Close()
			return fmt.Errorf("store: stat segment: %w", err)
		}
		l.segments = append(l.segments, &segment{num: num, path: name, file: f, size: info.Size()})
	}
	if len(l.segments) == 0 {
		if err := l.roll(1); err != nil {
			return err
		}
	}
	l.active = l.segments[len(l.segments)-1]
	return nil
}

func (l *Log) roll(num int) error {
	path := filepath.Join(l.dir, fmt.Sprintf("%06d.seg", num))
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("store: create segment: %w", err)
	}
	seg := &segment{num: num, path: path, file: f}
	l.segments = append(l.segments, seg)
	l.active = seg
	return nil
}

// replay rebuilds the in-memory index from every segment.
func (l *Log) replay() error {
	for i, seg := range l.segments {
		offset := int64(0)
		reader := io.NewSectionReader(seg.file, 0, seg.size)
		var header [entryHeaderSize]byte
		for {
			if _, err := io.ReadFull(reader, header[:]); err != nil {
				if err == io.EOF {
					break
				}
				// A header that does not fit is an interrupted write.
				l.truncateFrom(i, offset)
				break
			}
			length := int(binary.BigEndian.Uint32(header[0:4]))
			wantCRC := binary.BigEndian.Uint32(header[4:8])
			if length <= 0 || length > maxEntryBytes {
				l.truncateFrom(i, offset)
				break
			}
			payload := make([]byte, length)
			if _, err := io.ReadFull(reader, payload); err != nil {
				l.truncateFrom(i, offset)
				break
			}
			if crc32.Checksum(payload, crcTable) != wantCRC {
				// Damage in the middle of a segment is real corruption; damage at
				// the tail is an interrupted write. Distinguish them by whether
				// anything follows.
				if offset+int64(entryHeaderSize+length) < seg.size || i != len(l.segments)-1 {
					return fmt.Errorf("%w: bad checksum at %s offset %d, with data after it",
						ErrCorrupt, seg.path, offset)
				}
				l.truncateFrom(i, offset)
				break
			}
			entry, used, err := wire.UnmarshalEnvelope(l.space, payload)
			if err != nil {
				return fmt.Errorf("%w: unparseable entry at %s offset %d: %v", ErrCorrupt, seg.path, offset, err)
			}
			if used != length {
				return fmt.Errorf("%w: entry at %s offset %d has %d trailing bytes",
					ErrCorrupt, seg.path, offset, length-used)
			}
			l.remember(entry, entryLoc{segment: i, offset: offset + entryHeaderSize, length: length})
			offset += int64(entryHeaderSize + length)
			l.bytes += int64(length)
		}
	}
	for node := range l.byNode {
		ids := l.byNode[node]
		sort.Slice(ids, func(a, b int) bool { return ids[a].Compare(ids[b]) < 0 })
		l.byNode[node] = ids
	}
	l.active = l.segments[len(l.segments)-1]
	return nil
}

// truncateFrom discards a torn tail: the partial entry at offset, and any whole
// segments after this one.
func (l *Log) truncateFrom(segIdx int, offset int64) {
	seg := l.segments[segIdx]
	if offset < seg.size {
		l.truncatedTail = true
		_ = seg.file.Truncate(offset)
		seg.size = offset
	}
	for _, later := range l.segments[segIdx+1:] {
		l.truncatedTail = true
		later.file.Close()
		_ = os.Remove(later.path)
	}
	l.segments = l.segments[:segIdx+1]
}

// remember records an entry in the in-memory structures. Caller holds the lock or
// is in replay.
func (l *Log) remember(entry *wire.SealedRecord, loc entryLoc) {
	if _, seen := l.index[entry.ID]; seen {
		return
	}
	l.index[entry.ID] = loc
	l.byNode[entry.AuthorNode] = append(l.byNode[entry.AuthorNode], entry.ID)
	l.vector.Observe(entry.AuthorNode, entry.ID)
}

// TruncatedTail reports whether opening this log recovered from an interrupted
// write. Worth surfacing in status: it means a write was lost, even though the log
// is now consistent.
func (l *Log) TruncatedTail() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.truncatedTail
}

// Append writes entries that are not already present and returns how many were
// new.
//
// Appending the same record twice is a no-op, which is what makes sync idempotent:
// a peer may hand over a record this node already has — during overlapping
// push-on-write and pull anti-entropy, that is routine — and nothing needs to
// deduplicate upstream.
//
// Entries are fsynced before the call returns. A memory system whose writes can
// silently vanish on power loss is not a memory system, and the write path here is
// one sequential append, so the cost is a single flush rather than a tree of them.
func (l *Log) Append(entries ...*wire.SealedRecord) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return 0, ErrClosed
	}

	written := 0
	for _, entry := range entries {
		if entry == nil {
			return written, fmt.Errorf("store: nil entry")
		}
		if entry.Space != l.space {
			return written, fmt.Errorf("store: entry is for space %s, this log holds %s", entry.Space, l.space)
		}
		if entry.ID.IsZero() || !entry.AuthorNode.Valid() {
			return written, fmt.Errorf("store: entry has an invalid envelope")
		}
		if _, exists := l.index[entry.ID]; exists {
			continue
		}
		if err := l.appendOne(entry); err != nil {
			return written, err
		}
		written++
	}
	if written > 0 {
		if err := l.active.file.Sync(); err != nil {
			return written, fmt.Errorf("store: sync: %w", err)
		}
	}
	return written, nil
}

func (l *Log) appendOne(entry *wire.SealedRecord) error {
	payload := entry.MarshalEnvelope()
	if len(payload) > maxEntryBytes {
		return fmt.Errorf("store: entry is %d bytes, max %d", len(payload), maxEntryBytes)
	}
	if l.active.size > 0 && l.active.size+int64(entryHeaderSize+len(payload)) > int64(segmentTargetForTest) {
		if err := l.roll(l.active.num + 1); err != nil {
			return err
		}
	}
	var header [entryHeaderSize]byte
	binary.BigEndian.PutUint32(header[0:4], uint32(len(payload)))
	binary.BigEndian.PutUint32(header[4:8], crc32.Checksum(payload, crcTable))

	buf := make([]byte, 0, entryHeaderSize+len(payload))
	buf = append(buf, header[:]...)
	buf = append(buf, payload...)

	if _, err := l.active.file.WriteAt(buf, l.active.size); err != nil {
		return fmt.Errorf("store: write entry: %w", err)
	}
	loc := entryLoc{
		segment: len(l.segments) - 1,
		offset:  l.active.size + entryHeaderSize,
		length:  len(payload),
	}
	l.active.size += int64(len(buf))
	l.bytes += int64(len(payload))

	l.index[entry.ID] = loc
	ids := l.byNode[entry.AuthorNode]
	// Appends from the local node arrive in ascending order, so the common case
	// is a tail append. Records arriving from a peer can be out of order, so fall
	// back to an insertion that keeps the slice sorted.
	if n := len(ids); n == 0 || ids[n-1].Compare(entry.ID) < 0 {
		ids = append(ids, entry.ID)
	} else {
		at := sort.Search(n, func(i int) bool { return ids[i].Compare(entry.ID) >= 0 })
		ids = append(ids, ulid.ULID{})
		copy(ids[at+1:], ids[at:])
		ids[at] = entry.ID
	}
	l.byNode[entry.AuthorNode] = ids
	l.vector.Observe(entry.AuthorNode, entry.ID)
	return nil
}

// Get returns one sealed record by id.
func (l *Log) Get(id ulid.ULID) (*wire.SealedRecord, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed {
		return nil, ErrClosed
	}
	loc, ok := l.index[id]
	if !ok {
		return nil, fmt.Errorf("%w: %s in %s", ErrNotFound, id, l.space)
	}
	return l.readAt(loc)
}

// readAt reads and parses the entry at loc. Caller holds at least a read lock.
func (l *Log) readAt(loc entryLoc) (*wire.SealedRecord, error) {
	payload := make([]byte, loc.length)
	if _, err := l.segments[loc.segment].file.ReadAt(payload, loc.offset); err != nil {
		return nil, fmt.Errorf("store: read entry: %w", err)
	}
	// The CRC was verified during replay; re-checking on every read would cost a
	// pass over the payload for a failure mode that only appears if the file
	// changed underneath us, which the AEAD tag catches anyway on open.
	entry, _, err := wire.UnmarshalEnvelope(l.space, payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	return entry, nil
}

// Has reports whether this node holds a record.
func (l *Log) Has(id ulid.ULID) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	_, ok := l.index[id]
	return ok
}

// Count returns how many records the log holds.
func (l *Log) Count() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.index)
}

// Bytes returns the total sealed payload size, which is what a relay reports for a
// space it cannot read.
func (l *Log) Bytes() int64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.bytes
}

// Segments returns how many segment files back this log.
func (l *Log) Segments() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.segments)
}

// Vector returns a copy of the log's version vector: the high-water record id per
// authoring node.
//
// This is the sync handshake payload for this space, and it is derived rather than
// stored, so it cannot drift from the log's actual contents.
func (l *Log) Vector() record.VersionVector {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.vector.Clone()
}

// Range returns up to limit records from one authoring node whose ids fall inside
// r, in ascending id order. A limit of zero or less means no limit.
//
// Ascending order matters to the caller: a receiver that applies a partial range
// can advance its high-water mark to the last id it actually stored and resume from
// there, so an interrupted backfill never has to start over.
func (l *Log) Range(node record.NodeID, r record.Range, limit int) ([]*wire.SealedRecord, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if l.closed {
		return nil, ErrClosed
	}
	ids := l.byNode[node]
	start := sort.Search(len(ids), func(i int) bool { return ids[i].Compare(r.After) > 0 })

	out := make([]*wire.SealedRecord, 0, 16)
	for _, id := range ids[start:] {
		if id.Compare(r.Through) > 0 {
			break
		}
		entry, err := l.readAt(l.index[id])
		if err != nil {
			return nil, err
		}
		out = append(out, entry)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

// Missing returns the ranges this log needs in order to catch up to peer, or nil if
// it is already current.
func (l *Log) Missing(peer record.VersionVector) map[record.NodeID]record.Range {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.vector.MissingFrom(peer)
}

// All returns every record id in the log, in ascending order across all nodes.
// Used by catalog rebuilds and by the index warm-up.
func (l *Log) All() []ulid.ULID {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]ulid.ULID, 0, len(l.index))
	for id := range l.index {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Compare(out[j]) < 0 })
	return out
}

// Replay calls fn for every record in ascending id order, stopping on the first
// error. This is how every derived structure is rebuilt.
func (l *Log) Replay(fn func(*wire.SealedRecord) error) error {
	for _, id := range l.All() {
		l.mu.RLock()
		loc, ok := l.index[id]
		if !ok {
			l.mu.RUnlock()
			continue
		}
		entry, err := l.readAt(loc)
		l.mu.RUnlock()
		if err != nil {
			return err
		}
		if err := fn(entry); err != nil {
			return err
		}
	}
	return nil
}

// MaxLocalID returns the highest record id this log holds that was authored by the
// given node.
//
// The daemon calls this on boot to re-seed its ULID generator, which is what stops
// a backwards wall clock across a restart producing an id below one already
// published (docs/decisions/0001).
func (l *Log) MaxLocalID(node record.NodeID) ulid.ULID {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.vector.Get(node)
}

// Close flushes and closes the log.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	var firstErr error
	for _, seg := range l.segments {
		if err := seg.file.Sync(); err != nil && firstErr == nil {
			firstErr = err
		}
		if err := seg.file.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
