package store

import (
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/coryforsythe/memmesh/internal/clock"
	"github.com/coryforsythe/memmesh/internal/crypto"
	"github.com/coryforsythe/memmesh/internal/hlc"
	"github.com/coryforsythe/memmesh/internal/record"
	"github.com/coryforsythe/memmesh/internal/ulid"
	"github.com/coryforsythe/memmesh/internal/wire"
)

type detReader struct{ rng *rand.Rand }

func (d detReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(d.rng.Intn(256))
	}
	return len(p), nil
}

type harness struct {
	root    string
	keys    *crypto.Keyring
	builder *record.Builder
	entropy io.Reader
	fake    *clock.Fake
	node    record.NodeID
}

func newHarness(t *testing.T, node record.NodeID, seed int64, spaces ...record.SpaceID) *harness {
	t.Helper()
	ent := detReader{rng: rand.New(rand.NewSource(seed))}
	signer, err := record.GenerateSigner(ent)
	if err != nil {
		t.Fatal(err)
	}
	fake := clock.NewFake(1_757_700_000_000)
	b, err := record.NewBuilder(record.BuilderConfig{
		Node:        node,
		Signer:      signer,
		IDs:         ulid.NewMonotonic(fake, ent),
		Stamps:      hlc.New(fake),
		AuthorModel: "claude-opus-5",
		EmbedModel:  "memmesh-hashembed-v1-384",
	})
	if err != nil {
		t.Fatal(err)
	}
	ring := crypto.NewKeyring()
	for _, s := range spaces {
		key, err := crypto.GenerateContentKey(ent)
		if err != nil {
			t.Fatal(err)
		}
		ring.Install(string(s), 0, key)
	}
	return &harness{
		root:    t.TempDir(),
		keys:    ring,
		builder: b,
		entropy: ent,
		fake:    fake,
		node:    node,
	}
}

func (h *harness) write(t *testing.T, s *Space, d record.Draft) *record.Record {
	t.Helper()
	h.fake.Advance(1)
	if d.Space == "" {
		d.Space = s.ID()
	}
	r, err := h.builder.Build(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write(r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestLogAppendGetRoundTrip(t *testing.T) {
	h := newHarness(t, "alpha", 1, "user/cory")
	s, err := OpenSpace(h.root, "user/cory", h.keys, h.entropy)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	r := h.write(t, s, record.Draft{Kind: record.KindFact, Body: []byte("parse_ts assumes UTC input"), Evidence: record.EvidenceObserved})

	if !s.Log().Has(r.ID) {
		t.Fatal("the record is not in the log")
	}
	back, err := s.Record(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if back.ID != r.ID || string(back.Body) != string(r.Body) {
		t.Fatal("the record did not survive the round trip")
	}
	if s.Log().Count() != 1 {
		t.Errorf("count = %d, want 1", s.Log().Count())
	}
	if s.Log().Bytes() <= 0 {
		t.Error("Bytes is zero after a write")
	}

	if _, err := s.Record(ulid.MustParse("01J000000000000000000000ZZ")); !errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestAppendIsIdempotent(t *testing.T) {
	h := newHarness(t, "alpha", 2, "user/cory")
	s, err := OpenSpace(h.root, "user/cory", h.keys, h.entropy)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	r := h.write(t, s, record.Draft{Kind: record.KindEpisode, Body: []byte("x")})
	sealed, err := s.Log().Get(r.ID)
	if err != nil {
		t.Fatal(err)
	}

	// Re-offering a record the node already has must be free and must not grow the
	// log. This is what makes push-on-write and pull anti-entropy safe to overlap.
	before := s.Log().Bytes()
	n, err := s.Accept(sealed, sealed, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("accepted %d duplicates, want 0", n)
	}
	if s.Log().Bytes() != before {
		t.Error("re-appending a duplicate grew the log")
	}
	if s.Log().Count() != 1 {
		t.Errorf("count = %d, want 1", s.Log().Count())
	}
}

func TestReopenRebuildsFromTheLog(t *testing.T) {
	h := newHarness(t, "alpha", 3, "user/cory")
	s, err := OpenSpace(h.root, "user/cory", h.keys, h.entropy)
	if err != nil {
		t.Fatal(err)
	}

	var written []*record.Record
	for i := 0; i < 50; i++ {
		written = append(written, h.write(t, s, record.Draft{
			Kind: record.KindEpisode,
			Body: []byte(fmt.Sprintf("episode %d", i)),
			Tags: []string{"batch", fmt.Sprintf("n%d", i%5)},
		}))
	}
	wantVector := s.Vector()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Everything in memory is derived. Reopening must reconstruct all of it from
	// the log alone.
	reopened, err := OpenSpace(h.root, "user/cory", h.keys, h.entropy)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()

	if got := reopened.Log().Count(); got != len(written) {
		t.Fatalf("count after reopen = %d, want %d", got, len(written))
	}
	if !reopened.Vector().Equal(wantVector) {
		t.Errorf("version vector did not survive reopen: %s vs %s", reopened.Vector(), wantVector)
	}
	if reopened.Catalog().Count() != len(written) {
		t.Errorf("catalog count = %d, want %d", reopened.Catalog().Count(), len(written))
	}
	for _, r := range written {
		back, err := reopened.Record(r.ID)
		if err != nil {
			t.Fatalf("record %s lost: %v", r.ID, err)
		}
		if string(back.Body) != string(r.Body) {
			t.Fatalf("record %s body changed", r.ID)
		}
	}
	if got := reopened.Catalog().LiveByTag("batch", 0); len(got) != len(written) {
		t.Errorf("tag index after reopen has %d entries, want %d", len(got), len(written))
	}
}

func TestTornTailIsRecoveredNotFatal(t *testing.T) {
	h := newHarness(t, "alpha", 4, "user/cory")
	s, err := OpenSpace(h.root, "user/cory", h.keys, h.entropy)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		h.write(t, s, record.Draft{Kind: record.KindEpisode, Body: []byte(fmt.Sprintf("e%d", i))})
	}
	last := h.write(t, s, record.Draft{Kind: record.KindEpisode, Body: []byte("the interrupted one")})
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Simulate a process killed mid-append: chop bytes off the end of the segment.
	seg := filepath.Join(h.root, record.SpaceID("user/cory").Filename(), "000001.seg")
	info, err := os.Stat(seg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(seg, info.Size()-20); err != nil {
		t.Fatal(err)
	}

	reopened, err := OpenSpace(h.root, "user/cory", h.keys, h.entropy)
	if err != nil {
		t.Fatalf("a torn tail must be recoverable, not fatal: %v", err)
	}
	defer reopened.Close()

	if !reopened.Log().TruncatedTail() {
		t.Error("the log did not report that it recovered a torn tail")
	}
	if reopened.Log().Has(last.ID) {
		t.Error("the interrupted write survived; it should have been discarded")
	}
	if got := reopened.Log().Count(); got != 5 {
		t.Errorf("count = %d, want the 5 complete records", got)
	}

	// And the log must still be writable afterwards.
	fresh := h.write(t, reopened, record.Draft{Kind: record.KindEpisode, Body: []byte("after recovery")})
	if !reopened.Log().Has(fresh.ID) {
		t.Error("the log is not writable after recovering a torn tail")
	}
}

func TestRangeReturnsAscendingAndRespectsLimits(t *testing.T) {
	h := newHarness(t, "alpha", 5, "user/cory")
	s, err := OpenSpace(h.root, "user/cory", h.keys, h.entropy)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	var ids []ulid.ULID
	for i := 0; i < 20; i++ {
		ids = append(ids, h.write(t, s, record.Draft{Kind: record.KindEpisode, Body: []byte{byte('a' + i)}}).ID)
	}

	all, err := s.Log().Range("alpha", record.Range{Through: ids[len(ids)-1]}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != len(ids) {
		t.Fatalf("got %d records, want %d", len(all), len(ids))
	}
	for i := 1; i < len(all); i++ {
		if all[i-1].ID.Compare(all[i].ID) >= 0 {
			t.Fatal("Range did not return ascending ids; a partial apply could not resume")
		}
	}

	// After is exclusive, Through inclusive.
	mid, err := s.Log().Range("alpha", record.Range{After: ids[4], Through: ids[9]}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(mid) != 5 || mid[0].ID != ids[5] || mid[4].ID != ids[9] {
		t.Errorf("range [%s, %s] returned %d records starting at %s", ids[4], ids[9], len(mid), mid[0].ID)
	}

	limited, err := s.Log().Range("alpha", record.Range{Through: ids[len(ids)-1]}, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(limited) != 3 || limited[0].ID != ids[0] {
		t.Errorf("limit was not respected: got %d records", len(limited))
	}

	if got, _ := s.Log().Range("beta", record.Range{Through: ids[0]}, 0); len(got) != 0 {
		t.Errorf("range for an unknown node returned %d records", len(got))
	}
}

func TestOutOfOrderArrivalsKeepRangeOrdering(t *testing.T) {
	// Records from a peer do not arrive in id order. The per-node id list has to
	// stay sorted anyway, or a later range request silently skips records.
	h := newHarness(t, "alpha", 6, "shared/crew")
	source, err := OpenSpace(h.root, "shared/crew", h.keys, h.entropy)
	if err != nil {
		t.Fatal(err)
	}
	var sealed []*wire.SealedRecord
	for i := 0; i < 10; i++ {
		r := h.write(t, source, record.Draft{Kind: record.KindEpisode, Body: []byte{byte('a' + i)}})
		s, err := source.Log().Get(r.ID)
		if err != nil {
			t.Fatal(err)
		}
		sealed = append(sealed, s)
	}
	source.Close()

	// Deliver them to a second node in reverse order.
	dest := t.TempDir()
	target, err := OpenSpace(dest, "shared/crew", h.keys, h.entropy)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	for i := len(sealed) - 1; i >= 0; i-- {
		if _, err := target.Accept(sealed[i]); err != nil {
			t.Fatal(err)
		}
	}

	got, err := target.Log().Range("alpha", record.Range{Through: sealed[len(sealed)-1].ID}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(sealed) {
		t.Fatalf("got %d records, want %d", len(got), len(sealed))
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].ID.Compare(got[i].ID) >= 0 {
			t.Fatal("out-of-order arrivals left the per-node id list unsorted")
		}
	}
	if !target.Vector().Equal(map[record.NodeID]ulid.ULID{"alpha": sealed[len(sealed)-1].ID}) {
		t.Errorf("vector = %s, want the highest id", target.Vector())
	}
}

func TestSegmentsRollAndReplayAcrossThem(t *testing.T) {
	// Shrink the target so a handful of records spans several segments.
	original := segmentTargetForTest
	segmentTargetForTest = 2048
	defer func() { segmentTargetForTest = original }()

	h := newHarness(t, "alpha", 7, "user/cory")
	s, err := OpenSpace(h.root, "user/cory", h.keys, h.entropy)
	if err != nil {
		t.Fatal(err)
	}
	var ids []ulid.ULID
	for i := 0; i < 40; i++ {
		ids = append(ids, h.write(t, s, record.Draft{Kind: record.KindEpisode, Body: []byte(fmt.Sprintf("record %d", i))}).ID)
	}
	if s.Log().Segments() < 2 {
		t.Fatalf("expected the log to roll; it has %d segment(s)", s.Log().Segments())
	}
	s.Close()

	reopened, err := OpenSpace(h.root, "user/cory", h.keys, h.entropy)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if got := reopened.Log().Count(); got != len(ids) {
		t.Fatalf("count after reopen across segments = %d, want %d", got, len(ids))
	}
	for _, id := range ids {
		if _, err := reopened.Record(id); err != nil {
			t.Fatalf("record %s lost across a segment boundary: %v", id, err)
		}
	}
}

func TestRelayedSpaceStoresWithoutReading(t *testing.T) {
	// Produce sealed records on a node that holds the key.
	h := newHarness(t, "alpha", 8, "shared/crew")
	source, err := OpenSpace(h.root, "shared/crew", h.keys, h.entropy)
	if err != nil {
		t.Fatal(err)
	}
	var sealed []*wire.SealedRecord
	for i := 0; i < 5; i++ {
		r := h.write(t, source, record.Draft{Kind: record.KindFact, Body: []byte("a claim nobody else can read")})
		got, err := source.Log().Get(r.ID)
		if err != nil {
			t.Fatal(err)
		}
		sealed = append(sealed, got)
	}
	source.Close()

	// A relay holds no key at all.
	relayRing := crypto.NewKeyring()
	relay, err := OpenSpace(t.TempDir(), "shared/crew", relayRing, h.entropy)
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()

	if relay.Readable() {
		t.Fatal("a space with no key reports as readable")
	}
	if relay.Catalog() != nil {
		t.Fatal("a relayed space has a catalog; there is nothing to build it from")
	}

	n, err := relay.Accept(sealed...)
	if err != nil {
		t.Fatalf("a relay must be able to store records it cannot read: %v", err)
	}
	if n != len(sealed) {
		t.Fatalf("stored %d of %d", n, len(sealed))
	}

	// It can gossip: version vector and range requests work with no key, because
	// both are defined over the plaintext envelope.
	if !relay.Vector().Equal(map[record.NodeID]ulid.ULID{"alpha": sealed[len(sealed)-1].ID}) {
		t.Errorf("a relay could not maintain a version vector: %s", relay.Vector())
	}
	served, err := relay.Log().Range("alpha", record.Range{Through: sealed[len(sealed)-1].ID}, 0)
	if err != nil {
		t.Fatalf("a relay could not serve a range: %v", err)
	}
	if len(served) != len(sealed) {
		t.Errorf("served %d of %d records", len(served), len(sealed))
	}

	// But it cannot read, write, or index.
	if _, err := relay.Record(sealed[0].ID); !errors.Is(err, ErrRelayed) {
		t.Errorf("Record err = %v, want ErrRelayed", err)
	}
	r, _ := h.builder.Build(record.Draft{Space: "shared/crew", Kind: record.KindEpisode, Body: []byte("x")})
	if _, err := relay.Write(r); !errors.Is(err, ErrRelayed) {
		t.Errorf("Write err = %v, want ErrRelayed", err)
	}

	// And its stats expose counts and bytes only.
	st := relay.Stats()
	if st.Readable || st.Records != len(sealed) || st.Bytes <= 0 {
		t.Errorf("relay stats are wrong: %+v", st)
	}
	if st.ByKind != nil || st.EmbedModels != nil {
		t.Error("relay stats leak decrypted detail")
	}
}

func TestGainingAKeyMakesAStoredSpaceReadable(t *testing.T) {
	// The records are already on disk. Gaining the key must turn them into a
	// readable corpus with no network traffic at all.
	h := newHarness(t, "alpha", 9, "shared/crew")
	source, err := OpenSpace(h.root, "shared/crew", h.keys, h.entropy)
	if err != nil {
		t.Fatal(err)
	}
	var sealed []*wire.SealedRecord
	for i := 0; i < 4; i++ {
		r := h.write(t, source, record.Draft{Kind: record.KindFact, Body: []byte(fmt.Sprintf("claim %d", i))})
		got, _ := source.Log().Get(r.ID)
		sealed = append(sealed, got)
	}
	source.Close()

	lateRing := crypto.NewKeyring()
	dest := t.TempDir()
	mgr, err := NewManager(dest, lateRing, h.entropy)
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()

	space, err := mgr.Open("shared/crew")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := space.Accept(sealed...); err != nil {
		t.Fatal(err)
	}
	if space.Readable() {
		t.Fatal("readable before the key arrived")
	}

	// The key arrives.
	key, err := h.keys.Key("shared/crew", 0)
	if err != nil {
		t.Fatal(err)
	}
	lateRing.Install("shared/crew", 0, key)
	if err := mgr.Reindex("shared/crew"); err != nil {
		t.Fatal(err)
	}

	if !space.Readable() {
		t.Fatal("still not readable after the key arrived")
	}
	if space.Catalog().Count() != len(sealed) {
		t.Errorf("catalog has %d records, want %d", space.Catalog().Count(), len(sealed))
	}
	for _, s := range sealed {
		if _, err := space.Record(s.ID); err != nil {
			t.Errorf("record %s still unreadable: %v", s.ID, err)
		}
	}
}

func TestAcceptRejectsAnUnverifiableRecord(t *testing.T) {
	h := newHarness(t, "alpha", 10, "user/cory")
	source, err := OpenSpace(h.root, "user/cory", h.keys, h.entropy)
	if err != nil {
		t.Fatal(err)
	}
	good := h.write(t, source, record.Draft{Kind: record.KindEpisode, Body: []byte("honest")})
	sealed, _ := source.Log().Get(good.ID)
	source.Close()

	dest, err := OpenSpace(t.TempDir(), "user/cory", h.keys, h.entropy)
	if err != nil {
		t.Fatal(err)
	}
	defer dest.Close()

	tampered := &wire.SealedRecord{
		Space: sealed.Space, ID: sealed.ID, AuthorNode: sealed.AuthorNode, Epoch: sealed.Epoch,
		Blob: append([]byte(nil), sealed.Blob...),
	}
	tampered.Blob[len(tampered.Blob)-1] ^= 1

	if _, err := dest.Accept(tampered); err == nil {
		t.Fatal("Accept stored a record that failed authentication")
	}
	if dest.Log().Count() != 0 {
		t.Error("a rejected record reached the log")
	}

	// A batch with one bad record must not half-apply.
	if _, err := dest.Accept(sealed, tampered); err == nil {
		t.Fatal("Accept stored a batch containing a bad record")
	}
	if dest.Log().Count() != 0 {
		t.Error("a partially-bad batch left records in the log")
	}
}

func TestSupersessionResolution(t *testing.T) {
	h := newHarness(t, "alpha", 11, "user/cory")
	s, err := OpenSpace(h.root, "user/cory", h.keys, h.entropy)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cat := s.Catalog()

	claim := h.write(t, s, record.Draft{Kind: record.KindFact, Body: []byte("parse_ts assumes UTC")})
	if !cat.Live(claim.ID) {
		t.Fatal("a fresh record is not live")
	}

	h.fake.Advance(1)
	retraction, err := h.builder.Retract("user/cory", 0, "measured it; it assumes local time", nil, claim.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write(retraction); err != nil {
		t.Fatal(err)
	}

	if cat.Live(claim.ID) {
		t.Error("a retracted record is still live")
	}
	by, ok := cat.Superseded(claim.ID)
	if !ok || len(by) != 1 || by[0] != retraction.ID {
		t.Errorf("Superseded = %v, %v", by, ok)
	}
	if cat.Tombstoned(claim.ID) {
		t.Error("a retraction was reported as a tombstone; the distinction is the whole point")
	}
	rets := cat.Retractions(claim.ID)
	if len(rets) != 1 || rets[0].ID != retraction.ID {
		t.Errorf("Retractions = %v", rets)
	}

	// The superseded record is still present and still readable. Append-only means
	// supersession changes what is surfaced, not what exists.
	if _, err := s.Record(claim.ID); err != nil {
		t.Errorf("a superseded record became unreadable: %v", err)
	}
	if _, ok := cat.Get(claim.ID); !ok {
		t.Error("a superseded record vanished from the catalog")
	}
}

func TestTombstoneIsDistinctFromRetraction(t *testing.T) {
	h := newHarness(t, "alpha", 12, "user/cory")
	s, err := OpenSpace(h.root, "user/cory", h.keys, h.entropy)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cat := s.Catalog()

	claim := h.write(t, s, record.Draft{Kind: record.KindEpisode, Body: []byte("should not be here")})
	h.fake.Advance(1)
	tomb, err := h.builder.Tombstone("user/cory", 0, nil, claim.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write(tomb); err != nil {
		t.Fatal(err)
	}

	if !cat.Tombstoned(claim.ID) {
		t.Error("a tombstoned record does not report as tombstoned")
	}
	if len(cat.Retractions(claim.ID)) != 0 {
		t.Error("a tombstone was reported as a retraction")
	}
	if cat.Live(claim.ID) {
		t.Error("a tombstoned record is still live")
	}
}

func TestSupersessionArrivingBeforeItsTarget(t *testing.T) {
	// A correction can outrun the claim it corrects. When the claim finally lands
	// it must arrive already superseded, not briefly surface as current.
	h := newHarness(t, "alpha", 13, "shared/crew")
	source, err := OpenSpace(h.root, "shared/crew", h.keys, h.entropy)
	if err != nil {
		t.Fatal(err)
	}
	claim := h.write(t, source, record.Draft{Kind: record.KindFact, Body: []byte("the original claim")})
	h.fake.Advance(1)
	retraction, err := h.builder.Retract("shared/crew", 0, "wrong", nil, claim.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Write(retraction); err != nil {
		t.Fatal(err)
	}
	sealedClaim, _ := source.Log().Get(claim.ID)
	sealedRetraction, _ := source.Log().Get(retraction.ID)
	source.Close()

	dest, err := OpenSpace(t.TempDir(), "shared/crew", h.keys, h.entropy)
	if err != nil {
		t.Fatal(err)
	}
	defer dest.Close()
	cat := dest.Catalog()

	// Retraction first.
	if _, err := dest.Accept(sealedRetraction); err != nil {
		t.Fatal(err)
	}
	if pending := cat.PendingSupersessions(); len(pending) != 1 || pending[0] != claim.ID {
		t.Errorf("PendingSupersessions = %v, want the absent claim", pending)
	}

	// Then the claim it retracts.
	if _, err := dest.Accept(sealedClaim); err != nil {
		t.Fatal(err)
	}
	if cat.Live(claim.ID) {
		t.Fatal("the claim surfaced as live even though a retraction for it had already arrived")
	}
	if len(cat.PendingSupersessions()) != 0 {
		t.Errorf("the pending edge was not resolved: %v", cat.PendingSupersessions())
	}
}

func TestCatalogIndexesAndCounts(t *testing.T) {
	h := newHarness(t, "alpha", 14, "user/cory")
	s, err := OpenSpace(h.root, "user/cory", h.keys, h.entropy)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cat := s.Catalog()

	h.write(t, s, record.Draft{Kind: record.KindEpisode, Body: []byte("e1"), Tags: []string{"parse_ts"}})
	h.write(t, s, record.Draft{Kind: record.KindEpisode, Body: []byte("e2"), Tags: []string{"parse_ts", "flake"}})
	fact := h.write(t, s, record.Draft{Kind: record.KindFact, Body: []byte("f1"), Tags: []string{"parse_ts"}, Evidence: record.EvidenceObserved})

	if got := cat.CountsByKind(); got[record.KindEpisode] != 2 || got[record.KindFact] != 1 {
		t.Errorf("CountsByKind = %v", got)
	}
	if got := cat.LiveByTag("parse_ts", 0); len(got) != 3 {
		t.Errorf("LiveByTag = %d entries, want 3", len(got))
	}
	if got := cat.LiveByTag("parse_ts", 2); len(got) != 2 {
		t.Errorf("limit was not respected: %d entries", len(got))
	}
	if got := cat.LiveByKind(record.KindFact, 0); len(got) != 1 || got[0].ID != fact.ID {
		t.Errorf("LiveByKind = %v", got)
	}

	// Newest first, by HLC.
	byKind := cat.LiveByKind(record.KindEpisode, 0)
	if len(byKind) == 2 && byKind[0].HLC.Before(byKind[1].HLC) {
		t.Error("LiveByKind is not newest-first")
	}

	if got := cat.EmbedModels(); got["memmesh-hashembed-v1-384"] != 3 {
		t.Errorf("EmbedModels = %v", got)
	}
	if got := cat.Agents(); len(got) != 1 || got[h.builder.AgentID()] != 3 {
		t.Errorf("Agents = %v", got)
	}

	meta, ok := cat.Get(fact.ID)
	if !ok {
		t.Fatal("Get missed a record it holds")
	}
	if meta.Kind != record.KindFact || meta.Evidence != record.EvidenceObserved || meta.Bytes <= 0 {
		t.Errorf("meta is wrong: %+v", meta)
	}
}

func TestCatalogTracksRefsAndConflicts(t *testing.T) {
	h := newHarness(t, "alpha", 15, "shared/crew")
	s, err := OpenSpace(h.root, "shared/crew", h.keys, h.entropy)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	cat := s.Catalog()

	utc := h.write(t, s, record.Draft{Kind: record.KindFact, Body: []byte("assumes UTC"), Evidence: record.EvidenceObserved})
	local := h.write(t, s, record.Draft{Kind: record.KindFact, Body: []byte("assumes local time"), Evidence: record.EvidenceObserved})

	h.fake.Advance(1)
	conflict, err := h.builder.Conflict("shared/crew", 0, "contradictory timezone assumptions", nil, utc.ID, local.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write(conflict); err != nil {
		t.Fatal(err)
	}

	// Both sides must still be live: a conflict links, it does not supersede.
	if !cat.Live(utc.ID) || !cat.Live(local.ID) {
		t.Fatal("linking two records in a conflict suppressed them; siblings must both survive")
	}
	for _, id := range []ulid.ULID{utc.ID, local.ID} {
		got := cat.Conflicts(id)
		if len(got) != 1 || got[0].ID != conflict.ID {
			t.Errorf("Conflicts(%s) = %v", id, got)
		}
		if refs := cat.ReferencedBy(id); len(refs) != 1 || refs[0] != conflict.ID {
			t.Errorf("ReferencedBy(%s) = %v", id, refs)
		}
	}
}

func TestManagerDiscoversSpacesOnDisk(t *testing.T) {
	h := newHarness(t, "alpha", 16, "user/cory", "shared/crew", "agent/ag_one")
	mgr, err := NewManager(h.root, h.keys, h.entropy)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []record.SpaceID{"user/cory", "shared/crew", "agent/ag_one"} {
		s, err := mgr.Open(id)
		if err != nil {
			t.Fatal(err)
		}
		h.write(t, s, record.Draft{Kind: record.KindEpisode, Body: []byte("hello")})
	}
	if got := mgr.Spaces(); len(got) != 3 {
		t.Fatalf("Spaces = %v", got)
	}
	if got := mgr.Vectors(); len(got) != 3 {
		t.Errorf("Vectors covers %d spaces", len(got))
	}
	maxID := mgr.MaxLocalID("alpha")
	if maxID.IsZero() {
		t.Error("MaxLocalID is zero after writes")
	}
	mgr.Close()

	// A fresh Manager must find the same spaces from the filesystem alone, with no
	// configuration telling it they exist.
	reopened, err := NewManager(h.root, h.keys, h.entropy)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if got := reopened.Spaces(); len(got) != 3 {
		t.Errorf("a reopened manager found %v", got)
	}
	if reopened.MaxLocalID("alpha") != maxID {
		t.Error("MaxLocalID did not survive a restart; the id generator could regress")
	}
	if len(reopened.Stats()) != 3 {
		t.Errorf("Stats covers %d spaces", len(reopened.Stats()))
	}
}

func TestManifestGuardsAgainstAMisplacedDirectory(t *testing.T) {
	h := newHarness(t, "alpha", 17, "user/cory")
	l, err := OpenLog(h.root, "user/cory")
	if err != nil {
		t.Fatal(err)
	}
	l.Close()

	// Rewrite the manifest to claim a different space. Opening must refuse rather
	// than mixing two spaces' records into one log.
	path := filepath.Join(h.root, record.SpaceID("user/cory").Filename(), manifestName)
	if err := os.WriteFile(path, []byte("memmesh-log v1 space=shared/other\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenLog(h.root, "user/cory"); !errors.Is(err, ErrSpaceMismatch) {
		t.Fatalf("err = %v, want ErrSpaceMismatch", err)
	}
}

func TestClosedLogRefusesWork(t *testing.T) {
	h := newHarness(t, "alpha", 18, "user/cory")
	s, err := OpenSpace(h.root, "user/cory", h.keys, h.entropy)
	if err != nil {
		t.Fatal(err)
	}
	r := h.write(t, s, record.Draft{Kind: record.KindEpisode, Body: []byte("x")})
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("closing twice returned %v", err)
	}
	if _, err := s.Log().Get(r.ID); !errors.Is(err, ErrClosed) {
		t.Errorf("Get after close = %v, want ErrClosed", err)
	}
	if _, err := s.Log().Append(); !errors.Is(err, ErrClosed) {
		t.Errorf("Append after close = %v, want ErrClosed", err)
	}
}

func TestSpaceFilenameRoundTrip(t *testing.T) {
	for _, id := range []record.SpaceID{"user/cory", "shared/crew", "agent/ag_abc123"} {
		back, err := spaceFromFilename(id.Filename())
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if back != id {
			t.Errorf("%s round tripped to %s", id, back)
		}
	}
	if _, err := spaceFromFilename("not-a-space"); err == nil {
		t.Error("spaceFromFilename accepted a non-space directory name")
	}
}

func TestConcurrentAppendsAndReads(t *testing.T) {
	h := newHarness(t, "alpha", 19, "user/cory")
	s, err := OpenSpace(h.root, "user/cory", h.keys, h.entropy)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// The builder is per-agent and not concurrency-safe, so serialise record
	// construction and parallelise the store operations, which is exactly the
	// shape the daemon has.
	var sealed []*wire.SealedRecord
	for i := 0; i < 100; i++ {
		r := h.write(t, s, record.Draft{Kind: record.KindEpisode, Body: []byte(fmt.Sprintf("r%d", i))})
		got, _ := s.Log().Get(r.ID)
		sealed = append(sealed, got)
	}

	done := make(chan error, 8)
	for w := 0; w < 8; w++ {
		go func(w int) {
			for i := range sealed {
				if _, err := s.Log().Get(sealed[i].ID); err != nil {
					done <- err
					return
				}
				if _, err := s.Accept(sealed[i]); err != nil {
					done <- err
					return
				}
				s.Vector()
				s.Log().Count()
			}
			done <- nil
		}(w)
	}
	for w := 0; w < 8; w++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if s.Log().Count() != len(sealed) {
		t.Errorf("count = %d, want %d", s.Log().Count(), len(sealed))
	}
}
