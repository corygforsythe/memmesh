package wire

import (
	"bytes"
	"errors"
	"io"
	"math/rand"
	"testing"

	"github.com/coryforsythe/memmesh/internal/clock"
	"github.com/coryforsythe/memmesh/internal/crypto"
	"github.com/coryforsythe/memmesh/internal/hlc"
	"github.com/coryforsythe/memmesh/internal/record"
	"github.com/coryforsythe/memmesh/internal/ulid"
)

type detReader struct{ rng *rand.Rand }

func (d detReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(d.rng.Intn(256))
	}
	return len(p), nil
}

// testKeys is a minimal KeyProvider: one space, one epoch, no keyring.
type testKeys struct {
	keys    map[string]map[uint32]crypto.ContentKey
	current map[string]uint32
}

func newTestKeys(ent io.Reader, spaces ...string) *testKeys {
	tk := &testKeys{
		keys:    make(map[string]map[uint32]crypto.ContentKey),
		current: make(map[string]uint32),
	}
	for _, s := range spaces {
		k, err := crypto.GenerateContentKey(ent)
		if err != nil {
			panic(err)
		}
		tk.keys[s] = map[uint32]crypto.ContentKey{0: k}
		tk.current[s] = 0
	}
	return tk
}

func (t *testKeys) rotate(ent io.Reader, space string) uint32 {
	k, err := crypto.GenerateContentKey(ent)
	if err != nil {
		panic(err)
	}
	next := t.current[space] + 1
	t.keys[space][next] = k
	t.current[space] = next
	return next
}

func (t *testKeys) Key(space string, epoch uint32) (crypto.ContentKey, error) {
	byEpoch, ok := t.keys[space]
	if !ok {
		return crypto.ContentKey{}, crypto.ErrNoKey
	}
	k, ok := byEpoch[epoch]
	if !ok {
		return crypto.ContentKey{}, crypto.ErrNoKey
	}
	return k, nil
}

func (t *testKeys) CurrentEpoch(space string) (uint32, error) {
	e, ok := t.current[space]
	if !ok {
		return 0, crypto.ErrNoKey
	}
	return e, nil
}

func harness(t *testing.T, seed int64) (*record.Builder, *record.Signer, *testKeys, io.Reader) {
	t.Helper()
	ent := detReader{rng: rand.New(rand.NewSource(seed))}
	signer, err := record.GenerateSigner(ent)
	if err != nil {
		t.Fatal(err)
	}
	fake := clock.NewFake(1_757_700_000_000)
	b, err := record.NewBuilder(record.BuilderConfig{
		Node:        "alpha",
		Signer:      signer,
		IDs:         ulid.NewMonotonic(fake, ent),
		Stamps:      hlc.New(fake),
		AuthorModel: "claude-opus-5",
		EmbedModel:  "memmesh-hashembed-v1-384",
	})
	if err != nil {
		t.Fatal(err)
	}
	return b, signer, newTestKeys(ent, "shared/crew", "user/cory"), ent
}

func TestNegotiate(t *testing.T) {
	tests := []struct {
		name    string
		offered []uint8
		want    uint8
		wantErr bool
	}{
		{"exact match", []uint8{1}, 1, false},
		{"picks the highest common", []uint8{1, 2, 99}, 1, false},
		{"ignores versions above this build", []uint8{7, 8}, 0, true},
		{"ignores zero", []uint8{0}, 0, true},
		{"empty offer", nil, 0, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Negotiate(tc.offered)
			if tc.wantErr {
				if !errors.Is(err, ErrVersion) {
					t.Fatalf("err = %v, want ErrVersion", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
	if got := SupportedVersions(); len(got) == 0 || got[0] != Version {
		t.Errorf("SupportedVersions = %v, want the newest first", got)
	}
}

func TestPaddingLandsOnBuckets(t *testing.T) {
	buckets := Buckets()
	for _, n := range []int{0, 1, 100, 200, 250, 255, 256, 257, 1000, 4000, 20000, 65000, 70000, 200000} {
		data := bytes.Repeat([]byte{0xab}, n)
		padded, err := pad(TransformNone, data)
		if err != nil {
			t.Fatalf("pad(%d): %v", n, err)
		}

		onBucket := false
		for _, b := range buckets {
			if len(padded) == b {
				onBucket = true
			}
		}
		if !onBucket && len(padded)%bucketStep != 0 {
			t.Errorf("pad(%d) produced %d bytes, which is neither a bucket nor a whole step", n, len(padded))
		}
		if len(padded) < n {
			t.Errorf("pad(%d) produced %d bytes", n, len(padded))
		}

		transform, back, err := unpad(padded)
		if err != nil {
			t.Fatalf("unpad(%d): %v", n, err)
		}
		if transform != TransformNone {
			t.Errorf("transform = %s", transform)
		}
		if !bytes.Equal(back, data) {
			t.Errorf("round trip lost data at n=%d", n)
		}
	}
}

// TestPaddingHidesSmallSizeDifferences is the property §3.4 asks for: two
// payloads of different length in the same bucket must be indistinguishable by
// size.
func TestPaddingHidesSmallSizeDifferences(t *testing.T) {
	short, err := pad(TransformNone, []byte("parse_ts assumes UTC"))
	if err != nil {
		t.Fatal(err)
	}
	long, err := pad(TransformNone, bytes.Repeat([]byte("x"), 200))
	if err != nil {
		t.Fatal(err)
	}
	if len(short) != len(long) {
		t.Errorf("payloads of 20 and 200 bytes padded to %d and %d", len(short), len(long))
	}
}

func TestUnpadRejectsCorruptPadding(t *testing.T) {
	padded, err := pad(TransformNone, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		mutis func([]byte) []byte
	}{
		{"non-zero padding", func(b []byte) []byte { b[len(b)-1] = 1; return b }},
		{"length beyond the buffer", func(b []byte) []byte { b[1] = 0xff; b[2] = 0xff; return b }},
		{"not a bucket size", func(b []byte) []byte { return b[:len(b)-1] }},
		{"empty", func(b []byte) []byte { return nil }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cp := append([]byte(nil), padded...)
			if _, _, err := unpad(tc.mutis(cp)); err == nil {
				t.Fatal("unpad accepted corrupt input")
			}
		})
	}
}

func TestSealOpenRecordRoundTrip(t *testing.T) {
	b, _, keys, ent := harness(t, 1)
	r, err := b.Build(record.Draft{
		Space: "shared/crew", Kind: record.KindFact,
		Body: []byte("parse_ts assumes UTC input"), Evidence: record.EvidenceObserved,
	})
	if err != nil {
		t.Fatal(err)
	}

	sealed, err := SealRecord(keys, r, TransformNone, ent)
	if err != nil {
		t.Fatal(err)
	}
	if sealed.Space != r.Space || sealed.Epoch != r.Epoch {
		t.Errorf("envelope metadata is wrong: %+v", sealed)
	}
	if bytes.Contains(sealed.Blob, []byte("parse_ts")) {
		t.Fatal("the record body appears in the sealed payload in the clear")
	}
	if sealed.Len() != len(sealed.Blob) {
		t.Error("Len disagrees with the blob length")
	}

	back, err := OpenRecord(keys, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if back.ID != r.ID || !bytes.Equal(back.Body, r.Body) || back.Evidence != r.Evidence {
		t.Error("the record did not survive the round trip")
	}
	if err := record.Verify(back); err != nil {
		t.Errorf("the opened record does not verify: %v", err)
	}
}

func TestSealedPayloadsAreBucketed(t *testing.T) {
	b, _, keys, ent := harness(t, 2)
	// All three bodies are small enough that the whole canonical record still
	// fits the 256-byte bucket, so all three must seal to the same size. A body
	// large enough to cross into the next bucket legitimately shows a different
	// size; padding hides differences within a bucket, not across them.
	sizes := make(map[int]bool)
	for _, body := range []string{"a", "a slightly longer body", string(bytes.Repeat([]byte("x"), 40))} {
		r, err := b.Build(record.Draft{Space: "shared/crew", Kind: record.KindEpisode, Body: []byte(body)})
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := SealRecord(keys, r, TransformNone, ent)
		if err != nil {
			t.Fatal(err)
		}
		sizes[sealed.Len()] = true
	}
	if len(sizes) != 1 {
		t.Errorf("three small records produced %d distinct sealed sizes; padding is not hiding length", len(sizes))
	}
}

func TestOpenRecordRejectsARelabelledEnvelope(t *testing.T) {
	b, _, keys, ent := harness(t, 3)
	r, err := b.Build(record.Draft{Space: "shared/crew", Kind: record.KindEpisode, Body: []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := SealRecord(keys, r, TransformNone, ent)
	if err != nil {
		t.Fatal(err)
	}

	// Relabelling the envelope changes the additional data, so the payload no
	// longer authenticates. That is what stops a relay moving a frame between
	// spaces.
	for _, tc := range []struct {
		name  string
		mutis func(*SealedRecord)
	}{
		{"space", func(s *SealedRecord) { s.Space = "user/cory" }},
		{"epoch", func(s *SealedRecord) { s.Epoch++ }},
		{"record id", func(s *SealedRecord) { s.ID = ulid.MustParse("01J000000000000000000000AA") }},
		{"author node", func(s *SealedRecord) { s.AuthorNode = "impostor" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			forged := *sealed
			tc.mutis(&forged)
			if _, err := OpenRecord(keys, &forged); err == nil {
				t.Fatalf("OpenRecord accepted a payload with a relabelled %s", tc.name)
			}
		})
	}
}

func TestSealRecordNeedsAKey(t *testing.T) {
	b, _, keys, ent := harness(t, 4)
	r, err := b.Build(record.Draft{Space: "shared/other", Kind: record.KindEpisode, Body: []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SealRecord(keys, r, TransformNone, ent); !errors.Is(err, crypto.ErrNoKey) {
		t.Fatalf("err = %v, want crypto.ErrNoKey", err)
	}
}

func TestUnsupportedTransformIsRefused(t *testing.T) {
	b, _, keys, ent := harness(t, 5)
	r, err := b.Build(record.Draft{Space: "shared/crew", Kind: record.KindEpisode, Body: []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SealRecord(keys, r, Transform(9), ent); !errors.Is(err, ErrTransform) {
		t.Fatalf("err = %v, want ErrTransform", err)
	}

	// A peer that already applied an unknown transform must be refused on open
	// too, rather than having bytes stored that this node can never interpret.
	canonical, err := r.Encode()
	if err != nil {
		t.Fatal(err)
	}
	padded, err := pad(TransformNone, canonical)
	if err != nil {
		t.Fatal(err)
	}
	padded[0] = 9 // claim a future compression stage
	key, err := keys.Key("shared/crew", 0)
	if err != nil {
		t.Fatal(err)
	}
	envelope := &SealedRecord{Space: "shared/crew", ID: r.ID, AuthorNode: r.AuthorNode, Epoch: 0}
	blob, err := crypto.SealRandom(&key, padded, envelope.aad(), ent)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Blob = blob
	if _, err := OpenRecord(keys, envelope); !errors.Is(err, ErrTransform) {
		t.Fatalf("err = %v, want ErrTransform", err)
	}
}

func TestSealedPayloadSurvivesEpochRotation(t *testing.T) {
	b, _, keys, ent := harness(t, 6)
	old, err := b.Build(record.Draft{Space: "shared/crew", Kind: record.KindEpisode, Body: []byte("before"), Epoch: 0})
	if err != nil {
		t.Fatal(err)
	}
	sealedOld, err := SealRecord(keys, old, TransformNone, ent)
	if err != nil {
		t.Fatal(err)
	}

	next := keys.rotate(ent, "shared/crew")
	fresh, err := b.Build(record.Draft{Space: "shared/crew", Kind: record.KindEpisode, Body: []byte("after"), Epoch: next})
	if err != nil {
		t.Fatal(err)
	}
	sealedNew, err := SealRecord(keys, fresh, TransformNone, ent)
	if err != nil {
		t.Fatal(err)
	}

	// Both open, because the node retained the old epoch key. Rotation stops new
	// writes reaching a removed member; it does not destroy readable history.
	for _, s := range []*SealedRecord{sealedOld, sealedNew} {
		if _, err := OpenRecord(keys, s); err != nil {
			t.Errorf("epoch %d payload did not open: %v", s.Epoch, err)
		}
	}
}

func TestFrameRoundTripThroughAStream(t *testing.T) {
	b, signer, keys, ent := harness(t, 7)
	r, err := b.Build(record.Draft{Space: "shared/crew", Kind: record.KindFact, Body: []byte("a claim")})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := SealRecord(keys, r, TransformNone, ent)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := EncodeBundle([]*SealedRecord{sealed})
	if err != nil {
		t.Fatal(err)
	}
	f, err := NewBundleFrame(MsgRecords, Version, "shared/crew", bundle, signer)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := WriteFrame(&buf, f); err != nil {
		t.Fatal(err)
	}
	got, err := ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != MsgRecords || got.Space != "shared/crew" || got.Sender != signer.AgentID() {
		t.Errorf("frame header lost in transit: %+v", got)
	}
	entries, err := DecodeBundle(got.Space, got.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !bytes.Equal(entries[0].Blob, sealed.Blob) {
		t.Fatal("the bundle did not survive the round trip byte for byte")
	}
	back, err := OpenRecord(keys, entries[0])
	if err != nil {
		t.Fatal(err)
	}
	if back.ID != r.ID {
		t.Error("wrong record came out the other end")
	}
}

func TestMultipleFramesOnOneStream(t *testing.T) {
	_, signer, _, _ := harness(t, 8)
	var buf bytes.Buffer
	for i := 0; i < 5; i++ {
		l := &Liveness{Nonce: uint64(i), WallMillis: 1000 + uint64(i)}
		f, err := NewControlFrame(MsgPing, Version, l.Encode(), signer)
		if err != nil {
			t.Fatal(err)
		}
		if err := WriteFrame(&buf, f); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 5; i++ {
		f, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		l, err := DecodeLiveness(f.Payload)
		if err != nil {
			t.Fatal(err)
		}
		if l.Nonce != uint64(i) {
			t.Errorf("frame %d carries nonce %d", i, l.Nonce)
		}
	}
	if _, err := ReadFrame(&buf); !errors.Is(err, io.EOF) {
		t.Errorf("err = %v, want io.EOF at the end of the stream", err)
	}
}

func TestFrameSignatureCoversHeaderAndPayload(t *testing.T) {
	_, signer, _, _ := harness(t, 9)
	l := &Liveness{Nonce: 7, WallMillis: 42}
	f, err := NewControlFrame(MsgPing, Version, l.Encode(), signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Verify(); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		mutis func(*Frame)
	}{
		{"type", func(f *Frame) { f.Type = MsgPong }},
		{"payload", func(f *Frame) { f.Payload[0] ^= 1 }},
		{"sender", func(f *Frame) { f.Sender[0] ^= 1 }},
		{"signature", func(f *Frame) { f.Sig[0] ^= 1 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cp := *f
			cp.Payload = append([]byte(nil), f.Payload...)
			tc.mutis(&cp)
			if err := cp.Verify(); !errors.Is(err, ErrBadFrameSignature) {
				t.Fatalf("err = %v, want ErrBadFrameSignature", err)
			}
		})
	}
}

func TestFrameSpaceIsCoveredBySignature(t *testing.T) {
	b, signer, keys, ent := harness(t, 10)
	r, err := b.Build(record.Draft{Space: "shared/crew", Kind: record.KindEpisode, Body: []byte("x")})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := SealRecord(keys, r, TransformNone, ent)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := EncodeBundle([]*SealedRecord{sealed})
	if err != nil {
		t.Fatal(err)
	}
	f, err := NewBundleFrame(MsgRecords, Version, "shared/crew", bundle, signer)
	if err != nil {
		t.Fatal(err)
	}
	f.Space = "user/cory"
	if err := f.Verify(); !errors.Is(err, ErrBadFrameSignature) {
		t.Fatalf("relabelling the space left the signature valid: %v", err)
	}
}

func TestFrameValidationRules(t *testing.T) {
	_, signer, _, _ := harness(t, 11)
	tests := []struct {
		name  string
		frame Frame
	}{
		{"unknown type", Frame{Version: Version, Type: MsgType(200)}},
		{"bad version", Frame{Version: 99, Type: MsgPing}},
		{"control frame naming a space", Frame{Version: Version, Type: MsgPing, Space: "user/cory"}},
		{"control frame naming an epoch", Frame{Version: Version, Type: MsgPing, Epoch: 3}},
		{"meta frame with no space", Frame{Version: Version, Type: MsgWant}},
		{"bundle with a header epoch", Frame{Version: Version, Type: MsgRecords, Space: "user/cory", Epoch: 2}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.frame
			if err := f.Sign(signer); err == nil {
				t.Fatal("Sign accepted an invalid frame")
			}
			if _, err := f.Marshal(); err == nil {
				t.Fatal("Marshal accepted an invalid frame")
			}
		})
	}

	if _, err := NewControlFrame(MsgRecords, Version, nil, signer); err == nil {
		t.Error("NewControlFrame accepted a bundle type")
	}
	if _, err := NewMetaFrame(MsgPing, Version, "user/cory", 0, nil, signer); err == nil {
		t.Error("NewMetaFrame accepted a control type")
	}
	if _, err := NewBundleFrame(MsgWant, Version, "user/cory", nil, signer); err == nil {
		t.Error("NewBundleFrame accepted a meta type")
	}
}

func TestReadFrameRejectsOversizeAnnouncements(t *testing.T) {
	// A peer announcing a huge frame must be refused before the allocation, not
	// after.
	buf := bytes.NewBuffer([]byte{0xff, 0xff, 0xff, 0xff})
	if _, err := ReadFrame(buf); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge", err)
	}

	short := bytes.NewBuffer([]byte{0, 0, 0, 3, 1, 2, 3})
	if _, err := ReadFrame(short); !errors.Is(err, ErrMalformed) {
		t.Fatalf("err = %v, want ErrMalformed", err)
	}
}

func TestReadFrameRejectsAnUnverifiedFrame(t *testing.T) {
	_, signer, _, _ := harness(t, 12)
	f, err := NewControlFrame(MsgPing, Version, (&Liveness{Nonce: 1}).Encode(), signer)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := f.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 1 // corrupt the signature

	if _, err := ReadFrame(bytes.NewReader(raw)); !errors.Is(err, ErrBadFrameSignature) {
		t.Fatalf("err = %v, want ErrBadFrameSignature: the reader is the enforcement point", err)
	}
}

func TestHelloRoundTrip(t *testing.T) {
	in := &Hello{
		Versions:   SupportedVersions(),
		Node:       "alpha",
		Software:   "memd/0.1.0",
		WallMillis: 1_757_700_000_000,
		Spaces:     []record.SpaceID{"user/cory", "shared/crew"},
		Relaying:   true,
		EmbedModel: "memmesh-hashembed-v1-384",
	}
	got, err := DecodeHello(in.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if got.Node != in.Node || got.Software != in.Software || got.WallMillis != in.WallMillis {
		t.Errorf("identity fields lost: %+v", got)
	}
	if !got.Relaying || got.EmbedModel != in.EmbedModel {
		t.Errorf("relay flag or embed model lost: %+v", got)
	}
	if len(got.Spaces) != 2 || got.Spaces[0] != "user/cory" {
		t.Errorf("spaces lost: %v", got.Spaces)
	}
	if len(got.Versions) != len(in.Versions) {
		t.Errorf("versions lost: %v", got.Versions)
	}
}

func TestHelloRejectsJunk(t *testing.T) {
	valid := (&Hello{Versions: []uint8{1}, Node: "alpha"}).Encode()
	for _, bad := range [][]byte{
		nil,
		valid[:len(valid)-1],
		append(append([]byte(nil), valid...), 0),
		(&Hello{Versions: []uint8{1}, Node: "has spaces"}).Encode(),
	} {
		if _, err := DecodeHello(bad); err == nil {
			t.Errorf("DecodeHello accepted %q", bad)
		}
	}
}

func TestVectorsRoundTripAndDeterminism(t *testing.T) {
	vv1 := record.NewVersionVector()
	vv1.Observe("alpha", ulid.MustParse("01J0000000000000000000000A"))
	vv1.Observe("beta", ulid.MustParse("01J0000000000000000000000B"))
	vv2 := record.NewVersionVector()
	vv2.Observe("gamma", ulid.MustParse("01J0000000000000000000000C"))

	in := &Vectors{Vectors: map[record.SpaceID]record.VersionVector{
		"shared/crew": vv1,
		"user/cory":   vv2,
	}}

	first := in.Encode()
	for i := 0; i < 20; i++ {
		if !bytes.Equal(in.Encode(), first) {
			t.Fatal("Vectors.Encode is not deterministic; map iteration order is leaking")
		}
	}

	got, err := DecodeVectors(first)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Vectors) != 2 {
		t.Fatalf("got %d spaces", len(got.Vectors))
	}
	if !got.Vectors["shared/crew"].Equal(vv1) || !got.Vectors["user/cory"].Equal(vv2) {
		t.Error("vectors did not survive the round trip")
	}
}

func TestWantRoundTrip(t *testing.T) {
	in := &Want{
		Limit: 500,
		Ranges: map[record.NodeID]record.Range{
			"alpha": {After: ulid.MustParse("01J0000000000000000000000A"), Through: ulid.MustParse("01J0000000000000000000000Z")},
			"beta":  {Through: ulid.MustParse("01J0000000000000000000000B")},
		},
	}
	first := in.Encode()
	for i := 0; i < 20; i++ {
		if !bytes.Equal(in.Encode(), first) {
			t.Fatal("Want.Encode is not deterministic")
		}
	}
	got, err := DecodeWant(first)
	if err != nil {
		t.Fatal(err)
	}
	if got.Limit != 500 || len(got.Ranges) != 2 {
		t.Fatalf("got %+v", got)
	}
	if got.Ranges["alpha"] != in.Ranges["alpha"] || got.Ranges["beta"] != in.Ranges["beta"] {
		t.Error("ranges did not survive the round trip")
	}

	// A range that ends before it starts is nonsense and must be refused.
	bad := &Want{Ranges: map[record.NodeID]record.Range{
		"alpha": {After: ulid.MustParse("01J0000000000000000000000Z"), Through: ulid.MustParse("01J0000000000000000000000A")},
	}}
	if _, err := DecodeWant(bad.Encode()); !errors.Is(err, ErrMalformed) {
		t.Errorf("err = %v, want ErrMalformed", err)
	}
}

func TestBundleRoundTripWithMixedEpochs(t *testing.T) {
	b, _, keys, ent := harness(t, 13)
	var entries []*SealedRecord
	for i, epoch := range []uint32{0, 0, 1} {
		if epoch == 1 && keys.current["shared/crew"] == 0 {
			keys.rotate(ent, "shared/crew")
		}
		r, err := b.Build(record.Draft{
			Space: "shared/crew", Kind: record.KindEpisode,
			Body: []byte{byte('a' + i)}, Epoch: epoch,
		})
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := SealRecord(keys, r, TransformNone, ent)
		if err != nil {
			t.Fatal(err)
		}
		entries = append(entries, sealed)
	}

	encoded, err := EncodeBundle(entries)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeBundle("shared/crew", encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(entries) {
		t.Fatalf("got %d entries, want %d", len(got), len(entries))
	}
	for i := range got {
		if got[i].Epoch != entries[i].Epoch || !bytes.Equal(got[i].Blob, entries[i].Blob) {
			t.Fatalf("entry %d changed in the round trip", i)
		}
		if _, err := OpenRecord(keys, got[i]); err != nil {
			t.Errorf("entry %d (epoch %d) did not open: %v", i, got[i].Epoch, err)
		}
	}
}

func TestBundleRejectsJunk(t *testing.T) {
	if _, err := DecodeBundle("user/cory", nil); err == nil {
		t.Error("DecodeBundle accepted an empty payload")
	}
	// A count far larger than the payload can hold must be refused up front.
	huge := append([]byte{0xff, 0xff, 0xff, 0x7f}, 0)
	if _, err := DecodeBundle("user/cory", huge); err == nil {
		t.Error("DecodeBundle accepted an implausible entry count")
	}
	if _, err := EncodeBundle(make([]*SealedRecord, MaxBundleEntries+1)); !errors.Is(err, ErrTooLarge) {
		t.Error("EncodeBundle accepted too many entries")
	}
}

func TestLivenessAndErrorRoundTrip(t *testing.T) {
	l := &Liveness{Nonce: 9, WallMillis: 1_757_700_000_000, HLC: hlc.HLC{Wall: 1_757_700_000_001, Counter: 4}}
	gotL, err := DecodeLiveness(l.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if *gotL != *l {
		t.Errorf("liveness round trip: got %+v, want %+v", gotL, l)
	}

	e := &ErrorPayload{Code: ErrCodeNoKey, Message: "space shared/crew is relayed on this node"}
	gotE, err := DecodeError(e.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if *gotE != *e {
		t.Errorf("error round trip: got %+v, want %+v", gotE, e)
	}
}

func TestSealPayloadRoundTrip(t *testing.T) {
	_, _, keys, ent := harness(t, 14)
	vv := record.NewVersionVector()
	vv.Observe("alpha", ulid.MustParse("01J0000000000000000000000A"))
	plain := (&Vectors{Vectors: map[record.SpaceID]record.VersionVector{"shared/crew": vv}}).Encode()

	sealed, err := SealPayload(keys, "shared/crew", 0, plain, TransformNone, ent)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenPayload(keys, "shared/crew", 0, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Error("sealed control payload did not round trip")
	}
	if _, err := OpenPayload(keys, "user/cory", 0, sealed); err == nil {
		t.Error("a control payload opened under the wrong space")
	}
}

func TestMsgTypeClasses(t *testing.T) {
	tests := []struct {
		typ  MsgType
		want PayloadClass
	}{
		{MsgHello, ClassPlain},
		{MsgHelloAck, ClassPlain},
		{MsgPing, ClassPlain},
		{MsgPong, ClassPlain},
		{MsgError, ClassPlain},
		{MsgVectors, ClassPlain},
		{MsgWant, ClassMeta},
		{MsgRecords, ClassBundle},
		{MsgBackfillChunk, ClassBundle},
	}
	for _, tc := range tests {
		if got := tc.typ.Class(); got != tc.want {
			t.Errorf("%s class = %d, want %d", tc.typ, got, tc.want)
		}
		if !tc.typ.Known() {
			t.Errorf("%s is not Known", tc.typ)
		}
	}
	if MsgType(250).Known() {
		t.Error("an undefined type reports as Known")
	}
	if TransformNone.Supported() != true || Transform(200).Supported() {
		t.Error("Transform.Supported is wrong")
	}
	if TransformNone.String() != "none" {
		t.Errorf("TransformNone renders as %q", TransformNone)
	}
}
