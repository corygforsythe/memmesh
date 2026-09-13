package record

import (
	"bytes"
	"errors"
	"math/rand"
	"strings"
	"testing"

	"github.com/coryforsythe/memmesh/internal/clock"
	"github.com/coryforsythe/memmesh/internal/hlc"
	"github.com/coryforsythe/memmesh/internal/ulid"
)

// deterministicEntropy makes key generation and ULIDs reproducible.
type deterministicEntropy struct{ rng *rand.Rand }

func (d deterministicEntropy) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(d.rng.Intn(256))
	}
	return len(p), nil
}

func newHarness(t *testing.T, seed int64) (*Builder, *clock.Fake, *Signer) {
	t.Helper()
	ent := deterministicEntropy{rng: rand.New(rand.NewSource(seed))}
	signer, err := GenerateSigner(ent)
	if err != nil {
		t.Fatal(err)
	}
	fake := clock.NewFake(1_757_700_000_000)
	b, err := NewBuilder(BuilderConfig{
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
	return b, fake, signer
}

func sampleDraft() Draft {
	ctx := NewVersionVector()
	ctx.Observe("beta", ulid.MustParse("01J0000000000000000000000B"))
	ctx.Observe("alpha", ulid.MustParse("01J0000000000000000000000A"))
	return Draft{
		Space:     "shared/crew",
		Kind:      KindFact,
		Body:      []byte("parse_ts assumes UTC input"),
		Tags:      []string{"parse_ts", "timezones"},
		Evidence:  EvidenceObserved,
		CausalCtx: ctx,
		Epoch:     3,
	}
}

func TestBuildProducesAValidSignedRecord(t *testing.T) {
	b, _, signer := newHarness(t, 1)
	r, err := b.Build(sampleDraft())
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if err := Verify(r); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if r.AuthorAgent != signer.AgentID() {
		t.Error("author agent was not stamped")
	}
	if r.AuthorNode != "alpha" {
		t.Errorf("author node = %q", r.AuthorNode)
	}
	if r.AuthorModel != "claude-opus-5" || r.EmbedModel != "memmesh-hashembed-v1-384" {
		t.Error("model ids were not stamped")
	}
	if r.HLC.IsZero() {
		t.Error("hlc was not stamped")
	}
}

func TestBuildDefaultsEvidenceToAsserted(t *testing.T) {
	b, _, _ := newHarness(t, 2)
	d := sampleDraft()
	d.Evidence = ""
	r, err := b.Build(d)
	if err != nil {
		t.Fatal(err)
	}
	if r.Evidence != EvidenceAsserted {
		t.Errorf("evidence = %q, want asserted: an unsourced claim must not default to the highest rank", r.Evidence)
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	b, _, _ := newHarness(t, 3)
	tests := []struct {
		name  string
		mutis func(*Draft)
	}{
		{"full", func(*Draft) {}},
		{"no tags", func(d *Draft) { d.Tags = nil }},
		{"no causal context", func(d *Draft) { d.CausalCtx = nil }},
		{"empty body", func(d *Draft) { d.Body = nil }},
		{"zero epoch", func(d *Draft) { d.Epoch = 0 }},
		{"large body", func(d *Draft) { d.Body = bytes.Repeat([]byte("x"), 100_000) }},
		{"many tags", func(d *Draft) {
			d.Tags = nil
			for i := 0; i < MaxTags; i++ {
				d.Tags = append(d.Tags, string(rune('a'+i%26))+strings.Repeat("z", i%7))
			}
		}},
		{"unicode body", func(d *Draft) { d.Body = []byte("héllo — ünïcode ✓ 日本語") }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := sampleDraft()
			tc.mutis(&d)
			r, err := b.Build(d)
			if err != nil {
				t.Fatal(err)
			}
			enc, err := r.Encode()
			if err != nil {
				t.Fatal(err)
			}
			back, err := DecodeVerified(enc)
			if err != nil {
				t.Fatalf("DecodeVerified: %v", err)
			}
			reenc, err := back.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(enc, reenc) {
				t.Fatal("re-encoding a decoded record produced different bytes")
			}
			if !back.CausalCtx.Equal(r.CausalCtx) {
				t.Errorf("causal ctx lost: %s vs %s", back.CausalCtx, r.CausalCtx)
			}
			if !bytes.Equal(back.Body, r.Body) {
				t.Error("body lost")
			}
			if back.Epoch != r.Epoch {
				t.Errorf("epoch = %d, want %d", back.Epoch, r.Epoch)
			}
		})
	}
}

func TestCanonicalEncodingIsStable(t *testing.T) {
	b, _, _ := newHarness(t, 4)
	r, err := b.Build(sampleDraft())
	if err != nil {
		t.Fatal(err)
	}
	first, err := r.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		again, err := r.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first, again) {
			t.Fatal("Canonical is not deterministic across calls")
		}
	}
	if first[0] != FormatVersion {
		t.Errorf("first byte = %d, want the format version %d", first[0], FormatVersion)
	}
}

func TestNormalizeSortsAndDeduplicates(t *testing.T) {
	idA := ulid.MustParse("01J000000000000000000000AA")
	idB := ulid.MustParse("01J000000000000000000000BB")
	r := &Record{
		Tags:       []string{"zeta", "alpha", "zeta", "mid"},
		Supersedes: []ulid.ULID{idB, idA, idB},
	}
	r.Normalize()
	if got := strings.Join(r.Tags, ","); got != "alpha,mid,zeta" {
		t.Errorf("tags = %q", got)
	}
	if len(r.Supersedes) != 2 || r.Supersedes[0] != idA || r.Supersedes[1] != idB {
		t.Errorf("supersedes = %v", r.Supersedes)
	}

	// Two records differing only in input order must encode identically, or the
	// same logical record would have two signatures.
	b, _, _ := newHarness(t, 5)
	d1 := sampleDraft()
	d1.Tags = []string{"a", "b", "c"}
	d2 := sampleDraft()
	d2.Tags = []string{"c", "a", "b", "a"}

	r1, err := b.Build(d1)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := b.Build(d2)
	if err != nil {
		t.Fatal(err)
	}
	// Neutralize the fields that legitimately differ between two writes.
	r2.ID, r2.HLC = r1.ID, r1.HLC
	c1, _ := r1.Canonical()
	c2, _ := r2.Canonical()
	if !bytes.Equal(c1, c2) {
		t.Error("tag input order leaked into the canonical encoding")
	}
}

func TestDecodeRejectsNonCanonicalOrdering(t *testing.T) {
	b, _, signer := newHarness(t, 6)
	d := sampleDraft()
	d.Tags = []string{"aaa", "bbb"}
	r, err := b.Build(d)
	if err != nil {
		t.Fatal(err)
	}

	// Hand-build an encoding with the tags reversed and sign it honestly. The
	// signature is valid over those bytes; the decoder must still refuse them,
	// because otherwise one record has two verifiable encodings.
	r.Tags = []string{"bbb", "aaa"}
	raw := r.appendCanonical(nil)
	sig := signer.SignBytes(SignDomain, raw)
	enc := append(raw, sig...)

	if _, err := Decode(enc); !errors.Is(err, ErrNotCanonical) {
		t.Fatalf("err = %v, want ErrNotCanonical", err)
	}
}

func TestDecodeRejectsNonMinimalVarint(t *testing.T) {
	b, _, _ := newHarness(t, 7)
	r, err := b.Build(sampleDraft())
	if err != nil {
		t.Fatal(err)
	}
	enc, err := r.Encode()
	if err != nil {
		t.Fatal(err)
	}

	// The space length prefix sits right after the version byte and the 16-byte
	// id. Rewrite it as a two-byte overlong varint encoding the same value.
	at := 1 + ulid.Size
	if enc[at] >= 0x80 {
		t.Skip("space length is already multi-byte")
	}
	bad := append([]byte{}, enc[:at]...)
	bad = append(bad, enc[at]|0x80, 0x00)
	bad = append(bad, enc[at+1:]...)

	if _, err := Decode(bad); !errors.Is(err, ErrNotCanonical) {
		t.Fatalf("err = %v, want ErrNotCanonical", err)
	}
}

func TestDecodeRejectsTrailingBytes(t *testing.T) {
	b, _, _ := newHarness(t, 8)
	r, _ := b.Build(sampleDraft())
	enc, _ := r.Encode()

	// Insert a junk byte just before the signature so the signature stays the
	// right length and the canonical section is the part that is wrong.
	bad := append([]byte{}, enc[:len(enc)-SigSize]...)
	bad = append(bad, 0x00)
	bad = append(bad, enc[len(enc)-SigSize:]...)

	if _, err := Decode(bad); !errors.Is(err, ErrNotCanonical) {
		t.Fatalf("err = %v, want ErrNotCanonical", err)
	}
}

func TestDecodeRejectsWrongFormatVersion(t *testing.T) {
	b, _, _ := newHarness(t, 9)
	r, _ := b.Build(sampleDraft())
	enc, _ := r.Encode()
	enc[0] = FormatVersion + 1
	if _, err := Decode(enc); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("err = %v, want ErrUnsupportedVersion", err)
	}
}

func TestDecodeRejectsTruncation(t *testing.T) {
	b, _, _ := newHarness(t, 10)
	r, _ := b.Build(sampleDraft())
	enc, _ := r.Encode()
	for _, cut := range []int{0, 1, 10, SigSize, SigSize + 1, len(enc) - 5} {
		if _, err := Decode(enc[:cut]); err == nil {
			t.Errorf("Decode accepted %d of %d bytes", cut, len(enc))
		}
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	b, _, _ := newHarness(t, 11)
	r, err := b.Build(sampleDraft())
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		mutis func(*Record)
	}{
		{"body", func(r *Record) { r.Body = []byte("parse_ts assumes local time") }},
		{"space", func(r *Record) { r.Space = "shared/other" }},
		{"evidence", func(r *Record) { r.Evidence = EvidenceDerived }},
		{"epoch", func(r *Record) { r.Epoch = 99 }},
		{"hlc", func(r *Record) { r.HLC.Counter++ }},
		{"tags", func(r *Record) { r.Tags = append(r.Tags, "injected") }},
		{"causal ctx", func(r *Record) {
			r.CausalCtx = r.CausalCtx.Clone()
			r.CausalCtx.Observe("gamma", ulid.MustParse("01J0000000000000000000000C"))
		}},
		{"author node", func(r *Record) { r.AuthorNode = "impostor" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tampered := r.Clone()
			tc.mutis(tampered)
			if err := Verify(tampered); !errors.Is(err, ErrBadSignature) {
				t.Fatalf("Verify err = %v, want ErrBadSignature", err)
			}
		})
	}
}

func TestVerifyRejectsASubstitutedAgentKey(t *testing.T) {
	b, _, _ := newHarness(t, 12)
	r, _ := b.Build(sampleDraft())

	other, err := GenerateSigner(deterministicEntropy{rng: rand.New(rand.NewSource(999))})
	if err != nil {
		t.Fatal(err)
	}
	forged := r.Clone()
	forged.AuthorAgent = other.AgentID()
	if err := Verify(forged); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature", err)
	}
}

func TestSignatureDomainsAreSeparated(t *testing.T) {
	b, _, signer := newHarness(t, 13)
	r, _ := b.Build(sampleDraft())
	canonical, _ := r.Canonical()

	// A signature made under the frame domain must not verify as a record
	// signature over the same bytes, and vice versa.
	frameSig := signer.SignBytes(FrameSignDomain, canonical)
	crossed := r.Clone()
	copy(crossed.Sig[:], frameSig)
	if err := Verify(crossed); !errors.Is(err, ErrBadSignature) {
		t.Errorf("a frame-domain signature verified as a record signature")
	}
	if VerifyBytes(signer.AgentID(), FrameSignDomain, canonical, r.Sig[:]) {
		t.Errorf("a record-domain signature verified under the frame domain")
	}
	if !VerifyBytes(signer.AgentID(), FrameSignDomain, canonical, frameSig) {
		t.Errorf("a frame-domain signature failed under its own domain")
	}
}

func TestValidateRejectsStructuralProblems(t *testing.T) {
	b, _, _ := newHarness(t, 14)
	good, _ := b.Build(sampleDraft())

	tests := []struct {
		name  string
		mutis func(*Record)
	}{
		{"zero id", func(r *Record) { r.ID = ulid.Zero }},
		{"bad space class", func(r *Record) { r.Space = "team/crew" }},
		{"nested space path", func(r *Record) { r.Space = "shared/a/b" }},
		{"empty space", func(r *Record) { r.Space = "" }},
		{"bad node", func(r *Record) { r.AuthorNode = "has spaces" }},
		{"empty node", func(r *Record) { r.AuthorNode = "" }},
		{"zero agent", func(r *Record) { r.AuthorAgent = ZeroAgent }},
		{"unknown kind", func(r *Record) { r.Kind = "musing" }},
		{"unknown evidence", func(r *Record) { r.Evidence = "vibes" }},
		{"empty tag", func(r *Record) { r.Tags = []string{""} }},
		{"oversize body", func(r *Record) { r.Body = bytes.Repeat([]byte("x"), MaxBodyBytes+1) }},
		{"self supersession", func(r *Record) { r.Supersedes = []ulid.ULID{r.ID} }},
		{"zero supersedes entry", func(r *Record) { r.Supersedes = []ulid.ULID{ulid.Zero} }},
		{"tombstone without targets", func(r *Record) { r.Kind = KindTombstone; r.Supersedes = nil }},
		{"retraction without targets", func(r *Record) { r.Kind = KindRetraction; r.Supersedes = nil }},
		{"causal ctx with bad node", func(r *Record) {
			r.CausalCtx = VersionVector{"bad node": ulid.MustParse("01J0000000000000000000000A")}
		}},
		{"causal ctx with zero id", func(r *Record) { r.CausalCtx = VersionVector{"beta": ulid.Zero} }},
		{"oversize model id", func(r *Record) { r.AuthorModel = strings.Repeat("m", MaxModelIDBytes+1) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := good.Clone()
			tc.mutis(r)
			if err := r.Validate(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Validate err = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestTombstoneAndRetract(t *testing.T) {
	b, _, _ := newHarness(t, 15)
	target := ulid.MustParse("01J000000000000000000000AA")

	tomb, err := b.Tombstone("user/cory", 1, nil, target)
	if err != nil {
		t.Fatal(err)
	}
	if tomb.Kind != KindTombstone || len(tomb.Supersedes) != 1 || tomb.Supersedes[0] != target {
		t.Errorf("tombstone is malformed: %+v", tomb)
	}
	if err := Verify(tomb); err != nil {
		t.Fatal(err)
	}

	ret, err := b.Retract("user/cory", 1, "measured it; the assumption was local time", nil, target)
	if err != nil {
		t.Fatal(err)
	}
	if ret.Kind != KindRetraction || string(ret.Body) == "" {
		t.Errorf("retraction is malformed: %+v", ret)
	}
	if _, err := b.Retract("user/cory", 1, "", nil, target); err == nil {
		t.Error("Retract accepted an empty reason; that is what Tombstone is for")
	}
}

func TestSawRecordSeparatesDisagreementFromIgnorance(t *testing.T) {
	b, _, _ := newHarness(t, 16)
	first, err := b.Build(Draft{Space: "user/cory", Kind: KindFact, Body: []byte("UTC"), Evidence: EvidenceObserved})
	if err != nil {
		t.Fatal(err)
	}

	ctx := NewVersionVector()
	ctx.Observe(first.AuthorNode, first.ID)
	informed, err := b.Build(Draft{
		Space: "user/cory", Kind: KindFact, Body: []byte("local"),
		Evidence: EvidenceObserved, CausalCtx: ctx,
	})
	if err != nil {
		t.Fatal(err)
	}
	blind, err := b.Build(Draft{Space: "user/cory", Kind: KindFact, Body: []byte("local"), Evidence: EvidenceObserved})
	if err != nil {
		t.Fatal(err)
	}

	if !informed.SawRecord(first) {
		t.Error("a record carrying the earlier claim in its causal context reports not having seen it")
	}
	if blind.SawRecord(first) {
		t.Error("a record with no causal context reports having seen the earlier claim")
	}
}

func TestKindAndEvidenceHelpers(t *testing.T) {
	if !KindTombstone.Supersedable() || !KindRetraction.Supersedable() || KindFact.Supersedable() {
		t.Error("Supersedable is wrong")
	}
	if !KindFact.Claims() || !KindProcedure.Claims() || KindEpisode.Claims() {
		t.Error("Claims is wrong")
	}
	if !(EvidenceObserved.Rank() > EvidenceAsserted.Rank() && EvidenceAsserted.Rank() > EvidenceDerived.Rank()) {
		t.Error("evidence ranking is not observed > asserted > derived")
	}
	if Evidence("future-level").Rank() != 0 {
		t.Error("an unknown evidence level must rank lowest, not win comparisons")
	}
}

func TestPolicyForEncodesTheTrustBoundaryRule(t *testing.T) {
	tests := []struct {
		space SpaceID
		want  ConflictPolicy
	}{
		{"agent/ag_abc", PolicyLWW},
		{"user/cory", PolicySiblingsAuto},
		{"shared/crew", PolicySiblingsManual},
		{"nonsense", PolicySiblingsManual},
	}
	for _, tc := range tests {
		if got := PolicyFor(tc.space); got != tc.want {
			t.Errorf("PolicyFor(%q) = %q, want %q", tc.space, got, tc.want)
		}
	}
	if PolicyFor("shared/crew").AutoResolves() {
		t.Error("a shared space must never auto-resolve: that is a trust boundary")
	}
	if !PolicyFor("agent/x").AutoResolves() {
		t.Error("an agent-private space should auto-resolve without ceremony")
	}
	if PolicyFor("agent/x").KeepsSiblings() {
		t.Error("LWW does not keep siblings")
	}
}

func TestSpaceIDHelpers(t *testing.T) {
	if got := SpaceID("shared/crew").Filename(); got != "shared__crew" {
		t.Errorf("Filename = %q", got)
	}
	if got := SpaceID("user/cory").Name(); got != "cory" {
		t.Errorf("Name = %q", got)
	}
	for _, bad := range []SpaceID{"", "shared", "shared/", "/crew", "shared/a b", "team/x", SpaceID("shared/" + strings.Repeat("x", 300))} {
		if err := bad.Validate(); err == nil {
			t.Errorf("Validate(%q) accepted an invalid space", string(bad))
		}
	}
}

func TestAgentIDEncoding(t *testing.T) {
	signer, err := GenerateSigner(deterministicEntropy{rng: rand.New(rand.NewSource(21))})
	if err != nil {
		t.Fatal(err)
	}
	id := signer.AgentID()
	s := id.String()
	if !strings.HasPrefix(s, "ag_") {
		t.Errorf("String = %q, want an ag_ prefix", s)
	}
	back, err := ParseAgentID(s)
	if err != nil {
		t.Fatal(err)
	}
	if back != id {
		t.Error("agent id round trip failed")
	}
	if _, err := ParseAgentID("ag_!!!!"); !errors.Is(err, ErrBadAgentID) {
		t.Error("ParseAgentID accepted junk")
	}
	if fp := id.Fingerprint(); len(fp) == 0 || !strings.Contains(fp, "…") {
		t.Errorf("Fingerprint = %q", fp)
	}
	text, _ := id.MarshalText()
	var viaText AgentID
	if err := viaText.UnmarshalText(text); err != nil || viaText != id {
		t.Error("text marshalling round trip failed")
	}
}

func TestNewSignerFromExistingKey(t *testing.T) {
	original, err := GenerateSigner(deterministicEntropy{rng: rand.New(rand.NewSource(31))})
	if err != nil {
		t.Fatal(err)
	}
	restored, err := NewSigner(original.PrivateKey())
	if err != nil {
		t.Fatal(err)
	}
	if restored.AgentID() != original.AgentID() {
		t.Error("restoring a signer from its private key changed its identity")
	}
	if _, err := NewSigner([]byte("too short")); err == nil {
		t.Error("NewSigner accepted a malformed key")
	}
}

func TestBuilderConfigValidation(t *testing.T) {
	signer, _ := GenerateSigner(deterministicEntropy{rng: rand.New(rand.NewSource(41))})
	fake := clock.NewFake(1)
	tests := []struct {
		name string
		cfg  BuilderConfig
	}{
		{"no node", BuilderConfig{Signer: signer, IDs: ulid.NewMonotonic(fake, nil), Stamps: hlc.New(fake)}},
		{"bad node", BuilderConfig{Node: "a b", Signer: signer, IDs: ulid.NewMonotonic(fake, nil), Stamps: hlc.New(fake)}},
		{"no signer", BuilderConfig{Node: "alpha", IDs: ulid.NewMonotonic(fake, nil), Stamps: hlc.New(fake)}},
		{"no ids", BuilderConfig{Node: "alpha", Signer: signer, Stamps: hlc.New(fake)}},
		{"no stamps", BuilderConfig{Node: "alpha", Signer: signer, IDs: ulid.NewMonotonic(fake, nil)}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewBuilder(tc.cfg); err == nil {
				t.Error("NewBuilder accepted an incomplete config")
			}
		})
	}
}

func TestRefsRoundTripAndCanonicalOrder(t *testing.T) {
	b, _, signer := newHarness(t, 17)
	a := ulid.MustParse("01J000000000000000000000AA")
	c := ulid.MustParse("01J000000000000000000000CC")

	// Refs must come out sorted regardless of input order, so two logically
	// identical link records cannot have two different signatures.
	r1, err := b.Build(Draft{Space: "user/cory", Kind: KindFact, Body: []byte("x"), Refs: []ulid.ULID{c, a, c}})
	if err != nil {
		t.Fatal(err)
	}
	if len(r1.Refs) != 2 || r1.Refs[0] != a || r1.Refs[1] != c {
		t.Fatalf("refs = %v, want sorted and deduplicated", r1.Refs)
	}

	enc, err := r1.Encode()
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeVerified(enc)
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Refs) != 2 || back.Refs[0] != a || back.Refs[1] != c {
		t.Fatalf("refs did not survive the round trip: %v", back.Refs)
	}

	// Descending refs must be refused even with an honest signature over them.
	r1.Refs = []ulid.ULID{c, a}
	raw := r1.appendCanonical(nil)
	bad := append(raw, signer.SignBytes(SignDomain, raw)...)
	if _, err := Decode(bad); !errors.Is(err, ErrNotCanonical) {
		t.Fatalf("err = %v, want ErrNotCanonical", err)
	}
}

func TestRefsAreNotSupersedes(t *testing.T) {
	b, _, _ := newHarness(t, 18)
	a := ulid.MustParse("01J000000000000000000000AA")
	c := ulid.MustParse("01J000000000000000000000CC")

	conflict, err := b.Conflict("shared/crew", 0, "UTC versus local time", nil, a, c)
	if err != nil {
		t.Fatal(err)
	}
	if conflict.Kind != KindConflict {
		t.Errorf("kind = %q", conflict.Kind)
	}
	if len(conflict.Refs) != 2 {
		t.Fatalf("refs = %v", conflict.Refs)
	}
	if conflict.IsSupersession() {
		t.Fatal("a conflict record supersedes something; siblings must both survive")
	}
	if conflict.Evidence != EvidenceDerived {
		t.Errorf("evidence = %q, want derived: a conflict is a conclusion", conflict.Evidence)
	}
	if err := Verify(conflict); err != nil {
		t.Fatal(err)
	}
}

func TestConflictAndLinkNeedTwoTargets(t *testing.T) {
	b, _, _ := newHarness(t, 19)
	a := ulid.MustParse("01J000000000000000000000AA")

	if _, err := b.Conflict("shared/crew", 0, "note", nil, a); err == nil {
		t.Error("Conflict accepted a single side")
	}
	if _, err := b.Link("user/cory", 0, "see also", nil, a); err == nil {
		t.Error("Link accepted a single target")
	}

	link, err := b.Link("user/cory", 0, "see also", nil, a, ulid.MustParse("01J000000000000000000000BB"))
	if err != nil {
		t.Fatal(err)
	}
	if len(link.Refs) != 2 || link.IsSupersession() {
		t.Errorf("link is malformed: %+v", link)
	}
}

func TestValidateRejectsBadRefs(t *testing.T) {
	b, _, _ := newHarness(t, 20)
	good, _ := b.Build(sampleDraft())

	tests := []struct {
		name  string
		mutis func(*Record)
	}{
		{"self reference", func(r *Record) { r.Refs = []ulid.ULID{r.ID} }},
		{"zero ref", func(r *Record) { r.Refs = []ulid.ULID{ulid.Zero} }},
		{"conflict with one ref", func(r *Record) {
			r.Kind = KindConflict
			r.Refs = []ulid.ULID{ulid.MustParse("01J000000000000000000000AA")}
		}},
		{"conflict with no refs", func(r *Record) { r.Kind = KindConflict; r.Refs = nil }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := good.Clone()
			tc.mutis(r)
			if err := r.Validate(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Validate err = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestRefsAreCoveredBySignature(t *testing.T) {
	b, _, _ := newHarness(t, 21)
	r, err := b.Build(sampleDraft())
	if err != nil {
		t.Fatal(err)
	}
	tampered := r.Clone()
	tampered.Refs = []ulid.ULID{ulid.MustParse("01J000000000000000000000AA")}
	if err := Verify(tampered); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("err = %v, want ErrBadSignature", err)
	}
}
