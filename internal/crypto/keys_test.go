package crypto

import (
	"bytes"
	"errors"
	"math/rand"
	"strings"
	"testing"
)

type detReader struct{ rng *rand.Rand }

func (d detReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(d.rng.Intn(256))
	}
	return len(p), nil
}

func reader(seed int64) detReader { return detReader{rng: rand.New(rand.NewSource(seed))} }

func TestWrapUnwrapRoundTrip(t *testing.T) {
	ent := reader(1)
	member, err := GenerateRecipient(ent)
	if err != nil {
		t.Fatal(err)
	}
	key, err := GenerateContentKey(ent)
	if err != nil {
		t.Fatal(err)
	}

	w, err := Wrap("shared/crew", 3, key, member.Public(), ent)
	if err != nil {
		t.Fatal(err)
	}
	got, err := member.Unwrap(w)
	if err != nil {
		t.Fatal(err)
	}
	if got != key {
		t.Fatal("unwrapped key does not match")
	}
	if w.Space != "shared/crew" || w.Epoch != 3 {
		t.Errorf("wrap metadata lost: %+v", w)
	}
	if bytes.Equal(w.Sealed, key[:]) {
		t.Fatal("the content key appears in the wrap in the clear")
	}
}

func TestWrapIsNonDeterministic(t *testing.T) {
	ent := reader(2)
	member, _ := GenerateRecipient(ent)
	key, _ := GenerateContentKey(ent)

	a, err := Wrap("user/cory", 0, key, member.Public(), ent)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Wrap("user/cory", 0, key, member.Public(), ent)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a.Sealed, b.Sealed) || a.Ephemeral == b.Ephemeral {
		t.Fatal("wrapping the same key twice produced identical bytes")
	}
	// Both must still open.
	for i, w := range []*WrappedKey{a, b} {
		got, err := member.Unwrap(w)
		if err != nil || got != key {
			t.Errorf("wrap %d did not unwrap: %v", i, err)
		}
	}
}

func TestUnwrapRejectsTheWrongRecipient(t *testing.T) {
	ent := reader(3)
	intended, _ := GenerateRecipient(ent)
	other, _ := GenerateRecipient(ent)
	key, _ := GenerateContentKey(ent)

	w, err := Wrap("shared/crew", 1, key, intended.Public(), ent)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Unwrap(w); !errors.Is(err, ErrUnwrap) {
		t.Fatalf("err = %v, want ErrUnwrap", err)
	}

	// Relabelling the wrap as addressed to the other recipient must not help:
	// the recipient key is mixed into the KDF salt and bound as AAD.
	forged := *w
	forged.Recipient = other.Public()
	if _, err := other.Unwrap(&forged); !errors.Is(err, ErrUnwrap) {
		t.Fatalf("relabelled wrap err = %v, want ErrUnwrap", err)
	}
}

func TestUnwrapRejectsRelabelledSpaceOrEpoch(t *testing.T) {
	ent := reader(4)
	member, _ := GenerateRecipient(ent)
	key, _ := GenerateContentKey(ent)
	w, err := Wrap("shared/crew", 2, key, member.Public(), ent)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		mutis func(*WrappedKey)
	}{
		{"different space", func(w *WrappedKey) { w.Space = "shared/other" }},
		{"different epoch", func(w *WrappedKey) { w.Epoch = 7 }},
		{"flipped ciphertext bit", func(w *WrappedKey) { w.Sealed[len(w.Sealed)-1] ^= 1 }},
		{"substituted ephemeral", func(w *WrappedKey) { w.Ephemeral[0] ^= 1 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			forged := *w
			forged.Sealed = append([]byte(nil), w.Sealed...)
			tc.mutis(&forged)
			if _, err := member.Unwrap(&forged); err == nil {
				t.Fatal("Unwrap accepted a tampered wrap")
			}
		})
	}
}

func TestAddingAMemberIsJustARewrap(t *testing.T) {
	ent := reader(5)
	alice, _ := GenerateRecipient(ent)
	bob, _ := GenerateRecipient(ent)
	key, _ := GenerateContentKey(ent)

	forAlice, _ := Wrap("shared/crew", 0, key, alice.Public(), ent)
	forBob, _ := Wrap("shared/crew", 0, key, bob.Public(), ent)

	gotA, err := alice.Unwrap(forAlice)
	if err != nil {
		t.Fatal(err)
	}
	gotB, err := bob.Unwrap(forBob)
	if err != nil {
		t.Fatal(err)
	}
	if gotA != key || gotB != key {
		t.Fatal("re-wrapping to a second member did not give both the same content key")
	}
}

func TestRotationIsForwardOnlyRevocation(t *testing.T) {
	ent := reader(6)
	staying, _ := GenerateRecipient(ent)

	ring := NewKeyring()
	epoch0, key0, err := ring.Rotate("shared/crew", ent)
	if err != nil {
		t.Fatal(err)
	}
	if epoch0 != 0 {
		t.Fatalf("first epoch = %d, want 0", epoch0)
	}

	// Both members hold epoch 0, so both can read what was written under it.
	oldRecord, err := SealRandom(&key0, []byte("written while both were members"), SpaceAAD("shared/crew", epoch0), ent)
	if err != nil {
		t.Fatal(err)
	}

	// Remove the departing member: rotate, and wrap the new epoch only to the
	// member who stays.
	epoch1, key1, err := ring.Rotate("shared/crew", ent)
	if err != nil {
		t.Fatal(err)
	}
	if epoch1 != 1 {
		t.Fatalf("rotated epoch = %d, want 1", epoch1)
	}
	if key1 == key0 {
		t.Fatal("rotation reused the old content key")
	}
	if _, err := Wrap("shared/crew", epoch1, key1, staying.Public(), ent); err != nil {
		t.Fatal(err)
	}

	newRecord, err := SealRandom(&key1, []byte("written after the removal"), SpaceAAD("shared/crew", epoch1), ent)
	if err != nil {
		t.Fatal(err)
	}

	// The departed member's epoch-0 key still opens the old record: revocation
	// is forward-only, and that is the documented property.
	if _, err := Open(&key0, oldRecord, SpaceAAD("shared/crew", epoch0)); err != nil {
		t.Fatalf("the old record should still open under epoch 0: %v", err)
	}
	// But it does not open the new one.
	if _, err := Open(&key0, newRecord, SpaceAAD("shared/crew", epoch1)); !errors.Is(err, ErrOpen) {
		t.Fatalf("the old key opened a post-rotation record: %v", err)
	}

	// The node that stayed keeps both epochs and can read the whole history.
	for _, e := range []uint32{epoch0, epoch1} {
		if _, err := ring.Key("shared/crew", e); err != nil {
			t.Errorf("epoch %d should be retained: %v", e, err)
		}
	}
	if cur, _ := ring.CurrentEpoch("shared/crew"); cur != epoch1 {
		t.Errorf("current epoch = %d, want %d", cur, epoch1)
	}
}

func TestSpaceAADBindsSpaceAndEpoch(t *testing.T) {
	ent := reader(7)
	key, _ := GenerateContentKey(ent)
	sealed, err := SealRandom(&key, []byte("body"), SpaceAAD("shared/crew", 2), ent)
	if err != nil {
		t.Fatal(err)
	}
	for _, aad := range [][]byte{
		SpaceAAD("shared/other", 2),
		SpaceAAD("shared/crew", 3),
		SpaceAAD("user/crew", 2),
		nil,
	} {
		if _, err := Open(&key, sealed, aad); !errors.Is(err, ErrOpen) {
			t.Errorf("a frame opened under the wrong space/epoch binding")
		}
	}
	if _, err := Open(&key, sealed, SpaceAAD("shared/crew", 2)); err != nil {
		t.Errorf("the correct binding failed: %v", err)
	}
}

func TestKeyringReadableVersusRelayed(t *testing.T) {
	ent := reader(8)
	ring := NewKeyring()
	key, _ := GenerateContentKey(ent)
	ring.Install("user/cory", 0, key)
	ring.MarkRelaying("shared/someone-elses")

	if !ring.Readable("user/cory") {
		t.Error("an installed space is not reported readable")
	}
	if ring.Readable("shared/someone-elses") {
		t.Error("a relayed space is reported readable")
	}
	if got := ring.ReadableSpaces(); len(got) != 1 || got[0] != "user/cory" {
		t.Errorf("ReadableSpaces = %v", got)
	}
	if got := ring.RelayedSpaces(); len(got) != 1 || got[0] != "shared/someone-elses" {
		t.Errorf("RelayedSpaces = %v", got)
	}

	// Installing a key for a relayed space promotes it.
	ring.Install("shared/someone-elses", 0, key)
	if len(ring.RelayedSpaces()) != 0 {
		t.Error("installing a key did not clear the relaying marker")
	}

	if _, err := ring.Key("shared/unknown", 0); !errors.Is(err, ErrNoKey) {
		t.Errorf("err = %v, want ErrNoKey", err)
	}
	if _, err := ring.Key("user/cory", 99); !errors.Is(err, ErrNoKey) {
		t.Errorf("err = %v, want ErrNoKey for a missing epoch", err)
	}
	if _, err := ring.CurrentEpoch("shared/unknown"); !errors.Is(err, ErrNoKey) {
		t.Errorf("err = %v, want ErrNoKey", err)
	}
}

func TestKeyringForgetMakesASpaceRelayed(t *testing.T) {
	ent := reader(9)
	ring := NewKeyring()
	key, _ := GenerateContentKey(ent)
	ring.Install("shared/crew", 0, key)

	ring.Forget("shared/crew")
	if ring.Readable("shared/crew") {
		t.Error("a forgotten space is still readable")
	}
	if got := ring.RelayedSpaces(); len(got) != 1 || got[0] != "shared/crew" {
		t.Errorf("RelayedSpaces = %v, want the forgotten space", got)
	}
}

func TestKeyringInstallWrapped(t *testing.T) {
	ent := reader(10)
	member, _ := GenerateRecipient(ent)
	key, _ := GenerateContentKey(ent)
	w, _ := Wrap("shared/crew", 4, key, member.Public(), ent)

	ring := NewKeyring()
	if err := ring.InstallWrapped(member, w); err != nil {
		t.Fatal(err)
	}
	got, err := ring.Key("shared/crew", 4)
	if err != nil {
		t.Fatal(err)
	}
	if got != key {
		t.Error("installed key does not match")
	}
	if cur, _ := ring.CurrentEpoch("shared/crew"); cur != 4 {
		t.Errorf("current epoch = %d, want 4", cur)
	}

	other, _ := GenerateRecipient(ent)
	if err := ring.InstallWrapped(other, w); err == nil {
		t.Error("InstallWrapped accepted a wrap for a different recipient")
	}
}

func TestKeyringSnapshotRestore(t *testing.T) {
	ent := reader(11)
	ring := NewKeyring()
	k0, _ := GenerateContentKey(ent)
	k1, _ := GenerateContentKey(ent)
	ring.Install("user/cory", 0, k0)
	ring.Install("user/cory", 1, k1)
	ring.Install("shared/crew", 0, k0)

	snap := ring.Snapshot()
	restored := NewKeyring()
	restored.Restore(snap)

	for _, tc := range []struct {
		space string
		epoch uint32
		want  ContentKey
	}{
		{"user/cory", 0, k0},
		{"user/cory", 1, k1},
		{"shared/crew", 0, k0},
	} {
		got, err := restored.Key(tc.space, tc.epoch)
		if err != nil || got != tc.want {
			t.Errorf("%s epoch %d did not survive the round trip: %v", tc.space, tc.epoch, err)
		}
	}
	if cur, _ := restored.CurrentEpoch("user/cory"); cur != 1 {
		t.Errorf("current epoch = %d, want 1", cur)
	}

	// The snapshot must be a copy, not a view.
	delete(snap["user/cory"].Epochs, 1)
	if _, err := restored.Key("user/cory", 1); err != nil {
		t.Error("mutating the snapshot affected the restored keyring")
	}
}

func TestKeyringIsConcurrencySafe(t *testing.T) {
	ent := reader(12)
	ring := NewKeyring()
	key, _ := GenerateContentKey(ent)
	done := make(chan struct{})
	for i := 0; i < 4; i++ {
		go func(i int) {
			for j := 0; j < 200; j++ {
				ring.Install("user/cory", uint32(j%5), key)
				ring.Readable("user/cory")
				ring.ReadableSpaces()
				_, _ = ring.CurrentEpoch("user/cory")
			}
			done <- struct{}{}
		}(i)
	}
	for i := 0; i < 4; i++ {
		<-done
	}
}

func TestRecipientKeyEncoding(t *testing.T) {
	ent := reader(13)
	r, err := GenerateRecipient(ent)
	if err != nil {
		t.Fatal(err)
	}
	pub := r.Public()
	s := pub.String()
	if !strings.HasPrefix(s, "rk_") {
		t.Errorf("String = %q, want an rk_ prefix", s)
	}
	back, err := ParseRecipientPublic(s)
	if err != nil || back != pub {
		t.Errorf("round trip failed: %v", err)
	}
	if _, err := ParseRecipientPublic("rk_!!!"); !errors.Is(err, ErrBadRecipient) {
		t.Error("ParseRecipientPublic accepted junk")
	}
	if !strings.Contains(pub.Fingerprint(), "…") {
		t.Errorf("Fingerprint = %q", pub.Fingerprint())
	}
	text, _ := pub.MarshalText()
	var viaText RecipientPublic
	if err := viaText.UnmarshalText(text); err != nil || viaText != pub {
		t.Error("text marshalling round trip failed")
	}

	restored, err := NewRecipient(r.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if restored.Public() != pub {
		t.Error("restoring a recipient from its private bytes changed its identity")
	}
	if _, err := NewRecipient([]byte("short")); !errors.Is(err, ErrBadRecipient) {
		t.Error("NewRecipient accepted a malformed key")
	}
}
