package crypto

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/rand"
	"os"
	"testing"
)

// The vectors in testdata/vectors.json were produced by an independent,
// externally audited implementation (Python's `cryptography`, which wraps
// OpenSSL) and are committed rather than regenerated, so a refactor here cannot
// quietly move the goalposts. Regenerate only with a deliberate reason recorded
// in docs/decisions/.
type vectorFile struct {
	AEADIETF []struct {
		Key        string `json:"key"`
		Nonce      string `json:"nonce"`
		Plaintext  string `json:"plaintext"`
		AAD        string `json:"aad"`
		Ciphertext string `json:"ciphertext"`
		Tag        string `json:"tag"`
	} `json:"aead_ietf"`
	ChaCha20Block []struct {
		Key       string `json:"key"`
		Nonce     string `json:"nonce"`
		Counter   uint32 `json:"counter"`
		Keystream string `json:"keystream"`
	} `json:"chacha20_block"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(v.AEADIETF) == 0 || len(v.ChaCha20Block) == 0 {
		t.Fatal("vector file is empty")
	}
	return v
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestChaCha20KeystreamMatchesReference(t *testing.T) {
	for i, tc := range loadVectors(t).ChaCha20Block {
		var key ContentKey
		copy(key[:], unhex(t, tc.Key))
		nonce := unhex(t, tc.Nonce)
		want := unhex(t, tc.Keystream)

		var got [chachaBlockSize]byte
		chachaBlock(&got, &key, nonce, tc.Counter)
		if !bytes.Equal(got[:], want) {
			t.Errorf("vector %d (counter %d): keystream mismatch\n got %x\nwant %x", i, tc.Counter, got, want)
		}
	}
}

func TestChaCha20Poly1305MatchesReference(t *testing.T) {
	for i, tc := range loadVectors(t).AEADIETF {
		var key ContentKey
		copy(key[:], unhex(t, tc.Key))
		nonce := unhex(t, tc.Nonce)
		pt := unhex(t, tc.Plaintext)
		aad := unhex(t, tc.AAD)
		wantCT := unhex(t, tc.Ciphertext)
		wantTag := unhex(t, tc.Tag)

		gotCT := make([]byte, len(pt))
		var gotTag [TagSize]byte
		ietfSeal(gotCT, &gotTag, &key, nonce, pt, aad)

		if !bytes.Equal(gotCT, wantCT) {
			t.Errorf("vector %d: ciphertext mismatch\n got %x\nwant %x", i, gotCT, wantCT)
		}
		if !bytes.Equal(gotTag[:], wantTag) {
			t.Errorf("vector %d: tag mismatch (pt %d bytes, aad %d bytes)\n got %x\nwant %x",
				i, len(pt), len(aad), gotTag, wantTag)
		}
	}
}

// TestHChaCha20KnownVector pins the subkey derivation against the test vector in
// draft-irtf-cfrg-xchacha. The round function it uses is already anchored by the
// ChaCha20 reference test above, so this covers the remaining difference: the
// state layout and which words are emitted.
func TestHChaCha20KnownVector(t *testing.T) {
	var key ContentKey
	for i := range key {
		key[i] = byte(i)
	}
	nonce := unhex(t, "000000090000004a0000000031415927")
	want := unhex(t, "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")

	got := hChaCha20(&key, nonce)
	if !bytes.Equal(got[:], want) {
		t.Errorf("HChaCha20 mismatch\n got %x\nwant %x", got, want)
	}
}

// TestXChaCha20ReducesToIETF checks the nonce-extension wiring: sealing with a
// 24-byte nonce must equal deriving the subkey and sealing with the derived
// 12-byte nonce. If this and the two reference tests pass, the full construction
// is correct.
func TestXChaCha20ReducesToIETF(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	var key ContentKey
	var nonce [NonceSize]byte
	fill(rng, key[:])
	fill(rng, nonce[:])
	pt := make([]byte, 200)
	aad := make([]byte, 30)
	fill(rng, pt)
	fill(rng, aad)

	sealed, err := Seal(&key, &nonce, pt, aad)
	if err != nil {
		t.Fatal(err)
	}

	subkey, ietfNonce := xchachaSubkey(&key, &nonce)
	wantCT := make([]byte, len(pt))
	var wantTag [TagSize]byte
	ietfSeal(wantCT, &wantTag, &subkey, ietfNonce[:], pt, aad)

	if !bytes.Equal(sealed[:NonceSize], nonce[:]) {
		t.Error("sealed output does not begin with the nonce")
	}
	if !bytes.Equal(sealed[NonceSize:NonceSize+len(pt)], wantCT) {
		t.Error("ciphertext does not match the reduced IETF construction")
	}
	if !bytes.Equal(sealed[NonceSize+len(pt):], wantTag[:]) {
		t.Error("tag does not match the reduced IETF construction")
	}
	if ietfNonce[0] != 0 || ietfNonce[1] != 0 || ietfNonce[2] != 0 || ietfNonce[3] != 0 {
		t.Error("the derived IETF nonce must be zero-padded in its top four bytes")
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(6))
	var key ContentKey
	fill(rng, key[:])

	sizes := []int{0, 1, 15, 16, 17, 63, 64, 65, 1024, 65536}
	aadSizes := []int{0, 1, 16, 17, 500}
	for _, n := range sizes {
		for _, a := range aadSizes {
			pt := make([]byte, n)
			aad := make([]byte, a)
			fill(rng, pt)
			fill(rng, aad)

			sealed, err := SealRandom(&key, pt, aad, rng)
			if err != nil {
				t.Fatalf("SealRandom(%d,%d): %v", n, a, err)
			}
			if len(sealed) != n+Overhead {
				t.Fatalf("sealed length = %d, want %d", len(sealed), n+Overhead)
			}
			got, err := Open(&key, sealed, aad)
			if err != nil {
				t.Fatalf("Open(%d,%d): %v", n, a, err)
			}
			if !bytes.Equal(got, pt) {
				t.Fatalf("round trip mismatch at pt=%d aad=%d", n, a)
			}
		}
	}
}

func TestSealRandomUsesAFreshNonceEachTime(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	var key ContentKey
	fill(rng, key[:])
	pt := []byte("the same plaintext every time")

	seen := make(map[string]bool)
	for i := 0; i < 500; i++ {
		sealed, err := SealRandom(&key, pt, nil, rng)
		if err != nil {
			t.Fatal(err)
		}
		nonce := string(sealed[:NonceSize])
		if seen[nonce] {
			t.Fatal("SealRandom repeated a nonce")
		}
		seen[nonce] = true
	}
}

func TestOpenRejectsTampering(t *testing.T) {
	rng := rand.New(rand.NewSource(8))
	var key ContentKey
	fill(rng, key[:])
	pt := []byte("parse_ts assumes UTC input")
	aad := []byte("space=shared/crew epoch=3")

	sealed, err := SealRandom(&key, pt, aad, rng)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name  string
		mutis func([]byte) []byte
		aad   []byte
	}{
		{"flip a nonce bit", func(b []byte) []byte { b[0] ^= 1; return b }, aad},
		{"flip a ciphertext bit", func(b []byte) []byte { b[NonceSize] ^= 1; return b }, aad},
		{"flip a tag bit", func(b []byte) []byte { b[len(b)-1] ^= 1; return b }, aad},
		{"truncate", func(b []byte) []byte { return b[:len(b)-1] }, aad},
		{"extend", func(b []byte) []byte { return append(b, 0) }, aad},
		{"changed aad", func(b []byte) []byte { return b }, []byte("space=shared/other epoch=3")},
		{"dropped aad", func(b []byte) []byte { return b }, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			b := append([]byte(nil), sealed...)
			if _, err := Open(&key, tc.mutis(b), tc.aad); err == nil {
				t.Fatal("Open accepted a tampered message")
			}
		})
	}
}

func TestOpenRejectsTheWrongKey(t *testing.T) {
	rng := rand.New(rand.NewSource(9))
	var key, other ContentKey
	fill(rng, key[:])
	fill(rng, other[:])

	sealed, err := SealRandom(&key, []byte("secret"), nil, rng)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(&other, sealed, nil); !errors.Is(err, ErrOpen) {
		t.Fatalf("err = %v, want ErrOpen", err)
	}
}

func TestOpenRejectsShortInput(t *testing.T) {
	var key ContentKey
	for _, n := range []int{0, 1, NonceSize, Overhead - 1} {
		if _, err := Open(&key, make([]byte, n), nil); !errors.Is(err, ErrSize) {
			t.Errorf("Open(%d bytes) err = %v, want ErrSize", n, err)
		}
	}
}

// TestAADLengthBindingPreventsShifting checks the RFC 8439 trailing length
// fields do their job: moving a byte from the additional data into the plaintext
// must not produce the same tag.
func TestAADLengthBindingPreventsShifting(t *testing.T) {
	rng := rand.New(rand.NewSource(10))
	var key ContentKey
	var nonce [NonceSize]byte
	fill(rng, key[:])
	fill(rng, nonce[:])

	all := []byte("HEADERBODY")
	a, err := Seal(&key, &nonce, all[6:], all[:6])
	if err != nil {
		t.Fatal(err)
	}
	b, err := Seal(&key, &nonce, all[5:], all[:5])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a[len(a)-TagSize:], b[len(b)-TagSize:]) {
		t.Fatal("moving the aad/plaintext boundary produced the same tag")
	}
}

func TestPoly1305IsIncrementalSafe(t *testing.T) {
	// The AEAD writes the MAC input in several pieces; feeding the same bytes in
	// different chunkings must give the same tag.
	rng := rand.New(rand.NewSource(11))
	var polyKey [polyKeySize]byte
	fill(rng, polyKey[:])
	msg := make([]byte, 300)
	fill(rng, msg)

	whole := newPoly1305(&polyKey)
	whole.write(msg)
	var want [TagSize]byte
	whole.sum(&want)

	for _, chunk := range []int{1, 3, 15, 16, 17, 64, 299} {
		p := newPoly1305(&polyKey)
		for i := 0; i < len(msg); i += chunk {
			end := i + chunk
			if end > len(msg) {
				end = len(msg)
			}
			p.write(msg[i:end])
		}
		var got [TagSize]byte
		p.sum(&got)
		if got != want {
			t.Errorf("chunk size %d changed the tag", chunk)
		}
	}
}

func fill(rng *rand.Rand, b []byte) {
	for i := range b {
		b[i] = byte(rng.Intn(256))
	}
}
