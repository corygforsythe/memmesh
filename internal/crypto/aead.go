package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Sizes of the AEAD parameters.
const (
	// KeySize is the content key length.
	KeySize = 32
	// NonceSize is the XChaCha20-Poly1305 nonce length: 192 bits.
	NonceSize = 24
	// TagSize is the Poly1305 authenticator length.
	TagSize = 16
	// Overhead is how much longer a sealed message is than its plaintext:
	// nonce plus tag, both carried inline.
	Overhead = NonceSize + TagSize
)

// maxPlaintext caps a single sealed message. It is far below the ChaCha20
// counter limit, so keystream can never repeat within one nonce.
const maxPlaintext = 1 << 28 // 256 MiB

// Errors returned by this package's AEAD operations.
var (
	// ErrOpen reports a message that failed authentication. It deliberately
	// says nothing about why: a padded frame, a wrong key, a wrong epoch and a
	// flipped bit are indistinguishable to an attacker and should stay that
	// way.
	ErrOpen = errors.New("crypto: message authentication failed")
	// ErrSize reports a plaintext or ciphertext of unusable length.
	ErrSize = errors.New("crypto: bad message length")
)

// Seal encrypts and authenticates plaintext under key and nonce, binding
// additionalData without encrypting it, and returns nonce||ciphertext||tag.
//
// XChaCha20-Poly1305 rather than ChaCha20-Poly1305: the 192-bit nonce can be
// drawn at random for every frame with no birthday concern, which means no node
// has to track a per-peer nonce counter. In a mesh with no coordination and no
// consensus, a construction that needs counter state would be a liability.
func Seal(key *ContentKey, nonce *[NonceSize]byte, plaintext, additionalData []byte) ([]byte, error) {
	if len(plaintext) > maxPlaintext {
		return nil, fmt.Errorf("%w: plaintext is %d bytes, max %d", ErrSize, len(plaintext), maxPlaintext)
	}

	subkey, ietfNonce := xchachaSubkey(key, nonce)
	defer zero(subkey[:])

	out := make([]byte, NonceSize+len(plaintext)+TagSize)
	copy(out, nonce[:])
	ciphertext := out[NonceSize : NonceSize+len(plaintext)]

	var tag [TagSize]byte
	ietfSeal(ciphertext, &tag, &subkey, ietfNonce[:], plaintext, additionalData)
	copy(out[NonceSize+len(plaintext):], tag[:])
	return out, nil
}

// SealRandom draws a fresh random nonce and seals with it. A nil entropy source
// means crypto/rand. This is the form callers should reach for; a caller that
// picks its own nonce has taken on the job of never repeating one.
func SealRandom(key *ContentKey, plaintext, additionalData []byte, entropy io.Reader) ([]byte, error) {
	if entropy == nil {
		entropy = rand.Reader
	}
	var nonce [NonceSize]byte
	if _, err := io.ReadFull(entropy, nonce[:]); err != nil {
		return nil, fmt.Errorf("crypto: read nonce: %w", err)
	}
	return Seal(key, &nonce, plaintext, additionalData)
}

// Open authenticates and decrypts a message produced by Seal.
//
// It returns ErrOpen for every failure mode, and never returns partially
// decrypted output: the tag is checked before any plaintext is handed back.
func Open(key *ContentKey, sealed, additionalData []byte) ([]byte, error) {
	if len(sealed) < Overhead {
		return nil, fmt.Errorf("%w: %d bytes cannot hold a nonce and tag", ErrSize, len(sealed))
	}
	var nonce [NonceSize]byte
	copy(nonce[:], sealed[:NonceSize])
	ciphertext := sealed[NonceSize : len(sealed)-TagSize]
	wantTag := sealed[len(sealed)-TagSize:]

	subkey, ietfNonce := xchachaSubkey(key, &nonce)
	defer zero(subkey[:])

	var gotTag [TagSize]byte
	ietfTag(&gotTag, &subkey, ietfNonce[:], ciphertext, additionalData)
	if subtle.ConstantTimeCompare(gotTag[:], wantTag) != 1 {
		return nil, ErrOpen
	}

	plaintext := make([]byte, len(ciphertext))
	chachaXOR(plaintext, ciphertext, &subkey, ietfNonce[:], 1)
	return plaintext, nil
}

// xchachaSubkey performs the XChaCha20 nonce extension: the first 16 bytes of
// the 24-byte nonce select a subkey via HChaCha20, and the remaining 8 become
// the low bytes of a 12-byte IETF nonce whose top 4 bytes are zero.
func xchachaSubkey(key *ContentKey, nonce *[NonceSize]byte) (ContentKey, [chachaNonceSize]byte) {
	subkey := hChaCha20(key, nonce[:hchachaNonceSize])
	var ietfNonce [chachaNonceSize]byte
	copy(ietfNonce[4:], nonce[hchachaNonceSize:])
	return subkey, ietfNonce
}

// ietfSeal is RFC 8439 ChaCha20-Poly1305 with a 96-bit nonce: the construction
// XChaCha20-Poly1305 reduces to once the subkey is derived. dst must be exactly
// len(plaintext) bytes.
func ietfSeal(dst []byte, tag *[TagSize]byte, key *ContentKey, nonce, plaintext, additionalData []byte) {
	chachaXOR(dst, plaintext, key, nonce, 1)
	ietfTag(tag, key, nonce, dst, additionalData)
}

// ietfTag derives the one-time Poly1305 key from counter block 0 and computes
// the tag over the AEAD's MAC input.
func ietfTag(tag *[TagSize]byte, key *ContentKey, nonce, ciphertext, additionalData []byte) {
	var block [chachaBlockSize]byte
	chachaBlock(&block, key, nonce, 0)
	var polyKey [polyKeySize]byte
	copy(polyKey[:], block[:polyKeySize])
	defer func() {
		zero(block[:])
		zero(polyKey[:])
	}()
	macFrame(tag, &polyKey, additionalData, ciphertext)
}

// macFrame computes the RFC 8439 AEAD tag input:
//
//	aad || pad16 || ciphertext || pad16 || le64(len(aad)) || le64(len(ciphertext))
//
// The trailing lengths are what stop an attacker moving bytes between the
// authenticated-but-unencrypted header and the ciphertext.
func macFrame(tag *[TagSize]byte, polyKey *[polyKeySize]byte, additionalData, ciphertext []byte) {
	p := newPoly1305(polyKey)
	p.write(additionalData)
	p.writeZeroPad(len(additionalData))
	p.write(ciphertext)
	p.writeZeroPad(len(ciphertext))

	var lengths [16]byte
	binary.LittleEndian.PutUint64(lengths[0:8], uint64(len(additionalData)))
	binary.LittleEndian.PutUint64(lengths[8:16], uint64(len(ciphertext)))
	p.write(lengths[:])
	p.sum(tag)
}

// zero overwrites a buffer. Go gives no guarantee the compiler keeps this, and
// it cannot reach copies the GC has already moved, so treat it as hygiene rather
// than a security boundary.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
