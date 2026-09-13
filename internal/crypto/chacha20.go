package crypto

import "encoding/binary"

// ChaCha20 as specified in RFC 8439, plus the HChaCha20 construction from
// draft-irtf-cfrg-xchacha that XChaCha20 uses to derive a subkey.
//
// This is hand-rolled because golang.org/x/crypto is not available to this build
// (see docs/decisions/0002-stdlib-only.md). It is a portable, constant-time
// implementation: no data-dependent branches and no table lookups. It is not
// vectorised, which costs throughput but nothing else — and the frames it
// protects are small.

// chachaSigma is the ASCII constant "expand 32-byte k" as four little-endian
// words, occupying state words 0-3.
var chachaSigma = [4]uint32{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}

const (
	// chachaNonceSize is the IETF nonce length: 96 bits, leaving a 32-bit
	// counter.
	chachaNonceSize = 12
	// chachaBlockSize is the keystream block length.
	chachaBlockSize = 64
	// hchachaNonceSize is the input length HChaCha20 consumes.
	hchachaNonceSize = 16
)

// quarterRound is the ChaCha quarter round on four state words.
func quarterRound(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	a += b
	d ^= a
	d = d<<16 | d>>16
	c += d
	b ^= c
	b = b<<12 | b>>20
	a += b
	d ^= a
	d = d<<8 | d>>24
	c += d
	b ^= c
	b = b<<7 | b>>25
	return a, b, c, d
}

// permute applies the 20-round ChaCha permutation to a state in place. It does
// not add the original state back in; both callers need different behaviour
// there, so that step is theirs.
func permute(s *[16]uint32) {
	for i := 0; i < 10; i++ {
		// Column rounds.
		s[0], s[4], s[8], s[12] = quarterRound(s[0], s[4], s[8], s[12])
		s[1], s[5], s[9], s[13] = quarterRound(s[1], s[5], s[9], s[13])
		s[2], s[6], s[10], s[14] = quarterRound(s[2], s[6], s[10], s[14])
		s[3], s[7], s[11], s[15] = quarterRound(s[3], s[7], s[11], s[15])
		// Diagonal rounds.
		s[0], s[5], s[10], s[15] = quarterRound(s[0], s[5], s[10], s[15])
		s[1], s[6], s[11], s[12] = quarterRound(s[1], s[6], s[11], s[12])
		s[2], s[7], s[8], s[13] = quarterRound(s[2], s[7], s[8], s[13])
		s[3], s[4], s[9], s[14] = quarterRound(s[3], s[4], s[9], s[14])
	}
}

// initialState lays out the RFC 8439 state: constants, key, counter, nonce.
func initialState(key *ContentKey, nonce []byte, counter uint32) [16]uint32 {
	var s [16]uint32
	copy(s[0:4], chachaSigma[:])
	for i := 0; i < 8; i++ {
		s[4+i] = binary.LittleEndian.Uint32(key[i*4:])
	}
	s[12] = counter
	s[13] = binary.LittleEndian.Uint32(nonce[0:4])
	s[14] = binary.LittleEndian.Uint32(nonce[4:8])
	s[15] = binary.LittleEndian.Uint32(nonce[8:12])
	return s
}

// chachaBlock writes one 64-byte keystream block for the given counter into dst.
func chachaBlock(dst *[chachaBlockSize]byte, key *ContentKey, nonce []byte, counter uint32) {
	initial := initialState(key, nonce, counter)
	working := initial
	permute(&working)
	for i := 0; i < 16; i++ {
		binary.LittleEndian.PutUint32(dst[i*4:], working[i]+initial[i])
	}
}

// chachaXOR XORs the ChaCha20 keystream, starting at the given block counter,
// into dst from src. dst and src may alias exactly.
//
// The counter is 32 bits and is allowed to wrap arithmetically, which would
// repeat keystream. Callers must not feed it more than 256 GiB under one nonce;
// the AEAD wrapper enforces a far smaller limit, so the condition is unreachable
// in practice.
func chachaXOR(dst, src []byte, key *ContentKey, nonce []byte, counter uint32) {
	var block [chachaBlockSize]byte
	for len(src) > 0 {
		chachaBlock(&block, key, nonce, counter)
		counter++
		n := len(src)
		if n > chachaBlockSize {
			n = chachaBlockSize
		}
		for i := 0; i < n; i++ {
			dst[i] = src[i] ^ block[i]
		}
		dst, src = dst[n:], src[n:]
	}
}

// hChaCha20 derives a 32-byte subkey from a key and 16 bytes of nonce.
//
// It differs from ChaCha20 in two ways that matter: the whole 16-byte input
// occupies words 12-15 (so there is no counter), and the original state is not
// added back after the permutation. The output is words 0-3 and 12-15.
//
// This is what gives XChaCha20 its 192-bit nonce: 16 bytes select a subkey, the
// remaining 8 become the IETF nonce. A 192-bit nonce is large enough to choose
// at random for every frame without tracking counters per peer, which is the
// only reason this system can encrypt without coordination.
func hChaCha20(key *ContentKey, nonce []byte) ContentKey {
	var s [16]uint32
	copy(s[0:4], chachaSigma[:])
	for i := 0; i < 8; i++ {
		s[4+i] = binary.LittleEndian.Uint32(key[i*4:])
	}
	for i := 0; i < 4; i++ {
		s[12+i] = binary.LittleEndian.Uint32(nonce[i*4:])
	}
	permute(&s)

	var out ContentKey
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint32(out[i*4:], s[i])
		binary.LittleEndian.PutUint32(out[16+i*4:], s[12+i])
	}
	return out
}
