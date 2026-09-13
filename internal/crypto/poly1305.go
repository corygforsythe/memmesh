package crypto

import "encoding/binary"

// Poly1305 as specified in RFC 8439, using the five 26-bit limb representation.
//
// The limbs keep every intermediate product inside a uint64, so the whole
// evaluation needs no big-integer arithmetic and no data-dependent branching.
// The final reduction is a constant-time conditional subtract rather than a
// comparison, because Poly1305 is a one-time authenticator and a timing leak in
// the reduction is a leak of the tag.

const (
	// polyTagSize is the authenticator length.
	polyTagSize = 16
	// polyKeySize is the one-time key length: 16 bytes of r followed by 16 of s.
	polyKeySize = 32
	// polyBlockSize is the message block length.
	polyBlockSize = 16
)

// poly1305 accumulates a message and produces a 16-byte tag.
//
// The zero value is not usable; construct with newPoly1305. A poly1305 key must
// never be reused across two messages, which is why the AEAD derives a fresh one
// from the ChaCha20 keystream for every frame.
type poly1305 struct {
	r   [5]uint32
	pad [4]uint32
	h   [5]uint32

	buf [polyBlockSize]byte
	n   int
}

func newPoly1305(key *[polyKeySize]byte) *poly1305 {
	p := &poly1305{}
	// r is clamped: the top four bits of each 32-bit word are cleared and the
	// low two bits of the upper three words are cleared. Splitting into 26-bit
	// limbs and masking does both at once.
	p.r[0] = binary.LittleEndian.Uint32(key[0:4]) & 0x3ffffff
	p.r[1] = (binary.LittleEndian.Uint32(key[3:7]) >> 2) & 0x3ffff03
	p.r[2] = (binary.LittleEndian.Uint32(key[6:10]) >> 4) & 0x3ffc0ff
	p.r[3] = (binary.LittleEndian.Uint32(key[9:13]) >> 6) & 0x3f03fff
	p.r[4] = (binary.LittleEndian.Uint32(key[12:16]) >> 8) & 0x00fffff

	p.pad[0] = binary.LittleEndian.Uint32(key[16:20])
	p.pad[1] = binary.LittleEndian.Uint32(key[20:24])
	p.pad[2] = binary.LittleEndian.Uint32(key[24:28])
	p.pad[3] = binary.LittleEndian.Uint32(key[28:32])
	return p
}

// write absorbs message bytes.
func (p *poly1305) write(msg []byte) {
	if p.n > 0 {
		n := copy(p.buf[p.n:], msg)
		p.n += n
		msg = msg[n:]
		if p.n < polyBlockSize {
			return
		}
		p.blocks(p.buf[:], false)
		p.n = 0
	}
	if full := len(msg) - len(msg)%polyBlockSize; full > 0 {
		p.blocks(msg[:full], false)
		msg = msg[full:]
	}
	if len(msg) > 0 {
		p.n = copy(p.buf[:], msg)
	}
}

// blocks absorbs whole 16-byte blocks. When final is set the implicit high bit
// is omitted, which is how the padded last block is distinguished from a full
// one.
func (p *poly1305) blocks(msg []byte, final bool) {
	var hibit uint32 = 1 << 24
	if final {
		hibit = 0
	}

	r0, r1, r2, r3, r4 := p.r[0], p.r[1], p.r[2], p.r[3], p.r[4]
	// Multiplying the wrapped-around limbs by 5 folds the reduction modulo
	// 2^130-5 into the multiplication itself.
	s1, s2, s3, s4 := r1*5, r2*5, r3*5, r4*5
	h0, h1, h2, h3, h4 := p.h[0], p.h[1], p.h[2], p.h[3], p.h[4]

	for len(msg) >= polyBlockSize {
		t0 := binary.LittleEndian.Uint32(msg[0:4])
		t1 := binary.LittleEndian.Uint32(msg[4:8])
		t2 := binary.LittleEndian.Uint32(msg[8:12])
		t3 := binary.LittleEndian.Uint32(msg[12:16])

		h0 += t0 & 0x3ffffff
		h1 += uint32(((uint64(t1)<<32 | uint64(t0)) >> 26) & 0x3ffffff)
		h2 += uint32(((uint64(t2)<<32 | uint64(t1)) >> 20) & 0x3ffffff)
		h3 += uint32(((uint64(t3)<<32 | uint64(t2)) >> 14) & 0x3ffffff)
		h4 += (t3 >> 8) | hibit

		d0 := uint64(h0)*uint64(r0) + uint64(h1)*uint64(s4) + uint64(h2)*uint64(s3) + uint64(h3)*uint64(s2) + uint64(h4)*uint64(s1)
		d1 := uint64(h0)*uint64(r1) + uint64(h1)*uint64(r0) + uint64(h2)*uint64(s4) + uint64(h3)*uint64(s3) + uint64(h4)*uint64(s2)
		d2 := uint64(h0)*uint64(r2) + uint64(h1)*uint64(r1) + uint64(h2)*uint64(r0) + uint64(h3)*uint64(s4) + uint64(h4)*uint64(s3)
		d3 := uint64(h0)*uint64(r3) + uint64(h1)*uint64(r2) + uint64(h2)*uint64(r1) + uint64(h3)*uint64(r0) + uint64(h4)*uint64(s4)
		d4 := uint64(h0)*uint64(r4) + uint64(h1)*uint64(r3) + uint64(h2)*uint64(r2) + uint64(h3)*uint64(r1) + uint64(h4)*uint64(r0)

		c := uint32(d0 >> 26)
		h0 = uint32(d0) & 0x3ffffff
		d1 += uint64(c)
		c = uint32(d1 >> 26)
		h1 = uint32(d1) & 0x3ffffff
		d2 += uint64(c)
		c = uint32(d2 >> 26)
		h2 = uint32(d2) & 0x3ffffff
		d3 += uint64(c)
		c = uint32(d3 >> 26)
		h3 = uint32(d3) & 0x3ffffff
		d4 += uint64(c)
		c = uint32(d4 >> 26)
		h4 = uint32(d4) & 0x3ffffff
		h0 += c * 5
		c = h0 >> 26
		h0 &= 0x3ffffff
		h1 += c

		msg = msg[polyBlockSize:]
	}
	p.h[0], p.h[1], p.h[2], p.h[3], p.h[4] = h0, h1, h2, h3, h4
}

// sum finishes the accumulation and writes the 16-byte tag.
func (p *poly1305) sum(tag *[polyTagSize]byte) {
	if p.n > 0 {
		// Pad the trailing partial block with a single 1 byte followed by
		// zeroes, and absorb it with the implicit high bit suppressed.
		p.buf[p.n] = 1
		for i := p.n + 1; i < polyBlockSize; i++ {
			p.buf[i] = 0
		}
		p.blocks(p.buf[:], true)
		p.n = 0
	}

	h0, h1, h2, h3, h4 := p.h[0], p.h[1], p.h[2], p.h[3], p.h[4]

	// Carry fully.
	c := h1 >> 26
	h1 &= 0x3ffffff
	h2 += c
	c = h2 >> 26
	h2 &= 0x3ffffff
	h3 += c
	c = h3 >> 26
	h3 &= 0x3ffffff
	h4 += c
	c = h4 >> 26
	h4 &= 0x3ffffff
	h0 += c * 5
	c = h0 >> 26
	h0 &= 0x3ffffff
	h1 += c

	// Compute h + -p, i.e. h + 5 - 2^130.
	g0 := h0 + 5
	c = g0 >> 26
	g0 &= 0x3ffffff
	g1 := h1 + c
	c = g1 >> 26
	g1 &= 0x3ffffff
	g2 := h2 + c
	c = g2 >> 26
	g2 &= 0x3ffffff
	g3 := h3 + c
	c = g3 >> 26
	g3 &= 0x3ffffff
	g4 := h4 + c - (1 << 26)

	// Select h if h < p, otherwise h + -p. g4's sign bit carries the decision,
	// so the choice is a mask rather than a branch.
	mask := (g4 >> 31) - 1
	g0 &= mask
	g1 &= mask
	g2 &= mask
	g3 &= mask
	g4 &= mask
	mask = ^mask
	h0 = (h0 & mask) | g0
	h1 = (h1 & mask) | g1
	h2 = (h2 & mask) | g2
	h3 = (h3 & mask) | g3
	h4 = (h4 & mask) | g4

	// Collapse the 26-bit limbs back into four 32-bit words, mod 2^128.
	h0 = (h0 | h1<<26)
	h1 = (h1 >> 6) | (h2 << 20)
	h2 = (h2 >> 12) | (h3 << 14)
	h3 = (h3 >> 18) | (h4 << 8)

	// Add s.
	f := uint64(h0) + uint64(p.pad[0])
	h0 = uint32(f)
	f = uint64(h1) + uint64(p.pad[1]) + (f >> 32)
	h1 = uint32(f)
	f = uint64(h2) + uint64(p.pad[2]) + (f >> 32)
	h2 = uint32(f)
	f = uint64(h3) + uint64(p.pad[3]) + (f >> 32)
	h3 = uint32(f)

	binary.LittleEndian.PutUint32(tag[0:4], h0)
	binary.LittleEndian.PutUint32(tag[4:8], h1)
	binary.LittleEndian.PutUint32(tag[8:12], h2)
	binary.LittleEndian.PutUint32(tag[12:16], h3)
}

// writeZeroPad absorbs zero bytes so the next field starts on a 16-byte
// boundary, as the AEAD's MAC input requires.
func (p *poly1305) writeZeroPad(written int) {
	if rem := written % polyBlockSize; rem != 0 {
		var zeros [polyBlockSize]byte
		p.write(zeros[:polyBlockSize-rem])
	}
}
