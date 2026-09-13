// Package ulid implements the 128-bit ULID identifier used for record IDs.
//
// A ULID is a 48-bit big-endian millisecond timestamp followed by 80 bits of
// entropy, rendered as 26 characters of Crockford base32. The encoding sorts
// lexicographically in the same order the bytes sort, which is why records can
// be reconciled as an ordered set without a separate sequence column.
//
// Both the clock and the entropy source are injected. Nothing in this package
// reads the ambient wall clock or the global RNG, because convergence tests
// must be reproducible (plan §0.5).
package ulid

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Size is the length of a ULID in bytes.
const Size = 16

// EncodedSize is the length of a ULID in Crockford base32 characters.
const EncodedSize = 26

// MaxTime is the largest millisecond timestamp a ULID can carry.
const MaxTime = uint64(1)<<48 - 1

// ULID is a lexicographically sortable, 128-bit identifier.
//
// The zero ULID is a valid value and sorts before every generated one; it is
// used as the "no such record" sentinel throughout the tree.
type ULID [Size]byte

// Zero is the zero ULID.
var Zero ULID

// ErrBadTime reports a timestamp that does not fit in 48 bits.
var ErrBadTime = errors.New("ulid: timestamp overflows 48 bits")

// ErrBadEncoding reports a string that is not a valid Crockford base32 ULID.
var ErrBadEncoding = errors.New("ulid: malformed encoding")

// New builds a ULID from an explicit millisecond timestamp and 10 bytes of
// entropy read from entropy. It is the primitive the Monotonic generator is
// built from; callers that need per-node monotonicity should use that instead.
func New(ms uint64, entropy io.Reader) (ULID, error) {
	var u ULID
	if ms > MaxTime {
		return Zero, ErrBadTime
	}
	putTime(&u, ms)
	if _, err := io.ReadFull(entropy, u[6:]); err != nil {
		return Zero, fmt.Errorf("ulid: read entropy: %w", err)
	}
	return u, nil
}

// Time returns the millisecond timestamp embedded in the ULID.
func (u ULID) Time() uint64 {
	return uint64(u[0])<<40 | uint64(u[1])<<32 | uint64(u[2])<<24 |
		uint64(u[3])<<16 | uint64(u[4])<<8 | uint64(u[5])
}

// Entropy returns the 10 random bytes following the timestamp.
func (u ULID) Entropy() []byte {
	out := make([]byte, 10)
	copy(out, u[6:])
	return out
}

// IsZero reports whether u is the zero ULID.
func (u ULID) IsZero() bool { return u == Zero }

// Compare orders two ULIDs bytewise, which is also timestamp order.
// It returns -1, 0 or +1.
func (u ULID) Compare(other ULID) int {
	for i := range u {
		switch {
		case u[i] < other[i]:
			return -1
		case u[i] > other[i]:
			return 1
		}
	}
	return 0
}

// Bytes returns a copy of the raw 16 bytes.
func (u ULID) Bytes() []byte {
	out := make([]byte, Size)
	copy(out, u[:])
	return out
}

func putTime(u *ULID, ms uint64) {
	u[0] = byte(ms >> 40)
	u[1] = byte(ms >> 32)
	u[2] = byte(ms >> 24)
	u[3] = byte(ms >> 16)
	u[4] = byte(ms >> 8)
	u[5] = byte(ms)
}

// crockford is the Crockford base32 alphabet: no I, L, O or U.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// dec maps ASCII back to 5-bit values; 0xff marks an invalid character.
var dec [256]byte

func init() {
	for i := range dec {
		dec[i] = 0xff
	}
	for i := 0; i < len(crockford); i++ {
		dec[crockford[i]] = byte(i)
		// Crockford decoding is case-insensitive.
		c := crockford[i]
		if c >= 'A' && c <= 'Z' {
			dec[c-'A'+'a'] = byte(i)
		}
	}
	// Crockford's documented confusable aliases.
	for _, p := range []struct {
		from byte
		to   byte
	}{{'o', '0'}, {'O', '0'}, {'i', '1'}, {'I', '1'}, {'l', '1'}, {'L', '1'}} {
		dec[p.from] = dec[p.to]
	}
}

// String renders the ULID as 26 Crockford base32 characters.
func (u ULID) String() string {
	// 128 bits into 26 base32 characters leaves the first character carrying
	// only 3 significant bits, so the high 2 bits are always zero.
	var out [EncodedSize]byte
	hi := binary.BigEndian.Uint64(u[0:8])
	lo := binary.BigEndian.Uint64(u[8:16])
	// Walk from the least significant end so the shifting stays simple.
	for i := EncodedSize - 1; i >= 0; i-- {
		out[i] = crockford[lo&0x1f]
		lo >>= 5
		// Pull the low 5 bits of hi down into the top of lo as it empties.
		lo |= (hi & 0x1f) << 59
		hi >>= 5
	}
	return string(out[:])
}

// MarshalText implements encoding.TextMarshaler.
func (u ULID) MarshalText() ([]byte, error) { return []byte(u.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (u *ULID) UnmarshalText(b []byte) error {
	parsed, err := Parse(string(b))
	if err != nil {
		return err
	}
	*u = parsed
	return nil
}

// Parse decodes a 26-character Crockford base32 ULID.
func Parse(s string) (ULID, error) {
	if len(s) != EncodedSize {
		return Zero, fmt.Errorf("%w: want %d chars, got %d", ErrBadEncoding, EncodedSize, len(s))
	}
	var hi, lo uint64
	for i := 0; i < EncodedSize; i++ {
		v := dec[s[i]]
		if v == 0xff {
			return Zero, fmt.Errorf("%w: bad character %q at %d", ErrBadEncoding, s[i], i)
		}
		if i == 0 && v > 7 {
			// The leading character carries 3 bits; anything larger overflows 128 bits.
			return Zero, fmt.Errorf("%w: leading character overflows 128 bits", ErrBadEncoding)
		}
		hi = hi<<5 | lo>>59
		lo = lo<<5 | uint64(v)
	}
	var u ULID
	binary.BigEndian.PutUint64(u[0:8], hi)
	binary.BigEndian.PutUint64(u[8:16], lo)
	return u, nil
}

// MustParse is Parse that panics on failure. For tests and constants only.
func MustParse(s string) ULID {
	u, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}
