package wire

import (
	"encoding/binary"
	"fmt"
)

// Size buckets for payload padding.
//
// Space IDs, record counts, timing and sizes stay visible to a relay no matter
// what (plan §3.4). Padding cannot hide that traffic happened; it blunts size
// correlation, which is the part that leaks content. A 40-byte "assumes UTC" and
// a 40-byte "assumes local time" were always indistinguishable; padding is what
// stops a 300-byte record being distinguishable from a 3000-byte one.
//
// This matters because the threat model includes a curious *member* — someone
// who legitimately relays a space they cannot read — not only an outside
// observer.
var sizeBuckets = []int{256, 1024, 4096, 16384, 65536}

// bucketStep is the granularity above the largest bucket. Payloads larger than
// the top bucket round up to a multiple of this, so a 400 KB blob does not
// advertise its exact length either.
const bucketStep = 65536

// maxPayload caps a padded payload, bounding what a decoder will allocate.
const maxPayload = 4 << 20

// bucketFor returns the padded length for a plaintext of n bytes.
func bucketFor(n int) int {
	for _, b := range sizeBuckets {
		if n <= b {
			return b
		}
	}
	// Round up to the next whole step above the top bucket.
	steps := (n + bucketStep - 1) / bucketStep
	return steps * bucketStep
}

// Buckets returns the configured size buckets, for documentation and tests.
func Buckets() []int { return append([]int(nil), sizeBuckets...) }

// pad frames a payload for encryption: the transform byte, the true length, the
// data, and zeroes out to a size bucket.
//
// The length prefix is what makes unpadding unambiguous. Trailing-zero stripping
// would be ambiguous for any payload that legitimately ends in a zero byte, and
// record bodies frequently do.
func pad(transform Transform, data []byte) ([]byte, error) {
	header := 1 + binary.MaxVarintLen64
	if len(data)+header > maxPayload {
		return nil, fmt.Errorf("%w: payload of %d bytes exceeds the %d byte limit", ErrTooLarge, len(data), maxPayload)
	}

	var prefix [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(prefix[:], uint64(len(data)))
	body := 1 + n + len(data)
	total := bucketFor(body)

	out := make([]byte, total)
	out[0] = byte(transform)
	copy(out[1:], prefix[:n])
	copy(out[1+n:], data)
	return out, nil
}

// unpad reverses pad, returning the transform and the original data.
//
// It checks that the padding is actually zeroes. A peer that hides bytes in the
// padding is either broken or probing, and either way the payload should be
// refused rather than silently accepted.
func unpad(padded []byte) (Transform, []byte, error) {
	if len(padded) < 2 {
		return 0, nil, fmt.Errorf("%w: padded payload is %d bytes", ErrMalformed, len(padded))
	}
	transform := Transform(padded[0])
	length, n := binary.Uvarint(padded[1:])
	switch {
	case n == 0:
		return 0, nil, fmt.Errorf("%w: truncated payload length", ErrMalformed)
	case n < 0:
		return 0, nil, fmt.Errorf("%w: overlong payload length", ErrMalformed)
	}
	start := 1 + n
	if uint64(len(padded)-start) < length {
		return 0, nil, fmt.Errorf("%w: payload claims %d bytes, %d available", ErrMalformed, length, len(padded)-start)
	}
	end := start + int(length)
	for i := end; i < len(padded); i++ {
		if padded[i] != 0 {
			return 0, nil, fmt.Errorf("%w: padding at offset %d is not zero", ErrMalformed, i)
		}
	}
	if want := bucketFor(end); want != len(padded) {
		return 0, nil, fmt.Errorf("%w: payload is %d bytes, the bucket for %d bytes is %d", ErrMalformed, len(padded), end, want)
	}
	out := make([]byte, length)
	copy(out, padded[start:end])
	return transform, out, nil
}
