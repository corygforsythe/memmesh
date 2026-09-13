package record

import (
	"encoding/binary"
	"fmt"
	"math"

	"github.com/coryforsythe/memmesh/internal/hlc"
	"github.com/coryforsythe/memmesh/internal/ulid"
)

// The canonical encoding is a length-prefixed, fixed-field-order byte string.
//
// Layout, in order, with all integers as protobuf-style unsigned varints and all
// variable-length fields preceded by their byte length:
//
//	byte      FormatVersion
//	[16]byte  id
//	string    space
//	string    author_node
//	[32]byte  author_agent
//	string    author_model
//	uvarint   hlc.wall
//	uvarint   hlc.counter
//	uvarint   epoch
//	string    kind
//	bytes     body
//	uvarint   len(tags);       tags ascending, deduplicated, each a string
//	uvarint   len(supersedes); ids ascending, deduplicated, each [16]byte
//	uvarint   len(refs);        ids ascending, deduplicated, each [16]byte
//	uvarint   len(causal_ctx); entries by node ascending, each string + [16]byte
//	string    evidence
//	string    embed_model
//
// Three properties are load-bearing:
//
//   - Determinism. The same record always produces the same bytes, on any
//     platform, so a signature made on one node verifies on another.
//   - Uniqueness. Repeated fields must arrive already sorted and deduplicated,
//     and the decoder rejects anything else. Without that check a peer could
//     reorder tags and present a second valid encoding of the same signed
//     record, which is signature malleability.
//   - No self-description. Field names are not on the wire. The format version
//     byte is the only negotiation point, which is why adding a field requires
//     bumping it.

// maxEncodedSize bounds a decoder's willingness to allocate.
const maxEncodedSize = 2 << 20

// Canonical returns the signable byte string for the record, excluding the
// signature. It normalizes the record first, so calling it is how a builder
// guarantees canonical order.
func (r *Record) Canonical() ([]byte, error) {
	r.Normalize()
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r.appendCanonical(make([]byte, 0, r.estimateSize())), nil
}

// Encode returns the canonical encoding followed by the 64-byte signature. This
// is what goes to disk and, once encrypted, onto the wire.
func (r *Record) Encode() ([]byte, error) {
	body, err := r.Canonical()
	if err != nil {
		return nil, err
	}
	return append(body, r.Sig[:]...), nil
}

func (r *Record) estimateSize() int {
	n := 1 + ulid.Size + len(r.Space) + len(r.AuthorNode) + len(r.AuthorAgent) +
		len(r.AuthorModel) + len(r.Body) + len(r.Kind) + len(r.Evidence) + len(r.EmbedModel) + 48
	for _, t := range r.Tags {
		n += len(t) + 2
	}
	n += (len(r.Supersedes) + len(r.Refs)) * (ulid.Size + 1)
	for node := range r.CausalCtx {
		n += len(node) + ulid.Size + 2
	}
	return n
}

func (r *Record) appendCanonical(b []byte) []byte {
	b = append(b, FormatVersion)
	b = append(b, r.ID[:]...)
	b = appendString(b, string(r.Space))
	b = appendString(b, string(r.AuthorNode))
	b = append(b, r.AuthorAgent[:]...)
	b = appendString(b, r.AuthorModel)
	b = binary.AppendUvarint(b, r.HLC.Wall)
	b = binary.AppendUvarint(b, uint64(r.HLC.Counter))
	b = binary.AppendUvarint(b, uint64(r.Epoch))
	b = appendString(b, string(r.Kind))
	b = appendBytes(b, r.Body)

	b = binary.AppendUvarint(b, uint64(len(r.Tags)))
	for _, t := range r.Tags {
		b = appendString(b, t)
	}

	b = binary.AppendUvarint(b, uint64(len(r.Supersedes)))
	for _, id := range r.Supersedes {
		b = append(b, id[:]...)
	}

	b = binary.AppendUvarint(b, uint64(len(r.Refs)))
	for _, id := range r.Refs {
		b = append(b, id[:]...)
	}

	b = binary.AppendUvarint(b, uint64(len(r.CausalCtx)))
	for _, node := range r.CausalCtx.Nodes() {
		b = appendString(b, string(node))
		id := r.CausalCtx[node]
		b = append(b, id[:]...)
	}

	b = appendString(b, string(r.Evidence))
	b = appendString(b, r.EmbedModel)
	return b
}

func appendString(b []byte, s string) []byte {
	b = binary.AppendUvarint(b, uint64(len(s)))
	return append(b, s...)
}

func appendBytes(b, v []byte) []byte {
	b = binary.AppendUvarint(b, uint64(len(v)))
	return append(b, v...)
}

// Decode parses a record from the encoding produced by Encode: canonical bytes
// followed by a 64-byte signature.
//
// Decode enforces canonical ordering and rejects trailing bytes. It does not
// verify the signature; call Verify for that. Decoding and verifying are
// separate so a relay node can move records it cannot decrypt without ever
// needing an author's key, and so a caller can inspect a record that failed
// verification in order to report why.
func Decode(b []byte) (*Record, error) {
	if len(b) > maxEncodedSize {
		return nil, fmt.Errorf("%w: %d bytes exceeds the %d byte limit", ErrInvalid, len(b), maxEncodedSize)
	}
	if len(b) < SigSize+1 {
		return nil, fmt.Errorf("%w: %d bytes is too short to hold a signature", ErrTruncated, len(b))
	}
	split := len(b) - SigSize
	canonical, sig := b[:split], b[split:]

	d := &decoder{buf: canonical}
	var r Record

	version, err := d.byteValue()
	if err != nil {
		return nil, err
	}
	if version != FormatVersion {
		return nil, fmt.Errorf("%w: got %d, this build speaks %d", ErrUnsupportedVersion, version, FormatVersion)
	}

	if err := d.fixed(r.ID[:]); err != nil {
		return nil, err
	}
	space, err := d.str("space")
	if err != nil {
		return nil, err
	}
	r.Space = SpaceID(space)

	node, err := d.str("author_node")
	if err != nil {
		return nil, err
	}
	r.AuthorNode = NodeID(node)

	if err := d.fixed(r.AuthorAgent[:]); err != nil {
		return nil, err
	}
	if r.AuthorModel, err = d.str("author_model"); err != nil {
		return nil, err
	}

	wall, err := d.uvarint("hlc.wall")
	if err != nil {
		return nil, err
	}
	counter, err := d.uvarint("hlc.counter")
	if err != nil {
		return nil, err
	}
	if counter > math.MaxUint32 {
		return nil, fmt.Errorf("%w: hlc.counter %d overflows uint32", ErrInvalid, counter)
	}
	r.HLC = hlc.HLC{Wall: wall, Counter: uint32(counter)}

	epoch, err := d.uvarint("epoch")
	if err != nil {
		return nil, err
	}
	if epoch > math.MaxUint32 {
		return nil, fmt.Errorf("%w: epoch %d overflows uint32", ErrInvalid, epoch)
	}
	r.Epoch = uint32(epoch)

	kind, err := d.str("kind")
	if err != nil {
		return nil, err
	}
	r.Kind = Kind(kind)

	if r.Body, err = d.byteSlice("body", MaxBodyBytes); err != nil {
		return nil, err
	}

	nTags, err := d.uvarint("tag count")
	if err != nil {
		return nil, err
	}
	if nTags > MaxTags {
		return nil, fmt.Errorf("%w: %d tags, max %d", ErrInvalid, nTags, MaxTags)
	}
	if nTags > 0 {
		r.Tags = make([]string, 0, nTags)
		for i := uint64(0); i < nTags; i++ {
			t, err := d.str("tag")
			if err != nil {
				return nil, err
			}
			if i > 0 && t <= r.Tags[len(r.Tags)-1] {
				return nil, fmt.Errorf("%w: tags are not strictly ascending at index %d", ErrNotCanonical, i)
			}
			r.Tags = append(r.Tags, t)
		}
	}

	nSup, err := d.uvarint("supersedes count")
	if err != nil {
		return nil, err
	}
	if nSup > MaxSupersedes {
		return nil, fmt.Errorf("%w: %d supersedes, max %d", ErrInvalid, nSup, MaxSupersedes)
	}
	if nSup > 0 {
		r.Supersedes = make([]ulid.ULID, 0, nSup)
		for i := uint64(0); i < nSup; i++ {
			var id ulid.ULID
			if err := d.fixed(id[:]); err != nil {
				return nil, err
			}
			if i > 0 && id.Compare(r.Supersedes[len(r.Supersedes)-1]) <= 0 {
				return nil, fmt.Errorf("%w: supersedes is not strictly ascending at index %d", ErrNotCanonical, i)
			}
			r.Supersedes = append(r.Supersedes, id)
		}
	}

	nRefs, err := d.uvarint("refs count")
	if err != nil {
		return nil, err
	}
	if nRefs > MaxRefs {
		return nil, fmt.Errorf("%w: %d refs, max %d", ErrInvalid, nRefs, MaxRefs)
	}
	if nRefs > 0 {
		r.Refs = make([]ulid.ULID, 0, nRefs)
		for i := uint64(0); i < nRefs; i++ {
			var id ulid.ULID
			if err := d.fixed(id[:]); err != nil {
				return nil, err
			}
			if i > 0 && id.Compare(r.Refs[len(r.Refs)-1]) <= 0 {
				return nil, fmt.Errorf("%w: refs is not strictly ascending at index %d", ErrNotCanonical, i)
			}
			r.Refs = append(r.Refs, id)
		}
	}

	nCtx, err := d.uvarint("causal_ctx count")
	if err != nil {
		return nil, err
	}
	if nCtx > MaxCausalEntries {
		return nil, fmt.Errorf("%w: causal_ctx has %d entries, max %d", ErrInvalid, nCtx, MaxCausalEntries)
	}
	if nCtx > 0 {
		r.CausalCtx = make(VersionVector, nCtx)
		var prev string
		for i := uint64(0); i < nCtx; i++ {
			name, err := d.str("causal_ctx node")
			if err != nil {
				return nil, err
			}
			if i > 0 && name <= prev {
				return nil, fmt.Errorf("%w: causal_ctx nodes are not strictly ascending at index %d", ErrNotCanonical, i)
			}
			prev = name
			var id ulid.ULID
			if err := d.fixed(id[:]); err != nil {
				return nil, err
			}
			r.CausalCtx[NodeID(name)] = id
		}
	}

	evidence, err := d.str("evidence")
	if err != nil {
		return nil, err
	}
	r.Evidence = Evidence(evidence)

	if r.EmbedModel, err = d.str("embed_model"); err != nil {
		return nil, err
	}

	if d.remaining() != 0 {
		return nil, fmt.Errorf("%w: %d trailing bytes after the last field", ErrNotCanonical, d.remaining())
	}

	copy(r.Sig[:], sig)

	if err := r.Validate(); err != nil {
		return nil, err
	}
	return &r, nil
}

// decoder is a bounds-checked cursor over the canonical bytes. Every read
// reports its own field name so a rejection says which field was wrong, which
// matters when the sender is a different version of the daemon.
type decoder struct {
	buf []byte
	pos int
}

func (d *decoder) remaining() int { return len(d.buf) - d.pos }

func (d *decoder) byteValue() (byte, error) {
	if d.remaining() < 1 {
		return 0, fmt.Errorf("%w: want 1 byte for the format version", ErrTruncated)
	}
	v := d.buf[d.pos]
	d.pos++
	return v, nil
}

func (d *decoder) fixed(dst []byte) error {
	if d.remaining() < len(dst) {
		return fmt.Errorf("%w: want %d bytes, have %d", ErrTruncated, len(dst), d.remaining())
	}
	copy(dst, d.buf[d.pos:d.pos+len(dst)])
	d.pos += len(dst)
	return nil
}

func (d *decoder) uvarint(field string) (uint64, error) {
	v, n := binary.Uvarint(d.buf[d.pos:])
	switch {
	case n == 0:
		return 0, fmt.Errorf("%w: reading %s", ErrTruncated, field)
	case n < 0:
		return 0, fmt.Errorf("%w: %s has an overlong varint", ErrNotCanonical, field)
	}
	// A varint with leading zero groups encodes the same value in more bytes,
	// which would be a second valid encoding of the same record.
	if minimalUvarintLen(v) != n {
		return 0, fmt.Errorf("%w: %s varint is not minimally encoded", ErrNotCanonical, field)
	}
	d.pos += n
	return v, nil
}

func minimalUvarintLen(v uint64) int {
	n := 1
	for v >= 0x80 {
		v >>= 7
		n++
	}
	return n
}

func (d *decoder) byteSlice(field string, max int) ([]byte, error) {
	n, err := d.uvarint(field + " length")
	if err != nil {
		return nil, err
	}
	if n > uint64(max) {
		return nil, fmt.Errorf("%w: %s is %d bytes, max %d", ErrInvalid, field, n, max)
	}
	if uint64(d.remaining()) < n {
		return nil, fmt.Errorf("%w: %s wants %d bytes, have %d", ErrTruncated, field, n, d.remaining())
	}
	if n == 0 {
		d.pos += 0
		return nil, nil
	}
	out := make([]byte, n)
	copy(out, d.buf[d.pos:d.pos+int(n)])
	d.pos += int(n)
	return out, nil
}

func (d *decoder) str(field string) (string, error) {
	b, err := d.byteSlice(field, maxEncodedSize)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
