package wire

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/coryforsythe/memmesh/internal/crypto"
	"github.com/coryforsythe/memmesh/internal/record"
	"github.com/coryforsythe/memmesh/internal/ulid"
)

// KeyProvider is the subset of a keyring the wire layer needs.
//
// It is an interface so the wire layer never holds keys itself and never learns
// which spaces a node subscribes to beyond the one it is asked about.
type KeyProvider interface {
	// Key returns the content key for a space and epoch, or an error wrapping
	// crypto.ErrNoKey if this node cannot read it.
	Key(space string, epoch uint32) (crypto.ContentKey, error)
	// CurrentEpoch returns the epoch new writes should use.
	CurrentEpoch(space string) (uint32, error)
}

// SealedRecord is a record's canonical bytes, transformed, padded and encrypted
// under a space key, wrapped in the small envelope sync needs in the clear.
//
// This is simultaneously the wire payload and the on-disk representation. Storing
// exactly what was received is what lets a node relay a space it cannot read, and
// it makes at-rest encryption a property of the format rather than an extra
// feature to remember to turn on.
//
// # Why the envelope is plaintext
//
// Space, epoch, record id and authoring node are readable without any key. That
// is not laziness: a relay has to maintain version vectors and answer range
// requests for spaces it cannot decrypt, and both operations are defined over the
// record id and the authoring node. A relay that could not read them could not
// gossip, which is the one job a relay has. See docs/decisions/0006.
//
// All four are bound into the AEAD's additional data, so a relay can withhold or
// misreport an envelope — detectable by any peer holding the key — but cannot
// alter one and still have the payload open.
type SealedRecord struct {
	// Space is the space the payload belongs to.
	Space record.SpaceID `json:"space"`
	// ID is the record id. Plaintext: it is the sortable key sync reconciles on.
	ID ulid.ULID `json:"id"`
	// AuthorNode is the machine that wrote the record. Plaintext: it keys version
	// vectors.
	AuthorNode record.NodeID `json:"author_node"`
	// Epoch is the key epoch the payload was sealed under, so a receiver knows
	// which key to reach for after a rotation.
	Epoch uint32 `json:"epoch"`
	// Blob is nonce||ciphertext||tag.
	Blob []byte `json:"blob"`
}

// Len returns the sealed size in bytes, which is what a relay accounts for.
func (s *SealedRecord) Len() int { return len(s.Blob) }

// aad returns the additional data binding this envelope to its ciphertext.
func (s *SealedRecord) aad() []byte {
	return crypto.RecordAAD(string(s.Space), s.Epoch, s.ID[:], string(s.AuthorNode))
}

// SealRecord runs the encrypt half of the pipeline over a record.
//
// The transform is applied before encryption and recorded inside the ciphertext,
// not in the envelope: a relay has no business knowing whether a payload was
// compressed, and putting it inside means a future transform cannot be stripped
// or forged by a node in the middle.
func SealRecord(keys KeyProvider, r *record.Record, transform Transform, entropy io.Reader) (*SealedRecord, error) {
	if !transform.Supported() {
		return nil, fmt.Errorf("%w: %s", ErrTransform, transform)
	}
	canonical, err := r.Encode()
	if err != nil {
		return nil, err
	}
	key, err := keys.Key(string(r.Space), r.Epoch)
	if err != nil {
		return nil, err
	}
	defer wipe(key[:])

	padded, err := pad(transform, canonical)
	if err != nil {
		return nil, err
	}
	out := &SealedRecord{Space: r.Space, ID: r.ID, AuthorNode: r.AuthorNode, Epoch: r.Epoch}
	blob, err := crypto.SealRandom(&key, padded, out.aad(), entropy)
	if err != nil {
		return nil, err
	}
	out.Blob = blob
	return out, nil
}

// OpenRecord reverses SealRecord and verifies the record's author signature.
//
// Verification happens here rather than being left to the caller because there is
// no legitimate path that decrypts a record and then trusts it without checking
// who wrote it. Tailnet identity authenticated the connection; this is the only
// check that survives the record having been relayed through a third node.
func OpenRecord(keys KeyProvider, s *SealedRecord) (*record.Record, error) {
	key, err := keys.Key(string(s.Space), s.Epoch)
	if err != nil {
		return nil, err
	}
	defer wipe(key[:])

	padded, err := crypto.Open(&key, s.Blob, s.aad())
	if err != nil {
		return nil, err
	}
	transform, canonical, err := unpad(padded)
	if err != nil {
		return nil, err
	}
	if !transform.Supported() {
		return nil, fmt.Errorf("%w: payload used %s", ErrTransform, transform)
	}
	r, err := record.DecodeVerified(canonical)
	if err != nil {
		return nil, err
	}
	// The envelope is what a relay routed on; the record is what the author
	// signed. If they disagree, the envelope was wrong, and the signed record is
	// the one to believe — so refuse rather than quietly preferring either.
	if r.Space != s.Space || r.Epoch != s.Epoch || r.ID != s.ID || r.AuthorNode != s.AuthorNode {
		return nil, fmt.Errorf("%w: envelope says %s/%d %s by %s, record says %s/%d %s by %s",
			ErrMalformed, s.Space, s.Epoch, s.ID, s.AuthorNode, r.Space, r.Epoch, r.ID, r.AuthorNode)
	}
	return r, nil
}

// MarshalEnvelope renders the envelope and blob as one self-describing byte
// string, which is the on-disk log entry payload and the bundle entry format.
func (s *SealedRecord) MarshalEnvelope() []byte {
	b := make([]byte, 0, 32+len(s.AuthorNode)+len(s.Blob))
	b = binary.AppendUvarint(b, uint64(s.Epoch))
	b = append(b, s.ID[:]...)
	b = binary.AppendUvarint(b, uint64(len(s.AuthorNode)))
	b = append(b, s.AuthorNode...)
	b = binary.AppendUvarint(b, uint64(len(s.Blob)))
	return append(b, s.Blob...)
}

// UnmarshalEnvelope parses what MarshalEnvelope produced, for a known space.
func UnmarshalEnvelope(space record.SpaceID, b []byte) (*SealedRecord, int, error) {
	p := &parser{buf: b}
	epoch, err := p.uvarint("entry epoch")
	if err != nil {
		return nil, 0, err
	}
	if epoch > 0xffffffff {
		return nil, 0, fmt.Errorf("%w: entry epoch %d overflows uint32", ErrMalformed, epoch)
	}
	out := &SealedRecord{Space: space, Epoch: uint32(epoch)}
	if err := p.fixed(out.ID[:], "entry id"); err != nil {
		return nil, 0, err
	}
	node, err := p.str("entry node")
	if err != nil {
		return nil, 0, err
	}
	out.AuthorNode = record.NodeID(node)
	if out.Blob, err = p.bytes("entry blob", maxPayload+crypto.Overhead); err != nil {
		return nil, 0, err
	}
	if out.ID.IsZero() {
		return nil, 0, fmt.Errorf("%w: entry id is zero", ErrMalformed)
	}
	if !out.AuthorNode.Valid() {
		return nil, 0, fmt.Errorf("%w: entry node %q is not a valid node id", ErrMalformed, node)
	}
	return out, p.pos, nil
}

// SealPayload seals arbitrary space-scoped content under the same pipeline as a
// record.
//
// No v1 message type uses it: the sync protocol's own payloads name only
// envelope-level facts a relay must read in the clear, so sealing them would break
// relaying. It exists for content that genuinely needs the space key — a future
// backfill manifest, or a distiller summary shipped as one blob — and is kept tested
// so that arrives without inventing a second sealing path.
func SealPayload(keys KeyProvider, space record.SpaceID, epoch uint32, plaintext []byte, transform Transform, entropy io.Reader) ([]byte, error) {
	if !transform.Supported() {
		return nil, fmt.Errorf("%w: %s", ErrTransform, transform)
	}
	key, err := keys.Key(string(space), epoch)
	if err != nil {
		return nil, err
	}
	defer wipe(key[:])
	padded, err := pad(transform, plaintext)
	if err != nil {
		return nil, err
	}
	return crypto.SealRandom(&key, padded, crypto.SpaceAAD(string(space), epoch), entropy)
}

// OpenPayload reverses SealPayload.
func OpenPayload(keys KeyProvider, space record.SpaceID, epoch uint32, blob []byte) ([]byte, error) {
	key, err := keys.Key(string(space), epoch)
	if err != nil {
		return nil, err
	}
	defer wipe(key[:])
	padded, err := crypto.Open(&key, blob, crypto.SpaceAAD(string(space), epoch))
	if err != nil {
		return nil, err
	}
	transform, plaintext, err := unpad(padded)
	if err != nil {
		return nil, err
	}
	if !transform.Supported() {
		return nil, fmt.Errorf("%w: payload used %s", ErrTransform, transform)
	}
	return plaintext, nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
