package wire

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/coryforsythe/memmesh/internal/record"
)

// MaxFrameSize caps one frame on the wire.
//
// It bounds what a receiver will allocate for a peer it has not yet decided to
// trust. Backfill is chunked rather than sent as one giant frame precisely so this
// limit can stay small (plan §5.1.5).
const MaxFrameSize = 8 << 20

// maxSpaceLen is the longest space id a frame header can carry, matching the
// record package's limit.
const maxSpaceLen = 200

// Frame is one message between peers.
//
// The header is deliberately readable by a relay: it needs the space and the
// message type to route and account for a frame it cannot decrypt. Everything
// content-bearing is inside Payload, already sealed.
type Frame struct {
	// Version is the negotiated wire version.
	Version uint8 `json:"version"`
	// Type says what the frame carries.
	Type MsgType `json:"type"`
	// Space is the space the frame concerns, empty for connection-level control
	// frames.
	Space record.SpaceID `json:"space,omitempty"`
	// Epoch is the key epoch the payload was sealed under, zero for plaintext
	// control frames.
	Epoch uint32 `json:"epoch"`
	// Payload is sealed content for space frames, or plaintext for control
	// frames whose type is not encrypted.
	Payload []byte `json:"payload"`
	// Sender is the agent key of the node that sent this frame — not
	// necessarily the author of the records inside it.
	Sender record.AgentID `json:"sender"`
	// Sig is the sender's signature over the header and payload.
	Sig [record.SigSize]byte `json:"sig"`
}

// PayloadClass says how a frame's payload is protected, which determines what the
// frame header may carry and who can read the contents.
type PayloadClass uint8

// The payload classes.
const (
	// ClassPlain is an unencrypted control payload. Hello and the liveness types
	// are plaintext by necessity: a node must be able to greet a peer and measure
	// clock skew against it before the two share any key.
	ClassPlain PayloadClass = iota
	// ClassMeta is a space-scoped payload carried in the clear.
	//
	// It may name only envelope-level facts — space, epoch, node ids, record ids —
	// which a relay already reads in order to gossip (docs/decisions/0006). It
	// never carries record content. Keeping these plaintext is not a concession:
	// a relay holds no key, so a sealed want list would make relaying impossible,
	// which is the one job a relay exists to do.
	ClassMeta
	// ClassBundle is a collection of record payloads that were already sealed
	// when they were written. The frame does not re-encrypt them: they are
	// forwarded byte for byte, which is what allows a relay to pass on a space it
	// cannot read, and what lets a receiver store exactly what the author signed.
	// Each entry carries its own epoch, so one bundle may span a rotation.
	ClassBundle
)

// Class returns how this message type's payload is protected.
func (t MsgType) Class() PayloadClass {
	switch t {
	case MsgHello, MsgHelloAck, MsgPing, MsgPong, MsgError, MsgVectors:
		// Vectors carries its own space list in the payload rather than in the
		// header, because one exchange covers every space at once.
		return ClassPlain
	case MsgRecords, MsgBackfillChunk:
		return ClassBundle
	default:
		return ClassMeta
	}
}

// header returns the signed prefix: everything except the sender key and
// signature. The outer length field is excluded, so a frame's signature does not
// depend on how it was length-delimited.
func (f *Frame) header() []byte {
	b := make([]byte, 0, 16+len(f.Space))
	b = append(b, f.Version, byte(f.Type))
	var epoch [4]byte
	binary.BigEndian.PutUint32(epoch[:], f.Epoch)
	b = append(b, epoch[:]...)
	b = append(b, byte(len(f.Space)))
	b = append(b, f.Space...)
	var plen [4]byte
	binary.BigEndian.PutUint32(plen[:], uint32(len(f.Payload)))
	return append(b, plen[:]...)
}

// signable is the byte string a frame signature covers: header then payload.
func (f *Frame) signable() []byte {
	return append(f.header(), f.Payload...)
}

// Sign fills in the frame's Sender and Sig.
func (f *Frame) Sign(signer *record.Signer) error {
	if err := f.validate(); err != nil {
		return err
	}
	f.Sender = signer.AgentID()
	sig := signer.SignBytes(record.FrameSignDomain, f.signable())
	copy(f.Sig[:], sig)
	return nil
}

// Verify checks the frame signature against the sender key the frame claims.
//
// This authenticates the hop, which is a different question from who authored the
// records inside. A relay can and should verify frames it cannot decrypt; that is
// what stops it being used to inject traffic it did not originate.
func (f *Frame) Verify() error {
	if f.Sender.IsZero() {
		return fmt.Errorf("%w: frame has no sender", ErrBadFrameSignature)
	}
	if !record.VerifyBytes(f.Sender, record.FrameSignDomain, f.signable(), f.Sig[:]) {
		return fmt.Errorf("%w: %s frame from %s", ErrBadFrameSignature, f.Type, f.Sender.Fingerprint())
	}
	return nil
}

func (f *Frame) validate() error {
	if f.Version < MinVersion || f.Version > Version {
		return fmt.Errorf("%w: frame declares version %d", ErrVersion, f.Version)
	}
	if !f.Type.Known() {
		return fmt.Errorf("%w: unknown message type %d", ErrMalformed, uint8(f.Type))
	}
	if len(f.Space) > maxSpaceLen {
		return fmt.Errorf("%w: space id is %d bytes, max %d", ErrMalformed, len(f.Space), maxSpaceLen)
	}
	switch f.Type.Class() {
	case ClassPlain:
		if f.Space != "" {
			return fmt.Errorf("%w: %s is a control frame and must not name a space", ErrMalformed, f.Type)
		}
		if f.Epoch != 0 {
			return fmt.Errorf("%w: %s is a control frame and must not name an epoch", ErrMalformed, f.Type)
		}
	case ClassMeta:
		if f.Space == "" {
			return fmt.Errorf("%w: %s frames must name a space", ErrMalformed, f.Type)
		}
	case ClassBundle:
		if f.Space == "" {
			return fmt.Errorf("%w: %s frames must name a space", ErrMalformed, f.Type)
		}
		// Each entry in a bundle carries its own epoch, so a header epoch would
		// be either redundant or a lie about entries that disagree with it.
		if f.Epoch != 0 {
			return fmt.Errorf("%w: %s carries per-entry epochs; the header epoch must be zero", ErrMalformed, f.Type)
		}
	}
	if len(f.Payload) > MaxFrameSize {
		return fmt.Errorf("%w: payload is %d bytes", ErrTooLarge, len(f.Payload))
	}
	return nil
}

// Marshal renders the frame with a 4-byte big-endian length prefix, ready to
// write to a stream.
func (f *Frame) Marshal() ([]byte, error) {
	if err := f.validate(); err != nil {
		return nil, err
	}
	body := f.signable()
	total := len(body) + record.PublicKeySize + record.SigSize
	if total+4 > MaxFrameSize {
		return nil, fmt.Errorf("%w: %d bytes", ErrTooLarge, total+4)
	}
	out := make([]byte, 0, 4+total)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(total))
	out = append(out, length[:]...)
	out = append(out, body...)
	out = append(out, f.Sender[:]...)
	return append(out, f.Sig[:]...), nil
}

// WriteFrame marshals a frame and writes it to w.
func WriteFrame(w io.Writer, f *Frame) error {
	b, err := f.Marshal()
	if err != nil {
		return err
	}
	if _, err := w.Write(b); err != nil {
		return fmt.Errorf("wire: write frame: %w", err)
	}
	return nil
}

// ReadFrame reads one length-delimited frame from r and verifies its signature.
//
// Verification is not optional here. An unverified frame has no business reaching
// the sync layer, and making the reader the enforcement point means no call site
// can forget.
func ReadFrame(r io.Reader) (*Frame, error) {
	var length [4]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		if err == io.EOF {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("wire: read frame length: %w", err)
	}
	total := binary.BigEndian.Uint32(length[:])
	if total > MaxFrameSize {
		return nil, fmt.Errorf("%w: peer announced %d bytes, limit is %d", ErrTooLarge, total, MaxFrameSize)
	}
	minimum := uint32(2 + 4 + 1 + 4 + record.PublicKeySize + record.SigSize)
	if total < minimum {
		return nil, fmt.Errorf("%w: frame of %d bytes cannot hold a header", ErrMalformed, total)
	}
	buf := make([]byte, total)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("wire: read frame body: %w", err)
	}
	f, err := Unmarshal(buf)
	if err != nil {
		return nil, err
	}
	if err := f.Verify(); err != nil {
		return nil, err
	}
	return f, nil
}

// Unmarshal parses a frame body, excluding the length prefix. It does not verify
// the signature; ReadFrame does that.
func Unmarshal(buf []byte) (*Frame, error) {
	const tail = record.PublicKeySize + record.SigSize
	if len(buf) < tail+11 {
		return nil, fmt.Errorf("%w: frame body is %d bytes", ErrMalformed, len(buf))
	}
	var f Frame
	p := 0
	f.Version = buf[p]
	p++
	f.Type = MsgType(buf[p])
	p++
	f.Epoch = binary.BigEndian.Uint32(buf[p : p+4])
	p += 4
	spaceLen := int(buf[p])
	p++
	if spaceLen > maxSpaceLen || p+spaceLen+4 > len(buf)-tail {
		return nil, fmt.Errorf("%w: space length %d does not fit the frame", ErrMalformed, spaceLen)
	}
	f.Space = record.SpaceID(buf[p : p+spaceLen])
	p += spaceLen
	payloadLen := int(binary.BigEndian.Uint32(buf[p : p+4]))
	p += 4
	if p+payloadLen != len(buf)-tail {
		return nil, fmt.Errorf("%w: payload length %d does not match the frame size", ErrMalformed, payloadLen)
	}
	if payloadLen > 0 {
		f.Payload = make([]byte, payloadLen)
		copy(f.Payload, buf[p:p+payloadLen])
	}
	p += payloadLen
	copy(f.Sender[:], buf[p:p+record.PublicKeySize])
	p += record.PublicKeySize
	copy(f.Sig[:], buf[p:p+record.SigSize])

	if err := f.validate(); err != nil {
		return nil, err
	}
	return &f, nil
}

// NewControlFrame builds and signs an unencrypted control frame.
func NewControlFrame(typ MsgType, version uint8, payload []byte, signer *record.Signer) (*Frame, error) {
	if typ.Class() != ClassPlain {
		return nil, fmt.Errorf("%w: %s is not a control frame", ErrMalformed, typ)
	}
	f := &Frame{Version: version, Type: typ, Payload: payload}
	if err := f.Sign(signer); err != nil {
		return nil, err
	}
	return f, nil
}

// NewMetaFrame builds and signs a space-scoped frame whose payload is plaintext
// envelope-level metadata.
func NewMetaFrame(typ MsgType, version uint8, space record.SpaceID, epoch uint32, payload []byte, signer *record.Signer) (*Frame, error) {
	if typ.Class() != ClassMeta {
		return nil, fmt.Errorf("%w: %s does not carry space-scoped metadata", ErrMalformed, typ)
	}
	f := &Frame{Version: version, Type: typ, Space: space, Epoch: epoch, Payload: payload}
	if err := f.Sign(signer); err != nil {
		return nil, err
	}
	return f, nil
}

// NewBundleFrame builds and signs a frame carrying already-sealed record payloads.
func NewBundleFrame(typ MsgType, version uint8, space record.SpaceID, bundle []byte, signer *record.Signer) (*Frame, error) {
	if typ.Class() != ClassBundle {
		return nil, fmt.Errorf("%w: %s does not carry a bundle", ErrMalformed, typ)
	}
	f := &Frame{Version: version, Type: typ, Space: space, Payload: bundle}
	if err := f.Sign(signer); err != nil {
		return nil, err
	}
	return f, nil
}
