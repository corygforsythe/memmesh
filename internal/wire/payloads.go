package wire

import (
	"encoding/binary"
	"fmt"

	"github.com/coryforsythe/memmesh/internal/hlc"
	"github.com/coryforsythe/memmesh/internal/record"
	"github.com/coryforsythe/memmesh/internal/ulid"
)

// This file holds the payload codecs for each message type. They use the same
// length-prefixed, minimally-encoded style as the record's canonical encoding, so
// there is one set of parsing habits in the codebase rather than two.
//
// Payloads are not signed individually: the frame signature covers the header and
// the whole payload together, which is what stops a relay splicing a payload from
// one frame into another.

// Hello opens a connection.
//
// It is plaintext, so everything in it is visible to anyone who can see the
// connection. That is why it carries no space contents — only the identifiers a
// peer needs to decide whether to talk, and the clock reading the skew check
// depends on.
type Hello struct {
	// Versions are the wire versions the sender supports, newest first.
	Versions []uint8
	// Node is the sender's node id.
	Node record.NodeID
	// Software identifies the build, for the version column in memctl members.
	Software string
	// WallMillis is the sender's physical clock reading. Comparing it with the
	// receiver's is the clock-skew health check: HLC tiebreaking degrades quietly
	// under drift, so the drift has to be measured explicitly (plan §8.4).
	WallMillis uint64
	// Spaces are the spaces the sender wants to sync. Subscriptions are residual
	// metadata a peer necessarily learns (plan §3.4); there is no way to ask for a
	// space without naming it.
	Spaces []record.SpaceID
	// Relaying reports whether the sender is willing to carry spaces it holds no
	// key for. Opt-in and off by default (plan §3.5), so a peer must not assume
	// its records will be relayed.
	Relaying bool
	// EmbedModel is the sender's local embedding model id. A mismatch does not
	// prevent sync — text is shipped and re-embedded locally — but it degrades
	// recall silently, so peers exchange it in order to complain loudly.
	EmbedModel string
}

// Encode renders the Hello payload.
func (h *Hello) Encode() []byte {
	b := make([]byte, 0, 64+len(h.Node)+len(h.Software)+len(h.EmbedModel)+len(h.Spaces)*24)
	b = binary.AppendUvarint(b, uint64(len(h.Versions)))
	b = append(b, h.Versions...)
	b = appendStr(b, string(h.Node))
	b = appendStr(b, h.Software)
	b = binary.AppendUvarint(b, h.WallMillis)
	b = binary.AppendUvarint(b, uint64(len(h.Spaces)))
	for _, s := range h.Spaces {
		b = appendStr(b, string(s))
	}
	if h.Relaying {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	return appendStr(b, h.EmbedModel)
}

// DecodeHello parses a Hello payload.
func DecodeHello(payload []byte) (*Hello, error) {
	p := &parser{buf: payload}
	var h Hello

	n, err := p.uvarint("version count")
	if err != nil {
		return nil, err
	}
	if n > 32 {
		return nil, fmt.Errorf("%w: hello offers %d versions", ErrMalformed, n)
	}
	for i := uint64(0); i < n; i++ {
		v, err := p.byteValue("version")
		if err != nil {
			return nil, err
		}
		h.Versions = append(h.Versions, v)
	}
	node, err := p.str("node")
	if err != nil {
		return nil, err
	}
	h.Node = record.NodeID(node)
	if h.Software, err = p.str("software"); err != nil {
		return nil, err
	}
	if h.WallMillis, err = p.uvarint("wall"); err != nil {
		return nil, err
	}
	spaces, err := p.uvarint("space count")
	if err != nil {
		return nil, err
	}
	if spaces > 4096 {
		return nil, fmt.Errorf("%w: hello lists %d spaces", ErrMalformed, spaces)
	}
	for i := uint64(0); i < spaces; i++ {
		s, err := p.str("space")
		if err != nil {
			return nil, err
		}
		h.Spaces = append(h.Spaces, record.SpaceID(s))
	}
	relaying, err := p.byteValue("relaying")
	if err != nil {
		return nil, err
	}
	if relaying > 1 {
		return nil, fmt.Errorf("%w: relaying flag is %d", ErrMalformed, relaying)
	}
	h.Relaying = relaying == 1
	if h.EmbedModel, err = p.str("embed_model"); err != nil {
		return nil, err
	}
	if err := p.done(); err != nil {
		return nil, err
	}
	if !h.Node.Valid() {
		return nil, fmt.Errorf("%w: hello node %q is not a valid node id", ErrMalformed, string(h.Node))
	}
	return &h, nil
}

// Vectors is a peer's sync state: one version vector per space it is offering.
//
// This is the whole handshake payload. Cost scales with the number of spaces and
// participating nodes, not with corpus size, which is what makes reconnecting
// after three weeks offline cheap.
type Vectors struct {
	// Vectors maps space to the sender's high-water marks for that space.
	Vectors map[record.SpaceID]record.VersionVector
}

// Encode renders the Vectors payload, deterministically.
func (v *Vectors) Encode() []byte {
	spaces := make([]string, 0, len(v.Vectors))
	for s := range v.Vectors {
		spaces = append(spaces, string(s))
	}
	sortStrings(spaces)

	b := binary.AppendUvarint(nil, uint64(len(spaces)))
	for _, s := range spaces {
		b = appendStr(b, s)
		vv := v.Vectors[record.SpaceID(s)]
		nodes := vv.Nodes()
		b = binary.AppendUvarint(b, uint64(len(nodes)))
		for _, node := range nodes {
			b = appendStr(b, string(node))
			id := vv[node]
			b = append(b, id[:]...)
		}
	}
	return b
}

// DecodeVectors parses a Vectors payload.
func DecodeVectors(payload []byte) (*Vectors, error) {
	p := &parser{buf: payload}
	nSpaces, err := p.uvarint("space count")
	if err != nil {
		return nil, err
	}
	if nSpaces > 4096 {
		return nil, fmt.Errorf("%w: %d spaces in one vectors payload", ErrMalformed, nSpaces)
	}
	out := &Vectors{Vectors: make(map[record.SpaceID]record.VersionVector, nSpaces)}
	for i := uint64(0); i < nSpaces; i++ {
		space, err := p.str("space")
		if err != nil {
			return nil, err
		}
		nNodes, err := p.uvarint("node count")
		if err != nil {
			return nil, err
		}
		if nNodes > record.MaxCausalEntries {
			return nil, fmt.Errorf("%w: %d nodes in one vector", ErrMalformed, nNodes)
		}
		vv := record.NewVersionVector()
		for j := uint64(0); j < nNodes; j++ {
			node, err := p.str("node")
			if err != nil {
				return nil, err
			}
			var id ulid.ULID
			if err := p.fixed(id[:], "high-water id"); err != nil {
				return nil, err
			}
			vv.Observe(record.NodeID(node), id)
		}
		out.Vectors[record.SpaceID(space)] = vv
	}
	if err := p.done(); err != nil {
		return nil, err
	}
	return out, nil
}

// Want asks a peer for the record ranges the sender is missing, per authoring
// node.
type Want struct {
	// Ranges maps authoring node to the interval the sender needs.
	Ranges map[record.NodeID]record.Range
	// Limit caps how many records the peer should return in one response, so a
	// receiver can pace a large backfill instead of being handed all of it.
	Limit uint32
}

// Encode renders the Want payload, deterministically.
func (w *Want) Encode() []byte {
	nodes := make([]string, 0, len(w.Ranges))
	for n := range w.Ranges {
		nodes = append(nodes, string(n))
	}
	sortStrings(nodes)

	b := binary.AppendUvarint(nil, uint64(w.Limit))
	b = binary.AppendUvarint(b, uint64(len(nodes)))
	for _, n := range nodes {
		b = appendStr(b, n)
		r := w.Ranges[record.NodeID(n)]
		b = append(b, r.After[:]...)
		b = append(b, r.Through[:]...)
	}
	return b
}

// DecodeWant parses a Want payload.
func DecodeWant(payload []byte) (*Want, error) {
	p := &parser{buf: payload}
	limit, err := p.uvarint("limit")
	if err != nil {
		return nil, err
	}
	if limit > 1<<20 {
		return nil, fmt.Errorf("%w: want limit %d is implausible", ErrMalformed, limit)
	}
	n, err := p.uvarint("range count")
	if err != nil {
		return nil, err
	}
	if n > record.MaxCausalEntries {
		return nil, fmt.Errorf("%w: %d ranges in one want", ErrMalformed, n)
	}
	out := &Want{Ranges: make(map[record.NodeID]record.Range, n), Limit: uint32(limit)}
	for i := uint64(0); i < n; i++ {
		node, err := p.str("node")
		if err != nil {
			return nil, err
		}
		var r record.Range
		if err := p.fixed(r.After[:], "range after"); err != nil {
			return nil, err
		}
		if err := p.fixed(r.Through[:], "range through"); err != nil {
			return nil, err
		}
		if r.After.Compare(r.Through) > 0 {
			return nil, fmt.Errorf("%w: range for %q ends before it starts", ErrMalformed, node)
		}
		out.Ranges[record.NodeID(node)] = r
	}
	if err := p.done(); err != nil {
		return nil, err
	}
	return out, nil
}

// MaxBundleEntries caps how many sealed payloads one bundle may carry, bounding
// both allocation and the work a receiver commits to before it can refuse.
const MaxBundleEntries = 4096

// EncodeBundle renders a list of sealed record payloads for one space.
//
// The payloads are passed through untouched. A relay can build and forward a
// bundle for a space it cannot read, and a receiver stores the same bytes the
// author sealed — so the author's signature stays verifiable no matter how many
// hops it took.
func EncodeBundle(entries []*SealedRecord) ([]byte, error) {
	if len(entries) > MaxBundleEntries {
		return nil, fmt.Errorf("%w: %d entries, max %d", ErrTooLarge, len(entries), MaxBundleEntries)
	}
	b := binary.AppendUvarint(nil, uint64(len(entries)))
	for i, e := range entries {
		if e == nil {
			return nil, fmt.Errorf("%w: bundle entry %d is nil", ErrMalformed, i)
		}
		b = append(b, e.MarshalEnvelope()...)
		if len(b) > MaxFrameSize {
			return nil, fmt.Errorf("%w: bundle exceeds the frame limit", ErrTooLarge)
		}
	}
	return b, nil
}

// DecodeBundle parses a bundle for the given space.
func DecodeBundle(space record.SpaceID, payload []byte) ([]*SealedRecord, error) {
	p := &parser{buf: payload}
	n, err := p.uvarint("entry count")
	if err != nil {
		return nil, err
	}
	if n > MaxBundleEntries {
		return nil, fmt.Errorf("%w: bundle claims %d entries, max %d", ErrTooLarge, n, MaxBundleEntries)
	}
	out := make([]*SealedRecord, 0, n)
	for i := uint64(0); i < n; i++ {
		entry, used, err := UnmarshalEnvelope(space, p.buf[p.pos:])
		if err != nil {
			return nil, fmt.Errorf("bundle entry %d: %w", i, err)
		}
		p.pos += used
		out = append(out, entry)
	}
	if err := p.done(); err != nil {
		return nil, err
	}
	return out, nil
}

// Liveness is the payload of a ping or pong.
//
// It carries a clock reading rather than only a nonce, because reachability and
// clock skew are measured on the same round trip and there is no reason to make
// two.
type Liveness struct {
	// Nonce matches a pong to its ping.
	Nonce uint64
	// WallMillis is the sender's physical clock reading.
	WallMillis uint64
	// HLC is the sender's current logical reading, which reveals how far ahead
	// its logical clock has been dragged by peers.
	HLC hlc.HLC
}

// Encode renders the Liveness payload.
func (l *Liveness) Encode() []byte {
	b := binary.AppendUvarint(nil, l.Nonce)
	b = binary.AppendUvarint(b, l.WallMillis)
	b = binary.AppendUvarint(b, l.HLC.Wall)
	return binary.AppendUvarint(b, uint64(l.HLC.Counter))
}

// DecodeLiveness parses a Liveness payload.
func DecodeLiveness(payload []byte) (*Liveness, error) {
	p := &parser{buf: payload}
	var l Liveness
	var err error
	if l.Nonce, err = p.uvarint("nonce"); err != nil {
		return nil, err
	}
	if l.WallMillis, err = p.uvarint("wall"); err != nil {
		return nil, err
	}
	if l.HLC.Wall, err = p.uvarint("hlc.wall"); err != nil {
		return nil, err
	}
	counter, err := p.uvarint("hlc.counter")
	if err != nil {
		return nil, err
	}
	if counter > 0xffffffff {
		return nil, fmt.Errorf("%w: hlc counter overflows uint32", ErrMalformed)
	}
	l.HLC.Counter = uint32(counter)
	if err := p.done(); err != nil {
		return nil, err
	}
	return &l, nil
}

// ErrorPayload reports a refusal to a peer.
//
// It carries a machine-readable code and a human-readable message, and never
// space content: a node must be able to say "I have no key for that space"
// without that answer itself leaking anything.
type ErrorPayload struct {
	Code    string
	Message string
}

// Error codes a peer may send.
const (
	// ErrCodeVersion means no common wire version.
	ErrCodeVersion = "version"
	// ErrCodeNoSpace means the sender does not carry that space.
	ErrCodeNoSpace = "no_space"
	// ErrCodeNoKey means the sender carries the space but cannot read it.
	ErrCodeNoKey = "no_key"
	// ErrCodeRejected means the request was refused by policy.
	ErrCodeRejected = "rejected"
	// ErrCodeMalformed means the request did not parse.
	ErrCodeMalformed = "malformed"
	// ErrCodeBusy means the sender is shedding load; retry later.
	ErrCodeBusy = "busy"
)

// Encode renders the error payload.
func (e *ErrorPayload) Encode() []byte {
	return appendStr(appendStr(nil, e.Code), e.Message)
}

// DecodeError parses an error payload.
func DecodeError(payload []byte) (*ErrorPayload, error) {
	p := &parser{buf: payload}
	code, err := p.str("code")
	if err != nil {
		return nil, err
	}
	msg, err := p.str("message")
	if err != nil {
		return nil, err
	}
	if err := p.done(); err != nil {
		return nil, err
	}
	return &ErrorPayload{Code: code, Message: msg}, nil
}

func appendStr(b []byte, s string) []byte {
	b = binary.AppendUvarint(b, uint64(len(s)))
	return append(b, s...)
}

func sortStrings(s []string) {
	// Insertion sort: these lists are short (spaces per node, nodes per space)
	// and this keeps the package free of a sort import for one call site.
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// parser is a bounds-checked cursor shared by the payload decoders.
type parser struct {
	buf []byte
	pos int
}

func (p *parser) remaining() int { return len(p.buf) - p.pos }

func (p *parser) done() error {
	if p.remaining() != 0 {
		return fmt.Errorf("%w: %d trailing bytes in payload", ErrMalformed, p.remaining())
	}
	return nil
}

func (p *parser) byteValue(field string) (byte, error) {
	if p.remaining() < 1 {
		return 0, fmt.Errorf("%w: truncated reading %s", ErrMalformed, field)
	}
	v := p.buf[p.pos]
	p.pos++
	return v, nil
}

func (p *parser) uvarint(field string) (uint64, error) {
	v, n := binary.Uvarint(p.buf[p.pos:])
	switch {
	case n == 0:
		return 0, fmt.Errorf("%w: truncated reading %s", ErrMalformed, field)
	case n < 0:
		return 0, fmt.Errorf("%w: overlong varint for %s", ErrMalformed, field)
	}
	p.pos += n
	return v, nil
}

func (p *parser) fixed(dst []byte, field string) error {
	if p.remaining() < len(dst) {
		return fmt.Errorf("%w: want %d bytes for %s, have %d", ErrMalformed, len(dst), field, p.remaining())
	}
	copy(dst, p.buf[p.pos:p.pos+len(dst)])
	p.pos += len(dst)
	return nil
}

func (p *parser) bytes(field string, max int) ([]byte, error) {
	n, err := p.uvarint(field + " length")
	if err != nil {
		return nil, err
	}
	if n > uint64(max) {
		return nil, fmt.Errorf("%w: %s is %d bytes, max %d", ErrTooLarge, field, n, max)
	}
	if uint64(p.remaining()) < n {
		return nil, fmt.Errorf("%w: %s wants %d bytes, have %d", ErrMalformed, field, n, p.remaining())
	}
	out := make([]byte, n)
	copy(out, p.buf[p.pos:p.pos+int(n)])
	p.pos += int(n)
	return out, nil
}

func (p *parser) str(field string) (string, error) {
	b, err := p.bytes(field, maxPayload)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
