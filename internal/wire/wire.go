// Package wire defines the on-the-wire and on-disk envelope for records, and
// the frame format peers exchange.
//
// The pipeline is:
//
//	serialize → [reserved] → encrypt → frame → sign
//
// Each stage has a job, and the order is load-bearing:
//
//   - serialize produces the record's canonical bytes (internal/record).
//   - [reserved] is a transform slot that is a no-op passthrough today.
//     Compression is out of scope for v1, but the slot exists so re-adding it
//     later is not a breaking change (plan §5.2, §10).
//   - encrypt seals the transformed bytes under the space's content key for the
//     epoch in force, binding the space and epoch as additional data.
//   - frame wraps the sealed payload in a header a relay can route on without
//     holding any key.
//   - sign covers the header and payload with the sending agent's key, so a
//     relay can verify a frame it cannot read.
//
// The sealed payload is also the on-disk representation. A node stores exactly
// what it received, which is what lets it relay a space whose key it does not
// hold, and what makes at-rest encryption free rather than a separate feature.
//
// # Two signature layers
//
// Frames are signed by the sender; records are signed by their author. They are
// different questions — "who sent me this" versus "who wrote it" — and only the
// second survives relaying through a third node (plan §5.3). The two use
// distinct domain separators so a signature from one can never be replayed as
// the other.
package wire

import (
	"errors"
	"fmt"
)

// Version is the wire protocol version this build speaks.
//
// Two peers negotiate the highest version both support. Bumping it is how a
// frame-format change ships without a flag day; changing a field's meaning
// without bumping it is not.
const Version uint8 = 1

// MinVersion is the oldest version this build will negotiate down to.
const MinVersion uint8 = 1

// MsgType identifies what a frame carries.
//
// The numbers are a frozen contract. New types may be appended; existing ones
// never change meaning.
type MsgType uint8

// The message types.
const (
	// MsgHello opens a connection and offers supported wire versions. It is
	// unencrypted by necessity: it precedes any agreement about keys.
	MsgHello MsgType = 1
	// MsgHelloAck accepts a version and identifies the responding node.
	MsgHelloAck MsgType = 2
	// MsgVectors carries a peer's version vectors, one per subscribed space:
	// the sync handshake.
	MsgVectors MsgType = 3
	// MsgWant requests the ranges the sender is missing.
	MsgWant MsgType = 4
	// MsgRecords delivers sealed record payloads.
	MsgRecords MsgType = 5
	// MsgPing and MsgPong measure reachability and carry the sender's clock
	// reading for the skew check.
	MsgPing MsgType = 6
	MsgPong MsgType = 7
	// MsgError reports a refusal. It never carries space content.
	MsgError MsgType = 8
	// MsgBackfillChunk carries one resumable chunk of a bootstrap or
	// long-partition backfill. Reserved here so the type number is stable
	// before the M5 implementation lands.
	MsgBackfillChunk MsgType = 9
)

var msgNames = map[MsgType]string{
	MsgHello:         "hello",
	MsgHelloAck:      "hello_ack",
	MsgVectors:       "vectors",
	MsgWant:          "want",
	MsgRecords:       "records",
	MsgPing:          "ping",
	MsgPong:          "pong",
	MsgError:         "error",
	MsgBackfillChunk: "backfill_chunk",
}

// String implements fmt.Stringer.
func (t MsgType) String() string {
	if n, ok := msgNames[t]; ok {
		return n
	}
	return fmt.Sprintf("msg(%d)", uint8(t))
}

// Known reports whether this build understands the message type.
func (t MsgType) Known() bool {
	_, ok := msgNames[t]
	return ok
}

// Transform identifies the [reserved] pipeline stage applied to a payload
// before encryption.
//
// It exists so compression can return without a breaking change. When it does,
// the rule is that a compression context never spans two keys: compress per
// payload, inside the per-space encryption boundary. Compressing across tenants
// before encrypting leaks plaintext through length — the CRIME/BREACH shape —
// and with multiple users writing into batched frames that hazard is live rather
// than theoretical (plan §10).
type Transform uint8

// The transforms.
const (
	// TransformNone is the identity passthrough: the only transform in v1.
	TransformNone Transform = 0
)

var transformNames = map[Transform]string{
	TransformNone: "none",
}

// String implements fmt.Stringer.
func (t Transform) String() string {
	if n, ok := transformNames[t]; ok {
		return n
	}
	return fmt.Sprintf("transform(%d)", uint8(t))
}

// Supported reports whether this build can apply and reverse the transform.
func (t Transform) Supported() bool {
	_, ok := transformNames[t]
	return ok
}

// Errors returned by this package.
var (
	// ErrVersion reports a frame from an unsupported wire version, or a failed
	// negotiation.
	ErrVersion = errors.New("wire: unsupported version")
	// ErrTransform reports a payload transformed by a stage this build does not
	// implement. A node that cannot reverse a transform must refuse the payload
	// rather than store bytes it can never interpret.
	ErrTransform = errors.New("wire: unsupported transform")
	// ErrMalformed reports a frame or payload that does not parse.
	ErrMalformed = errors.New("wire: malformed")
	// ErrTooLarge reports a frame beyond the size limit.
	ErrTooLarge = errors.New("wire: frame exceeds the size limit")
	// ErrBadFrameSignature reports a frame whose signature does not verify
	// against the sending agent's key.
	ErrBadFrameSignature = errors.New("wire: frame signature does not verify")
)

// Negotiate picks the highest version this build supports that the peer also
// offers.
//
// It fails rather than falling back to an unlisted version: a peer that offers
// nothing in common is a peer to refuse, not to guess with.
func Negotiate(offered []uint8) (uint8, error) {
	best := uint8(0)
	for _, v := range offered {
		if v < MinVersion || v > Version {
			continue
		}
		if v > best {
			best = v
		}
	}
	if best == 0 {
		return 0, fmt.Errorf("%w: peer offers %v, this build speaks %d-%d", ErrVersion, offered, MinVersion, Version)
	}
	return best, nil
}

// SupportedVersions lists what this build offers in a Hello, newest first.
func SupportedVersions() []uint8 {
	out := make([]uint8, 0, Version-MinVersion+1)
	for v := Version; v >= MinVersion; v-- {
		out = append(out, v)
	}
	return out
}
