package record

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
)

// SignDomain is prepended to the canonical bytes before signing.
//
// The same agent key signs both records and wire frames. Without a domain
// separator, a signature harvested from one context could be replayed as a valid
// signature in the other. The separator is part of the frozen contract: changing
// it invalidates every existing signature.
const SignDomain = "memmesh/record/v1\x00"

// FrameSignDomain is the separator used for wire frames, defined here so the two
// domains are visibly distinct and cannot drift apart in separate files.
const FrameSignDomain = "memmesh/frame/v1\x00"

// Signer holds an agent's keypair and stamps records with its identity.
//
// One Signer is one agent: a Hermes profile, or a single firstmate crewmate.
// Machines do not sign; agents do (plan §2.1).
type Signer struct {
	id   AgentID
	priv ed25519.PrivateKey
}

// GenerateSigner creates a new agent keypair. A nil entropy source means
// crypto/rand.
func GenerateSigner(entropy io.Reader) (*Signer, error) {
	if entropy == nil {
		entropy = rand.Reader
	}
	pub, priv, err := ed25519.GenerateKey(entropy)
	if err != nil {
		return nil, fmt.Errorf("record: generate agent key: %w", err)
	}
	id, err := AgentIDFromPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return &Signer{id: id, priv: priv}, nil
}

// NewSigner wraps an existing private key.
func NewSigner(priv ed25519.PrivateKey) (*Signer, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("record: private key is %d bytes, want %d", len(priv), ed25519.PrivateKeySize)
	}
	id, err := AgentIDFromPublicKey(priv.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, err
	}
	return &Signer{id: id, priv: priv}, nil
}

// AgentID returns the signer's public identity.
func (s *Signer) AgentID() AgentID { return s.id }

// PrivateKey returns the raw private key, for persisting to the node's key file.
func (s *Signer) PrivateKey() ed25519.PrivateKey {
	out := make(ed25519.PrivateKey, len(s.priv))
	copy(out, s.priv)
	return out
}

// Sign fills in the record's AuthorAgent and Sig.
//
// It normalizes and validates first, so a record that has been signed is known
// to be canonical: the signature covers exactly the bytes a peer will re-derive.
func (s *Signer) Sign(r *Record) error {
	r.AuthorAgent = s.id
	canonical, err := r.Canonical()
	if err != nil {
		return err
	}
	sig := ed25519.Sign(s.priv, signedMessage(canonical))
	copy(r.Sig[:], sig)
	return nil
}

// SignBytes signs an arbitrary message under the frame domain. Used by the wire
// layer so frame signing and record signing cannot be confused.
func (s *Signer) SignBytes(domain string, msg []byte) []byte {
	return ed25519.Sign(s.priv, append([]byte(domain), msg...))
}

// Verify checks a record's signature against the agent key the record claims.
//
// Verification is intentionally self-contained: the record carries the public
// key, so a record relayed through a third node needs no directory lookup and no
// trust in the relay. Tailnet identity authenticates the connection; this
// authenticates the provenance, and only the second one survives relaying
// (plan §5.3).
func Verify(r *Record) error {
	if r.AuthorAgent.IsZero() {
		return fmt.Errorf("%w: author_agent is unset", ErrBadSignature)
	}
	canonical, err := r.Canonical()
	if err != nil {
		return err
	}
	if !ed25519.Verify(r.AuthorAgent.PublicKey(), signedMessage(canonical), r.Sig[:]) {
		return fmt.Errorf("%w: record %s by %s", ErrBadSignature, r.ID, r.AuthorAgent.Fingerprint())
	}
	return nil
}

// VerifyBytes checks a detached signature under an explicit domain.
func VerifyBytes(agent AgentID, domain string, msg, sig []byte) bool {
	if agent.IsZero() || len(sig) != SigSize {
		return false
	}
	return ed25519.Verify(agent.PublicKey(), append([]byte(domain), msg...), sig)
}

// DecodeVerified decodes and verifies in one step. This is the only entry point
// the store and sync layers should use for records arriving from anywhere other
// than the local agent.
func DecodeVerified(b []byte) (*Record, error) {
	r, err := Decode(b)
	if err != nil {
		return nil, err
	}
	if err := Verify(r); err != nil {
		return nil, err
	}
	return r, nil
}

func signedMessage(canonical []byte) []byte {
	msg := make([]byte, 0, len(SignDomain)+len(canonical))
	msg = append(msg, SignDomain...)
	return append(msg, canonical...)
}
