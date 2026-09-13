package record

import (
	"crypto/ed25519"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
)

// NodeID names a machine in the mesh. It is the stable tailnet name of the
// node, and it is the key of a version vector: "which records from this machine
// have I seen".
//
// A NodeID is not an identity for authorship. Several agents share one machine,
// and firstmate crewmates are disposable enough that machine-level attribution
// would blur them into each other (plan §2.1).
type NodeID string

// Valid reports whether n is a usable node identifier.
func (n NodeID) Valid() bool {
	if n == "" || len(n) > 128 {
		return false
	}
	for _, r := range n {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '.', r == '_':
		default:
			return false
		}
	}
	return true
}

// AgentID is the ed25519 public key of an authoring agent.
//
// Using the key itself as the identifier means a record carries everything
// needed to verify it: no directory lookup, no trust in the relaying node. One
// user's Hermes profile and each of their firstmate crewmates carry distinct
// keys, so one can be attributed or revoked without touching the others.
type AgentID [ed25519.PublicKeySize]byte

// ZeroAgent is the unset AgentID.
var ZeroAgent AgentID

// AgentIDFromPublicKey converts an ed25519 public key to an AgentID.
func AgentIDFromPublicKey(pub ed25519.PublicKey) (AgentID, error) {
	var a AgentID
	if len(pub) != ed25519.PublicKeySize {
		return a, fmt.Errorf("record: public key is %d bytes, want %d", len(pub), ed25519.PublicKeySize)
	}
	copy(a[:], pub)
	return a, nil
}

// PublicKey returns the AgentID as an ed25519 public key.
func (a AgentID) PublicKey() ed25519.PublicKey {
	out := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(out, a[:])
	return out
}

// IsZero reports whether a is unset.
func (a AgentID) IsZero() bool { return a == ZeroAgent }

// agentEnc is unpadded lowercase base32, chosen over hex because fingerprints
// get read aloud and typed into memctl arguments.
var agentEnc = base32.StdEncoding.WithPadding(base32.NoPadding)

// String renders the full agent identifier, prefixed so it is unmistakable in
// logs and CLI output.
func (a AgentID) String() string {
	return "ag_" + strings.ToLower(agentEnc.EncodeToString(a[:]))
}

// Fingerprint renders a short, human-comparable form of the agent identifier.
// It is for display only; never match on it.
func (a AgentID) Fingerprint() string {
	s := strings.ToLower(agentEnc.EncodeToString(a[:]))
	return s[:8] + "…" + s[len(s)-4:]
}

// MarshalText implements encoding.TextMarshaler.
func (a AgentID) MarshalText() ([]byte, error) { return []byte(a.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (a *AgentID) UnmarshalText(b []byte) error {
	parsed, err := ParseAgentID(string(b))
	if err != nil {
		return err
	}
	*a = parsed
	return nil
}

// ErrBadAgentID reports an unparseable agent identifier.
var ErrBadAgentID = errors.New("record: malformed agent id")

// ParseAgentID decodes the form produced by AgentID.String.
func ParseAgentID(s string) (AgentID, error) {
	var a AgentID
	s = strings.TrimPrefix(s, "ag_")
	raw, err := agentEnc.DecodeString(strings.ToUpper(s))
	if err != nil {
		return a, fmt.Errorf("%w: %v", ErrBadAgentID, err)
	}
	if len(raw) != len(a) {
		return a, fmt.Errorf("%w: decoded %d bytes, want %d", ErrBadAgentID, len(raw), len(a))
	}
	copy(a[:], raw)
	return a, nil
}

// SpaceID names a space: the unit of subscription, encryption and sync.
//
// The prefix is meaningful, because conflict policy is per space (plan §6.8)
// and the class is what selects it. Layout:
//
//	agent/<agent-id>   private to one agent, never shared
//	user/<user-id>     one user, shared across their own agents and machines
//	shared/<name>      shared across users who hold the key
type SpaceID string

// SpaceClass is the policy-bearing prefix of a SpaceID.
type SpaceClass string

// The three space classes.
const (
	ClassAgent   SpaceClass = "agent"
	ClassUser    SpaceClass = "user"
	ClassShared  SpaceClass = "shared"
	ClassInvalid SpaceClass = ""
)

// ErrBadSpaceID reports a space identifier that does not match the layout.
var ErrBadSpaceID = errors.New("record: malformed space id")

// Class returns the space's class, or ClassInvalid if the identifier is
// malformed.
func (s SpaceID) Class() SpaceClass {
	prefix, rest, found := strings.Cut(string(s), "/")
	if !found || rest == "" {
		return ClassInvalid
	}
	switch SpaceClass(prefix) {
	case ClassAgent, ClassUser, ClassShared:
		return SpaceClass(prefix)
	}
	return ClassInvalid
}

// Name returns the portion of the identifier after the class prefix.
func (s SpaceID) Name() string {
	_, rest, _ := strings.Cut(string(s), "/")
	return rest
}

// Validate checks the identifier against the space layout.
func (s SpaceID) Validate() error {
	if len(s) == 0 || len(s) > 200 {
		return fmt.Errorf("%w: length %d out of range", ErrBadSpaceID, len(s))
	}
	if s.Class() == ClassInvalid {
		return fmt.Errorf("%w: %q has no recognised class prefix (agent/, user/, shared/)", ErrBadSpaceID, string(s))
	}
	name := s.Name()
	if strings.Contains(name, "/") {
		return fmt.Errorf("%w: %q has more than one path separator", ErrBadSpaceID, string(s))
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '.', r == '_':
		default:
			return fmt.Errorf("%w: %q contains %q", ErrBadSpaceID, string(s), r)
		}
	}
	return nil
}

// Filename returns a path-safe rendering of the space identifier, used as the
// per-space directory name. Per-space files make subscription, key rotation and
// eviction into file operations rather than query predicates (plan §4.1).
func (s SpaceID) Filename() string {
	return strings.ReplaceAll(string(s), "/", "__")
}
