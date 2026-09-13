// Package crypto implements the mesh's content encryption and key hierarchy.
//
// Encryption is phase 1, not a hardening pass. With multiple users, a relay node
// holding another user's plaintext is not acceptable at any point in the
// timeline (plan §3).
//
// The hierarchy has three levels:
//
//   - Each space has a content key, used with XChaCha20-Poly1305.
//   - The content key is wrapped to each member's X25519 recipient key,
//     age-style. Adding a member is a re-wrap, not a re-encryption of the
//     corpus.
//   - Removing a member rotates the content key into a new epoch. Records carry
//     the epoch they were written under, so old records stay readable by
//     everyone who could already read them.
//
// That last point is the design's most important user-facing property:
// revocation is forward-only. A removed member keeps whatever they already
// synced. This is not a bug to be fixed later — a space that cannot tolerate it
// should not have been shared.
package crypto

import (
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
)

// Domain separation strings. They are part of the frozen key hierarchy: changing
// one invalidates every wrapped key produced under it.
const (
	// wrapInfo separates the key-wrapping KDF from every other use of X25519.
	wrapInfo = "memmesh/wrap/v1"
	// aadPrefix begins the additional data bound to every sealed payload.
	aadPrefix = "memmesh/space/v1"
)

// RecipientKeySize is the length of an X25519 public or private key.
const RecipientKeySize = 32

// Errors returned by the key hierarchy.
var (
	// ErrNoKey reports that this node holds no key for a space, or none for the
	// requested epoch. A node can only index what it can decrypt, so this is a
	// routine answer for a relayed space, not a failure (plan §3.3).
	ErrNoKey = errors.New("crypto: no key held")
	// ErrBadRecipient reports a malformed recipient key.
	ErrBadRecipient = errors.New("crypto: malformed recipient key")
	// ErrUnwrap reports a wrapped key that this recipient cannot open.
	ErrUnwrap = errors.New("crypto: cannot unwrap key for this recipient")
)

// ContentKey is a space's symmetric key for one epoch.
type ContentKey [KeySize]byte

// GenerateContentKey draws a fresh content key. A nil entropy source means
// crypto/rand.
func GenerateContentKey(entropy io.Reader) (ContentKey, error) {
	if entropy == nil {
		entropy = rand.Reader
	}
	var k ContentKey
	if _, err := io.ReadFull(entropy, k[:]); err != nil {
		return k, fmt.Errorf("crypto: generate content key: %w", err)
	}
	return k, nil
}

// RecipientPublic is a member's X25519 public key: the address a content key is
// wrapped to.
type RecipientPublic [RecipientKeySize]byte

// recipientEnc renders keys in unpadded lowercase base32, matching the agent id
// rendering so the two read alike in memctl output.
var recipientEnc = base32.StdEncoding.WithPadding(base32.NoPadding)

// String renders the public key with a prefix that makes it unmistakable.
func (p RecipientPublic) String() string {
	return "rk_" + strings.ToLower(recipientEnc.EncodeToString(p[:]))
}

// Fingerprint renders a short form for display. Never match on it.
func (p RecipientPublic) Fingerprint() string {
	s := strings.ToLower(recipientEnc.EncodeToString(p[:]))
	return s[:8] + "…" + s[len(s)-4:]
}

// MarshalText implements encoding.TextMarshaler.
func (p RecipientPublic) MarshalText() ([]byte, error) { return []byte(p.String()), nil }

// UnmarshalText implements encoding.TextUnmarshaler.
func (p *RecipientPublic) UnmarshalText(b []byte) error {
	parsed, err := ParseRecipientPublic(string(b))
	if err != nil {
		return err
	}
	*p = parsed
	return nil
}

// ParseRecipientPublic decodes the form produced by RecipientPublic.String.
func ParseRecipientPublic(s string) (RecipientPublic, error) {
	var p RecipientPublic
	raw, err := recipientEnc.DecodeString(strings.ToUpper(strings.TrimPrefix(s, "rk_")))
	if err != nil {
		return p, fmt.Errorf("%w: %v", ErrBadRecipient, err)
	}
	if len(raw) != RecipientKeySize {
		return p, fmt.Errorf("%w: decoded %d bytes, want %d", ErrBadRecipient, len(raw), RecipientKeySize)
	}
	copy(p[:], raw)
	return p, nil
}

// RecipientPrivate is a member's X25519 private key.
//
// Recipient keys are per member — a person or a machine that holds space keys —
// and are deliberately separate from the ed25519 agent keys that sign records.
// One answers "who may read this space", the other "who wrote this record", and
// conflating them would mean revoking read access also invalidated an agent's
// past signatures.
type RecipientPrivate struct {
	key *ecdh.PrivateKey
}

// GenerateRecipient creates a new recipient keypair. A nil entropy source means
// crypto/rand.
func GenerateRecipient(entropy io.Reader) (*RecipientPrivate, error) {
	if entropy == nil {
		entropy = rand.Reader
	}
	k, err := ecdh.X25519().GenerateKey(entropy)
	if err != nil {
		return nil, fmt.Errorf("crypto: generate recipient key: %w", err)
	}
	return &RecipientPrivate{key: k}, nil
}

// NewRecipient wraps existing private key bytes.
func NewRecipient(raw []byte) (*RecipientPrivate, error) {
	k, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadRecipient, err)
	}
	return &RecipientPrivate{key: k}, nil
}

// Public returns the recipient's public key.
func (r *RecipientPrivate) Public() RecipientPublic {
	var p RecipientPublic
	copy(p[:], r.key.PublicKey().Bytes())
	return p
}

// Bytes returns the raw private key, for persisting to the node's key file.
func (r *RecipientPrivate) Bytes() []byte { return r.key.Bytes() }

// WrappedKey is a content key encrypted to one recipient.
//
// Wrapping is per recipient and per epoch, so distributing a space to a new
// member means producing one of these and nothing else — no corpus rewrite, no
// coordination with other members.
type WrappedKey struct {
	// Space names the space the wrapped key belongs to.
	Space string `json:"space"`
	// Epoch is the key epoch.
	Epoch uint32 `json:"epoch"`
	// Recipient is who the key was wrapped to, for routing and display.
	Recipient RecipientPublic `json:"recipient"`
	// Ephemeral is the one-time X25519 public key used for this wrap.
	Ephemeral RecipientPublic `json:"ephemeral"`
	// Sealed is the content key under XChaCha20-Poly1305.
	Sealed []byte `json:"sealed"`
}

// Wrap encrypts a content key to a recipient.
//
// An ephemeral sender key is generated per wrap, so the same content key wrapped
// twice produces different bytes and the wrap reveals nothing about the sender.
// The recipient's public key is mixed into the KDF salt alongside the ephemeral
// one, which binds the wrap to its intended reader: a wrap cannot be replayed at
// a different recipient even by someone who holds the ephemeral key.
func Wrap(space string, epoch uint32, key ContentKey, to RecipientPublic, entropy io.Reader) (*WrappedKey, error) {
	if entropy == nil {
		entropy = rand.Reader
	}
	ephemeral, err := ecdh.X25519().GenerateKey(entropy)
	if err != nil {
		return nil, fmt.Errorf("crypto: generate ephemeral key: %w", err)
	}
	peer, err := ecdh.X25519().NewPublicKey(to[:])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadRecipient, err)
	}
	shared, err := ephemeral.ECDH(peer)
	if err != nil {
		return nil, fmt.Errorf("crypto: x25519: %w", err)
	}
	defer zero(shared)

	var ephPub RecipientPublic
	copy(ephPub[:], ephemeral.PublicKey().Bytes())

	wrapKey, err := deriveWrapKey(shared, ephPub, to)
	if err != nil {
		return nil, err
	}
	defer zero(wrapKey[:])

	// A fixed all-zero nonce is safe here and only here: the wrap key is derived
	// from a fresh ephemeral scalar, so it is used for exactly one message.
	var nonce [NonceSize]byte
	sealed, err := Seal(&wrapKey, &nonce, key[:], WrapAAD(space, epoch, to))
	if err != nil {
		return nil, err
	}
	return &WrappedKey{
		Space:     space,
		Epoch:     epoch,
		Recipient: to,
		Ephemeral: ephPub,
		Sealed:    sealed,
	}, nil
}

// Unwrap recovers a content key from a wrap addressed to this recipient.
func (r *RecipientPrivate) Unwrap(w *WrappedKey) (ContentKey, error) {
	var out ContentKey
	self := r.Public()
	if w.Recipient != self {
		return out, fmt.Errorf("%w: wrapped for %s, this node is %s",
			ErrUnwrap, w.Recipient.Fingerprint(), self.Fingerprint())
	}
	eph, err := ecdh.X25519().NewPublicKey(w.Ephemeral[:])
	if err != nil {
		return out, fmt.Errorf("%w: %v", ErrBadRecipient, err)
	}
	shared, err := r.key.ECDH(eph)
	if err != nil {
		return out, fmt.Errorf("crypto: x25519: %w", err)
	}
	defer zero(shared)

	wrapKey, err := deriveWrapKey(shared, w.Ephemeral, self)
	if err != nil {
		return out, err
	}
	defer zero(wrapKey[:])

	plain, err := Open(&wrapKey, w.Sealed, WrapAAD(w.Space, w.Epoch, self))
	if err != nil {
		return out, fmt.Errorf("%w: %v", ErrUnwrap, err)
	}
	defer zero(plain)
	if len(plain) != KeySize {
		return out, fmt.Errorf("%w: unwrapped %d bytes, want %d", ErrUnwrap, len(plain), KeySize)
	}
	copy(out[:], plain)
	return out, nil
}

func deriveWrapKey(shared []byte, ephemeral, recipient RecipientPublic) (ContentKey, error) {
	var out ContentKey
	salt := make([]byte, 0, 2*RecipientKeySize)
	salt = append(salt, ephemeral[:]...)
	salt = append(salt, recipient[:]...)
	derived, err := hkdf.Key(sha256.New, shared, salt, wrapInfo, KeySize)
	if err != nil {
		return out, fmt.Errorf("crypto: hkdf: %w", err)
	}
	copy(out[:], derived)
	zero(derived)
	return out, nil
}

// WrapAAD is the additional data bound to a wrapped key. Binding the space,
// epoch and recipient means a wrap cannot be relabelled as belonging to a
// different space or epoch without breaking authentication.
func WrapAAD(space string, epoch uint32, to RecipientPublic) []byte {
	aad := make([]byte, 0, len(wrapInfo)+len(space)+4+RecipientKeySize+2)
	aad = append(aad, wrapInfo...)
	aad = append(aad, 0)
	aad = append(aad, space...)
	aad = append(aad, 0)
	var e [4]byte
	binary.BigEndian.PutUint32(e[:], epoch)
	aad = append(aad, e[:]...)
	return append(aad, to[:]...)
}

// SpaceAAD is the additional data bound to a sealed payload for a space.
//
// It ties the ciphertext to the space and epoch it was written under, so a relay
// cannot move a frame between spaces or replay it under a rotated key and have
// it still authenticate.
func SpaceAAD(space string, epoch uint32) []byte {
	aad := make([]byte, 0, len(aadPrefix)+len(space)+6)
	aad = append(aad, aadPrefix...)
	aad = append(aad, 0)
	aad = append(aad, space...)
	aad = append(aad, 0)
	var e [4]byte
	binary.BigEndian.PutUint32(e[:], epoch)
	return append(aad, e[:]...)
}

// RecordAAD is the additional data bound to a sealed record payload.
//
// It extends SpaceAAD with the record id and authoring node, which a relay reads
// in the clear because the sync protocol is defined over exactly those two
// values (see docs/decisions/0006). Binding them here means a relay that alters
// either one produces a payload that no reader can open: it can withhold or
// misreport, which any peer holding the key will detect, but it cannot forge.
func RecordAAD(space string, epoch uint32, id []byte, node string) []byte {
	aad := SpaceAAD(space, epoch)
	aad = append(aad, id...)
	aad = append(aad, 0)
	return append(aad, node...)
}

// SpaceKeys holds every epoch key this node has for one space.
//
// Old epochs are retained deliberately: rotation stops a removed member reading
// *new* writes, and keeping the old keys is what lets everyone else still read
// the history. Dropping them would destroy readable data to no security benefit,
// since the removed member already holds whatever they synced.
type SpaceKeys struct {
	// Current is the epoch new writes use.
	Current uint32 `json:"current"`
	// Epochs maps epoch number to content key.
	Epochs map[uint32]ContentKey `json:"epochs"`
}

// Keyring is a node's view of which spaces it can read.
//
// A space absent from the keyring is a relayed space: the node stores and
// gossips its records, verifies their frame signatures, and can report counts
// and bytes, but cannot decrypt, embed, index or search them. Keeping that
// distinction in one place is what makes "readable vs relayed" reliably visible
// everywhere in memctl (plan §8).
//
// A Keyring is safe for concurrent use.
type Keyring struct {
	mu     sync.RWMutex
	spaces map[string]*SpaceKeys
	// relaying records spaces this node carries without a key, so status can
	// report them without pretending they are readable.
	relaying map[string]bool
}

// NewKeyring returns an empty keyring.
func NewKeyring() *Keyring {
	return &Keyring{
		spaces:   make(map[string]*SpaceKeys),
		relaying: make(map[string]bool),
	}
}

// Install adds a content key for a space and epoch. If the epoch is at or above
// the current one, it becomes current.
func (k *Keyring) Install(space string, epoch uint32, key ContentKey) {
	k.mu.Lock()
	defer k.mu.Unlock()
	sk, ok := k.spaces[space]
	if !ok {
		sk = &SpaceKeys{Epochs: make(map[uint32]ContentKey)}
		k.spaces[space] = sk
	}
	sk.Epochs[epoch] = key
	if epoch >= sk.Current {
		sk.Current = epoch
	}
	delete(k.relaying, space)
}

// InstallWrapped unwraps a key with the given recipient identity and installs
// it.
func (k *Keyring) InstallWrapped(r *RecipientPrivate, w *WrappedKey) error {
	key, err := r.Unwrap(w)
	if err != nil {
		return err
	}
	k.Install(w.Space, w.Epoch, key)
	return nil
}

// Rotate generates a new content key one epoch above the current one and makes
// it current, returning the new epoch.
//
// This is member removal: re-wrap the new epoch key to everyone who stays, and
// do not wrap it to the member who left. Revocation is forward-only by
// construction.
func (k *Keyring) Rotate(space string, entropy io.Reader) (uint32, ContentKey, error) {
	key, err := GenerateContentKey(entropy)
	if err != nil {
		return 0, key, err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	sk, ok := k.spaces[space]
	if !ok {
		sk = &SpaceKeys{Epochs: make(map[uint32]ContentKey)}
		k.spaces[space] = sk
		sk.Current = 0
		sk.Epochs[0] = key
		delete(k.relaying, space)
		return 0, key, nil
	}
	epoch := sk.Current + 1
	sk.Epochs[epoch] = key
	sk.Current = epoch
	return epoch, key, nil
}

// Key returns the content key for a space and epoch.
func (k *Keyring) Key(space string, epoch uint32) (ContentKey, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	sk, ok := k.spaces[space]
	if !ok {
		return ContentKey{}, fmt.Errorf("%w: space %q is not readable on this node", ErrNoKey, space)
	}
	key, ok := sk.Epochs[epoch]
	if !ok {
		return ContentKey{}, fmt.Errorf("%w: space %q epoch %d (current is %d)", ErrNoKey, space, epoch, sk.Current)
	}
	return key, nil
}

// CurrentEpoch returns the epoch new writes to a space should use.
func (k *Keyring) CurrentEpoch(space string) (uint32, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	sk, ok := k.spaces[space]
	if !ok {
		return 0, fmt.Errorf("%w: space %q is not readable on this node", ErrNoKey, space)
	}
	return sk.Current, nil
}

// Readable reports whether this node holds any key for a space.
func (k *Keyring) Readable(space string) bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	_, ok := k.spaces[space]
	return ok
}

// MarkRelaying records that this node carries a space it cannot read.
func (k *Keyring) MarkRelaying(space string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, ok := k.spaces[space]; ok {
		return
	}
	k.relaying[space] = true
}

// Forget drops every key for a space. The records stay on disk and keep syncing;
// the node simply stops being able to read them, and reports the space as
// relayed. Used when a member leaves a space voluntarily.
func (k *Keyring) Forget(space string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if sk, ok := k.spaces[space]; ok {
		for e := range sk.Epochs {
			key := sk.Epochs[e]
			zero(key[:])
			delete(sk.Epochs, e)
		}
		delete(k.spaces, space)
		k.relaying[space] = true
	}
}

// ReadableSpaces lists the spaces this node holds keys for, sorted.
func (k *Keyring) ReadableSpaces() []string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return sortedKeys(k.spaces)
}

// RelayedSpaces lists the spaces this node carries without keys, sorted.
func (k *Keyring) RelayedSpaces() []string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	out := make([]string, 0, len(k.relaying))
	for s := range k.relaying {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// Snapshot returns a deep copy of the keyring's contents, for persistence.
func (k *Keyring) Snapshot() map[string]SpaceKeys {
	k.mu.RLock()
	defer k.mu.RUnlock()
	out := make(map[string]SpaceKeys, len(k.spaces))
	for space, sk := range k.spaces {
		epochs := make(map[uint32]ContentKey, len(sk.Epochs))
		for e, key := range sk.Epochs {
			epochs[e] = key
		}
		out[space] = SpaceKeys{Current: sk.Current, Epochs: epochs}
	}
	return out
}

// Restore replaces the keyring's contents from a snapshot.
func (k *Keyring) Restore(snapshot map[string]SpaceKeys) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.spaces = make(map[string]*SpaceKeys, len(snapshot))
	for space, sk := range snapshot {
		epochs := make(map[uint32]ContentKey, len(sk.Epochs))
		for e, key := range sk.Epochs {
			epochs[e] = key
		}
		k.spaces[space] = &SpaceKeys{Current: sk.Current, Epochs: epochs}
		delete(k.relaying, space)
	}
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
