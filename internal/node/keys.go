package node

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/coryforsythe/memmesh/internal/crypto"
	"github.com/coryforsythe/memmesh/internal/record"
)

// Key material lives under <root>/keys:
//
//	keys/recipient.key      X25519 private key: who may read spaces on this node
//	keys/keyring.json       per-space content keys, by epoch
//	keys/agents/<name>.key  one ed25519 private key per agent
//
// Two key types, deliberately separate. The recipient key answers "may this node
// read this space"; agent keys answer "who wrote this record". Conflating them
// would mean revoking read access also invalidated an agent's past signatures,
// which would destroy the audit trail as a side effect of a membership change
// (plan §3.2, §2.1).
//
// Content keys are stored unencrypted at 0600 in a 0700 directory. That is the same
// trust model as an SSH private key: this file being readable means the space is
// readable, so the protection is filesystem permissions and whatever disk
// encryption the host provides. Anything stronger needs a passphrase prompt the
// daemon cannot answer when it starts unattended at boot, which is the usual reason
// tools land here.

const (
	keysDir      = "keys"
	agentsDir    = "agents"
	recipientKey = "recipient.key"
	keyringFile  = "keyring.json"
)

// keystore owns this node's key material and its persistence.
type keystore struct {
	dir     string
	entropy io.Reader

	mu        sync.Mutex
	recipient *crypto.RecipientPrivate
	ring      *crypto.Keyring
	agents    map[string]*record.Signer
}

func openKeystore(root string, entropy io.Reader) (*keystore, error) {
	dir := filepath.Join(root, keysDir)
	if err := os.MkdirAll(filepath.Join(dir, agentsDir), 0o700); err != nil {
		return nil, fmt.Errorf("node: create key dir: %w", err)
	}
	ks := &keystore{
		dir:     dir,
		entropy: entropy,
		ring:    crypto.NewKeyring(),
		agents:  make(map[string]*record.Signer),
	}
	if err := ks.loadRecipient(); err != nil {
		return nil, err
	}
	if err := ks.loadKeyring(); err != nil {
		return nil, err
	}
	if err := ks.loadAgents(); err != nil {
		return nil, err
	}
	return ks, nil
}

func (ks *keystore) loadRecipient() error {
	path := filepath.Join(ks.dir, recipientKey)
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		r, err := crypto.NewRecipient(raw)
		if err != nil {
			return fmt.Errorf("node: load recipient key: %w", err)
		}
		ks.recipient = r
		return nil
	case os.IsNotExist(err):
		r, err := crypto.GenerateRecipient(ks.entropy)
		if err != nil {
			return err
		}
		if err := writeSecret(path, r.Bytes()); err != nil {
			return err
		}
		ks.recipient = r
		return nil
	default:
		return fmt.Errorf("node: read recipient key: %w", err)
	}
}

// persistedKeyring is the on-disk form of the space keyring.
type persistedKeyring struct {
	Spaces map[string]persistedSpace `json:"spaces"`
}

type persistedSpace struct {
	Current uint32            `json:"current"`
	Epochs  map[string]string `json:"epochs"`
}

func (ks *keystore) loadKeyring() error {
	raw, err := os.ReadFile(filepath.Join(ks.dir, keyringFile))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("node: read keyring: %w", err)
	}
	var p persistedKeyring
	if err := json.Unmarshal(raw, &p); err != nil {
		return fmt.Errorf("node: parse keyring: %w", err)
	}
	snapshot := make(map[string]crypto.SpaceKeys, len(p.Spaces))
	for space, ps := range p.Spaces {
		epochs := make(map[uint32]crypto.ContentKey, len(ps.Epochs))
		for epochStr, encoded := range ps.Epochs {
			var epoch uint32
			if _, err := fmt.Sscanf(epochStr, "%d", &epoch); err != nil {
				return fmt.Errorf("node: keyring has a bad epoch %q for %s", epochStr, space)
			}
			decoded, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil || len(decoded) != crypto.KeySize {
				return fmt.Errorf("node: keyring has a bad key for %s epoch %d", space, epoch)
			}
			var key crypto.ContentKey
			copy(key[:], decoded)
			epochs[epoch] = key
		}
		snapshot[space] = crypto.SpaceKeys{Current: ps.Current, Epochs: epochs}
	}
	ks.ring.Restore(snapshot)
	return nil
}

func (ks *keystore) saveKeyring() error {
	snapshot := ks.ring.Snapshot()
	p := persistedKeyring{Spaces: make(map[string]persistedSpace, len(snapshot))}
	for space, sk := range snapshot {
		epochs := make(map[string]string, len(sk.Epochs))
		for epoch, key := range sk.Epochs {
			epochs[fmt.Sprintf("%d", epoch)] = base64.StdEncoding.EncodeToString(key[:])
		}
		p.Spaces[space] = persistedSpace{Current: sk.Current, Epochs: epochs}
	}
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("node: encode keyring: %w", err)
	}
	return writeSecret(filepath.Join(ks.dir, keyringFile), raw)
}

func (ks *keystore) loadAgents() error {
	dir := filepath.Join(ks.dir, agentsDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("node: read agents dir: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".key") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".key")
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return fmt.Errorf("node: read agent key %s: %w", name, err)
		}
		signer, err := record.NewSigner(ed25519.PrivateKey(raw))
		if err != nil {
			return fmt.Errorf("node: load agent key %s: %w", name, err)
		}
		ks.agents[name] = signer
	}
	return nil
}

// agent returns the signer for a named agent, creating its keypair on first use.
//
// Creating on first use is what makes firstmate crewmates workable: a crewmate is
// spun up, writes a few records, and is torn down, and nobody wants to provision a
// keypair for each one by hand. The key persists after the crewmate is gone, which
// is what keeps its records attributable.
func (ks *keystore) agent(name string) (*record.Signer, error) {
	if err := validAgentName(name); err != nil {
		return nil, err
	}
	ks.mu.Lock()
	defer ks.mu.Unlock()
	if s, ok := ks.agents[name]; ok {
		return s, nil
	}
	signer, err := record.GenerateSigner(ks.entropy)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(ks.dir, agentsDir, name+".key")
	if err := writeSecret(path, signer.PrivateKey()); err != nil {
		return nil, err
	}
	ks.agents[name] = signer
	return signer, nil
}

// agentNames lists the agents this node has keys for, sorted.
func (ks *keystore) agentNames() []string {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	out := make([]string, 0, len(ks.agents))
	for name := range ks.agents {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// validAgentName keeps agent names usable as filenames and as identifiers in
// memctl output.
func validAgentName(name string) error {
	if name == "" || len(name) > 64 {
		return fmt.Errorf("node: agent name must be 1-64 characters, got %d", len(name))
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.':
		default:
			return fmt.Errorf("node: agent name %q contains %q; use letters, digits, dash, underscore or dot", name, r)
		}
	}
	if name == "." || name == ".." {
		return fmt.Errorf("node: agent name %q is not allowed", name)
	}
	return nil
}

// writeSecret writes a file at 0600, replacing it atomically so an interrupted
// write cannot leave a half-written key in place.
func writeSecret(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("node: write %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("node: replace %s: %w", path, err)
	}
	return nil
}
