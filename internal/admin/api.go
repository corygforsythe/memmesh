// Package admin is the local control surface: the unix-socket protocol memctl uses
// to talk to memd, and the response types both sides share.
//
// # The transport is the local daemon, and only the local daemon
//
// memctl never speaks to the tailnet (plan §8). The admin surface is your own node;
// peer information comes from what your node already learned through sync. Two things
// follow, and both are deliberate:
//
//   - Every peer-derived number may be stale, and carries an "as of" age saying how
//     stale. No command blocks on the network.
//   - This cannot become a remote-admin channel into other people's machines. There
//     is no code path from memctl to another node, so there is nothing to secure, no
//     authentication to get wrong, and no way for a compromised node to reach further.
//
// Keeping the tool honest about the distributed reality is the point. A status command
// that quietly queried peers would show a consistent picture that does not exist.
//
// # One struct, two renderings
//
// Every response type here is what both the table renderer and --json serialise. They
// derive from the same struct so they cannot drift, which is what makes --json a
// stable integration point for a dashboard built later without touching the daemon
// (plan §8.6).
package admin

import (
	"time"

	"github.com/coryforsythe/memmesh/internal/record"
	"github.com/coryforsythe/memmesh/internal/store"
)

// Protocol is the admin protocol version. memctl refuses a daemon it does not match,
// because a silently misread status is worse than no status.
const Protocol = 1

// SocketName is the socket file inside the data directory.
const SocketName = "memd.sock"

// Request is a command from memctl.
type Request struct {
	Protocol int    `json:"protocol"`
	Command  string `json:"command"`
	// Space narrows a command to one space, where the command supports it.
	Space record.SpaceID `json:"space,omitempty"`
	// Peer narrows a command to one peer.
	Peer record.NodeID `json:"peer,omitempty"`
	// Check narrows health to one named check.
	Check string `json:"check,omitempty"`
	// Args carries command-specific extras.
	Args map[string]string `json:"args,omitempty"`
}

// The commands memctl can send.
const (
	CmdStatus  = "status"
	CmdSpaces  = "spaces"
	CmdMembers = "members"
	CmdHealth  = "health"
	CmdSync    = "sync"
	CmdKeys    = "keys"
)

// Response wraps every reply.
type Response struct {
	Protocol int    `json:"protocol"`
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`

	Status  *Status  `json:"status,omitempty"`
	Spaces  *Spaces  `json:"spaces,omitempty"`
	Members *Members `json:"members,omitempty"`
	Health  *Health  `json:"health,omitempty"`
	Sync    *Sync    `json:"sync,omitempty"`
	Keys    *Keys    `json:"keys,omitempty"`
}

// Status is the most-typed command's payload (plan §8.1).
type Status struct {
	Node        record.NodeID `json:"node"`
	Software    string        `json:"software"`
	WireVersion uint8         `json:"wire_version"`
	Protocol    int           `json:"admin_protocol"`
	UptimeSec   int64         `json:"uptime_sec"`
	// Agents are the agent keys this node holds, with fingerprints for display.
	Agents []AgentInfo `json:"agents"`

	SpacesReadable int `json:"spaces_readable"`
	SpacesRelayed  int `json:"spaces_relayed"`
	SpacesTotal    int `json:"spaces_total"`

	// Relaying reports whether this node carries spaces it holds no key for. Opt-in
	// and off by default (docs/decisions/0003).
	Relaying bool `json:"relaying"`

	Records int   `json:"records"`
	Bytes   int64 `json:"bytes"`

	// IndexResidentBytes is what the vector index actually occupies; RAMBudgetBytes
	// is what it is measured against. The budget is a reporting target, not an
	// enforced cap: evicting vectors to hit a number would degrade recall silently.
	IndexResidentBytes int64  `json:"index_resident_bytes"`
	RAMBudgetBytes     int64  `json:"ram_budget_bytes"`
	IndexedRecords     int    `json:"indexed_records"`
	EmbedModel         string `json:"embed_model"`
	// Warm distinguishes a ready index from one still replaying. A cold node
	// answers recall badly rather than not at all, which is worth knowing before
	// trusting an empty result.
	Warm bool `json:"warm"`

	// OutboundQueue is how many records are waiting to be pushed to peers.
	OutboundQueue int `json:"outbound_queue"`
	// LastSync is the most recent successful exchange, with whom.
	LastSync *SyncEvent `json:"last_sync,omitempty"`

	// Recipient is this node's X25519 identity: the address a space key is wrapped
	// to when someone shares a space with it.
	Recipient string `json:"recipient"`
}

// AgentInfo describes one agent key the node holds.
type AgentInfo struct {
	Name        string `json:"name"`
	AgentID     string `json:"agent_id"`
	Fingerprint string `json:"fingerprint"`
	Records     int    `json:"records"`
}

// SyncEvent records one exchange with a peer.
type SyncEvent struct {
	Peer record.NodeID `json:"peer"`
	At   time.Time     `json:"at"`
	// AgeSec is how long ago it happened. Peer-derived numbers always carry their
	// age, because they are local memories of a conversation, not live readings.
	AgeSec   int64 `json:"age_sec"`
	Sent     int   `json:"sent"`
	Received int   `json:"received"`
}

// Spaces is the space listing (plan §8.5).
type Spaces struct {
	Spaces []SpaceRow `json:"spaces"`
}

// SpaceRow is one space. For a relayed space, everything past Records and Bytes is
// left empty.
type SpaceRow struct {
	Space         record.SpaceID `json:"space"`
	Class         string         `json:"class"`
	Readable      bool           `json:"readable"`
	Policy        string         `json:"conflict_policy"`
	Epoch         uint32         `json:"epoch,omitempty"`
	Records       int            `json:"records"`
	Bytes         int64          `json:"bytes"`
	Indexed       int            `json:"indexed,omitempty"`
	Nodes         int            `json:"participating_nodes"`
	ByKind        map[string]int `json:"by_kind,omitempty"`
	Undecryptable int            `json:"undecryptable,omitempty"`
	Pending       int            `json:"pending_supersessions,omitempty"`
	TruncatedTail bool           `json:"truncated_tail,omitempty"`
}

// Members is the peer listing (plan §8.2).
//
// There are two populations and their divergence is the most useful signal in the
// system: a peer that is up on the tailnet but absent from your version vector is the
// failure you actually want to catch.
type Members struct {
	// Enrolled counts tailnet peers carrying the node tag.
	Enrolled int `json:"enrolled"`
	// Participating counts peers appearing in at least one of your version vectors.
	Participating int       `json:"participating"`
	Peers         []PeerRow `json:"peers"`
	// Discovery reports how the enrolled list was obtained, and why it is empty when
	// it is. "No peers" and "cannot ask" are different answers.
	Discovery string `json:"discovery"`
	// Notes carries conditions worth saying out loud.
	Notes []string `json:"notes,omitempty"`
}

// PeerRow is one peer.
type PeerRow struct {
	Node record.NodeID `json:"node"`
	// Enrolled reports whether the peer is visible on the tailnet with the node tag.
	Enrolled bool `json:"enrolled"`
	// Participating reports whether the peer appears in a version vector, i.e.
	// whether records from it have actually arrived.
	Participating bool   `json:"participating"`
	Address       string `json:"address,omitempty"`
	// Transport is direct or DERP, as reported by the local Tailscale daemon.
	Transport string `json:"transport,omitempty"`
	// AgentKeys are the agent fingerprints seen authoring records from this node.
	AgentKeys []string `json:"agent_keys,omitempty"`
	// LastContactAgeSec is how long since this node last exchanged frames with the
	// peer. Negative means never.
	LastContactAgeSec int64 `json:"last_contact_age_sec"`
	// SharedSpaces are the spaces both nodes hold.
	SharedSpaces []record.SpaceID `json:"shared_spaces,omitempty"`

	// LagBehind is how many records the peer has that this node does not.
	// LagAhead is the reverse.
	//
	// Print both prominently: bidirectional lag is the single most diagnostic
	// number here (plan §8.2). One-directional lag looks like a healthy sync right
	// up until you notice it never completes.
	LagBehind int `json:"lag_behind"`
	LagAhead  int `json:"lag_ahead"`

	// ClockSkewMS is the peer's clock offset as last measured. HLC tiebreaking
	// degrades quietly under drift, so this is measured rather than assumed.
	ClockSkewMS int64 `json:"clock_skew_ms"`
	// EmbedModel is the peer's embedding model. A mismatch poisons recall without
	// erroring.
	EmbedModel string `json:"embed_model,omitempty"`
	// KeyEpochs are the epochs seen on records from this peer, per space.
	KeyEpochs map[string]uint32 `json:"key_epochs,omitempty"`
	// Software is the peer's build.
	Software string `json:"software,omitempty"`
	// AsOfAgeSec is how old this whole row is. Everything here is what your node
	// last learned, not what is true now.
	AsOfAgeSec int64 `json:"as_of_age_sec"`
}

// Health is the check report (plan §8.4).
type Health struct {
	// Exit is the process exit code: 0 ok, 1 warn, 2 critical.
	Exit   int           `json:"exit"`
	Checks []HealthCheck `json:"checks"`
}

// Severity levels for a health check.
const (
	SeverityOK       = "ok"
	SeverityWarn     = "warn"
	SeverityCritical = "critical"
	// SeveritySkipped marks a check that could not run, which is not the same as
	// passing and must never be reported as such.
	SeveritySkipped = "skipped"
)

// HealthCheck is one check's outcome.
type HealthCheck struct {
	Name     string `json:"name"`
	Severity string `json:"severity"`
	// Detail says what was measured and why it matters, in a sentence an operator
	// woken at 3am can act on.
	Detail string `json:"detail"`
	// Value carries the measurement, when there is one.
	Value string `json:"value,omitempty"`
}

// ExitCode returns the process exit code for a severity.
func ExitCode(severity string) int {
	switch severity {
	case SeverityCritical:
		return 2
	case SeverityWarn:
		return 1
	default:
		return 0
	}
}

// Worse returns the more severe of two severities.
func Worse(a, b string) string {
	if ExitCode(a) >= ExitCode(b) {
		return a
	}
	return b
}

// Sync is the result of forcing anti-entropy.
type Sync struct {
	// Attempted lists the peers contacted.
	Attempted []record.NodeID   `json:"attempted"`
	Events    []SyncEvent       `json:"events"`
	Errors    map[string]string `json:"errors,omitempty"`
}

// Keys is the key listing (plan §8.5).
type Keys struct {
	// Recipient is this node's X25519 identity.
	Recipient            string        `json:"recipient"`
	RecipientFingerprint string        `json:"recipient_fingerprint"`
	Agents               []AgentInfo   `json:"agents"`
	SpaceKeys            []SpaceKeyRow `json:"space_keys"`
}

// SpaceKeyRow is one space's key state.
type SpaceKeyRow struct {
	Space record.SpaceID `json:"space"`
	// Current is the epoch new writes use.
	Current uint32 `json:"current_epoch"`
	// Epochs are every epoch this node holds a key for. Old epochs are retained on
	// purpose: rotation stops a removed member reading new writes, and keeping the
	// old keys is what lets everyone else still read the history.
	Epochs []uint32 `json:"epochs"`
	// Readable is false for a relayed space, which has no key at all.
	Readable bool `json:"readable"`
}

// StatsFromStore converts a store summary into a SpaceRow, so the daemon has one
// conversion rather than one per command.
func StatsFromStore(s store.Stats, indexed int) SpaceRow {
	return SpaceRow{
		Space:         s.Space,
		Class:         string(s.Space.Class()),
		Readable:      s.Readable,
		Policy:        s.Policy,
		Epoch:         s.Epoch,
		Records:       s.Records,
		Bytes:         s.Bytes,
		Indexed:       indexed,
		Nodes:         s.Nodes,
		ByKind:        s.ByKind,
		Undecryptable: s.Undecryptable,
		Pending:       s.Pending,
		TruncatedTail: s.TruncatedTail,
	}
}
