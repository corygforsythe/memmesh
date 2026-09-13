package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/coryforsythe/memmesh/internal/admin"
	"github.com/coryforsythe/memmesh/internal/record"
)

// Health thresholds. They are deliberately generous: a check that fires on normal
// operation trains its reader to ignore it, which is worse than not having it.
const (
	// ClockSkewWarnMS is the peer clock offset at which HLC tiebreaking starts to be
	// worth worrying about.
	ClockSkewWarnMS = 2_000
	// ClockSkewCriticalMS is drift large enough that a returning node's stale writes
	// will land with newer timestamps than the truth that replaced them.
	ClockSkewCriticalMS = 30_000
	// PeerSilentWarnSec is how long a peer may go unheard from before it counts as
	// possibly partitioned.
	PeerSilentWarnSec = 600
	// PeerSilentCriticalSec is when to call it a partition.
	PeerSilentCriticalSec = 3_600
	// OutboundQueueWarn is a queue depth that suggests sync is not keeping up.
	OutboundQueueWarn = 1_000
	// OutboundQueueCritical is a queue depth that suggests sync is stuck.
	OutboundQueueCritical = 10_000
	// ConflictBacklogWarn is how many unresolved contradictions may sit in shared
	// spaces before adjudication is falling behind.
	ConflictBacklogWarn = 20
)

// The check names, so --only and the JSON output agree on spelling.
const (
	CheckDaemon       = "daemon"
	CheckStore        = "store"
	CheckIndex        = "index"
	CheckClockSkew    = "clock-skew"
	CheckEmbedModel   = "embed-model"
	CheckKeyEpoch     = "key-epoch"
	CheckUnsendable   = "unsendable-backlog"
	CheckOutbound     = "outbound-queue"
	CheckPeers        = "peer-reachability"
	CheckConflicts    = "conflict-backlog"
	CheckTornTail     = "torn-tail"
	CheckParticipants = "enrolled-not-participating"
)

// AllChecks lists every check, in report order.
func AllChecks() []string {
	return []string{
		CheckDaemon, CheckStore, CheckIndex, CheckTornTail,
		CheckClockSkew, CheckEmbedModel, CheckKeyEpoch,
		CheckUnsendable, CheckOutbound, CheckPeers, CheckParticipants, CheckConflicts,
	}
}

// health runs the checks, or just one if named.
//
// Exit codes are 0 ok, 1 warn, 2 critical, so this drops into a launchd or systemd
// timer with no wrapper script.
//
// A check that cannot run reports skipped, never ok. Reporting an unrunnable check as
// passing is how a monitoring system comes to be trusted while measuring nothing.
func (d *Daemon) health(only string) *admin.Health {
	out := &admin.Health{}
	wanted := AllChecks()
	if only != "" {
		wanted = []string{only}
	}
	for _, name := range wanted {
		check := d.runCheck(name)
		out.Checks = append(out.Checks, check)
		if code := admin.ExitCode(check.Severity); code > out.Exit {
			out.Exit = code
		}
	}
	if only != "" && len(out.Checks) == 1 && out.Checks[0].Name == "" {
		out.Checks[0] = admin.HealthCheck{
			Name:     only,
			Severity: admin.SeveritySkipped,
			Detail:   fmt.Sprintf("no such check; known checks are %s", strings.Join(AllChecks(), ", ")),
		}
	}
	return out
}

func (d *Daemon) runCheck(name string) admin.HealthCheck {
	switch name {
	case CheckDaemon:
		return d.checkDaemon()
	case CheckStore:
		return d.checkStore()
	case CheckIndex:
		return d.checkIndex()
	case CheckTornTail:
		return d.checkTornTail()
	case CheckClockSkew:
		return d.checkClockSkew()
	case CheckEmbedModel:
		return d.checkEmbedModel()
	case CheckKeyEpoch:
		return d.checkKeyEpoch()
	case CheckUnsendable:
		return d.checkUnsendable()
	case CheckOutbound:
		return d.checkOutbound()
	case CheckPeers:
		return d.checkPeers()
	case CheckParticipants:
		return d.checkParticipants()
	case CheckConflicts:
		return d.checkConflicts()
	default:
		return admin.HealthCheck{}
	}
}

func (d *Daemon) checkDaemon() admin.HealthCheck {
	// Reaching this code is itself most of the liveness answer; what remains is
	// whether the data directory is still writable, since a read-only filesystem
	// turns every future write into a failure the agent sees rather than the
	// operator.
	probe := filepath.Join(filepath.Dir(d.AdminSocket()), ".write-probe")
	if err := os.WriteFile(probe, []byte("ok"), 0o600); err != nil {
		return admin.HealthCheck{
			Name:     CheckDaemon,
			Severity: admin.SeverityCritical,
			Detail:   fmt.Sprintf("the data directory is not writable: %v; every write from here will fail", err),
		}
	}
	_ = os.Remove(probe)
	return admin.HealthCheck{
		Name:     CheckDaemon,
		Severity: admin.SeverityOK,
		Detail:   "responsive, data directory writable",
		Value:    fmt.Sprintf("uptime %ds", int64(d.node.Clock().Now().Sub(d.started).Seconds())),
	}
}

func (d *Daemon) checkStore() admin.HealthCheck {
	stats := d.node.Store().Stats()
	var records int
	var bytes int64
	for _, s := range stats {
		records += s.Records
		bytes += s.Bytes
	}
	return admin.HealthCheck{
		Name:     CheckStore,
		Severity: admin.SeverityOK,
		Detail:   fmt.Sprintf("%d spaces open, all logs readable", len(stats)),
		Value:    fmt.Sprintf("%d records, %d bytes", records, bytes),
	}
}

// checkIndex compares the index population against the catalog.
//
// A silently shrinking index is the failure this catches. Recall against a
// half-populated index returns fewer results rather than an error, so nothing
// complains and the degradation is invisible from the outside (plan §8.4).
func (d *Daemon) checkIndex() admin.HealthCheck {
	if !d.node.Warm() {
		return admin.HealthCheck{
			Name:     CheckIndex,
			Severity: admin.SeverityWarn,
			Detail:   "index is still warming; recall will return incomplete results until it finishes",
		}
	}

	// Indexable records exclude tombstones and conflict records, which carry no
	// claim and are deliberately not indexed.
	indexable := 0
	for _, info := range d.node.ListSpaces() {
		if !info.Readable {
			continue
		}
		for kind, n := range info.ByKind {
			switch record.Kind(kind) {
			case record.KindTombstone, record.KindConflict:
			default:
				indexable += n
			}
		}
	}
	indexed := d.node.IndexedRecords()
	resident := d.node.IndexResidentBytes()
	budget := d.node.RAMBudgetBytes()

	value := fmt.Sprintf("%d indexed of %d indexable, %d of %d budget bytes resident",
		indexed, indexable, resident, budget)

	switch {
	case indexable > 0 && indexed == 0:
		return admin.HealthCheck{
			Name:     CheckIndex,
			Severity: admin.SeverityCritical,
			Detail:   "the index is empty but records exist: every recall will return nothing without erroring",
			Value:    value,
		}
	case indexed < indexable*9/10:
		return admin.HealthCheck{
			Name:     CheckIndex,
			Severity: admin.SeverityWarn,
			Detail:   "the index is missing records the catalog holds; recall will be quietly incomplete",
			Value:    value,
		}
	case resident > budget:
		return admin.HealthCheck{
			Name:     CheckIndex,
			Severity: admin.SeverityWarn,
			Detail:   "the index is larger than the configured RAM budget; raise ram_budget_mb or expect paging",
			Value:    value,
		}
	default:
		return admin.HealthCheck{Name: CheckIndex, Severity: admin.SeverityOK, Detail: "warm and consistent with the catalog", Value: value}
	}
}

func (d *Daemon) checkTornTail() admin.HealthCheck {
	var torn []string
	for _, s := range d.node.Store().Stats() {
		if s.TruncatedTail {
			torn = append(torn, string(s.Space))
		}
	}
	if len(torn) == 0 {
		return admin.HealthCheck{Name: CheckTornTail, Severity: admin.SeverityOK, Detail: "no interrupted writes recovered at startup"}
	}
	sort.Strings(torn)
	return admin.HealthCheck{
		Name:     CheckTornTail,
		Severity: admin.SeverityWarn,
		Detail: "an interrupted write was discarded at startup; the log is consistent but one write was lost. " +
			"If this recurs, the host is losing power or being killed mid-write",
		Value: strings.Join(torn, ", "),
	}
}

// checkClockSkew measures peer clock offsets.
//
// HLC gives a total order, and under drift that order degrades quietly rather than
// failing: nothing errors, results are just wrong in a way nobody can see. Worse, a
// node offline for a month syncs and its stale writes land with newer timestamps than
// the truth that replaced them. Measuring the drift explicitly is the only way it
// becomes visible (plan §6.1, §8.4).
func (d *Daemon) checkClockSkew() admin.HealthCheck {
	s := d.currentSyncer()
	if s == nil {
		return admin.HealthCheck{
			Name:     CheckClockSkew,
			Severity: admin.SeveritySkipped,
			Detail:   "no transport configured, so no peer clocks to compare against",
		}
	}
	peers := s.Peers()
	if len(peers) == 0 {
		return admin.HealthCheck{
			Name:     CheckClockSkew,
			Severity: admin.SeveritySkipped,
			Detail:   "no peers seen yet, so no clocks to compare against",
		}
	}

	worst := int64(0)
	var worstPeer record.NodeID
	for _, p := range peers {
		skew := p.ClockSkewMS
		if skew < 0 {
			skew = -skew
		}
		if skew > worst {
			worst, worstPeer = skew, p.Node
		}
	}
	value := fmt.Sprintf("worst %dms (%s), across %d peers", worst, worstPeer, len(peers))
	switch {
	case worst >= ClockSkewCriticalMS:
		return admin.HealthCheck{
			Name:     CheckClockSkew,
			Severity: admin.SeverityCritical,
			Detail: "peer clocks differ enough that HLC tiebreaking is unreliable: a stale write from a " +
				"returning node can outrank the truth that replaced it. Check NTP on both ends",
			Value: value,
		}
	case worst >= ClockSkewWarnMS:
		return admin.HealthCheck{
			Name:     CheckClockSkew,
			Severity: admin.SeverityWarn,
			Detail:   "peer clocks are drifting; HLC tiebreaking degrades silently as this grows",
			Value:    value,
		}
	default:
		return admin.HealthCheck{Name: CheckClockSkew, Severity: admin.SeverityOK, Detail: "peer clocks are in step", Value: value}
	}
}

// checkEmbedModel compares the local embedding model against peers and against what
// this node's own records were embedded under.
//
// A mismatch does not break sync — text is shipped and re-embedded locally — it makes
// recall quietly worse. There is no error to notice and no failed request to trace, so
// the mismatch has to be checked for deliberately (plan §4.3).
func (d *Daemon) checkEmbedModel() admin.HealthCheck {
	local := d.node.Embedder().ModelID()
	held := d.node.EmbedModelCounts()

	var stale []string
	for model, count := range held {
		if model != "" && model != local {
			stale = append(stale, fmt.Sprintf("%s (%d records)", model, count))
		}
	}
	sort.Strings(stale)

	var peerMismatch []string
	if s := d.currentSyncer(); s != nil {
		for _, p := range s.Peers() {
			if p.EmbedModel != "" && p.EmbedModel != local {
				peerMismatch = append(peerMismatch, fmt.Sprintf("%s uses %s", p.Node, p.EmbedModel))
			}
		}
		sort.Strings(peerMismatch)
	}

	switch {
	case len(peerMismatch) > 0:
		return admin.HealthCheck{
			Name:     CheckEmbedModel,
			Severity: admin.SeverityWarn,
			Detail: "a peer embeds with a different model. Sync is unaffected — text is re-embedded locally — " +
				"but similarity scores are not comparable across the mesh, and recall gets worse without erroring",
			Value: fmt.Sprintf("local %s; %s", local, strings.Join(peerMismatch, ", ")),
		}
	case len(stale) > 0:
		return admin.HealthCheck{
			Name:     CheckEmbedModel,
			Severity: admin.SeverityWarn,
			Detail: "this node holds records embedded under a model it no longer runs; those records are " +
				"searchable but their scores are not comparable to new ones. Re-embedding the space fixes it",
			Value: fmt.Sprintf("local %s; also holds %s", local, strings.Join(stale, ", ")),
		}
	default:
		return admin.HealthCheck{
			Name:     CheckEmbedModel,
			Severity: admin.SeverityOK,
			Detail:   "one embedding model everywhere this node can see",
			Value:    local,
		}
	}
}

// checkKeyEpoch looks for spaces where records arrive under an epoch this node has no
// key for, which means a rotation happened and the new key never reached here.
func (d *Daemon) checkKeyEpoch() admin.HealthCheck {
	var behind []string
	for _, info := range d.node.ListSpaces() {
		if info.Readable && info.Undecryptable > 0 {
			behind = append(behind, fmt.Sprintf("%s (%d records)", info.Space, info.Undecryptable))
		}
	}
	if len(behind) == 0 {
		return admin.HealthCheck{Name: CheckKeyEpoch, Severity: admin.SeverityOK, Detail: "every held record opens under a key this node has"}
	}
	sort.Strings(behind)
	return admin.HealthCheck{
		Name:     CheckKeyEpoch,
		Severity: admin.SeverityWarn,
		Detail: "records are held that this node cannot open, which usually means a key rotation whose new " +
			"epoch was never wrapped to this node. Ask the space owner to re-share it",
		Value: strings.Join(behind, ", "),
	}
}

// checkUnsendable looks for records queued for a space whose key this node has lost.
//
// An unsendable backlog grows forever and never completes, and it looks exactly like a
// slow sync from the outside (plan §8.4).
func (d *Daemon) checkUnsendable() admin.HealthCheck {
	var stuck []string
	for _, info := range d.node.ListSpaces() {
		if !info.Readable && info.Records > 0 && !d.node.Relaying() {
			stuck = append(stuck, fmt.Sprintf("%s (%d records)", info.Space, info.Records))
		}
	}
	if len(stuck) == 0 {
		return admin.HealthCheck{Name: CheckUnsendable, Severity: admin.SeverityOK, Detail: "no records held for spaces with no key"}
	}
	sort.Strings(stuck)
	return admin.HealthCheck{
		Name:     CheckUnsendable,
		Severity: admin.SeverityWarn,
		Detail: "this node holds records for spaces it has no key for, but relaying is off. They will never be " +
			"read here and never be usefully served. Either enable relaying or drop the space",
		Value: strings.Join(stuck, ", "),
	}
}

func (d *Daemon) checkOutbound() admin.HealthCheck {
	s := d.currentSyncer()
	if s == nil {
		return admin.HealthCheck{
			Name:     CheckOutbound,
			Severity: admin.SeveritySkipped,
			Detail:   "no transport configured, so nothing is queued outbound",
		}
	}
	depth := s.OutboundQueue()
	value := fmt.Sprintf("%d records", depth)
	switch {
	case depth >= OutboundQueueCritical:
		return admin.HealthCheck{
			Name:     CheckOutbound,
			Severity: admin.SeverityCritical,
			Detail:   "the outbound queue is very deep; sync is effectively stuck rather than slow",
			Value:    value,
		}
	case depth >= OutboundQueueWarn:
		return admin.HealthCheck{
			Name:     CheckOutbound,
			Severity: admin.SeverityWarn,
			Detail:   "the outbound queue is growing; peers are not keeping up with local writes",
			Value:    value,
		}
	default:
		return admin.HealthCheck{Name: CheckOutbound, Severity: admin.SeverityOK, Detail: "outbound queue is draining", Value: value}
	}
}

func (d *Daemon) checkPeers() admin.HealthCheck {
	s := d.currentSyncer()
	if s == nil {
		return admin.HealthCheck{
			Name:     CheckPeers,
			Severity: admin.SeveritySkipped,
			Detail:   "no transport configured; this node is deliberately alone",
		}
	}
	peers := s.Peers()
	if len(peers) == 0 {
		return admin.HealthCheck{
			Name:     CheckPeers,
			Severity: admin.SeveritySkipped,
			Detail:   fmt.Sprintf("no peers discovered (%s)", s.Discovery()),
		}
	}

	now := d.node.Clock().Now()
	var silent []string
	worst := admin.SeverityOK
	for _, p := range peers {
		if p.LastContact.IsZero() {
			silent = append(silent, fmt.Sprintf("%s (never)", p.Node))
			worst = admin.Worse(worst, admin.SeverityWarn)
			continue
		}
		age := int64(now.Sub(p.LastContact).Seconds())
		switch {
		case age >= PeerSilentCriticalSec:
			silent = append(silent, fmt.Sprintf("%s (%ds)", p.Node, age))
			worst = admin.Worse(worst, admin.SeverityCritical)
		case age >= PeerSilentWarnSec:
			silent = append(silent, fmt.Sprintf("%s (%ds)", p.Node, age))
			worst = admin.Worse(worst, admin.SeverityWarn)
		}
	}
	if len(silent) == 0 {
		return admin.HealthCheck{
			Name:     CheckPeers,
			Severity: admin.SeverityOK,
			Detail:   fmt.Sprintf("all %d peers heard from recently", len(peers)),
		}
	}
	sort.Strings(silent)
	return admin.HealthCheck{
		Name:     CheckPeers,
		Severity: worst,
		Detail:   "peers have gone quiet beyond the threshold, which is what a partition looks like from here",
		Value:    strings.Join(silent, ", "),
	}
}

// checkParticipants is the divergence the members command exists to show, promoted to
// a check: a peer that is up on the tailnet but absent from every version vector is
// reachable and not syncing, which is the failure you actually want to catch
// (plan §8.2).
func (d *Daemon) checkParticipants() admin.HealthCheck {
	members := d.members()
	if members.Enrolled == 0 {
		return admin.HealthCheck{
			Name:     CheckParticipants,
			Severity: admin.SeveritySkipped,
			Detail:   fmt.Sprintf("no enrolled peers to compare against (%s)", members.Discovery),
		}
	}
	var idle []string
	for _, p := range members.Peers {
		if p.Enrolled && !p.Participating {
			idle = append(idle, string(p.Node))
		}
	}
	if len(idle) == 0 {
		return admin.HealthCheck{
			Name:     CheckParticipants,
			Severity: admin.SeverityOK,
			Detail:   fmt.Sprintf("%d of %d enrolled peers are participating", members.Participating, members.Enrolled),
		}
	}
	sort.Strings(idle)
	return admin.HealthCheck{
		Name:     CheckParticipants,
		Severity: admin.SeverityWarn,
		Detail: "these peers are reachable on the tailnet but have never appeared in a version vector. " +
			"Reachability is not sync: check that they subscribe to a space in common and hold its key",
		Value: strings.Join(idle, ", "),
	}
}

// checkConflicts reports unresolved contradictions in shared spaces.
//
// Shared spaces never auto-resolve, by design, which means the backlog is a queue a
// human has to work. A growing queue is adjudication falling behind, not a bug
// (plan §6.8, §8.4).
func (d *Daemon) checkConflicts() admin.HealthCheck {
	total := 0
	var perSpace []string
	for _, info := range d.node.ListSpaces() {
		if !info.Readable {
			continue
		}
		n := info.ByKind[string(record.KindConflict)]
		if n == 0 {
			continue
		}
		total += n
		perSpace = append(perSpace, fmt.Sprintf("%s (%d)", info.Space, n))
	}
	sort.Strings(perSpace)
	value := strings.Join(perSpace, ", ")
	if total >= ConflictBacklogWarn {
		return admin.HealthCheck{
			Name:     CheckConflicts,
			Severity: admin.SeverityWarn,
			Detail: "unresolved contradictions are piling up. Shared spaces never auto-resolve on purpose, so " +
				"this is a queue someone has to work through with `memctl conflicts`",
			Value: value,
		}
	}
	return admin.HealthCheck{
		Name:     CheckConflicts,
		Severity: admin.SeverityOK,
		Detail:   fmt.Sprintf("%d unresolved contradictions", total),
		Value:    value,
	}
}
