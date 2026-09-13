// Command memctl is the memory mesh CLI.
//
// It talks to the local memd over a unix socket and never to the tailnet (plan §8).
// The admin surface is your own node; everything it says about peers is what your node
// already learned through sync, which means two things are always true and both are
// printed rather than hidden:
//
//   - Peer-derived numbers carry an "as of" age. They are memories of a conversation,
//     not live readings.
//   - Readable and relayed spaces are visibly different everywhere. For a space with
//     no key: counts and bytes only, never a body, never a tag, never a title.
//
// Every command supports --json, and both renderings derive from the same struct so
// they cannot drift.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/coryforsythe/memmesh/internal/admin"
	"github.com/coryforsythe/memmesh/internal/daemon"
	"github.com/coryforsythe/memmesh/internal/record"
)

func main() {
	code, err := run(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "memctl: %v\n", err)
		if errors.Is(err, admin.ErrNoDaemon) {
			fmt.Fprintln(os.Stderr, "\nIs memd running? Start it with:  memd serve")
		}
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

// options are the flags every command shares.
type options struct {
	home  string
	json  bool
	watch bool
	// only narrows health to one check.
	only string
	// space and peer narrow commands that support it.
	space string
	peer  string
}

func run(args []string) (int, error) {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		usage()
		return 0, nil
	}

	command := args[0]
	opts, rest, err := parseFlags(args[1:])
	if err != nil {
		return 1, err
	}
	_ = rest

	switch command {
	case "status":
		return withClient(opts, func(c *admin.Client) (int, error) {
			return renderLoop(opts, c, admin.Request{Command: admin.CmdStatus}, func(r *admin.Response) (int, error) {
				return 0, printStatus(r.Status)
			})
		})
	case "spaces":
		return withClient(opts, func(c *admin.Client) (int, error) {
			return renderLoop(opts, c, admin.Request{Command: admin.CmdSpaces, Space: record.SpaceID(opts.space)}, func(r *admin.Response) (int, error) {
				return 0, printSpaces(r.Spaces)
			})
		})
	case "members":
		return withClient(opts, func(c *admin.Client) (int, error) {
			return renderLoop(opts, c, admin.Request{Command: admin.CmdMembers}, func(r *admin.Response) (int, error) {
				return 0, printMembers(r.Members)
			})
		})
	case "health":
		return withClient(opts, func(c *admin.Client) (int, error) {
			return renderLoop(opts, c, admin.Request{Command: admin.CmdHealth, Check: opts.only}, func(r *admin.Response) (int, error) {
				if err := printHealth(r.Health); err != nil {
					return 1, err
				}
				return r.Health.Exit, nil
			})
		})
	case "keys":
		return withClient(opts, func(c *admin.Client) (int, error) {
			return renderLoop(opts, c, admin.Request{Command: admin.CmdKeys}, func(r *admin.Response) (int, error) {
				return 0, printKeys(r.Keys)
			})
		})
	case "sync":
		return withClient(opts, func(c *admin.Client) (int, error) {
			return renderLoop(opts, c, admin.Request{
				Command: admin.CmdSync,
				Space:   record.SpaceID(opts.space),
				Peer:    record.NodeID(opts.peer),
			}, func(r *admin.Response) (int, error) {
				return 0, printSync(r.Sync)
			})
		})
	case "doctor":
		return withClient(opts, func(c *admin.Client) (int, error) {
			return doctor(opts, c)
		})
	case "checks":
		for _, name := range daemon.AllChecks() {
			fmt.Println(name)
		}
		return 0, nil
	default:
		usage()
		return 1, fmt.Errorf("unknown command %q", command)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `memctl — talk to the local memd

  memctl status              node, spaces, RAM, queue, last sync
  memctl spaces              per-space records, bytes, epoch, conflict policy
  memctl members             peers: enrolled vs participating, and lag in both directions
  memctl health              checks with exit codes: 0 ok, 1 warn, 2 critical
  memctl doctor              health plus what to do about it
  memctl keys                recipient key, agent keys, per-space epochs
  memctl sync                force anti-entropy now
  memctl checks              list the health check names

Flags:
  --home <dir>     data directory (default $MEMMESH_HOME, else ~/.memmesh)
  --json           machine-readable output; stable schema, same struct as the table
  --watch          refresh every 2s (status and members)
  --only <check>   narrow health to one check
  --space <space>  narrow spaces or sync to one space
  --peer <node>    narrow sync to one peer

memctl only ever talks to your own daemon. Everything it reports about peers is what
your node last learned, so peer numbers carry an age. Nothing here blocks on the
network.
`)
}

func parseFlags(args []string) (options, []string, error) {
	opts := options{home: defaultHome()}
	var rest []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json":
			opts.json = true
		case "--watch":
			opts.watch = true
		case "--home", "--only", "--space", "--peer":
			if i+1 >= len(args) {
				return opts, nil, fmt.Errorf("%s needs a value", args[i])
			}
			value := args[i+1]
			i++
			switch args[i-1] {
			case "--home":
				opts.home = value
			case "--only":
				opts.only = value
			case "--space":
				opts.space = value
			case "--peer":
				opts.peer = value
			}
		default:
			if strings.HasPrefix(args[i], "-") {
				return opts, nil, fmt.Errorf("unknown flag %q", args[i])
			}
			rest = append(rest, args[i])
		}
	}
	return opts, rest, nil
}

func defaultHome() string {
	if dir := os.Getenv("MEMMESH_HOME"); dir != "" {
		return dir
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".memmesh")
	}
	return ".memmesh"
}

func withClient(opts options, fn func(*admin.Client) (int, error)) (int, error) {
	c, err := admin.Dial(opts.home)
	if err != nil {
		return 1, err
	}
	defer c.Close()
	return fn(c)
}

// renderLoop issues the request once, or repeatedly under --watch.
func renderLoop(opts options, c *admin.Client, req admin.Request, render func(*admin.Response) (int, error)) (int, error) {
	for {
		resp, err := c.Do(req)
		if err != nil {
			return 1, err
		}
		if opts.json {
			if err := emitJSON(resp); err != nil {
				return 1, err
			}
		} else {
			code, err := render(resp)
			if err != nil {
				return 1, err
			}
			if !opts.watch {
				return code, nil
			}
		}
		if !opts.watch {
			return 0, nil
		}
		time.Sleep(2 * time.Second)
		// Clear the screen between frames so a watched table reads as one live view
		// rather than an ever-growing scrollback.
		fmt.Print("\033[H\033[2J")
	}
}

// emitJSON writes the payload the command asked for, unwrapped from the envelope, so
// the schema a dashboard consumes is the payload type rather than a union.
func emitJSON(resp *admin.Response) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	switch {
	case resp.Status != nil:
		return enc.Encode(resp.Status)
	case resp.Spaces != nil:
		return enc.Encode(resp.Spaces)
	case resp.Members != nil:
		return enc.Encode(resp.Members)
	case resp.Health != nil:
		return enc.Encode(resp.Health)
	case resp.Keys != nil:
		return enc.Encode(resp.Keys)
	case resp.Sync != nil:
		return enc.Encode(resp.Sync)
	default:
		return enc.Encode(resp)
	}
}

func newTable() *tabwriter.Writer {
	return tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
}

func printStatus(s *admin.Status) error {
	if s == nil {
		return errors.New("daemon returned no status")
	}
	w := newTable()
	fmt.Fprintf(w, "node\t%s\n", s.Node)
	fmt.Fprintf(w, "software\t%s (wire v%d, admin protocol %d)\n", s.Software, s.WireVersion, s.Protocol)
	fmt.Fprintf(w, "uptime\t%s\n", humanDuration(s.UptimeSec))
	fmt.Fprintf(w, "recipient\t%s\n", s.Recipient)

	for i, a := range s.Agents {
		label := "agents"
		if i > 0 {
			label = ""
		}
		fmt.Fprintf(w, "%s\t%s  %s  (%d records)\n", label, a.Name, a.Fingerprint, a.Records)
	}
	if len(s.Agents) == 0 {
		fmt.Fprintf(w, "agents\tnone yet — keys are created when an agent first writes\n")
	}

	relayNote := "off"
	if s.Relaying {
		relayNote = fmt.Sprintf("on (%d relayed)", s.SpacesRelayed)
	}
	fmt.Fprintf(w, "spaces\t%d readable, %d relayed, %d total\n", s.SpacesReadable, s.SpacesRelayed, s.SpacesTotal)
	fmt.Fprintf(w, "relaying\t%s\n", relayNote)
	fmt.Fprintf(w, "records\t%d (%s on disk)\n", s.Records, humanBytes(s.Bytes))

	warm := "warm"
	if !s.Warm {
		warm = "REPLAYING — recall is incomplete until this finishes"
	}
	fmt.Fprintf(w, "index\t%d records, %s resident of %s budget (%s)\n",
		s.IndexedRecords, humanBytes(s.IndexResidentBytes), humanBytes(s.RAMBudgetBytes), warm)
	fmt.Fprintf(w, "embed model\t%s\n", s.EmbedModel)
	fmt.Fprintf(w, "outbound queue\t%d\n", s.OutboundQueue)
	if s.LastSync != nil {
		fmt.Fprintf(w, "last sync\t%s, %s ago (sent %d, received %d)\n",
			s.LastSync.Peer, humanDuration(s.LastSync.AgeSec), s.LastSync.Sent, s.LastSync.Received)
	} else {
		fmt.Fprintf(w, "last sync\tnever\n")
	}
	return w.Flush()
}

func printSpaces(s *admin.Spaces) error {
	if s == nil {
		return errors.New("daemon returned no spaces")
	}
	if len(s.Spaces) == 0 {
		fmt.Println("no spaces yet — create one with:  memd space create user/<you>")
		return nil
	}
	w := newTable()
	fmt.Fprintln(w, "SPACE\tACCESS\tPOLICY\tEPOCH\tRECORDS\tBYTES\tINDEXED\tNODES\tKINDS")
	for _, row := range s.Spaces {
		access := "readable"
		epoch := fmt.Sprintf("%d", row.Epoch)
		indexed := fmt.Sprintf("%d", row.Indexed)
		kinds := formatKinds(row.ByKind)
		if !row.Readable {
			// Counts and bytes only. Everything that would need the key stays blank
			// rather than showing a misleading zero.
			access = "RELAYED"
			epoch, indexed, kinds = "-", "-", "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%s\t%s\t%d\t%s\n",
			row.Space, access, row.Policy, epoch, row.Records, humanBytes(row.Bytes), indexed, row.Nodes, kinds)
	}
	if err := w.Flush(); err != nil {
		return err
	}

	var notes []string
	for _, row := range s.Spaces {
		if !row.Readable {
			notes = append(notes, fmt.Sprintf("%s is relayed: this node stores and gossips it but holds no key, so counts and bytes are all it can report", row.Space))
		}
		if row.Undecryptable > 0 {
			notes = append(notes, fmt.Sprintf("%s holds %d records this node cannot open — a rotation whose new epoch never reached here", row.Space, row.Undecryptable))
		}
		if row.Pending > 0 {
			notes = append(notes, fmt.Sprintf("%s has %d supersessions waiting for records that have not arrived", row.Space, row.Pending))
		}
		if row.TruncatedTail {
			notes = append(notes, fmt.Sprintf("%s recovered an interrupted write at startup; one write was lost", row.Space))
		}
	}
	printNotes(notes)
	return nil
}

func printMembers(m *admin.Members) error {
	if m == nil {
		return errors.New("daemon returned no members")
	}
	fmt.Printf("enrolled %d · participating %d · discovery: %s\n\n", m.Enrolled, m.Participating, m.Discovery)
	if len(m.Peers) == 0 {
		fmt.Println("no peers known yet.")
		fmt.Println("Enrolled means visible on the tailnet with the node tag; participating means records")
		fmt.Println("from that node have actually arrived. A peer can be the first without the second.")
		return nil
	}

	w := newTable()
	// Bidirectional lag is printed immediately after the node, because it is the
	// single most diagnostic number here (plan §8.2).
	fmt.Fprintln(w, "NODE\tBEHIND\tAHEAD\tSTATE\tTRANSPORT\tLAST CONTACT\tSKEW\tEMBED MODEL\tSPACES\tAS OF")
	for _, p := range m.Peers {
		state := "participating"
		switch {
		case p.Enrolled && !p.Participating:
			state = "ENROLLED ONLY"
		case !p.Enrolled && p.Participating:
			state = "seen, not enrolled"
		}
		transport := p.Transport
		if transport == "" {
			transport = "-"
		}
		contact := "never"
		if p.LastContactAgeSec >= 0 {
			contact = humanDuration(p.LastContactAgeSec) + " ago"
		}
		model := p.EmbedModel
		if model == "" {
			model = "-"
		}
		fmt.Fprintf(w, "%s\t%d\t%d\t%s\t%s\t%s\t%dms\t%s\t%d\t%s ago\n",
			p.Node, p.LagBehind, p.LagAhead, state, transport, contact,
			p.ClockSkewMS, model, len(p.SharedSpaces), humanDuration(p.AsOfAgeSec))
	}
	if err := w.Flush(); err != nil {
		return err
	}

	fmt.Println("\nBEHIND = records the peer has that you do not. AHEAD = the reverse.")
	fmt.Println("Lag in one direction only is what a stalled sync looks like.")
	printNotes(m.Notes)
	return nil
}

func printHealth(h *admin.Health) error {
	if h == nil {
		return errors.New("daemon returned no health report")
	}
	w := newTable()
	for _, c := range h.Checks {
		fmt.Fprintf(w, "%s\t%s\t%s\n", severityLabel(c.Severity), c.Name, c.Detail)
		if c.Value != "" {
			fmt.Fprintf(w, "\t\t%s\n", c.Value)
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	fmt.Printf("\nexit %d (%s)\n", h.Exit, exitLabel(h.Exit))
	return nil
}

// doctor is health plus remediation, which is the difference between a check that
// reports a problem and a tool that helps with one (plan §8.5).
func doctor(opts options, c *admin.Client) (int, error) {
	resp, err := c.Do(admin.Request{Command: admin.CmdHealth})
	if err != nil {
		return 1, err
	}
	if opts.json {
		return resp.Health.Exit, emitJSON(resp)
	}
	if err := printHealth(resp.Health); err != nil {
		return 1, err
	}

	var advice []string
	for _, check := range resp.Health.Checks {
		if check.Severity == admin.SeverityOK {
			continue
		}
		if remedy := remedyFor(check); remedy != "" {
			advice = append(advice, fmt.Sprintf("%s: %s", check.Name, remedy))
		}
	}
	if len(advice) > 0 {
		fmt.Println("\nWhat to do:")
		for _, line := range advice {
			fmt.Printf("  · %s\n", line)
		}
	}
	return resp.Health.Exit, nil
}

// remedyFor maps a check to the action that usually fixes it. Skipped checks get
// advice too, because "this could not run" is a condition worth resolving rather than
// a clean bill of health.
func remedyFor(c admin.HealthCheck) string {
	switch c.Name {
	case daemon.CheckDaemon:
		return "check disk space and filesystem permissions on the data directory"
	case daemon.CheckIndex:
		if c.Severity == admin.SeverityWarn && strings.Contains(c.Detail, "warming") {
			return "wait for warm-up; it is a full replay of the log"
		}
		return "restart memd to rebuild the index from the log — the index is a derived cache, so nothing is lost"
	case daemon.CheckTornTail:
		return "if this recurs, the host is losing power or memd is being killed mid-write; check for OOM kills"
	case daemon.CheckClockSkew:
		return "fix NTP on both ends; HLC tiebreaking cannot be trusted while clocks disagree"
	case daemon.CheckEmbedModel:
		return "align the embedding model across nodes, or re-embed the affected space so scores are comparable again"
	case daemon.CheckKeyEpoch:
		return "ask the space owner to re-share it: `memd space share <space> <your rk_…>`"
	case daemon.CheckUnsendable:
		return "either start memd with --relay to carry these spaces deliberately, or remove their directories"
	case daemon.CheckOutbound:
		return "check peer reachability; a deep queue with reachable peers usually means one peer is refusing records"
	case daemon.CheckPeers:
		return "check the tailnet: `tailscale status`, and that both ends carry the node tag"
	case daemon.CheckParticipants:
		return "reachability is not sync — confirm the peer subscribes to a space in common and holds its key"
	case daemon.CheckConflicts:
		return "work the queue with `memctl conflicts`; shared spaces never auto-resolve on purpose"
	default:
		return ""
	}
}

func printKeys(k *admin.Keys) error {
	if k == nil {
		return errors.New("daemon returned no keys")
	}
	fmt.Printf("recipient  %s\n", k.Recipient)
	fmt.Printf("           %s\n\n", k.RecipientFingerprint)

	if len(k.Agents) > 0 {
		w := newTable()
		fmt.Fprintln(w, "AGENT\tFINGERPRINT\tRECORDS")
		for _, a := range k.Agents {
			fmt.Fprintf(w, "%s\t%s\t%d\n", a.Name, a.Fingerprint, a.Records)
		}
		if err := w.Flush(); err != nil {
			return err
		}
		fmt.Println()
	}

	w := newTable()
	fmt.Fprintln(w, "SPACE\tACCESS\tCURRENT EPOCH\tEPOCHS HELD")
	for _, row := range k.SpaceKeys {
		if !row.Readable {
			fmt.Fprintf(w, "%s\tRELAYED\t-\t-\n", row.Space)
			continue
		}
		fmt.Fprintf(w, "%s\treadable\t%d\t%s\n", row.Space, row.Current, formatEpochs(row.Epochs))
	}
	if err := w.Flush(); err != nil {
		return err
	}
	fmt.Println("\nOld epochs are kept on purpose: rotation stops a removed member reading new")
	fmt.Println("writes, and keeping the old keys is what lets you still read the history.")
	return nil
}

func printSync(s *admin.Sync) error {
	if s == nil {
		return errors.New("daemon returned no sync result")
	}
	if len(s.Attempted) == 0 {
		fmt.Println("no peers to sync with.")
		return nil
	}
	w := newTable()
	fmt.Fprintln(w, "PEER\tSENT\tRECEIVED")
	for _, e := range s.Events {
		fmt.Fprintf(w, "%s\t%d\t%d\n", e.Peer, e.Sent, e.Received)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if len(s.Errors) > 0 {
		peers := make([]string, 0, len(s.Errors))
		for peer := range s.Errors {
			peers = append(peers, peer)
		}
		sort.Strings(peers)
		fmt.Println("\nfailed:")
		for _, peer := range peers {
			fmt.Printf("  %s: %s\n", peer, s.Errors[peer])
		}
	}
	return nil
}

func printNotes(notes []string) {
	if len(notes) == 0 {
		return
	}
	fmt.Println()
	for _, note := range notes {
		fmt.Printf("note: %s\n", note)
	}
}

func severityLabel(s string) string {
	switch s {
	case admin.SeverityOK:
		return "ok"
	case admin.SeverityWarn:
		return "WARN"
	case admin.SeverityCritical:
		return "CRIT"
	case admin.SeveritySkipped:
		// Deliberately not "ok": a check that could not run has measured nothing.
		return "skip"
	default:
		return s
	}
}

func exitLabel(code int) string {
	switch code {
	case 0:
		return "ok"
	case 1:
		return "warn"
	default:
		return "critical"
	}
}

func formatKinds(byKind map[string]int) string {
	if len(byKind) == 0 {
		return "-"
	}
	kinds := make([]string, 0, len(byKind))
	for kind := range byKind {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	parts := make([]string, 0, len(kinds))
	for _, kind := range kinds {
		if byKind[kind] == 0 {
			continue
		}
		parts = append(parts, fmt.Sprintf("%s:%d", kind, byKind[kind]))
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, " ")
}

func formatEpochs(epochs []uint32) string {
	if len(epochs) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(epochs))
	for _, e := range epochs {
		parts = append(parts, fmt.Sprintf("%d", e))
	}
	return strings.Join(parts, ",")
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	value := float64(n)
	units := []string{"KB", "MB", "GB", "TB"}
	for _, suffix := range units {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.1f%s", value, suffix)
		}
	}
	return fmt.Sprintf("%.1fPB", value/unit)
}

func humanDuration(seconds int64) string {
	if seconds < 0 {
		return "never"
	}
	d := time.Duration(seconds) * time.Second
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", seconds)
	case d < time.Hour:
		return fmt.Sprintf("%dm%ds", seconds/60, seconds%60)
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh%dm", seconds/3600, (seconds%3600)/60)
	default:
		return fmt.Sprintf("%dd%dh", seconds/86400, (seconds%86400)/3600)
	}
}
