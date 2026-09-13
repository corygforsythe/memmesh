// Command memd is the memory mesh daemon.
//
// It owns the per-space logs, the vector index, the key material, the MCP server and
// (from M3) the sync engine. Exactly one memd runs per data directory, because exactly
// one process can own the logs.
//
// Usage:
//
//	memd serve                      run the daemon
//	memd mcp                        bridge stdio to a running daemon's MCP socket
//	memd space create <space>       create a space and its content key
//	memd space share <space> <rk_>  wrap the space key to a recipient
//	memd space join <file>          install a wrapped key received from someone else
//	memd space rotate <space>       rotate into a new epoch (this is member removal)
//	memd identity                   print this node's recipient key
//	memd version                    print the build version
//
// The data directory defaults to $MEMMESH_HOME, then ~/.memmesh.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/coryforsythe/memmesh/internal/admin"
	"github.com/coryforsythe/memmesh/internal/crypto"
	"github.com/coryforsythe/memmesh/internal/daemon"
	"github.com/coryforsythe/memmesh/internal/node"
	"github.com/coryforsythe/memmesh/internal/record"
	"github.com/coryforsythe/memmesh/internal/sync"
	"github.com/coryforsythe/memmesh/internal/transport/tailnet"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "memd: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		args = []string{"serve"}
	}
	switch args[0] {
	case "serve":
		return cmdServe(args[1:])
	case "mcp":
		return cmdMCP(args[1:])
	case "space":
		return cmdSpace(args[1:])
	case "identity":
		return cmdIdentity(args[1:])
	case "version":
		fmt.Println(node.Software)
		return nil
	case "-h", "--help", "help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `memd — the memory mesh daemon

  memd serve                      run the daemon
  memd mcp                        bridge stdio to a running daemon (point your agent at this)
  memd space create <space>       create a space and its content key
  memd space share <space> <rk_…>  wrap the space key to a recipient, for handing over
  memd space join <file>          install a wrapped key someone shared with you
  memd space rotate <space>       rotate into a new epoch — this is how a member is removed
  memd identity                   print this node's recipient key
  memd version

Spaces are named agent/<id>, user/<id> or shared/<name>. The prefix selects the
conflict policy, so it is not cosmetic: shared/* never auto-resolves a contradiction.

Data directory: $MEMMESH_HOME, else ~/.memmesh
`)
}

// dataDir resolves the data directory the same way for every subcommand.
func dataDir(fs *flag.FlagSet) *string {
	def := os.Getenv("MEMMESH_HOME")
	if def == "" {
		if home, err := os.UserHomeDir(); err == nil {
			def = filepath.Join(home, ".memmesh")
		} else {
			def = ".memmesh"
		}
	}
	return fs.String("home", def, "data directory")
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	dir := dataDir(fs)
	nodeID := fs.String("node", defaultNodeID(), "this machine's node id; version vectors are keyed by it, so keep it stable")
	model := fs.String("author-model", os.Getenv("MEMMESH_AUTHOR_MODEL"), "model id recorded on records for audit; never used to filter")
	ram := fs.Int("ram-budget-mb", node.DefaultRAMBudgetMB, "budget the index footprint is reported against")
	relay := fs.Bool("relay", false, "carry spaces this node holds no key for (off by default: your disk would hold other people's ciphertext)")
	noSync := fs.Bool("no-sync", false, "run without a transport: a single machine with no peers, which is a supported deployment")
	port := fs.Int("port", tailnet.DefaultPort, "tcp port for tailnet peers")
	tag := fs.String("tag", tailnet.DefaultTag, "tailnet tag that selects participating machines")
	tsSocket := fs.String("tailscale-socket", "", "override the local Tailscale API socket path")
	bindAll := fs.Bool("bind-all", false, "listen on every interface rather than only the tailnet address")
	pullInterval := fs.Duration("pull-interval", sync.DefaultPullInterval, "base period between anti-entropy pulls")
	if err := fs.Parse(args); err != nil {
		return err
	}

	n, err := node.Open(node.Config{
		Root:        *dir,
		ID:          record.NodeID(*nodeID),
		AuthorModel: *model,
		RAMBudgetMB: *ram,
		Relay:       *relay,
	})
	if err != nil {
		return err
	}
	defer n.Close()

	d, err := daemon.Start(daemon.Config{Node: n, Dir: *dir})
	if err != nil {
		return err
	}
	defer d.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// The transport is optional. A node with no peers still serves its agents, still
	// writes and still reads, because the network is in neither path — so a tailnet
	// that is absent or down is a reporting condition, not a startup failure.
	var transportNote string
	if *noSync {
		transportNote = "disabled by --no-sync"
	} else {
		transport, err := tailnet.Open(tailnet.Config{
			NodeID:     n.ID(),
			Port:       *port,
			Tag:        *tag,
			SocketPath: *tsSocket,
			BindAll:    *bindAll,
		})
		if err != nil {
			// Losing the transport must not take the daemon with it.
			transportNote = fmt.Sprintf("unavailable: %v", err)
		} else {
			defer transport.Close()
			signer, err := n.FrameSigner()
			if err != nil {
				return err
			}
			engine, err := sync.New(sync.Config{
				Node:         n,
				Transport:    transport,
				Signer:       signer,
				Clock:        n.Clock(),
				PullInterval: *pullInterval,
			})
			if err != nil {
				return err
			}
			defer engine.Close()
			d.SetSyncer(engine)
			go engine.Run(ctx)
			// Query discovery once at startup, so the banner says what the mesh
			// actually looks like rather than "not queried yet".
			peers, peersErr := transport.Peers()
			if peersErr != nil {
				transportNote = fmt.Sprintf("%s — %s", transport.Addr(), transport.Discovery())
			} else {
				transportNote = fmt.Sprintf("%s — %s, %d reachable", transport.Addr(), transport.Discovery(), countOnline(peers))
			}
		}
	}

	fmt.Printf("memd %s started\n", node.Software)
	fmt.Printf("  node        %s\n", n.ID())
	fmt.Printf("  home        %s\n", *dir)
	fmt.Printf("  admin       %s\n", d.AdminSocket())
	fmt.Printf("  mcp         %s\n", d.MCPSocket())
	fmt.Printf("  recipient   %s\n", n.Recipient())
	fmt.Printf("  embed model %s\n", n.Embedder().ModelID())
	fmt.Printf("  spaces      %d readable, %d relayed\n", len(n.ReadableSpaces()), len(n.RelayedSpaces()))
	fmt.Printf("  tailnet     %s\n", transportNote)
	if !*relay {
		fmt.Println("  relaying    off — this node will not store spaces it cannot read")
	}

	<-ctx.Done()
	fmt.Println("\nmemd: shutting down")
	return nil
}

func countOnline(peers []sync.Peer) int {
	n := 0
	for _, p := range peers {
		if p.Online {
			n++
		}
	}
	return n
}

// defaultNodeID uses the hostname, which is also what the tailnet name is normally
// derived from, so the two agree without configuration in the common case.
func defaultNodeID() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		return "node"
	}
	// Node ids allow letters, digits, dash, dot and underscore; hostnames rarely
	// contain anything else, but sanitise rather than fail at startup.
	out := make([]rune, 0, len(host))
	for _, r := range host {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.', r == '_':
			out = append(out, r)
		default:
			out = append(out, '-')
		}
	}
	return string(out)
}

func cmdMCP(args []string) error {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	dir := dataDir(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	// The bridge is deliberately dumb: it does not parse MCP, so it cannot corrupt a
	// message and needs no version agreement with the daemon.
	return daemon.BridgeMCP(*dir, os.Stdin, os.Stdout)
}

func cmdSpace(args []string) error {
	if len(args) == 0 {
		return errors.New("space: expected create, share, join or rotate")
	}
	action := args[0]
	fs := flag.NewFlagSet("space "+action, flag.ContinueOnError)
	dir := dataDir(fs)
	nodeID := fs.String("node", defaultNodeID(), "this machine's node id")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	rest := fs.Args()

	// These subcommands open the node directly, so they must not run while a daemon
	// holds the same directory. Two processes writing one log is precisely the failure
	// the single-owner design exists to prevent, and it would corrupt the log rather
	// than merely confusing the operator.
	if err := refuseIfDaemonRunning(*dir); err != nil {
		return err
	}
	n, err := node.Open(node.Config{Root: *dir, ID: record.NodeID(*nodeID)})
	if err != nil {
		return err
	}
	defer n.Close()

	switch action {
	case "create":
		if len(rest) != 1 {
			return errors.New("space create <space>")
		}
		space := record.SpaceID(rest[0])
		if err := n.CreateSpace(space); err != nil {
			return err
		}
		epoch, _ := n.Keyring().CurrentEpoch(string(space))
		fmt.Printf("created %s (epoch %d, policy %s)\n", space, epoch, record.PolicyFor(space))
		fmt.Printf("share it with:  memd space share %s <their rk_…>\n", space)
		return nil

	case "share":
		if len(rest) != 2 {
			return errors.New("space share <space> <rk_…>")
		}
		pub, err := crypto.ParseRecipientPublic(rest[1])
		if err != nil {
			return err
		}
		wrapped, err := n.ShareSpace(record.SpaceID(rest[0]), pub)
		if err != nil {
			return err
		}
		encoded, err := json.MarshalIndent(wrapped, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(encoded))
		fmt.Fprintln(os.Stderr, "\nHand this to the recipient however you like; it is only usable by them.")
		fmt.Fprintln(os.Stderr, "Remember: sharing is forward-only. Revoking later does not unsend what they sync.")
		return nil

	case "join":
		if len(rest) != 1 {
			return errors.New("space join <file with the wrapped key, or - for stdin>")
		}
		var raw []byte
		if rest[0] == "-" {
			raw, err = readAll(os.Stdin)
		} else {
			raw, err = os.ReadFile(rest[0])
		}
		if err != nil {
			return err
		}
		var wrapped crypto.WrappedKey
		if err := json.Unmarshal(raw, &wrapped); err != nil {
			return fmt.Errorf("parse wrapped key: %w", err)
		}
		if err := n.JoinSpace(&wrapped); err != nil {
			return err
		}
		space := record.SpaceID(wrapped.Space)
		info := n.ListSpaces()
		for _, s := range info {
			if s.Space == space {
				fmt.Printf("joined %s (epoch %d): %d records now readable, %d indexed\n",
					space, wrapped.Epoch, s.Records, s.Indexed)
				return nil
			}
		}
		fmt.Printf("joined %s (epoch %d)\n", space, wrapped.Epoch)
		return nil

	case "rotate":
		if len(rest) != 1 {
			return errors.New("space rotate <space>")
		}
		space := record.SpaceID(rest[0])
		epoch, err := n.RotateSpace(space)
		if err != nil {
			return err
		}
		fmt.Printf("rotated %s into epoch %d\n", space, epoch)
		fmt.Println("Now re-share it to every member who stays:")
		fmt.Printf("  memd space share %s <their rk_…>\n", space)
		fmt.Println("Anyone you do not re-share to is removed from this point forward.")
		fmt.Println("They keep whatever they already synced; revocation is forward-only.")
		return nil

	default:
		return fmt.Errorf("space: unknown action %q", action)
	}
}

func cmdIdentity(args []string) error {
	fs := flag.NewFlagSet("identity", flag.ContinueOnError)
	dir := dataDir(fs)
	nodeID := fs.String("node", defaultNodeID(), "this machine's node id")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := refuseIfDaemonRunning(*dir); err != nil {
		return err
	}
	n, err := node.Open(node.Config{Root: *dir, ID: record.NodeID(*nodeID)})
	if err != nil {
		return err
	}
	defer n.Close()

	// One field per line, tab-separated and nothing else on it, so this is safe to
	// pipe into a script rather than having to be read by a human.
	fmt.Printf("node\t%s\n", n.ID())
	fmt.Printf("recipient\t%s\n", n.Recipient())
	fmt.Fprintln(os.Stderr, "\nGive the recipient key to anyone sharing a space with you.")
	return nil
}

// refuseIfDaemonRunning reports an error when a daemon already owns the data directory.
//
// The check is "is something listening on the admin socket", which is exactly the
// question that matters: a stale socket file left by a killed daemon does not answer, and
// a live daemon does.
func refuseIfDaemonRunning(dir string) error {
	conn, err := net.Dial("unix", filepath.Join(dir, admin.SocketName))
	if err != nil {
		return nil
	}
	conn.Close()
	return fmt.Errorf("a daemon is already running on %s; stop it first, or use memctl for read-only queries", dir)
}

func readAll(f *os.File) ([]byte, error) {
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, err := f.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil {
			return buf, nil
		}
	}
}
