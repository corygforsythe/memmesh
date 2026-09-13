package tailnet

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coryforsythe/memmesh/internal/record"
	"github.com/coryforsythe/memmesh/internal/sync"
	"github.com/coryforsythe/memmesh/internal/wire"
)

// fakeLocalAPI serves a canned Tailscale status over a unix socket.
//
// This is not a substitute for the real thing — a genuine two-machine exercise is what
// tailnet_integration_test.go is for, build-tagged out of the default run. What this
// covers is everything that can go wrong in parsing and filtering, which is where the
// bugs actually live: a missing tag, an offline peer, a DERP-relayed path, a peer with no
// address.
func fakeLocalAPI(t *testing.T, status any) string {
	t.Helper()
	dir := t.TempDir()
	// Unix socket paths are length-limited on some platforms; keep it short.
	path := filepath.Join(dir, "ts.sock")

	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/localapi/v0/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(status)
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	t.Cleanup(func() {
		srv.Close()
		os.Remove(path)
	})
	return path
}

// statusDoc builds a status document in the shape the LocalAPI returns.
func statusDoc(selfTags []string, peers ...map[string]any) map[string]any {
	peerMap := make(map[string]any, len(peers))
	for i, p := range peers {
		peerMap[string(rune('a'+i))] = p
	}
	return map[string]any{
		"Self": map[string]any{
			"HostName":     "alpha",
			"DNSName":      "alpha.example.ts.net.",
			"TailscaleIPs": []string{"127.0.0.1"},
			"Tags":         selfTags,
			"Online":       true,
		},
		"Peer": peerMap,
	}
}

func peerDoc(host string, tags []string, online bool, curAddr, relay string) map[string]any {
	return map[string]any{
		"HostName":     host,
		"DNSName":      host + ".example.ts.net.",
		"TailscaleIPs": []string{"100.64.0.2"},
		"Tags":         tags,
		"Online":       online,
		"CurAddr":      curAddr,
		"Relay":        relay,
	}
}

func openTransport(t *testing.T, socket string, port int) *Transport {
	t.Helper()
	tr, err := Open(Config{NodeID: "alpha", Port: port, SocketPath: socket, BindAll: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tr.Close() })
	return tr
}

func TestPeersFiltersByTag(t *testing.T) {
	socket := fakeLocalAPI(t, statusDoc(
		[]string{DefaultTag},
		peerDoc("beta", []string{DefaultTag}, true, "100.64.0.2:41641", ""),
		peerDoc("gamma", []string{"tag:something-else"}, true, "", "sfo"),
		peerDoc("delta", []string{DefaultTag}, false, "", "sfo"),
	))
	tr := openTransport(t, socket, 0)

	peers, err := tr.Peers()
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 2 {
		t.Fatalf("got %d peers, want the 2 tagged ones: %+v", len(peers), peers)
	}

	byNode := make(map[record.NodeID]sync.Peer)
	for _, p := range peers {
		byNode[p.Node] = p
	}
	beta, ok := byNode["beta"]
	if !ok {
		t.Fatal("beta is missing")
	}
	if beta.Transport != sync.TransportDirect {
		t.Errorf("beta transport = %q, want direct (it has a CurAddr)", beta.Transport)
	}
	if !beta.Online {
		t.Error("beta should be online")
	}
	if !strings.HasSuffix(beta.Address, ":"+itoa(DefaultPort)) {
		t.Errorf("beta address = %q, want the mesh port appended", beta.Address)
	}

	delta, ok := byNode["delta"]
	if !ok {
		t.Fatal("delta is missing")
	}
	if delta.Transport != sync.TransportDERP {
		t.Errorf("delta transport = %q, want derp (no CurAddr, a Relay region)", delta.Transport)
	}
	// An offline peer is still listed. It is enrolled; it is simply not reachable
	// right now, and dropping it would hide exactly the case worth seeing.
	if delta.Online {
		t.Error("delta should be reported offline, not omitted")
	}
	if _, ok := byNode["gamma"]; ok {
		t.Error("an untagged peer was included; the tag is what selects the mesh")
	}

	if !strings.Contains(tr.Discovery(), DefaultTag) {
		t.Errorf("Discovery = %q, want it to name the tag", tr.Discovery())
	}
}

func TestPeersRefusesAnUntaggedHost(t *testing.T) {
	socket := fakeLocalAPI(t, statusDoc(
		[]string{"tag:something-else"},
		peerDoc("beta", []string{DefaultTag}, true, "100.64.0.2:1", ""),
	))
	tr := openTransport(t, socket, 0)

	if _, err := tr.Peers(); !errors.Is(err, ErrNotTagged) {
		t.Fatalf("err = %v, want ErrNotTagged", err)
	}
	// The reason has to be in the discovery string, because an empty peer list with no
	// explanation is indistinguishable from a mesh of one.
	if !strings.Contains(tr.Discovery(), "does not carry") {
		t.Errorf("Discovery = %q", tr.Discovery())
	}
}

func TestUnreachableLocalAPIIsReportedNotFatal(t *testing.T) {
	// A socket path with nothing behind it.
	tr, err := Open(Config{
		NodeID:     "alpha",
		SocketPath: filepath.Join(t.TempDir(), "absent.sock"),
		BindAll:    true,
	})
	if err != nil {
		t.Fatalf("Open must not fail when Tailscale is down: %v", err)
	}
	defer tr.Close()

	if _, err := tr.Peers(); !errors.Is(err, ErrNoLocalAPI) {
		t.Fatalf("err = %v, want ErrNoLocalAPI", err)
	}
	if !strings.Contains(tr.Discovery(), "unreachable") {
		t.Errorf("Discovery = %q, want it to say the daemon is unreachable rather than that there are no peers", tr.Discovery())
	}
}

// TestPeersKeepsTheLastKnownListOnFailure guards against a transient discovery failure
// looking like a mesh-wide partition.
func TestPeersKeepsTheLastKnownListOnFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ts.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/localapi/v0/status", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(statusDoc(
			[]string{DefaultTag},
			peerDoc("beta", []string{DefaultTag}, true, "100.64.0.2:1", ""),
		))
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)

	tr, err := Open(Config{NodeID: "alpha", SocketPath: path, BindAll: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	first, err := tr.Peers()
	if err != nil || len(first) != 1 {
		t.Fatalf("first query: %d peers, %v", len(first), err)
	}

	// Take the daemon away.
	srv.Close()
	ln.Close()
	os.Remove(path)

	after, err := tr.Peers()
	if err == nil {
		t.Fatal("expected an error once the daemon went away")
	}
	if len(after) != 1 || after[0].Node != "beta" {
		t.Errorf("got %+v; a failed query should return the last known list, not an empty one", after)
	}
}

func TestDialAndAcceptCarryFrames(t *testing.T) {
	// Point discovery at a peer that is really this test's own listener, so a full
	// frame round trip runs over real TCP.
	tr, err := Open(Config{NodeID: "alpha", Port: 0, BindAll: true, SocketPath: filepath.Join(t.TempDir(), "absent.sock")})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	_, portStr, err := net.SplitHostPort(tr.Addr())
	if err != nil {
		t.Fatal(err)
	}
	// Inject the loopback listener as a known peer.
	tr.mu.Lock()
	tr.lastPeers = []sync.Peer{{
		Node:      "self-loop",
		Address:   net.JoinHostPort("127.0.0.1", portStr),
		Transport: sync.TransportDirect,
		Online:    true,
	}}
	tr.mu.Unlock()

	session, err := tr.Dial(context.Background(), "self-loop")
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5e9)
	defer cancel()
	inbound, err := tr.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer inbound.Close()

	signer, err := record.GenerateSigner(nil)
	if err != nil {
		t.Fatal(err)
	}
	live := &wire.Liveness{Nonce: 42, WallMillis: 1_757_700_000_000}
	frame, err := wire.NewControlFrame(wire.MsgPing, wire.Version, live.Encode(), signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Send(frame); err != nil {
		t.Fatal(err)
	}

	got, err := inbound.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != wire.MsgPing {
		t.Errorf("received %s", got.Type)
	}
	decoded, err := wire.DecodeLiveness(got.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Nonce != 42 {
		t.Errorf("nonce = %d", decoded.Nonce)
	}
	// The receiving end knows nothing about the peer until a Hello names it, and it
	// cannot tell a direct path from a relayed one either.
	if inbound.Peer() != "" {
		t.Errorf("inbound session claims peer %q before any Hello", inbound.Peer())
	}
	if inbound.Transport() != "" {
		t.Errorf("inbound session claims transport %q; the receiver cannot know", inbound.Transport())
	}
	inbound.SetPeer("beta")
	if inbound.Peer() != "beta" {
		t.Error("SetPeer did not take")
	}
}

func TestDialRejectsUnknownPeers(t *testing.T) {
	socket := fakeLocalAPI(t, statusDoc([]string{DefaultTag}))
	tr := openTransport(t, socket, 0)
	if _, err := tr.Dial(context.Background(), "nobody"); !errors.Is(err, sync.ErrNoSuchPeer) {
		t.Errorf("err = %v, want sync.ErrNoSuchPeer", err)
	}
}

func TestClosedTransportRefusesWork(t *testing.T) {
	socket := fakeLocalAPI(t, statusDoc([]string{DefaultTag}))
	tr, err := Open(Config{NodeID: "alpha", SocketPath: socket, BindAll: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tr.Close(); err != nil {
		t.Errorf("closing twice returned %v", err)
	}
	if _, err := tr.Dial(context.Background(), "beta"); !errors.Is(err, sync.ErrTransportClosed) {
		t.Errorf("err = %v, want sync.ErrTransportClosed", err)
	}
	if _, err := tr.Accept(context.Background()); !errors.Is(err, sync.ErrTransportClosed) {
		t.Errorf("Accept err = %v, want sync.ErrTransportClosed", err)
	}
}

func TestNodeIDDerivation(t *testing.T) {
	tests := []struct {
		host, dns string
		want      record.NodeID
	}{
		{"alpha", "alpha.example.ts.net.", "alpha"},
		{"", "beta.example.ts.net.", "beta"},
		{"has space", "x.y.", "has-space"},
		{"ok-name_1.2", "x.y.", "ok-name_1.2"},
	}
	for _, tc := range tests {
		if got := nodeIDFor(tc.host, tc.dns); got != tc.want {
			t.Errorf("nodeIDFor(%q, %q) = %q, want %q", tc.host, tc.dns, got, tc.want)
		}
		if !nodeIDFor(tc.host, tc.dns).Valid() {
			t.Errorf("nodeIDFor(%q, %q) produced an invalid node id", tc.host, tc.dns)
		}
	}
}

func TestOpenValidatesNodeID(t *testing.T) {
	if _, err := Open(Config{NodeID: "has space", BindAll: true}); err == nil {
		t.Error("Open accepted an invalid node id")
	}
}

func TestSocketPathDefaults(t *testing.T) {
	tr := &Transport{cfg: Config{}}
	if got := tr.socketPath(); got == "" {
		t.Error("socketPath returned nothing")
	}
	t.Setenv("TS_SOCKET", "/tmp/override.sock")
	if got := tr.socketPath(); got != "/tmp/override.sock" {
		t.Errorf("TS_SOCKET was ignored: %q", got)
	}
	explicit := &Transport{cfg: Config{SocketPath: "/explicit.sock"}}
	if got := explicit.socketPath(); got != "/explicit.sock" {
		t.Errorf("an explicit socket path was ignored: %q", got)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
