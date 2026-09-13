//go:build tailnet_integration

// This file is excluded from the default `go test ./...` by its build tag.
//
// Two-node and N-node correctness is proven in memory (internal/sync), where there is no
// timing, no DNS and no socket behaviour to muddy a failure. What cannot be proven there
// is that the real tailnet path works, so that gets exactly one test — and it is opt-in,
// because it needs a genuine Tailscale daemon and a genuine peer, and a test that cannot
// run in CI should not be able to fail CI (plan §0.4).
//
// Run it on a tagged machine with at least one tagged peer:
//
//	go test -tags tailnet_integration -run TestTailnet ./internal/transport/tailnet/
//
// Set MEMMESH_TEST_PEER to a specific peer's node id to test dialling as well as
// discovery.
package tailnet

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/coryforsythe/memmesh/internal/record"
	"github.com/coryforsythe/memmesh/internal/wire"
)

func TestTailnetDiscovery(t *testing.T) {
	host, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	tr, err := Open(Config{NodeID: nodeIDFor(host, ""), Port: DefaultPort})
	if err != nil {
		t.Fatalf("Open: %v (is tailscaled running?)", err)
	}
	defer tr.Close()

	peers, err := tr.Peers()
	if err != nil {
		if errors.Is(err, ErrNoLocalAPI) {
			t.Skipf("no local Tailscale daemon: %v", err)
		}
		if errors.Is(err, ErrNotTagged) {
			t.Skipf("this host does not carry %s: %v", DefaultTag, err)
		}
		t.Fatal(err)
	}
	t.Logf("listening on %s", tr.Addr())
	t.Logf("discovery: %s", tr.Discovery())
	for _, p := range peers {
		t.Logf("peer %s at %s via %s (online=%v)", p.Node, p.Address, p.Transport, p.Online)
		if p.Node == "" {
			t.Error("a discovered peer has no node id")
		}
		if p.Address == "" {
			t.Error("a discovered peer has no address")
		}
	}
	if len(peers) == 0 {
		t.Skip("no tagged peers to exercise; discovery worked")
	}
}

func TestTailnetFrameRoundTrip(t *testing.T) {
	target := os.Getenv("MEMMESH_TEST_PEER")
	if target == "" {
		t.Skip("set MEMMESH_TEST_PEER to a tagged peer running memd")
	}
	host, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	tr, err := Open(Config{NodeID: nodeIDFor(host, ""), Port: DefaultPort})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	session, err := tr.Dial(ctx, record.NodeID(target))
	if err != nil {
		t.Fatalf("dial %s: %v", target, err)
	}
	defer session.Close()
	t.Logf("connected to %s at %s via %s", session.Peer(), session.RemoteAddr(), session.Transport())

	signer, err := record.GenerateSigner(nil)
	if err != nil {
		t.Fatal(err)
	}
	hello := &wire.Hello{
		Versions:   wire.SupportedVersions(),
		Node:       nodeIDFor(host, ""),
		Software:   "tailnet-integration-test",
		WallMillis: uint64(time.Now().UnixMilli()),
	}
	frame, err := wire.NewControlFrame(wire.MsgHello, wire.Version, hello.Encode(), signer)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Send(frame); err != nil {
		t.Fatalf("send hello: %v", err)
	}

	reply, err := session.Receive()
	if err != nil {
		t.Fatalf("no hello_ack from %s: %v", target, err)
	}
	if reply.Type != wire.MsgHelloAck {
		t.Fatalf("expected hello_ack, got %s", reply.Type)
	}
	ack, err := wire.DecodeHello(reply.Payload)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("peer %s runs %s, embed model %s, relaying=%v, %d spaces",
		ack.Node, ack.Software, ack.EmbedModel, ack.Relaying, len(ack.Spaces))

	skew := int64(ack.WallMillis) - time.Now().UnixMilli()
	t.Logf("clock skew against %s: %dms", ack.Node, skew)
	if skew > 30_000 || skew < -30_000 {
		t.Errorf("clock skew is %dms, which is large enough that HLC tiebreaking is unreliable", skew)
	}
}
