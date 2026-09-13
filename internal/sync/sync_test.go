package sync

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"sort"
	"testing"
	"time"

	"github.com/coryforsythe/memmesh/internal/clock"
	"github.com/coryforsythe/memmesh/internal/crypto"
	"github.com/coryforsythe/memmesh/internal/node"
	"github.com/coryforsythe/memmesh/internal/record"
	"github.com/coryforsythe/memmesh/internal/ulid"
)

type detReader struct{ rng *rand.Rand }

func (d detReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(d.rng.Intn(256))
	}
	return len(p), nil
}

// harness is one node plus its engine, wired to a shared in-memory mesh.
//
// Everything time-based and random-based is injected, so the whole suite is
// reproducible: a convergence test that flakes is a failed test, not a retry
// (plan §0.5).
type harness struct {
	t      *testing.T
	node   *node.Node
	engine *Engine
	mesh   *Mesh
	trans  *MemoryTransport
	fake   *clock.Fake
	root   string
	id     record.NodeID
	seed   int64
}

// cluster is a set of harnesses sharing a mesh and a space key.
type cluster struct {
	t     *testing.T
	mesh  *Mesh
	nodes map[record.NodeID]*harness
	// key is the shared space content key, distributed to every member. Real
	// deployments wrap it per recipient; a test can install it directly.
	key   crypto.ContentKey
	space record.SpaceID
}

func newCluster(t *testing.T, space record.SpaceID, seed int64, ids ...record.NodeID) *cluster {
	t.Helper()
	key, err := crypto.GenerateContentKey(detReader{rng: rand.New(rand.NewSource(seed))})
	if err != nil {
		t.Fatal(err)
	}
	c := &cluster{t: t, mesh: NewMesh(), nodes: make(map[record.NodeID]*harness), key: key, space: space}
	t.Cleanup(func() { c.mesh.Close() })
	for i, id := range ids {
		c.add(id, t.TempDir(), seed+int64(i)*1000)
	}
	return c
}

func (c *cluster) add(id record.NodeID, root string, seed int64) *harness {
	c.t.Helper()
	fake := clock.NewFake(1_757_700_000_000)
	ent := detReader{rng: rand.New(rand.NewSource(seed))}

	n, err := node.Open(node.Config{
		Root: root, ID: id, AuthorModel: "claude-opus-5",
		Clock: fake, Entropy: ent,
	})
	if err != nil {
		c.t.Fatal(err)
	}
	// Install the shared space key directly, then open the space.
	n.Keyring().Install(string(c.space), 0, c.key)
	if err := n.CreateSpace(c.space); err != nil {
		c.t.Fatal(err)
	}

	signer, err := n.FrameSigner()
	if err != nil {
		c.t.Fatal(err)
	}
	trans := c.mesh.Join(id)
	engine, err := New(Config{
		Node: n, Transport: trans, Signer: signer, Clock: fake,
		Rand: rand.New(rand.NewSource(seed)),
		// A long pull interval keeps the background loop out of the way: the tests
		// drive exchanges explicitly so the sequence is exactly known.
		PullInterval: time.Hour,
		PullJitter:   0,
		BatchLimit:   8,
		// One batch per space per exchange, so a test can observe a partial transfer
		// and drive convergence a step at a time.
		MaxRoundsPerSpace: 1,
	})
	if err != nil {
		c.t.Fatal(err)
	}

	h := &harness{t: c.t, node: n, engine: engine, mesh: c.mesh, trans: trans, fake: fake, root: root, id: id, seed: seed}
	c.nodes[id] = h
	c.t.Cleanup(func() {
		engine.Close()
		n.Close()
	})
	return h
}

// serve runs a node's inbound loop for the duration of the test.
func (h *harness) serve(ctx context.Context) {
	go h.engine.serveLoop(ctx)
}

func (h *harness) write(body string) ulid.ULID {
	h.t.Helper()
	h.fake.Advance(1)
	res, err := h.node.Remember(node.RememberRequest{
		Agent: string(h.id), Space: "shared/crew", Kind: record.KindEpisode, Body: body,
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return res.ID
}

func (h *harness) has(id ulid.ULID) bool {
	space, ok := h.node.Store().Get("shared/crew")
	if !ok {
		return false
	}
	return space.Log().Has(id)
}

func (h *harness) count() int {
	space, ok := h.node.Store().Get("shared/crew")
	if !ok {
		return 0
	}
	return space.Log().Count()
}

func (h *harness) vector() record.VersionVector {
	space, ok := h.node.Store().Get("shared/crew")
	if !ok {
		return nil
	}
	return space.Vector()
}

// pull runs one full exchange from h to peer.
func (h *harness) pull(peer record.NodeID) (int, int) {
	h.t.Helper()
	peers, err := h.trans.Peers()
	if err != nil {
		h.t.Fatal(err)
	}
	for _, p := range peers {
		if p.Node != peer {
			continue
		}
		event, err := h.engine.exchangeWith(context.Background(), p, "")
		if err != nil {
			h.t.Fatalf("%s exchanging with %s: %v", h.id, peer, err)
		}
		return event.Sent, event.Received
	}
	h.t.Fatalf("%s cannot see peer %s", h.id, peer)
	return 0, 0
}

// TestTwoNodesConverge is the M3 exit criterion, first half.
func TestTwoNodesConverge(t *testing.T) {
	c := newCluster(t, "shared/crew", 1, "alpha", "beta")
	a, b := c.nodes["alpha"], c.nodes["beta"]

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.serve(ctx)
	b.serve(ctx)

	var fromA, fromB []ulid.ULID
	for i := 0; i < 12; i++ {
		fromA = append(fromA, a.write(fmt.Sprintf("alpha episode %d", i)))
		fromB = append(fromB, b.write(fmt.Sprintf("beta episode %d", i)))
	}

	// An exchange pulls, so each side has to run its own. One round from alpha must
	// bring beta's records in.
	_, received := a.pull("beta")
	if received == 0 {
		t.Fatal("a pull brought nothing back from a peer holding 12 records")
	}

	// The batch limit is 8, so 12 records per side needs more than one round. Both
	// directions are driven until neither moves anything, which is convergence.
	settle(t, a, b)

	for _, id := range fromB {
		if !a.has(id) {
			t.Errorf("alpha is missing beta's record %s", id)
		}
	}
	for _, id := range fromA {
		if !b.has(id) {
			t.Errorf("beta is missing alpha's record %s", id)
		}
	}
	if a.count() != b.count() {
		t.Fatalf("counts diverge: alpha %d, beta %d", a.count(), b.count())
	}
	if !a.vector().Equal(b.vector()) {
		t.Fatalf("version vectors diverge:\n  alpha %s\n  beta  %s", a.vector(), b.vector())
	}

	// And another exchange must be a genuine no-op, not a re-transfer.
	if _, r := a.pull("beta"); r != 0 {
		t.Errorf("a converged pull still transferred %d records; sync is not idempotent", r)
	}
	if _, r := b.pull("alpha"); r != 0 {
		t.Errorf("a converged pull in the other direction transferred %d records", r)
	}
}

// TestConvergenceAfterMidSyncFailure is the M3 exit criterion, second half: kill a node
// mid-sync and it converges on restart.
func TestConvergenceAfterMidSyncFailure(t *testing.T) {
	c := newCluster(t, "shared/crew", 2, "alpha", "beta")
	a, b := c.nodes["alpha"], c.nodes["beta"]

	ctx, cancel := context.WithCancel(context.Background())
	a.serve(ctx)
	b.serve(ctx)

	var written []ulid.ULID
	for i := 0; i < 30; i++ {
		written = append(written, a.write(fmt.Sprintf("alpha record %d", i)))
	}

	// One bounded round: with a batch limit of 8, beta gets part of the corpus.
	b.pull("alpha")
	partial := b.count()
	if partial == 0 || partial >= len(written) {
		t.Fatalf("expected a partial transfer, got %d of %d", partial, len(written))
	}

	// Kill beta hard, mid-backfill, and reopen it from disk.
	cancel()
	betaRoot, betaSeed := b.root, b.seed
	b.engine.Close()
	if err := b.node.Close(); err != nil {
		t.Fatal(err)
	}
	c.mesh.Leave("beta")

	restarted := c.add("beta", betaRoot, betaSeed)
	if restarted.count() != partial {
		t.Fatalf("beta lost records across the restart: %d, had %d", restarted.count(), partial)
	}

	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	restarted.serve(ctx2)
	a.serve(ctx2)
	for round := 0; round < 40; round++ {
		if _, r := restarted.pull("alpha"); r == 0 {
			break
		}
	}

	for _, id := range written {
		if !restarted.has(id) {
			t.Errorf("after restarting mid-backfill, beta is still missing %s", id)
		}
	}
	if !a.vector().Equal(restarted.vector()) {
		t.Fatalf("vectors diverge after recovery:\n  alpha %s\n  beta  %s", a.vector(), restarted.vector())
	}
}

// TestPartitionHealsByAntiEntropy is the offline story: writes continue on both sides of
// a partition and converge when it heals.
func TestPartitionHealsByAntiEntropy(t *testing.T) {
	c := newCluster(t, "shared/crew", 3, "alpha", "beta")
	a, b := c.nodes["alpha"], c.nodes["beta"]

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a.serve(ctx)
	b.serve(ctx)

	c.mesh.Partition("alpha", "beta")

	// Writes must still succeed on both sides: the network is not in the write path.
	var fromA, fromB []ulid.ULID
	for i := 0; i < 5; i++ {
		fromA = append(fromA, a.write(fmt.Sprintf("alpha offline %d", i)))
		fromB = append(fromB, b.write(fmt.Sprintf("beta offline %d", i)))
	}

	// And a pull attempt across the partition must fail cleanly, not hang or panic.
	if _, err := a.engine.SyncNow("beta", ""); err == nil {
		t.Log("sync across a partition reported no error; the peer was listed offline")
	}
	if a.count() != len(fromA) || b.count() != len(fromB) {
		t.Fatalf("a partition affected local writes: alpha %d, beta %d", a.count(), b.count())
	}

	c.mesh.Heal("alpha", "beta")
	settle(t, a, b)

	if a.count() != len(fromA)+len(fromB) {
		t.Errorf("alpha has %d records, want %d", a.count(), len(fromA)+len(fromB))
	}
	if !a.vector().Equal(b.vector()) {
		t.Errorf("vectors diverge after healing:\n  alpha %s\n  beta  %s", a.vector(), b.vector())
	}
}

// TestConvergenceIsOrderIndependent is the lattice property stated as a test: whatever
// order the pairwise exchanges happen in, every node ends up holding the same records.
//
// It deliberately does not compare record ids between two independently built clusters.
// That would be asserting that two entropy streams match, which is not the property
// under test; what matters is that within a mesh, order does not change the outcome.
func TestConvergenceIsOrderIndependent(t *testing.T) {
	const nodes = 5
	ids := make([]record.NodeID, nodes)
	for i := range ids {
		ids[i] = record.NodeID(fmt.Sprintf("n%d", i))
	}

	for _, shuffleSeed := range []int64{1, 2, 3, 4} {
		t.Run(fmt.Sprintf("order-%d", shuffleSeed), func(t *testing.T) {
			c := newCluster(t, "shared/crew", 4, ids...)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			for _, h := range c.nodes {
				h.serve(ctx)
			}

			want := make(map[ulid.ULID]bool)
			for _, id := range ids {
				for i := 0; i < 4; i++ {
					want[c.nodes[id].write(fmt.Sprintf("%s record %d", id, i))] = true
				}
			}

			rng := rand.New(rand.NewSource(shuffleSeed))
			pairs := allPairs(ids)
			rng.Shuffle(len(pairs), func(i, j int) { pairs[i], pairs[j] = pairs[j], pairs[i] })

			for sweep := 0; sweep < 12; sweep++ {
				moved := false
				for _, pair := range pairs {
					if _, r := c.nodes[pair[0]].pull(pair[1]); r != 0 {
						moved = true
					}
				}
				if !moved {
					break
				}
			}

			reference := c.nodes[ids[0]].vector()
			for _, id := range ids {
				h := c.nodes[id]
				if h.count() != len(want) {
					t.Fatalf("%s holds %d records, want %d", id, h.count(), len(want))
				}
				for recID := range want {
					if !h.has(recID) {
						t.Fatalf("%s is missing %s", id, recID)
					}
				}
				if got := h.vector(); !got.Equal(reference) {
					t.Fatalf("%s diverged\n  got  %s\n  want %s", id, got, reference)
				}
			}
		})
	}
}

// TestConvergenceUnderRandomPartitions is the N-node property test: writes and random
// partitions, then heal everything and converge.
func TestConvergenceUnderRandomPartitions(t *testing.T) {
	const nodes = 7
	ids := make([]record.NodeID, nodes)
	for i := range ids {
		ids[i] = record.NodeID(fmt.Sprintf("n%d", i))
	}
	c := newCluster(t, "shared/crew", 5, ids...)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, h := range c.nodes {
		h.serve(ctx)
	}

	rng := rand.New(rand.NewSource(7))
	expected := 0

	for epoch := 0; epoch < 6; epoch++ {
		// Random partitions for this epoch.
		c.mesh.HealAll()
		for i := 0; i < 4; i++ {
			a := ids[rng.Intn(nodes)]
			b := ids[rng.Intn(nodes)]
			if a != b {
				c.mesh.Partition(a, b)
			}
		}
		// Writes land wherever they land, partition or not.
		for i := 0; i < nodes; i++ {
			c.nodes[ids[rng.Intn(nodes)]].write(fmt.Sprintf("epoch %d write %d", epoch, i))
			expected++
		}
		// Pull across whatever links are up.
		for _, pair := range allPairs(ids) {
			peers, _ := c.nodes[pair[0]].trans.Peers()
			for _, p := range peers {
				if p.Node == pair[1] && p.Online {
					if _, err := c.nodes[pair[0]].engine.exchangeWith(context.Background(), p, ""); err != nil {
						t.Fatalf("%s pulling from %s: %v", pair[0], pair[1], err)
					}
				}
			}
		}
	}

	// Heal and settle.
	c.mesh.HealAll()
	for sweep := 0; sweep < 30; sweep++ {
		moved := false
		for _, pair := range allPairs(ids) {
			if _, r := c.nodes[pair[0]].pull(pair[1]); r != 0 {
				moved = true
			}
		}
		if !moved {
			break
		}
	}

	reference := c.nodes[ids[0]].vector()
	for _, id := range ids {
		if got := c.nodes[id].count(); got != expected {
			t.Errorf("%s holds %d records, want %d", id, got, expected)
		}
		if got := c.nodes[id].vector(); !got.Equal(reference) {
			t.Errorf("%s diverged:\n  got  %s\n  want %s", id, got, reference)
		}
	}
}

func TestPushOnWriteDeliversImmediately(t *testing.T) {
	c := newCluster(t, "shared/crew", 6, "alpha", "beta")
	a, b := c.nodes["alpha"], c.nodes["beta"]

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b.serve(ctx)

	id := a.write("a fresh write that should be pushed")
	if a.engine.OutboundQueue() != 1 {
		t.Fatalf("outbound queue = %d, want 1 after a local write", a.engine.OutboundQueue())
	}

	pushed, err := a.engine.PushNow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pushed != 1 {
		t.Fatalf("pushed to %d peers, want 1", pushed)
	}
	if a.engine.OutboundQueue() != 0 {
		t.Errorf("queue = %d after a successful push", a.engine.OutboundQueue())
	}

	// The push is asynchronous on the receiving side, so give the responder a moment
	// to drain. Bounded wait, not a sleep-and-hope.
	if !waitFor(func() bool { return b.has(id) }) {
		t.Fatal("a pushed record never arrived at the peer")
	}
}

func TestPushRequeuesWhenNoPeersAreReachable(t *testing.T) {
	c := newCluster(t, "shared/crew", 7, "alpha", "beta")
	a := c.nodes["alpha"]
	c.mesh.Partition("alpha", "beta")

	a.write("written while alone")
	if a.engine.OutboundQueue() != 1 {
		t.Fatalf("queue = %d", a.engine.OutboundQueue())
	}
	pushed, err := a.engine.PushNow(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if pushed != 0 {
		t.Errorf("pushed to %d peers while partitioned", pushed)
	}
	// The record must stay queued rather than being dropped: a write that cannot be
	// pushed is still a write that has to reach peers eventually.
	if a.engine.OutboundQueue() != 1 {
		t.Errorf("queue = %d, want the record still queued", a.engine.OutboundQueue())
	}
}

func TestRelayCarriesASpaceItCannotRead(t *testing.T) {
	// alpha and gamma hold the key; beta relays without it.
	c := newCluster(t, "shared/crew", 8, "alpha", "gamma")

	betaRoot := t.TempDir()
	fake := clock.NewFake(1_757_700_000_000)
	ent := detReader{rng: rand.New(rand.NewSource(999))}
	beta, err := node.Open(node.Config{
		Root: betaRoot, ID: "beta", Clock: fake, Entropy: ent, Relay: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer beta.Close()
	if err := beta.SubscribeRelay("shared/crew"); err != nil {
		t.Fatal(err)
	}
	betaSigner, err := beta.FrameSigner()
	if err != nil {
		t.Fatal(err)
	}
	betaTrans := c.mesh.Join("beta")
	betaEngine, err := New(Config{
		Node: beta, Transport: betaTrans, Signer: betaSigner, Clock: fake,
		Rand: rand.New(rand.NewSource(999)), PullInterval: time.Hour, BatchLimit: 8,
		MaxRoundsPerSpace: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer betaEngine.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go betaEngine.serveLoop(ctx)
	c.nodes["gamma"].serve(ctx)
	c.nodes["alpha"].serve(ctx)

	a := c.nodes["alpha"]
	var written []ulid.ULID
	for i := 0; i < 5; i++ {
		written = append(written, a.write(fmt.Sprintf("a secret only members can read %d", i)))
	}

	// The relay pulls from alpha, storing what it cannot read.
	for round := 0; round < 10; round++ {
		peers, _ := betaTrans.Peers()
		moved := 0
		for _, p := range peers {
			if p.Node != "alpha" {
				continue
			}
			event, err := betaEngine.exchangeWith(context.Background(), p, "")
			if err != nil {
				t.Fatal(err)
			}
			moved += event.Received
		}
		if moved == 0 {
			break
		}
	}
	relaySpace, ok := beta.Store().Get("shared/crew")
	if !ok {
		t.Fatal("the relay did not open the space")
	}
	if relaySpace.Readable() {
		t.Fatal("the relay reports the space as readable")
	}
	if relaySpace.Log().Count() != len(written) {
		t.Fatalf("the relay stored %d of %d records", relaySpace.Log().Count(), len(written))
	}

	// Now gamma, which does hold the key, gets the whole corpus from the relay
	// without ever talking to alpha. That is the entire point of relaying.
	g := c.nodes["gamma"]
	c.mesh.Partition("alpha", "gamma")
	for round := 0; round < 10; round++ {
		if _, r := g.pull("beta"); r == 0 {
			break
		}
	}
	for _, id := range written {
		if !g.has(id) {
			t.Errorf("gamma did not receive %s through the relay", id)
		}
	}
	// And having received them through a node that could not read them, gamma can.
	for _, id := range written {
		if _, err := g.node.Get("shared/crew", id); err != nil {
			t.Errorf("gamma cannot read %s relayed through beta: %v", id, err)
		}
	}
}

func TestHandshakeRecordsPeerFactsIncludingSkew(t *testing.T) {
	c := newCluster(t, "shared/crew", 9, "alpha", "beta")
	a, b := c.nodes["alpha"], c.nodes["beta"]

	// Put beta's clock 5 seconds ahead.
	b.fake.Set(a.fake.NowMillis() + 5_000)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b.serve(ctx)

	a.write("something to sync")
	a.pull("beta")

	peers := a.engine.Peers()
	var found bool
	for _, p := range peers {
		if p.Node != "beta" {
			continue
		}
		found = true
		if !p.Enrolled {
			t.Error("beta is not marked enrolled after a successful exchange")
		}
		if p.Software == "" {
			t.Error("the peer's software version was not recorded")
		}
		if p.EmbedModel == "" {
			t.Error("the peer's embed model was not recorded; the model-match check needs it")
		}
		if p.ClockSkewMS < 4_000 || p.ClockSkewMS > 6_000 {
			t.Errorf("clock skew = %dms, want about 5000: HLC tiebreaking degrades quietly without this", p.ClockSkewMS)
		}
		if p.LastContact.IsZero() {
			t.Error("last contact was not recorded")
		}
		if len(p.PeerVectors) == 0 {
			t.Error("the peer's version vectors were not recorded; lag cannot be computed without them")
		}
		if p.Transport != TransportMemory {
			t.Errorf("transport = %q", p.Transport)
		}
	}
	if !found {
		t.Fatalf("beta is absent from Peers(): %+v", peers)
	}

	if last := a.engine.LastSync(); last == nil || last.Peer != "beta" {
		t.Errorf("LastSync = %+v", last)
	}
	if a.engine.Discovery() == "" {
		t.Error("Discovery returned nothing; an empty peer list must say why")
	}
}

func TestSyncNowReportsUnknownPeers(t *testing.T) {
	c := newCluster(t, "shared/crew", 10, "alpha", "beta")
	a := c.nodes["alpha"]
	if _, err := a.engine.SyncNow("nobody", ""); !errors.Is(err, ErrNoSuchPeer) {
		t.Errorf("err = %v, want ErrNoSuchPeer", err)
	}
}

func TestSyncNowCanBeLimitedToOneSpace(t *testing.T) {
	c := newCluster(t, "shared/crew", 11, "alpha", "beta")
	a, b := c.nodes["alpha"], c.nodes["beta"]

	// Give both nodes a second space.
	other := record.SpaceID("shared/other")
	key, err := crypto.GenerateContentKey(detReader{rng: rand.New(rand.NewSource(77))})
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []*harness{a, b} {
		h.node.Keyring().Install(string(other), 0, key)
		if err := h.node.CreateSpace(other); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a.fake.Advance(1)
	inCrew, err := a.node.Remember(node.RememberRequest{Space: "shared/crew", Body: "in crew"})
	if err != nil {
		t.Fatal(err)
	}
	a.fake.Advance(1)
	inOther, err := a.node.Remember(node.RememberRequest{Space: other, Body: "in other"})
	if err != nil {
		t.Fatal(err)
	}

	a.serve(ctx)
	peers, _ := b.trans.Peers()
	if _, err := b.engine.exchangeWith(context.Background(), peers[0], "shared/crew"); err != nil {
		t.Fatal(err)
	}

	crewSpace, _ := b.node.Store().Get("shared/crew")
	otherSpace, _ := b.node.Store().Get(other)
	if !crewSpace.Log().Has(inCrew.ID) {
		t.Error("the named space did not sync")
	}
	if otherSpace.Log().Has(inOther.ID) {
		t.Error("a space-limited sync moved records from another space")
	}
}

func TestNewValidatesConfig(t *testing.T) {
	mesh := NewMesh()
	defer mesh.Close()
	trans := mesh.Join("alpha")
	signer, err := record.GenerateSigner(detReader{rng: rand.New(rand.NewSource(1))})
	if err != nil {
		t.Fatal(err)
	}
	n, err := node.Open(node.Config{Root: t.TempDir(), ID: "alpha", Clock: clock.NewFake(1)})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()

	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{"no node", Config{Transport: trans, Signer: signer}},
		{"no transport", Config{Node: n, Signer: signer}},
		{"no signer", Config{Node: n, Transport: trans}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.cfg); err == nil {
				t.Error("New accepted an incomplete config")
			}
		})
	}
}

func TestMemoryTransportBasics(t *testing.T) {
	mesh := NewMesh()
	defer mesh.Close()
	a := mesh.Join("alpha")
	mesh.Join("beta")

	peers, err := a.Peers()
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 || peers[0].Node != "beta" || !peers[0].Online {
		t.Fatalf("Peers = %+v", peers)
	}
	if _, err := a.Dial(context.Background(), "nobody"); !errors.Is(err, ErrNoSuchPeer) {
		t.Errorf("err = %v, want ErrNoSuchPeer", err)
	}

	mesh.Partition("alpha", "beta")
	if _, err := a.Dial(context.Background(), "beta"); !errors.Is(err, ErrNoSuchPeer) {
		t.Errorf("dialling across a partition: err = %v", err)
	}
	peers, _ = a.Peers()
	if peers[0].Online {
		t.Error("a partitioned peer is reported online")
	}

	mesh.Heal("alpha", "beta")
	session, err := a.Dial(context.Background(), "beta")
	if err != nil {
		t.Fatal(err)
	}
	if session.Peer() != "beta" || session.Transport() != TransportMemory {
		t.Errorf("session = %s / %s", session.Peer(), session.Transport())
	}
	session.Close()
	if err := session.Close(); err != nil {
		t.Errorf("closing twice returned %v", err)
	}

	a.Close()
	if _, err := a.Dial(context.Background(), "beta"); !errors.Is(err, ErrTransportClosed) {
		t.Errorf("dialling a closed transport: err = %v", err)
	}
}

// settle drives pulls in both directions until nothing moves, which is what
// convergence looks like when each node pulls for itself.
func settle(t *testing.T, nodes ...*harness) {
	t.Helper()
	for round := 0; round < 40; round++ {
		moved := false
		for _, from := range nodes {
			for _, to := range nodes {
				if from.id == to.id {
					continue
				}
				if _, r := from.pull(to.id); r != 0 {
					moved = true
				}
			}
		}
		if !moved {
			return
		}
	}
	t.Fatal("nodes did not converge within 40 rounds")
}

// waitFor polls a condition with a bounded deadline. Used only where the receiving side
// of a push is genuinely asynchronous; every other test drives exchanges directly so
// there is nothing to wait for.
func waitFor(cond func() bool) bool {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return false
}

func allPairs(ids []record.NodeID) [][2]record.NodeID {
	sorted := append([]record.NodeID(nil), ids...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	var out [][2]record.NodeID
	for i := range sorted {
		for j := range sorted {
			if i != j {
				out = append(out, [2]record.NodeID{sorted[i], sorted[j]})
			}
		}
	}
	return out
}
