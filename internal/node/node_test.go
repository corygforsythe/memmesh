package node

import (
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coryforsythe/memmesh/internal/clock"
	"github.com/coryforsythe/memmesh/internal/record"
	"github.com/coryforsythe/memmesh/internal/store"
	"github.com/coryforsythe/memmesh/internal/ulid"
)

type detReader struct{ rng *rand.Rand }

func (d detReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(d.rng.Intn(256))
	}
	return len(p), nil
}

type fixture struct {
	*Node
	root string
	fake *clock.Fake
	seed int64
}

func newFixture(t *testing.T, seed int64, spaces ...record.SpaceID) *fixture {
	t.Helper()
	root := t.TempDir()
	f := reopen(t, root, seed)
	for _, s := range spaces {
		if err := f.CreateSpace(s); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func reopen(t *testing.T, root string, seed int64) *fixture {
	t.Helper()
	fake := clock.NewFake(1_757_700_000_000)
	n, err := Open(Config{
		Root:        root,
		ID:          "alpha",
		AuthorModel: "claude-opus-5",
		Clock:       fake,
		Entropy:     detReader{rng: rand.New(rand.NewSource(seed))},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	return &fixture{Node: n, root: root, fake: fake, seed: seed}
}

func (f *fixture) remember(t *testing.T, req RememberRequest) *RememberResult {
	t.Helper()
	f.fake.Advance(1)
	res, err := f.Remember(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// TestOfflineSingleNodeIsUseful is the M2 exit criterion: one machine, one agent,
// remember and recall working with no network at all. Nothing in this test can reach a
// socket, so if it passes, the offline guarantee holds.
func TestOfflineSingleNodeIsUseful(t *testing.T) {
	f := newFixture(t, 1, "user/cory")

	written := []struct {
		body string
		tags []string
		kind record.Kind
	}{
		{"crewmate 3 found the flake was a timezone assumption in parse_ts", []string{"parse_ts", "flake"}, record.KindEpisode},
		{"parse_ts assumes UTC input", []string{"parse_ts"}, record.KindFact},
		{"before tearing down a worktree, write a procedure record", []string{"firstmate"}, record.KindProcedure},
		{"the release build needs a signing key from the keychain", []string{"release"}, record.KindEpisode},
	}
	for _, w := range written {
		f.remember(t, RememberRequest{
			Agent: "crew-1", Space: "user/cory", Kind: w.kind, Body: w.body, Tags: w.tags,
			Evidence: record.EvidenceObserved,
		})
	}

	res, err := f.Recall(RecallRequest{Query: "timezone assumption in parse_ts", Limit: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hits) == 0 {
		t.Fatal("recall returned nothing on a populated node")
	}
	if !strings.Contains(res.Hits[0].Body, "parse_ts") {
		t.Errorf("top hit is %q, which is not about parse_ts", res.Hits[0].Body)
	}
	if res.Hits[0].Provenance.AuthorNode != "alpha" || res.Hits[0].Provenance.Evidence != record.EvidenceObserved {
		t.Errorf("provenance is missing or wrong: %+v", res.Hits[0].Provenance)
	}
	if res.EmbedModel != f.Embedder().ModelID() {
		t.Errorf("result does not name the embedding model used")
	}
	if len(res.Searched) != 1 || res.Searched[0] != "user/cory" {
		t.Errorf("Searched = %v", res.Searched)
	}

	// Unrelated content must not crowd out the match.
	for _, hit := range res.Hits {
		if strings.Contains(hit.Body, "signing key") && hit.Score > res.Hits[0].Score {
			t.Error("an unrelated record outranked the relevant one")
		}
	}
}

func TestRecallFiltersByKindAndTag(t *testing.T) {
	f := newFixture(t, 2, "user/cory")
	f.remember(t, RememberRequest{Space: "user/cory", Kind: record.KindFact, Body: "parse_ts assumes UTC", Tags: []string{"parse_ts", "tz"}})
	f.remember(t, RememberRequest{Space: "user/cory", Kind: record.KindEpisode, Body: "parse_ts broke the nightly run", Tags: []string{"parse_ts"}})

	facts, err := f.Recall(RecallRequest{Query: "parse_ts", Kinds: []record.Kind{record.KindFact}})
	if err != nil {
		t.Fatal(err)
	}
	if len(facts.Hits) != 1 || facts.Hits[0].Kind != record.KindFact {
		t.Errorf("kind filter returned %d hits: %+v", len(facts.Hits), facts.Hits)
	}

	tagged, err := f.Recall(RecallRequest{Query: "parse_ts", Tags: []string{"tz"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(tagged.Hits) != 1 || !contains(tagged.Hits[0].Tags, "tz") {
		t.Errorf("tag filter returned %d hits", len(tagged.Hits))
	}

	both, err := f.Recall(RecallRequest{Query: "parse_ts", Tags: []string{"tz", "missing"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(both.Hits) != 0 {
		t.Error("a tag filter requiring an absent tag still matched")
	}
}

func TestForgetWithAReasonPreservesTheCorrection(t *testing.T) {
	f := newFixture(t, 3, "user/cory")
	claim := f.remember(t, RememberRequest{
		Space: "user/cory", Kind: record.KindFact,
		Body: "parse_ts assumes UTC input", Evidence: record.EvidenceObserved,
	})

	f.fake.Advance(1)
	got, err := f.Forget(ForgetRequest{Space: "user/cory", ID: claim.ID, Reason: "measured it; it assumes local time"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != record.KindRetraction {
		t.Errorf("a forget with a reason produced %q, want a retraction", got.Kind)
	}

	// The claim stops surfacing by default.
	res, err := f.Recall(RecallRequest{Query: "parse_ts assumes UTC"})
	if err != nil {
		t.Fatal(err)
	}
	for _, hit := range res.Hits {
		if hit.ID == claim.ID {
			t.Error("a retracted claim still surfaces in a default recall")
		}
	}

	// But it is still there, and the correction travels with it.
	withOld, err := f.Recall(RecallRequest{Query: "parse_ts assumes UTC", IncludeSuperseded: true})
	if err != nil {
		t.Fatal(err)
	}
	var found *Hit
	for i := range withOld.Hits {
		if withOld.Hits[i].ID == claim.ID {
			found = &withOld.Hits[i]
		}
	}
	if found == nil {
		t.Fatal("include_superseded did not surface the retracted claim")
	}
	if !found.Superseded || len(found.SupersededBy) != 1 {
		t.Errorf("the retracted claim is not marked superseded: %+v", found)
	}
	if len(found.Retractions) != 1 || !strings.Contains(found.Retractions[0], "local time") {
		t.Errorf("the retraction text did not travel with the claim: %v", found.Retractions)
	}

	// And it is still readable by id, because nothing is ever deleted.
	if _, err := f.Get("user/cory", claim.ID); err != nil {
		t.Errorf("a retracted record became unreadable: %v", err)
	}
}

func TestForgetWithoutAReasonIsATombstone(t *testing.T) {
	f := newFixture(t, 4, "user/cory")
	claim := f.remember(t, RememberRequest{Space: "user/cory", Body: "should not be here"})
	f.fake.Advance(1)
	got, err := f.Forget(ForgetRequest{Space: "user/cory", ID: claim.ID})
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != record.KindTombstone {
		t.Errorf("kind = %q, want a tombstone", got.Kind)
	}
	if _, err := f.Forget(ForgetRequest{Space: "user/cory", ID: ulid.MustParse("01J000000000000000000000ZZ")}); err == nil {
		t.Error("Forget accepted a record this node does not hold")
	}
}

func TestLinkRelatesWithoutReplacing(t *testing.T) {
	f := newFixture(t, 5, "user/cory")
	episode := f.remember(t, RememberRequest{Space: "user/cory", Kind: record.KindEpisode, Body: "found the flake"})
	fact := f.remember(t, RememberRequest{Space: "user/cory", Kind: record.KindFact, Body: "parse_ts assumes UTC"})

	f.fake.Advance(1)
	link, err := f.Link(LinkRequest{Space: "user/cory", IDs: []ulid.ULID{episode.ID, fact.ID}, Note: "the fact came from this episode"})
	if err != nil {
		t.Fatal(err)
	}
	if len(link.Linked) != 2 {
		t.Fatalf("Linked = %v", link.Linked)
	}

	// Neither end may be suppressed by being linked.
	for _, id := range []ulid.ULID{episode.ID, fact.ID} {
		hit, err := f.Get("user/cory", id)
		if err != nil {
			t.Fatal(err)
		}
		if hit.Superseded {
			t.Errorf("linking suppressed %s; a link is not a supersession", id)
		}
	}

	if _, err := f.Link(LinkRequest{Space: "user/cory", IDs: []ulid.ULID{episode.ID}}); err == nil {
		t.Error("Link accepted a single record")
	}
}

// TestSiblingsAreReturnedWithProvenance is the §6.2 contract: contradictory records
// come back side by side, with enough context for a model to weigh them.
func TestSiblingsAreReturnedWithProvenance(t *testing.T) {
	f := newFixture(t, 6, "shared/crew")

	utc := f.remember(t, RememberRequest{
		Agent: "crew-1", Space: "shared/crew", Kind: record.KindFact,
		Body: "parse_ts assumes UTC input", Evidence: record.EvidenceObserved,
	})
	local := f.remember(t, RememberRequest{
		Agent: "crew-2", Space: "shared/crew", Kind: record.KindFact,
		Body: "parse_ts assumes local time input", Evidence: record.EvidenceAsserted,
	})

	// A conflict record links them. Neither is superseded.
	f.fake.Advance(1)
	space, _ := f.Store().Get("shared/crew")
	builder, err := f.builderFor("distiller")
	if err != nil {
		t.Fatal(err)
	}
	epoch, _ := f.Keyring().CurrentEpoch("shared/crew")
	conflict, err := builder.Conflict("shared/crew", epoch, "contradictory timezone assumptions", space.Vector(), utc.ID, local.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := space.Write(conflict); err != nil {
		t.Fatal(err)
	}

	res, err := f.Recall(RecallRequest{Query: "parse_ts timezone assumption", Limit: 5})
	if err != nil {
		t.Fatal(err)
	}

	var withSiblings *Hit
	for i := range res.Hits {
		if len(res.Hits[i].Siblings) > 0 {
			withSiblings = &res.Hits[i]
			break
		}
	}
	if withSiblings == nil {
		t.Fatal("neither side of a recorded conflict carried the other as a sibling")
	}
	sib := withSiblings.Siblings[0]
	if sib.Body == "" || sib.Provenance.AuthorAgent == "" {
		t.Errorf("a sibling came back without provenance: %+v", sib)
	}
	if sib.ConflictRecord != conflict.ID {
		t.Errorf("the sibling does not name the conflict record that linked it")
	}
	if sib.Provenance.Evidence == "" {
		t.Error("a sibling came back without an evidence level, which is what resolution orders on")
	}

	// Both sides must still be live.
	for _, id := range []ulid.ULID{utc.ID, local.ID} {
		hit, err := f.Get("shared/crew", id)
		if err != nil {
			t.Fatal(err)
		}
		if hit.Superseded {
			t.Errorf("%s was suppressed by the conflict record; siblings must both survive", id)
		}
	}
}

// TestSiblingSawThisClaim checks the distinction HLC cannot make: whether the
// contradicting author had actually seen what they contradict.
func TestSiblingSawThisClaim(t *testing.T) {
	f := newFixture(t, 7, "shared/crew")
	space, _ := f.Store().Get("shared/crew")

	first := f.remember(t, RememberRequest{
		Agent: "crew-1", Space: "shared/crew", Kind: record.KindFact,
		Body: "parse_ts assumes UTC", Evidence: record.EvidenceObserved,
	})

	// A second agent writes afterwards, so its causal context includes the first.
	informed := f.remember(t, RememberRequest{
		Agent: "crew-2", Space: "shared/crew", Kind: record.KindFact,
		Body: "parse_ts assumes local time", Evidence: record.EvidenceObserved,
	})

	f.fake.Advance(1)
	builder, _ := f.builderFor("distiller")
	epoch, _ := f.Keyring().CurrentEpoch("shared/crew")
	conflict, err := builder.Conflict("shared/crew", epoch, "contradiction", space.Vector(), first.ID, informed.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := space.Write(conflict); err != nil {
		t.Fatal(err)
	}

	hit, err := f.Get("shared/crew", first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(hit.Siblings) != 1 {
		t.Fatalf("expected one sibling, got %d", len(hit.Siblings))
	}
	if !hit.Siblings[0].SawThisClaim {
		t.Error("the later author had seen the earlier claim, but the sibling reports otherwise: " +
			"this is the disagreement-versus-ignorance distinction the causal context exists for")
	}
}

func TestRelayedSpaceIsSkippedAndSaidSo(t *testing.T) {
	f := newFixture(t, 8, "user/cory")
	f.remember(t, RememberRequest{Space: "user/cory", Body: "something findable"})

	// Fabricate a relayed space: a directory with a manifest and no key.
	dir := filepath.Join(f.root, "spaces", record.SpaceID("shared/foreign").Filename())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest"), []byte("memmesh-log v1 space=shared/foreign\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.Node.Close()

	reopened := reopen(t, f.root, f.seed)
	if len(reopened.RelayedSpaces()) != 1 {
		t.Fatalf("RelayedSpaces = %v", reopened.RelayedSpaces())
	}

	res, err := reopened.Recall(RecallRequest{Query: "something findable"})
	if err != nil {
		t.Fatal(err)
	}
	if reason, ok := res.Skipped["shared/foreign"]; !ok {
		t.Error("a relayed space was not reported as skipped; an empty result would be indistinguishable from an empty space")
	} else if !strings.Contains(reason, "relayed") {
		t.Errorf("skip reason = %q", reason)
	}
	if len(res.Hits) == 0 {
		t.Error("the readable space was not searched")
	}

	// And writing to it must be refused rather than silently dropped.
	if _, err := reopened.Remember(RememberRequest{Space: "shared/foreign", Body: "x"}); !errors.Is(err, store.ErrRelayed) {
		t.Errorf("err = %v, want store.ErrRelayed", err)
	}
}

func TestRestartPreservesEverythingDerived(t *testing.T) {
	f := newFixture(t, 9, "user/cory", "shared/crew")
	var ids []ulid.ULID
	for i := 0; i < 25; i++ {
		res := f.remember(t, RememberRequest{
			Agent: "crew-1", Space: "user/cory", Kind: record.KindEpisode,
			Body: fmt.Sprintf("episode number %d about the parser", i),
			Tags: []string{"parser"},
		})
		ids = append(ids, res.ID)
	}
	before, err := f.Recall(RecallRequest{Query: "parser episode", Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	f.Node.Close()

	reopened := reopen(t, f.root, f.seed)
	if got := len(reopened.ReadableSpaces()); got != 2 {
		t.Fatalf("readable spaces after restart = %d, want 2", got)
	}
	if reopened.IndexedRecords() != len(ids) {
		t.Errorf("indexed %d records after restart, want %d", reopened.IndexedRecords(), len(ids))
	}
	if !reopened.Warm() {
		t.Error("the node did not report warm after startup")
	}

	after, err := reopened.Recall(RecallRequest{Query: "parser episode", Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Hits) != len(before.Hits) {
		t.Fatalf("hit count changed across restart: %d then %d", len(before.Hits), len(after.Hits))
	}
	for i := range after.Hits {
		if after.Hits[i].ID != before.Hits[i].ID {
			t.Errorf("hit %d changed across restart", i)
		}
	}
}

// TestIDGeneratorIsSeededOnBoot is the docs/decisions/0001 hazard: a wall clock that
// moved backwards while the node was down must not produce an id below one already
// published.
func TestIDGeneratorIsSeededOnBoot(t *testing.T) {
	f := newFixture(t, 10, "user/cory")
	last := f.remember(t, RememberRequest{Space: "user/cory", Body: "the last record before the crash"})
	f.Node.Close()

	// Restart with the clock a full day behind where it was.
	fake := clock.NewFake(1_757_700_000_000 - 86_400_000)
	n, err := Open(Config{
		Root: f.root, ID: "alpha", Clock: fake,
		Entropy: detReader{rng: rand.New(rand.NewSource(10))},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer n.Close()

	res, err := n.Remember(RememberRequest{Space: "user/cory", Body: "written after the clock went backwards"})
	if err != nil {
		t.Fatal(err)
	}
	if res.ID.Compare(last.ID) <= 0 {
		t.Fatalf("new id %s is not above the pre-restart high-water mark %s: a peer would never ask for it",
			res.ID, last.ID)
	}
}

func TestAgentsGetTheirOwnKeys(t *testing.T) {
	f := newFixture(t, 11, "shared/crew")
	one := f.remember(t, RememberRequest{Agent: "crewmate-1", Space: "shared/crew", Body: "from crewmate one"})
	two := f.remember(t, RememberRequest{Agent: "crewmate-2", Space: "shared/crew", Body: "from crewmate two"})

	if one.AuthorAgent == two.AuthorAgent {
		t.Fatal("two named agents shared one key; one could not be revoked without the other")
	}
	names := f.Agents()
	if !contains(names, "crewmate-1") || !contains(names, "crewmate-2") {
		t.Errorf("Agents = %v", names)
	}
	if _, ok := f.AgentIDFor("crewmate-1"); !ok {
		t.Error("AgentIDFor missed an agent this node holds")
	}
	if _, ok := f.AgentIDFor("never-used"); ok {
		t.Error("AgentIDFor invented an agent")
	}

	// Keys must survive a restart, or a departed crewmate's records become
	// unattributable.
	f.Node.Close()
	reopened := reopen(t, f.root, f.seed)
	if id, ok := reopened.AgentIDFor("crewmate-1"); !ok || id.String() != one.AuthorAgent {
		t.Error("an agent key did not survive a restart")
	}
}

func TestAgentNameValidation(t *testing.T) {
	f := newFixture(t, 12, "user/cory")
	for _, bad := range []string{"has space", "slash/name", "..", strings.Repeat("x", 100)} {
		if _, err := f.Remember(RememberRequest{Agent: bad, Space: "user/cory", Body: "x"}); err == nil {
			t.Errorf("accepted agent name %q", bad)
		}
	}
	// An unnamed agent falls back to a visibly shared identity rather than
	// borrowing someone else's key.
	res := f.remember(t, RememberRequest{Space: "user/cory", Body: "unattributed"})
	if res.AuthorAgent == "" {
		t.Error("a write with no agent name produced no author")
	}
	if !contains(f.Agents(), "default") {
		t.Errorf("Agents = %v, want the default identity", f.Agents())
	}
}

func TestCreateShareJoinRotate(t *testing.T) {
	owner := newFixture(t, 13, "shared/crew")
	owner.remember(t, RememberRequest{Space: "shared/crew", Kind: record.KindFact, Body: "a claim only members can read"})

	member := newFixture(t, 14)
	wrapped, err := owner.ShareSpace("shared/crew", member.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if err := member.JoinSpace(wrapped); err != nil {
		t.Fatal(err)
	}
	if !contains(spaceStrings(member.ReadableSpaces()), "shared/crew") {
		t.Fatalf("the member cannot read the space it joined: %v", member.ReadableSpaces())
	}

	// Rotation removes a member going forward. The old epoch key is kept, so the
	// history stays readable to whoever already had it.
	epoch, err := owner.RotateSpace("shared/crew")
	if err != nil {
		t.Fatal(err)
	}
	if epoch != 1 {
		t.Errorf("rotated to epoch %d, want 1", epoch)
	}
	if _, err := owner.Keyring().Key("shared/crew", 0); err != nil {
		t.Errorf("the pre-rotation epoch key was discarded: %v", err)
	}

	// A record written after the rotation uses the new epoch, which the removed
	// member has no key for.
	after := owner.remember(t, RememberRequest{Space: "shared/crew", Body: "written after the removal"})
	if after.Epoch != 1 {
		t.Errorf("post-rotation write used epoch %d, want 1", after.Epoch)
	}
	if _, err := member.Keyring().Key("shared/crew", 1); err == nil {
		t.Error("the removed member holds the post-rotation key")
	}
}

func TestKeyringSurvivesRestart(t *testing.T) {
	f := newFixture(t, 15, "user/cory", "shared/crew")
	if _, err := f.RotateSpace("shared/crew"); err != nil {
		t.Fatal(err)
	}
	recipient := f.Recipient()
	f.Node.Close()

	reopened := reopen(t, f.root, f.seed)
	if reopened.Recipient() != recipient {
		t.Error("the recipient identity changed across a restart; every wrapped key sent to this node would break")
	}
	for _, tc := range []struct {
		space record.SpaceID
		epoch uint32
	}{{"user/cory", 0}, {"shared/crew", 0}, {"shared/crew", 1}} {
		if _, err := reopened.Keyring().Key(string(tc.space), tc.epoch); err != nil {
			t.Errorf("%s epoch %d did not survive a restart: %v", tc.space, tc.epoch, err)
		}
	}
	if cur, err := reopened.Keyring().CurrentEpoch("shared/crew"); err != nil || cur != 1 {
		t.Errorf("current epoch after restart = %d (%v), want 1", cur, err)
	}
}

func TestListSpacesHidesRelayedDetail(t *testing.T) {
	f := newFixture(t, 16, "user/cory")
	f.remember(t, RememberRequest{Space: "user/cory", Body: "x", Tags: []string{"secret-tag"}})

	infos := f.ListSpaces()
	if len(infos) != 1 {
		t.Fatalf("ListSpaces = %v", infos)
	}
	if !infos[0].Readable || infos[0].ByKind == nil {
		t.Errorf("a readable space is missing its detail: %+v", infos[0])
	}
	if infos[0].Policy != string(record.PolicySiblingsAuto) {
		t.Errorf("user/* policy = %q, want siblings-auto", infos[0].Policy)
	}
}

func TestRecallRequiresAQuery(t *testing.T) {
	f := newFixture(t, 17, "user/cory")
	if _, err := f.Recall(RecallRequest{}); err == nil {
		t.Error("Recall accepted an empty query")
	}
	if _, err := f.Remember(RememberRequest{Space: "user/cory", Body: "   "}); !errors.Is(err, ErrEmptyBody) {
		t.Errorf("err = %v, want ErrEmptyBody", err)
	}
	if _, err := f.Remember(RememberRequest{Space: "user/nope", Body: "x"}); !errors.Is(err, ErrNoSuchSpace) {
		t.Errorf("err = %v, want ErrNoSuchSpace", err)
	}
}

func TestSupersededRecordsLeaveTheIndex(t *testing.T) {
	f := newFixture(t, 18, "user/cory")
	old := f.remember(t, RememberRequest{Space: "user/cory", Kind: record.KindFact, Body: "the parser reads ISO-8601 dates"})
	indexedBefore := f.IndexedRecords()

	f.fake.Advance(1)
	f.remember(t, RememberRequest{
		Space: "user/cory", Kind: record.KindFact,
		Body: "the parser reads RFC-3339 dates", Supersedes: []ulid.ULID{old.ID},
	})

	// The superseded record stays in the index — supersession is filtered at query
	// time, which is what keeps include_superseded working.
	if got := f.IndexedRecords(); got != indexedBefore+1 {
		t.Errorf("indexed count = %d, want %d", got, indexedBefore+1)
	}
	res, err := f.Recall(RecallRequest{Query: "the parser reads dates", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	for _, hit := range res.Hits {
		if hit.ID == old.ID {
			t.Error("a superseded record still comes back from a default recall")
		}
	}

	// But it is findable by content when explicitly asked for.
	withOld, err := f.Recall(RecallRequest{Query: "the parser reads ISO-8601 dates", Limit: 10, IncludeSuperseded: true})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, hit := range withOld.Hits {
		if hit.ID == old.ID {
			found = true
		}
	}
	if !found {
		t.Error("include_superseded could not find the superseded record by content")
	}
}

func TestRecallWarnsWhenCold(t *testing.T) {
	f := newFixture(t, 19, "user/cory")
	f.remember(t, RememberRequest{Space: "user/cory", Body: "findable"})

	f.mu.Lock()
	f.warm = false
	f.mu.Unlock()

	res, err := f.Recall(RecallRequest{Query: "findable"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range res.Warnings {
		if strings.Contains(w, "warming") {
			found = true
		}
	}
	if !found {
		t.Errorf("a cold node did not warn about incomplete results: %v", res.Warnings)
	}
}

func TestOpenValidatesConfig(t *testing.T) {
	if _, err := Open(Config{ID: "alpha"}); err == nil {
		t.Error("Open accepted an empty root")
	}
	if _, err := Open(Config{Root: t.TempDir(), ID: "has space"}); err == nil {
		t.Error("Open accepted an invalid node id")
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func spaceStrings(ids []record.SpaceID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = string(id)
	}
	return out
}
