# memmesh

A durable, shared, offline-capable memory substrate for multiple users running
multiple AI agents across multiple machines.

- **`memd`** — the daemon. Owns the store, the index, the MCP server, and sync.
- **`memctl`** — the CLI. Talks to the local `memd` over a unix socket and
  nothing else.

No server to run. No consensus. No quorum. No leader. Any member joins, leaves,
or participates partially, and the network is never in the read or write path.

## Status

Milestones M1 through M3 of `MEMORY-MESH-PLAN.md` are built: frozen contracts, a single
node that is useful offline, and two nodes that converge. M4–M7 (multi-user spaces beyond
the basics, Merkle reconciliation, the distiller, agent skill files, packaging) are not.
`CHANGELOG.md` says what landed; `docs/decisions/` says why the non-obvious parts are the
way they are.

```
go test ./...                                   # everything, no network required
go test -race -count=3 ./...                    # what CI should run
go test -tags tailnet_integration ./...         # opt-in, needs a real tailnet
go build ./cmd/...                              # memd and memctl
```

Every test in the default run is in-process and deterministic: injected clocks, injected
RNG, an in-memory transport. A convergence test that flakes is a failed test, not a retry.

This tree has **no external dependencies** — standard library only. That was
forced by the build environment rather than chosen; `docs/decisions/0002` records
what it substituted and how each substitution is reversed.

## The shape of it

**Records are immutable and append-only.** An edit is a new record. A delete is a
new record. Nothing is ever mutated in place. This is the decision everything else
leans on: sync becomes set reconciliation, structural conflicts become impossible,
and a write made offline needs no reconciliation logic when it finally lands.

**Append-only removes structural conflict, not semantic conflict.** Two agents can
still assert contradictory things — both valid, both signed, neither superseding
the other. That is represented, not prevented:

| Space | Policy |
|---|---|
| `agent/*` | last write wins on HLC, no ceremony |
| `user/*` | keep both, detect contradictions, may auto-resolve on evidence weight |
| `shared/*` | keep both, **never** auto-resolve, always queue for adjudication |

The hard rule: never auto-resolve across a trust boundary. If your agent and
someone else's contradict each other, the system surfaces it and stops. Picking a
winner there is a policy decision software has no standing to make.

**Evidence outranks recency.** `observed` beats `asserted` beats `derived`, and
only then does the clock break ties. Recency is a poor proxy for correctness in a
memory system: a node that was offline for a month syncs and its stale writes
arrive carrying *newer* timestamps than the truth that replaced them.

**Identity is per agent, not per machine.** One user's Hermes profiles and each of
their firstmate crewmates carry distinct keypairs, so one can be attributed or
revoked without touching the others. Records carry the signing public key, so a
record relayed through a third node verifies with no directory lookup and no trust
in the relay.

**Embeddings are local and never synced.** Text ships; each node re-embeds on
receive. Every node already needs a local embedder for offline ingest, so the
capability is not additional, and a whole class of version-skew bugs disappears. A
model mismatch between peers degrades recall *silently*, which is exactly why it is
a `memctl health` check rather than a footnote.

## Encryption

Encryption is phase 1, not a hardening pass. With multiple users, a relay node
holding another user's plaintext is not acceptable at any point in the timeline.

- Each space has a content key (XChaCha20-Poly1305).
- The content key is wrapped to each member's X25519 recipient key, age-style.
  **Adding a member is a re-wrap, not a re-encryption of the corpus.**
- Removing a member rotates the key into a new **epoch**. Records carry their
  epoch, so everyone who stays can still read the history.

### Revocation is forward-only

A removed member keeps whatever they already synced. This is a property of the
design, not a bug scheduled for later. **If a space cannot tolerate that, it should
not have been shared.**

### A node can only index what it can decrypt

| Capability | Readable space | Relayed space |
|---|---|---|
| Store and gossip records | yes | yes |
| Verify signatures | yes | yes (frame signatures) |
| Decrypt bodies | yes | **no** |
| Embed and index | yes | **no** |
| Search locally | yes | **no** |
| Show in `memctl` | full | counts and bytes only |

Carrying spaces you hold no key for is **opt-in and off by default**
(`docs/decisions/0003`). Turning it on helps everyone's availability; it also means
your disk holds other people's ciphertext, which is a decision the operator should
actually make rather than inherit.

### What a relay still learns

Space IDs, record counts, timing and sizes. Frames are padded to size buckets
(256B / 1K / 4K / 16K / 64K, then whole 64K steps) to blunt size correlation,
because the threat model here includes a curious *member*, not only an outside
observer. Padding cannot hide that traffic happened.

## Known limitation: tailnet identity

The plan calls for the daemon to be its own tailnet node via `tsnet`. That library
is unreachable in this build, so discovery uses the host's Tailscale LocalAPI and
peers are dialled directly over their tailnet addresses. The daemon therefore shares
the host's tailnet identity instead of having its own, and tailnet ACLs cannot
distinguish it from anything else running on that host.

Per-record and per-frame signatures are unaffected, so provenance still survives
relaying. If `tsnet` becomes available, the transport is an interface and this is a
drop-in replacement.

## Getting started

```sh
go build -o bin/ ./cmd/...

# One machine, no peers. This is a supported deployment, not a degraded one.
bin/memd space create user/you
bin/memd serve --no-sync &
bin/memctl status
```

Point an agent at it. `memd mcp` is a stdio bridge to the running daemon, which is what
every MCP client wants:

```json
{ "mcpServers": { "memmesh": { "command": "/path/to/memd", "args": ["mcp"] } } }
```

Hermes uses a YAML `mcp_servers:` block rather than this JSON shape; the fragment for it
lands with the rest of the agent integration work in M6.

### Sharing a space with another machine

```sh
# On the machine joining:
bin/memd identity                                   # prints its rk_… recipient key

# On the machine that owns the space:
bin/memd space share shared/crew rk_…  > wrapped.json

# Back on the joiner:
bin/memd space join wrapped.json
```

Adding a member is a re-wrap of one key, not a re-encryption of anything. Removing one is
`memd space rotate <space>` followed by re-sharing to everyone who stays — and the member
you do not re-share to keeps whatever they already synced, because revocation is
forward-only.

### Joining the mesh

Both machines need `tag:mem-node` in their tailnet ACLs. Then `memd serve` finds peers
through the local Tailscale daemon with no registry to run:

```sh
bin/memd serve
bin/memctl members      # enrolled vs participating, and lag in both directions
bin/memctl health       # exit 0 ok, 1 warn, 2 critical — drops into a systemd timer
```

`memctl members` deliberately shows two populations. **Enrolled** means visible on the
tailnet with the tag. **Participating** means records from that node have actually
arrived. A peer that is the first without being the second is reachable and not syncing,
which is the failure worth catching and the one a single "peers" count would hide.

## Layout

```
internal/clock               injected time sources; nothing reads the ambient wall clock
internal/ulid                sortable record ids, strictly monotonic per node
internal/hlc                 hybrid logical clock, and the skew primitive behind health
internal/record              the frozen record contract: encoding, signing, version vectors
internal/crypto              XChaCha20-Poly1305, X25519 key wrapping, the keyring, epochs
internal/wire                frame format, size-bucket padding, payload codecs
internal/store               per-space append-only log, and the catalog derived from it
internal/embed               the local embedder, behind an interface
internal/index               int8-quantized vectors resident, float32 on disk for rerank
internal/node                the five operations: remember, recall, forget, link, list_spaces
internal/mcp                 the MCP server and the tool descriptions that teach hygiene
internal/sync                anti-entropy: vectors, deltas, push-on-write, pull
internal/transport/tailnet   discovery and dialling over Tailscale
internal/admin               the local control protocol memctl speaks
internal/daemon              memd assembled, plus the health checks
docs/decisions/              why things are the way they are
```

## Reading the code

Start with `internal/record/record.go` for the data model and
`internal/record/canonical.go` for the encoding rules — those two files are the contract
everything else is written against.

Then the four decisions that are least obvious from the code:

- `docs/decisions/0001` — version vectors key on the record ID because the plan specified a
  sequence number that no field held.
- `docs/decisions/0004` — the decoder is strict rather than forgiving, because a record
  under a signature must have exactly one valid encoding.
- `docs/decisions/0006` — what a relay can read in the clear, and why it has to be able to.
- `docs/decisions/0007` — why an exchange pulls rather than offering, and what the
  bidirectional version got wrong.

## What is not built yet

Named here so nothing reads as finished when it is not:

- **Merkle prefix reconciliation and resumable chunked backfill** (M5). Delta sync by
  version vector works; what is missing is finding divergent ranges by content, which is
  what would catch a hole a version vector cannot see.
- **The distiller** (M6). `episode`, `fact` and `procedure` all exist and agents can write
  any of them, but nothing promotes episodes automatically, and nothing detects
  contradictions. `conflict` records are read correctly everywhere — recall returns
  siblings with provenance — but only a human or an agent writes them today.
- **`memctl conflicts`, `stats`, `doctor --fix`, `tail`** (M6–M7). `doctor` exists and
  explains remedies; it does not apply them.
- **Blob store for `artifact_ref`** (M5). The kind exists and records carry hashes; there
  is no content-addressed store behind them yet.
- **Agent skill files and packaging** (M6–M7). No `SKILL.md`, no `AGENTS.md` fragment, no
  launchd plist or systemd unit, no release build.
