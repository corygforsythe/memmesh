# Changelog

Every task adds a line here. Format loosely follows Keep a Changelog; the
milestone headings match the build plan.

## Unreleased

### M1 — Contracts

- `internal/clock`: injected millisecond time sources — a real one, a manually
  driven `Fake` for tests, and an `Offset` view for simulating a skewed peer.
  Nothing in the tree reads the ambient wall clock.
- `internal/ulid`: 128-bit ULID with Crockford base32 encoding, order-preserving
  so string sort equals byte sort. `Monotonic` generator with injected clock and
  entropy, strictly increasing per node even when the wall clock steps backwards.
- `internal/hlc`: hybrid logical clock with the standard update rule, `Observe`
  for inbound records, and `Skew` as the primitive behind the clock-skew health
  check.
- `internal/record`: the frozen record contract. `causal_ctx` and `evidence`
  present from the start; `epoch` carried per record for key rotation. Canonical
  deterministic encoding, strict non-malleable decoding (see
  `docs/decisions/0004`), ed25519 signing under a separated domain, `Builder` that
  stamps identity and ordering so call sites cannot get them wrong.
- `internal/record`: `VersionVector` keyed by record ID rather than a separate
  sequence number (see `docs/decisions/0001`), with lattice `Merge`, `Dominates`,
  `Concurrent` and `MissingFrom` producing the exact `MsgWant` payload.
- `internal/record`: `PolicyFor` encodes the per-space conflict policy table,
  including the hard rule that shared spaces never auto-resolve.
- `internal/crypto`: XChaCha20-Poly1305 (ChaCha20 + Poly1305 + HChaCha20),
  cross-validated against committed OpenSSL-derived vectors and the published
  HChaCha20 draft vector. X25519 age-style key wrapping with the recipient bound
  into both the KDF salt and the AAD. `Keyring` with epoch retention, rotation as
  member removal, and readable-versus-relayed as a first-class state.
- `internal/wire`: frame format with the `[reserved]` transform slot as a no-op
  passthrough, size-bucket padding (256B/1K/4K/16K/64K then whole 64K steps),
  version negotiation, and payload codecs for hello, vectors, want, record
  bundles, liveness and errors. Frames are signed by the sender; records stay
  signed by their author.
- `docs/decisions/`: 0001 record-ID version vectors, 0002 stdlib-only build,
  0003 relay-only nodes are opt-in (resolves plan §3.5), 0004 strict canonical
  decoding.

### M2 — Single node, useful on day one

- `internal/store`: per-space append-only segmented log with CRC-framed entries, so an
  interrupted write is a recoverable torn tail rather than corruption. Every derived
  structure — the index, the version vector, the catalog — is rebuilt by replaying the
  log, which is what makes §11.6 literally true. Plus the decrypted `Catalog`:
  supersession resolution, tombstone-versus-retraction, refs, and pending edges for
  corrections that outrun the claims they correct.
- `internal/store`: a relayed space has a log and no catalog, so there is no code path
  by which a node could index something it cannot decrypt. Gaining the key later makes
  the records already on disk searchable with no network traffic.
- `internal/embed`: `Embedder` interface plus a hashed bag-of-words embedder —
  unigrams and bigrams, sublinear term frequency, L2 normalized — with the model ID
  pinned onto every record.
- `internal/index`: int8-quantized resident vectors with float32 on disk for rerank,
  warm-on-boot from the persisted vectors, and a model change discarding the index
  rather than silently reusing incomparable vectors.
- `internal/node`: the five operations — remember, recall, forget, link, list_spaces.
  Recall returns siblings with full provenance and an explicit `saw_this_claim` flag,
  caps them, and warns rather than failing when results are degraded. Per-agent keypairs
  created on first use. The ULID generator is re-seeded from the store on boot, which
  closes the docs/decisions/0001 hazard.
- `internal/mcp`: JSON-RPC 2.0 MCP server whose tool descriptions teach memory hygiene
  and conflict handling, because the tools alone do not.
- `internal/admin`, `internal/daemon`: unix-socket control surface, the health checks
  including clock-skew and embed-model-match, and the MCP socket the `memd mcp` bridge
  attaches agents to.
- `cmd/memd`, `cmd/memctl`: the daemon and the CLI. Every memctl command supports
  `--json` from the same struct the table renders, and relayed spaces show counts and
  bytes only, everywhere.
- `docs/decisions/0006`: why the sealed envelope exposes record ID and authoring node.

### M3 — Two-node sync

- `internal/sync`: version-vector handshake, delta computation from `MissingFrom`,
  push-on-write to k=3 random peers, and jittered pull anti-entropy. Exchanges are
  pull-only (see `docs/decisions/0007`), batches are bounded, and `MaxRoundsPerSpace`
  stops one very stale peer monopolising a session.
- `internal/sync`: an in-process `Mesh` transport with partition and heal, which
  marshals and re-verifies every frame so the in-memory path exercises the same
  encoding and signature checks the network does. No test in the default run touches a
  socket.
- `internal/wire`: `MsgVectors` and `MsgWant` are plaintext. A relay holds no key, so a
  sealed want list would make relaying impossible — and both payloads name only the
  envelope-level facts a relay already reads (`docs/decisions/0006`).
- `internal/transport/tailnet`: discovery through the local Tailscale API over its unix
  socket, filtered on `tag:mem-node`, with peers dialled directly over their tailnet
  addresses. Listens on the tailnet address alone by default. A tailnet that is down is
  a reporting condition, not a startup failure, and a failed discovery keeps the last
  known peer list rather than reporting a mesh-wide partition.
- `internal/daemon`: `members` keeps enrolled and participating as separate populations
  and prints bidirectional lag first, because a peer that is reachable and not syncing
  is the failure worth catching. `health` gains live clock-skew and embed-model
  comparison against peers.
- `cmd/memd`: `--relay`, `--no-sync`, `--port`, `--tag`, `--pull-interval`, and a guard
  that refuses to open the data directory while a daemon already owns it.
- Tests: two-node convergence, convergence after a kill mid-backfill, partition and
  heal, order-independent convergence across four shuffled exchange orders, a 7-node
  property test under random partitions, and a relay carrying a space it cannot read
  through to a third node that can. Clean under `-race -count=3`.
- `docs/decisions/0007`: why an exchange pulls rather than offering.

### M6 (partial) — Agent-assisted installation

- `docs/agents/installation.md`: the install and configuration runbook written for an
  AI agent doing the install. Every command and every failure string in it was executed
  against a real build first, including the ones that are easy to get wrong: `--home`
  must precede the positional argument, `memd mcp` needs stdin held open or it returns
  nothing that looks exactly like a crash, and the `space`/`identity` subcommands refuse
  to run while a daemon owns the directory.
- `docs/agents/firstmate.md`: wiring memmesh into a firstmate crew — one key per
  crewmate because identity is per agent, one daemon per machine rather than per
  worktree, knowledge routed to its most specific owner rather than everything into
  memory, and the write-before-teardown habit that is the actual reason the combination
  is worth anything.
- Both files state the installing agent's limits rather than only its steps: never
  create a space the user did not name (the prefix picks the conflict policy), never
  `space share` unasked (sharing is forward-only and not cleanable), never enable
  `--relay` on the agent's own initiative (`docs/decisions/0003`).
- Not included, and still M6: the `SKILL.md`, the Hermes `mcp_servers:` config
  fragment, and a firstmate teardown-write skill.
