# Installing and configuring memmesh with an AI agent

The runbook for an AI agent asked to install, configure or troubleshoot memmesh
on someone's machine. It is written to be executed, not summarised at the user.
Everything here was run against a real build before it was written down; the
failure modes in particular are observed output, not predictions.

This is not a guide to changing memmesh's code. The record contract in
`internal/record/` is frozen, the reasoning behind the non-obvious parts lives
in `docs/decisions/`, and `MEMORY-MESH-PLAN.md` holds the design intent — read
those before proposing a change to either.

## Rules for the installing agent

1. **Never create a space the user did not ask for.** The name picks the
   conflict policy (see step 3); guessing silently picks a policy for them.
2. **Never run `memd space share` unasked, and never invent a recipient key.**
   Sharing is forward-only: revoking later does not unsend what the recipient
   already synced. It is not a mistake that can be cleaned up.
3. **Never enable `--relay` on your own initiative.** It makes the user's disk
   hold other people's ciphertext (`docs/decisions/0003`).
4. **Verify, do not assume.** Every step below has a command that proves it
   worked. Run it, and end on `memctl health`.
5. **Pass `agent` on your writes, with your own name.** Identity is per agent,
   not per machine; writing without it files your memories under a shared
   default that cannot later be attributed or revoked.

## Prerequisites

Go 1.24.7 or newer. Nothing else — this tree is standard library only
(`docs/decisions/0002` records what that substituted and how each substitution
is reversed).

Tailscale is needed only for multi-machine sync. A single node does not need it
and is not a degraded deployment.

## 1. Build

```sh
git clone https://github.com/coryforsythe/memmesh
cd memmesh
go build -o bin/ ./cmd/...
bin/memd version
```

Then, before going further:

```sh
go test ./...
```

Every test in the default run is in-process and deterministic — injected clocks,
injected RNG, an in-memory transport. There is no network flake to retry
through. If this fails, stop and report it rather than installing on top of it.

## 2. Choose the data directory

`memd` resolves it as `$MEMMESH_HOME`, else `~/.memmesh`. Every subcommand takes
`--home` to override it.

**`--home` must come before the positional argument.** The flag set is parsed
before positionals, so:

```sh
bin/memd space create --home /srv/memmesh user/cory   # works
bin/memd space create user/cory --home /srv/memmesh   # fails: "space create <space>"
```

The second form treats `--home` as a second space name and rejects the arity.
If you are scripting the install, put every flag first.

## 3. Create a space

Ask the user what to call it. Do not guess, because the prefix selects the
conflict policy and that is not cosmetic:

| Prefix | Policy reported by `memctl spaces` | Meaning |
|---|---|---|
| `agent/*` | `lww` | private to one agent; last write wins, no ceremony |
| `user/*` | `siblings-auto` | one person's space; contradictions detected, may auto-resolve on evidence weight |
| `shared/*` | `siblings-manual` | crosses a trust boundary; contradictions are **never** auto-resolved |

```sh
bin/memd space create user/cory
# created user/cory (epoch 0, policy siblings-auto)
```

The hard rule underneath that table: never auto-resolve across a trust boundary.
If the user's agent and someone else's contradict each other, the system
surfaces it and stops, because picking a winner there is a policy decision
software has no standing to make.

## 4. Start the daemon

```sh
bin/memd serve --no-sync      # single machine, no peers
bin/memd serve                # join the mesh over tailnet
```

The startup banner is the first verification step — it prints the node id, the
data directory, both socket paths, the recipient key, the embed model, the
readable/relayed space counts, and the transport state:

```
memd memd/0.1.0-m3 started
  node        ubuntu
  home        /srv/memmesh
  admin       /srv/memmesh/memd.sock
  mcp         /srv/memmesh/memd-mcp.sock
  recipient   rk_…
  embed model memmesh-hashembed-v1-384
  spaces      1 readable, 0 relayed
  tailnet     disabled by --no-sync
  relaying    off — this node will not store spaces it cannot read
```

A tailnet that is absent or down reports as `unavailable: …` on that line rather
than failing startup. That is deliberate: the network is in neither the read nor
the write path, so losing it is a reporting condition, not an outage.

### Do not turn on `--relay` unasked

`--relay` makes this node carry spaces it holds no key for. It helps everyone's
availability, and it also means the user's disk holds other people's ciphertext.
`docs/decisions/0003` is the full argument; the operative part for you is that it
is off by default on purpose and the operator should actually make that choice.
The asymmetry matters too — turning it on later is free, and turning it off
later does not unsend the ciphertext that already landed elsewhere.

## 5. Attach the agent

### Claude Code

```sh
# This project only (writes ./.mcp.json, shared via git):
claude mcp add memmesh -- /abs/path/to/memd mcp

# All projects for this user, pinned to one data directory:
claude mcp add memmesh --scope user -e MEMMESH_HOME=/abs/path -- /abs/path/to/memd mcp
```

Verify:

```sh
claude mcp get memmesh
```

- `Status: ✔ Connected` — done.
- `Status: ⏸ Pending approval (run \`claude\` to approve)` — expected for
  project scope. `.mcp.json` is shared through the repo, so Claude Code will not
  connect to one until the user approves it interactively. You cannot approve it
  on their behalf; say so and stop.

Use an absolute path to the binary. The MCP client does not inherit the shell's
`PATH`, and a relative path resolves against whatever directory the client
started in.

### Other clients

```json
{ "mcpServers": { "memmesh": { "command": "/abs/path/to/memd", "args": ["mcp"] } } }
```

Hermes uses a YAML `mcp_servers:` block rather than this JSON shape.

### Prove the tools are reachable

```sh
{ printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe","version":"1"}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'; sleep 2; } | bin/memd mcp
```

Expect `serverInfo.name: memmesh` and five tools: `remember`, `recall`,
`forget`, `link`, `list_spaces`.

`memd mcp` is a deliberately dumb pipe — it does not parse MCP, so it cannot
corrupt a message and needs no version agreement with the daemon. It reads stdin
until close. Without the `sleep`, stdin closes before the daemon answers and you
get empty output that looks exactly like a crash.

## 6. Write and read once, end to end

```sh
{ printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe","version":"1"}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"remember","arguments":{"space":"user/cory","body":"memmesh installed on this machine","kind":"episode","evidence":"observed","agent":"<your-name>"}}}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"recall","arguments":{"query":"memmesh install"}}}'; sleep 3; } | bin/memd mcp
```

Then confirm the write is attributed to you rather than to a shared default:

```sh
bin/memctl keys
```

```
AGENT   FINGERPRINT    RECORDS
hammil  34bi23fh…v7uq  1
```

Agent keys are created on first write, which is what makes disposable agents
workable — there is no enrolment step. It is also why `memctl status` says
`agents: none yet` on a fresh install and why that is not a problem.

## 7. Finish on health

```sh
bin/memctl health ; echo "exit $?"
```

Exit codes are 0 ok, 1 warn, 2 critical, which drops straight into a systemd
timer. On a healthy `--no-sync` node four checks report `skip`:

```
skip  clock-skew                  no transport configured, so no peer clocks to compare against
skip  outbound-queue              no transport configured, so nothing is queued outbound
skip  peer-reachability           no transport configured; this node is deliberately alone
skip  enrolled-not-participating  no enrolled peers to compare against (no transport configured)
```

That is correct output, not a partial install. Report it as such.

`memctl doctor` is `health` plus what to do about each finding. It explains
remedies; it does not apply them.

Every `memctl` command takes `--json`, and both renderings derive from the same
struct, so they cannot drift. Parse the JSON rather than the table.

## Failure modes

Each of these is real observed output.

**`memd: memd: no daemon is listening at <dir>/memd-mcp.sock: … no such file or directory`**
`memd serve` is not running, or is running on a different `--home` than the MCP
client is pointed at. This is the most common misconfiguration: the agent's
server entry has no `MEMMESH_HOME` and so defaults to `~/.memmesh` while the
daemon runs somewhere else.

**`memctl: admin: no daemon is listening at <dir>/memd.sock`**
Same cause. `memctl` already suggests `memd serve` on this error.

**`memd: a daemon is already running on <dir>; stop it first, or use memctl for read-only queries`**
`space` and `identity` open the node directly rather than going through the
daemon, so they refuse to run while one owns the directory. Two processes
writing one log is the exact failure the single-owner design exists to prevent,
and it would corrupt the log rather than merely confuse the operator. Stop
`memd`, run the command, start it again.

**`node: no such space: user/x`** (as an MCP `isError` result)
The space was never created. `memd space create` it — after asking which name.

**`memd: space create <space>`** on a command that looks right
A flag was placed after the positional argument. See step 2.

**`memd mcp` produces no output at all**
stdin closed before the daemon replied. Keep it open.

**recall finds nothing in a space that has records**
Check `memctl spaces` for that space's `ACCESS` column. A `relayed` space is one
this node stores but holds no key for: counts and bytes only, never a body,
never a tag, not even a title. An empty search of a relayed space is not
evidence that it contains nothing.

## Multi-machine

Only when asked for. Both machines need `tag:mem-node` in their tailnet ACLs.

```sh
# On the joining machine:
bin/memd identity
# node       <hostname>
# recipient  rk_…

# On the machine that owns the space:
bin/memd space share shared/crew rk_… > wrapped.json

# Back on the joiner:
bin/memd space join wrapped.json
# joined shared/crew (epoch 0): 0 records now readable, 0 indexed
```

The wrapped key is usable only by its recipient, so it can be handed over by any
channel. **Sharing is forward-only.** A removed member keeps whatever they
already synced; that is a property of the design, not a bug scheduled for later.
If a space cannot tolerate that, it should not have been shared. Never run
`space share` on your own initiative.

Member removal is `memd space rotate <space>`, then re-share to everyone who
stays. Old epochs are kept on purpose: rotation stops a removed member reading
new writes, and keeping the old keys is what lets everyone else still read the
history.

Then on both machines:

```sh
bin/memd serve
bin/memctl members
```

`members` deliberately shows enrolled and participating separately. Enrolled is
"visible on the tailnet with the tag"; participating is "records from that node
have actually arrived". Reachable-but-not-syncing is the failure worth catching,
and a single "peers" count would hide it.

### A caveat to state plainly

The daemon is not its own tailnet node. `tsnet` is unreachable in this build, so
discovery uses the host's Tailscale LocalAPI and peers are dialled directly over
their tailnet addresses. The daemon therefore shares the host's tailnet identity,
and tailnet ACLs cannot distinguish it from anything else on that host. Per-record
and per-frame signatures are unaffected, so provenance still survives relaying.

### Embedding model skew

Embeddings are local and never synced — text ships, and each node re-embeds on
receive. A model mismatch between peers degrades recall *silently*, which is why
`embed-model` is a health check rather than a footnote. Run `memctl health` on
both ends after joining, not just the one you are sitting at.

## Using it well

The MCP tool descriptions are load-bearing and the agent sees them at the point
of use, so they are not repeated in full here. The parts agents most often get
wrong:

- **Recall before starting work, not after getting stuck.**
- **Default to `kind: episode`.** Write `fact` only for a claim you would
  defend, `procedure` only for how things are actually done. A distiller is
  meant to promote episodes later — note that it is not built yet, so today
  nothing promotes them automatically.
- **Set `evidence` honestly.** `observed` means you saw the transcript, command
  output or file content. Claiming it for something you inferred corrupts
  conflict resolution for everyone and is not recoverable by anyone reading
  later.
- **Handle `siblings`.** A recall hit may carry contradicting memories that are
  equally current, both signed, neither resolved. Weigh by evidence first, then
  recency; check `saw_this_claim` (true means considered disagreement, false
  means the author never knew about the claim, which is much weaker grounds);
  look for a missing qualifier before assuming anyone is wrong; and say in your
  answer that the memories disagree. If `more_siblings` is non-zero the claim is
  contested beyond what is shown and needs a human.
- **Prefer `forget` with a `reason`.** With one it writes a retraction that
  preserves the correction. Without one it writes a tombstone that loses the
  fact anyone ever believed it. `forget` never erases: the original stays on
  disk, stays verifiable, stays reachable by id. If someone needs data actually
  deleted, this is not that.
- **Pass `agent`.** Identity is per agent, not per machine, so that one can be
  attributed or revoked without touching the others.
