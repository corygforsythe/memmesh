# memmesh with a firstmate crew

[firstmate](https://github.com/kunchenguid/firstmate) is a directory-based
orchestration layer: you talk to one agent, and it dispatches autonomous
crewmates, each in its own git worktree and session. Its own instructions live
in a tracked `AGENTS.md`, with agent-loaded skills under `.agents/skills/`.

This file is for an agent installing memmesh into that setup. Read
[`installation.md`](installation.md) first — the build, the daemon and the
failure modes are the same, and none of them are repeated here.

## Why the combination is worth anything

**Crewmate worktrees are disposable. That is the point of them, and it is also
the problem.** A crewmate reasons its way to a real conclusion — this test was
flaky for an environmental reason, this API needs a flag nobody documented, this
approach was tried and abandoned for a concrete cause — and then the worktree is
torn down and the conclusion goes with it. The next crewmate on a related task
starts from nothing and rediscovers it.

memmesh is a write target that outlives the worktree. It is not the only one
firstmate has; the distinction that matters is ownership:

| Knowledge | Belongs in |
|---|---|
| Captain preferences, working style | firstmate's own `data/captain.md` |
| Fleet-local operational facts | firstmate's `data/learnings.md` |
| Useful to every contributor to one project | that project's committed `AGENTS.md` |
| Task-scoped notes, investigation findings | the backlog item / the scout report |
| **Durable, cross-worktree, cross-machine, attributable per agent** | **memmesh** |

Route to the most specific owner. If a fact belongs in the project's committed
`AGENTS.md`, put it there — a memory system is not a substitute for
documentation that every human contributor should read. memmesh earns its place
for the material that is real but has no committed home: what was tried, what it
cost, what the environment actually does.

## Identity: one key per crewmate

Identity in memmesh is per agent, not per machine. A crewmate's agent key is
created on its first write, with no enrolment step — which is precisely what
makes disposable crewmates workable. Machine-level attribution would blur every
crewmate on a host into each other.

So: **every crewmate passes its own name as `agent` on every write.** A crew
that all writes under one default is a crew whose memories cannot be attributed
to whoever actually formed them, and cannot be revoked individually later.

## Space layout for a crew

Ask before creating any of these. The prefix picks the conflict policy and the
choice is not reversible by renaming.

- `user/<captain>` — the captain's own durable memory. Contradictions are
  detected and may auto-resolve on evidence weight.
- `shared/<crew>` — one space the whole crew writes to, when the crew spans more
  than one person's machines. **Contradictions here are never auto-resolved**,
  because the space crosses a trust boundary. Every contradiction queues for a
  human. That is the correct behaviour and the reason to use `shared/*`
  deliberately rather than by default.
- `agent/<name>` — a single agent's private scratch memory, last-write-wins.
  Rarely what you want for a crew, since nothing else can read it.

For a single captain running a crew on their own machines, `user/<captain>` is
usually the whole answer. Reach for `shared/*` when a second person's agents
join.

## Wiring it in

memmesh attaches over MCP, the same as anywhere else. Whichever harness the
crewmate runs under — Claude Code, Codex, Gemini CLI — the server entry is:

```json
{ "mcpServers": { "memmesh": { "command": "/abs/path/to/memd", "args": ["mcp"] } } }
```

Two things specific to a crew:

- **Use an absolute path to `memd`, and set `MEMMESH_HOME` explicitly.** A
  crewmate's working directory is a worktree that will not exist tomorrow.
  Anything resolved relative to it is a time bomb.
- **One daemon per machine, not one per worktree.** Exactly one `memd` can own a
  data directory, because exactly one process can own the logs. Every crewmate
  on a host talks to the same daemon through the same `memd mcp` bridge. If a
  second one is started against the same `--home`, the subcommands that open the
  node directly will refuse — that guard is protecting the log from two writers,
  not being awkward.

Start the daemon once per machine, outside the crew's lifecycle — a systemd unit
or launchd job, not a step in a task brief. `memctl health` exits 0/1/2 and
drops straight into a timer.

## The habit that makes it pay off

Two trigger points, and the second is the one that matters:

**Before starting a task**, recall against the task's subject. The cost is one
tool call and the alternative is rediscovering something a previous crewmate
already paid for.

**Before a worktree is torn down**, write what was learned. Not a log of what
happened — the PR already says that, and the diff says it better. Write what the
next agent would otherwise have to rediscover:

- a decision and the constraint that forced it
- an approach that was tried and abandoned, with the concrete reason
- something the environment actually does that its documentation denies

with `evidence: observed` only where the transcript, command output or file
content was genuinely seen, and `kind: episode` unless it is a claim you would
defend (`fact`) or how things are actually done here (`procedure`).

Note honestly: the distiller that is meant to promote episodes into facts and
detect contradictions is not built yet. Episodes written today stay episodes.
That is an argument for writing them well, not for skipping them.

## Handling contradiction in a crew

Parallel crewmates working from different worktrees will assert contradictory
things. Append-only removes structural conflict, not semantic conflict — both
memories are real, both signed, neither superseding the other, and that is
represented rather than prevented.

When `recall` returns a hit carrying `siblings`:

- Weigh evidence first (`observed` > `asserted` > `derived`), then recency.
  Recency is a poor proxy for correctness here: a machine that was offline for a
  week syncs and its stale writes arrive carrying *newer* timestamps than the
  truth that replaced them.
- Check `saw_this_claim` on each sibling. True means that author had already
  seen the memory they contradict — a considered disagreement. False means they
  wrote without knowing about it, which is ignorance rather than dispute.
- Look for a missing qualifier before concluding anyone is wrong. Two crewmates
  in different worktrees are often both right about their own worktree, and the
  fix is two scoped facts rather than a winner.
- Say in the answer that the memories disagree. Presenting one side as settled
  fact is worse than reporting a contradiction.
- If `more_siblings` is non-zero, it is contested beyond what is shown and needs
  a human. In a `shared/*` space it will never be resolved any other way, by
  design.

## Not shipped here

This file is guidance for wiring memmesh into a firstmate home. It is not a
firstmate skill, and memmesh does not ship one: the `SKILL.md` and the
teardown-write skill are M6 work and the README's "what is not built yet" list
says so. If you want the write-before-teardown step enforced rather than
remembered, that is a skill in the firstmate home's own `.agents/skills/`, and
it belongs to whoever owns that home — firstmate never writes a project's
instruction files directly, and neither should you.
