# 0005 — Records carry a `refs` list

**Status:** decided at the M1 gate, needs captain confirmation
**Affects:** the frozen record format (plan §2.1)
**Raised during:** M1 gate review

## The gap

Two things the plan requires cannot be expressed with the field list in §2.1.

**1. A `conflict` record cannot name the records it links.** §2.2 defines
`conflict` as a record that "links two contradictory records; carries no claim of
its own". The only structural pointer on a record is `supersedes`, and that means
replacement — §6.2 requires both siblings to be *kept* and both *returned*, so
putting their IDs in `supersedes` would delete exactly the two records the conflict
exists to preserve. With no claim of its own, the body cannot carry them either:
prose in a body is not something `memctl conflicts` can query or
`recall` can follow.

**2. The `link` MCP tool (§7) has nothing to write.** Relating two memories
without replacing either is not `supersedes`, and tags group by topic rather than
naming a specific edge.

## Decision

Add `refs []ULID` to the record: non-directional pointers to related records,
sorted and deduplicated by the canonical encoder exactly like `supersedes`.

- `conflict` records put both sides in `refs`, and validation requires at least two.
- The `link` tool writes a record whose `refs` name what is being related.
- `refs` never implies supersession. A reader that treats a ref as a replacement is
  wrong; that is what `supersedes` is for, and the two lists stay separate for
  precisely that reason.

## Why now rather than escalating and waiting

Plan §0 says to stop and escalate rather than change the record format in a
worktree — and the M1 gate is where that escalation is supposed to land. The format
has not shipped, nothing is signed with it, and no record exists on any disk, so the
change costs one line in the encoder today. Discovered in M6, where `conflict`
records and the `link` tool are actually built, it would cost a format version bump
and a migration of every signed record in every space.

The gate exists to catch this class of problem at the moment it is cheap. Deferring
a known format gap past the freeze would be using the gate backwards.

## Alternatives rejected

- **Overload `supersedes`.** Would delete the siblings a conflict record exists to
  preserve.
- **Structured body on conflict records.** Makes the two sides unqueryable without
  decoding and parsing every body, and contradicts "carries no claim of its own" by
  putting semantics in the claim slot.
- **A separate edge store outside the record log.** Breaks §11.6: the edges would
  not be rebuildable from the log, would not sync as records, and would need their
  own conflict handling.

## If the captain disagrees

Reversing this before M2 lands is free. After records exist on disk it is a format
version bump. This is the last cheap moment.
