# 0001 — Version vectors are keyed by record ID, not a separate sequence number

**Status:** decided, needs captain confirmation
**Affects:** the frozen record format (plan §2.1) and the sync protocol (§5.1)
**Raised during:** M1.2

## The gap

The plan specifies version vectors as `node_id → high-water seq` per space (§5.1),
but the record struct in §2.1 has no sequence field. There is nothing for a
version vector to hold a high-water mark *of*. Since both the record format and
the sync protocol are on the escalate-don't-decide list, this was worth stopping
on rather than inventing a field in a worktree.

## Options considered

1. **Add `seq uint64` to the record**, assigned per `(space, author_node)`.
   Matches the plan's wording literally, but it is a schema addition to a format
   the plan says must be frozen before anything else merges, and it introduces a
   second monotonic counter that has to agree with the ULID ordering or the store
   has two disagreeing notions of "later".

2. **Use the record's ULID as the high-water mark.** No schema change. ULIDs are
   already sortable and already per-author monotonic.

## Decision

Option 2. `VersionVector` is `map[NodeID]ulid.ULID`, and a delta is "everything
from node N with an ID greater than the mark you gave me".

This works because a node's ULIDs are strictly increasing, which the code
guarantees in two places:

- The daemon owns exactly **one** `ulid.Monotonic` per node, shared by every agent
  on the machine. Version vectors are keyed by node, so per-node monotonicity is
  the property that matters — not per-agent.
- `Monotonic.Next` pins to the last-issued millisecond and increments the entropy
  field when the wall clock repeats or steps backwards, so an NTP correction
  cannot produce a regression inside a process.

## The one real hazard, and what covers it

Across a **restart**, the generator's in-memory state is gone. If the wall clock
has moved backwards since the last write, a fresh generator could issue an ID
below one already published — and a peer that has advanced past that mark would
never ask for the record again.

Two mitigations, in order:

1. **Seed on boot.** `memd` re-seeds the generator from the store's maximum
   locally-authored ID before accepting writes. This closes the hole in the normal
   case and is required, not optional.
2. **Merkle reconciliation (M5)** compares ranges by content rather than by
   high-water mark, so any hole that does open is found and repaired rather than
   being invisible forever.

Defence in depth is the point: (1) is cheap and prevents it; (2) catches it if (1)
is ever wrong.

## Consequences

- No record-format change; `causal_ctx` is the same `VersionVector` type, so a
  record's carried context and a node's sync state are the same shape.
- The Merkle prefix tree in M5 is over record IDs, which is exactly what the
  vector already keys on — the two layers agree by construction.
- `MissingFrom` returns `map[NodeID]Range` with an exclusive `After` and an
  inclusive `Through`, which is the `MsgWant` payload verbatim.

## If the captain disagrees

Adding `seq` after records are signed means a format version bump and a migration
for every stored record. Now is the cheap moment to reverse this.
