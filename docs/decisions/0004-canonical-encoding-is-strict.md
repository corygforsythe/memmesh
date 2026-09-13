# 0004 — The decoder refuses non-canonical encodings

**Status:** decided
**Affects:** `internal/record`
**Decided during:** M1.2

## Decision

`record.Decode` rejects, rather than tolerating and normalizing:

- tags not in strictly ascending order, or duplicated
- `supersedes` IDs not in strictly ascending order, or duplicated
- `causal_ctx` node names not in strictly ascending order
- varints that are not minimally encoded
- any trailing byte after the last field

## Why it is not merely tidiness

The signature is over the canonical bytes. If two different byte strings both
decode to the same record and both carry a valid signature, then a record has more
than one valid encoding — and every downstream assumption that treats a record as
a single immutable thing becomes shaky:

- A node could store one encoding and gossip another, so two peers holding "the
  same" record disagree on its bytes and therefore on any hash over them. The
  Merkle prefix tree in M5 is a hash over record content; it would report
  divergence between two nodes that agree on every record.
- Content-addressed deduplication stops deduplicating.
- A relay could reorder a record's tags and produce a second frame that verifies,
  which is signature malleability dressed up as a formatting difference.

Tolerant parsers are the right default in most places. Not under a signature.

## Cost

A peer running a buggy encoder gets hard failures instead of silent acceptance. The
error messages name the field and the reason, which is the tradeoff being bought:
loud, locatable rejection instead of a divergence that surfaces three milestones
later as an unexplained Merkle mismatch.

## Related

Signing is domain-separated: records sign under `memmesh/record/v1\0` and frames
under `memmesh/frame/v1\0`. The same agent key signs both, and without separation a
signature harvested from one context could be replayed in the other. There is a
test that a frame-domain signature does not verify as a record signature and vice
versa.
