# 0006 — The sealed envelope exposes record ID and authoring node

**Status:** decided
**Affects:** `internal/wire`, `internal/store`, plan §3.4's residual-metadata list
**Decided during:** M2.1

## What is in the clear

Every stored and transmitted record payload carries four fields outside the
ciphertext: **space**, **epoch**, **record ID**, and **authoring node**.

Space and epoch were always going to be visible — a relay has to route on the space
and a reader has to know which key to reach for. Record ID and authoring node are an
addition to the list in plan §3.4, so they are recorded here.

## Why they cannot be inside the ciphertext

§3.3 says a relay-only node can "store and gossip records: yes" for spaces it
cannot decrypt. Gossiping means two operations:

- maintaining a version vector, which is `node → high-water record ID`
- answering a range request: "records from node N with ID greater than X"

Both are defined over exactly the two fields in question. A relay that could not
read them could not do the one job a relay exists to do. There is no encoding trick
that avoids this: the sync protocol reconciles on these values, so whoever
reconciles must be able to read them.

## What stops a relay abusing it

All four envelope fields are bound into the AEAD's additional data
(`crypto.RecordAAD`). A relay therefore cannot alter an envelope and have the
payload still open — any peer holding the key gets an authentication failure, and
`wire.OpenRecord` additionally cross-checks the envelope against the signed record
inside and refuses if they disagree.

What a relay *can* still do is withhold records, or lie about what it has. That is
true of any node in a system with no consensus and is not specific to relaying;
anti-entropy with another peer, and the Merkle reconciliation in M5, are what
detect it.

## The actual privacy cost

An observer who relays a space learns the shape of activity in it: how many records,
from which machines, at what times, in what size bucket. It learns nothing about
content, tags, kinds, evidence levels or authoring *agents* — `author_agent` stays
inside the ciphertext, so which agent on a machine wrote something is not exposed.

The node-level leak is worth stating plainly in user-facing docs: **relaying a space
tells you who is writing to it and when, but not what they said.**
