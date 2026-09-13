# 0003 — A relay-only node carries foreign spaces only if its operator opts in

**Status:** decided (resolves the open question in plan §3.5)
**Affects:** Milestone 4, `memctl status`, the Hello payload
**Decided during:** M1, ahead of the §3.5 deadline

## The question

Does a node accept and store spaces it holds no key for?

Carrying them improves availability for everyone: a space survives as long as any
node that ever relayed it is online, and a member returning after a long absence
can bootstrap from a peer that cannot read a word of what it is handing over.

The cost is that every member's disk holds every other member's ciphertext.

## Decision

**Opt-in per node, off by default.** The plan's own recommended default, adopted.

- A node relays a foreign space only when its operator has said so.
- The willingness is advertised in the `Hello` payload's `Relaying` flag, so a peer
  never assumes its records will be carried.
- `memctl status` reports `relaying: N spaces`, and every peer-facing surface keeps
  readable and relayed visibly distinct: for a space with no key, counts and bytes
  only, never a body, never a tag, never a decrypted title.

## Why off by default

The threat model here includes a curious *member*, not only an outside observer
(plan §3.4). Defaulting to carrying foreign ciphertext would mean that joining a
mesh silently enrols your disk as everyone else's backup — a decision with real
consequences that the operator never actually made. Availability is a property
worth opting into; it is not worth taking by default from someone who did not read
the docs.

The asymmetry also matters: turning relaying *on* later is free, and it
immediately starts helping. Turning it *off* after the fact does not unsend the
ciphertext that already landed on other people's disks.

## Consequences

- `Keyring` tracks relayed spaces explicitly rather than inferring them from key
  absence, so "I carry this but cannot read it" is a first-class state rather than
  an error path.
- A node that declines to relay is not a degraded node. Partial participation is
  the normal case (plan §3.1), and a mesh where nobody relays still converges for
  every space that has at least two readers online.
- The health check for "queued records for a space whose key is lost" (plan §8.4)
  stays meaningful: an unsendable backlog is a real problem whether or not
  relaying is on.
