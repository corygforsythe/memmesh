# 0007 — An anti-entropy exchange pulls; it does not offer

**Status:** decided
**Affects:** `internal/sync`
**Decided during:** M3.1

## Decision

The initiator of an exchange asks for what it is missing and stops. It does not push its
own records at the peer during a pull. Records travel the other way because the peer runs
its own pull, and because fresh writes are pushed immediately (plan §5.1.3).

So the protocol has exactly two shapes:

- **Pull** — request/response. Every transfer was asked for.
- **Push-on-write** — fire and forget. A failed push is dropped; the next pull delivers it.

## Why not make one round bidirectional

The obvious optimisation is to have the initiator also send what the peer lacks, halving
the number of exchanges. It was implemented that way first, and it was wrong for a reason
worth recording.

An offer means writing frames the peer never requested, on a session the initiator is
about to close. The peer's reader and the initiator's `Close` then race, and whether the
last batch survives depends on scheduling. That showed up immediately as a test that
passed or failed depending on goroutine timing — which is exactly the class of bug plan
§0.5 says not to tolerate ("a convergence test that flakes is a failed test, not a
retry").

The fix for the race is an acknowledgement, which means a second round trip, which is most
of the saving gone. And the saving was never large: both nodes were going to run their own
anti-entropy round anyway.

## What this costs

A node that can dial out but cannot accept connections would only ever give up records
through push-on-write, never through being pulled from. On a tailnet every node is
dialable, so the case does not arise here. If a transport ever appears where it does, the
answer is an explicit offer phase with an ack — not an unrequested write on a closing
session.

## What it buys beyond the race

- Every transfer is bounded by a request, so a receiver controls its own intake rate with
  `Want.Limit` rather than being handed whatever the sender felt like sending.
- `MaxRoundsPerSpace` can cap one exchange, so a very stale peer closing a huge gap does
  not monopolise a session while other peers wait.
- The responding side is a simple loop over one frame at a time, with no state machine
  tracking whose turn it is to speak.
