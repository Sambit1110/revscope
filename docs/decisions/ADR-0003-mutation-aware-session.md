# ADR-0003: Sessions trust only provider state they have verified

**Status:** accepted. Revised in Phase 3.6 to add state tokens and
mutation-in-progress tracking, replacing `fullStateRead`.

## Context

A batch mutation can fail after applying some of its items. The requirements
study found a session that kept serving cached pre-mutation reads, and kept
exporting an "immutable" snapshot, after a failed but partially applied batch.

Revscope's first design fixed that, but a review found two further gaps:

- **A race.** `snapshot()` and `state()` ran outside the operation queue. A
  provider that had already applied a change but not yet replied left the
  session reporting a stale state as consistent.
- **Weak recovery.** Recovery relied on a "full-state read" that each provider
  defined for itself. That cannot be verified, and it is impractical for large
  analysis databases.

## Decision

- **Every provider response carries a state token.** Providers must return an
  opaque token, changed whenever their analysis state changes, with every read
  and mutation outcome. They must also offer `observeState()`.
- **The session opens with a verified token.** It obtains one through
  `observeState()` when it opens. Cache entries are bound to the revision and
  token at which they were recorded.
- **Mutations are uncertain from the start.** The session becomes uncertain
  before the provider is called and reports `mutation_in_progress`. It returns
  to consistent only on `applied` with a valid token, or on `rejected` with an
  unchanged token.
- **Some outcomes leave the session uncertain:**
  - a partial outcome;
  - a provider exception;
  - a missing or invalid token;
  - a rejection whose token changed;
  - a read reporting an unexpected token.
- **While uncertain:**
  - reads are fresh, unverified and not cached;
  - mutations and snapshots are refused;
  - no ordinary read restores consistency.
- **Only `reconcile()` recovers.** A successful `observeState()` with a valid
  token starts a new revision. A failed observation leaves the session
  uncertain.
- **Stale observations do not recover.** The session remembers tokens it
  knows were replaced since its last verified state: the token before a
  change the provider reported, and a verified token that a read showed was
  replaced. An observation returning one of them is refused as stale.
- **Synchronous calls never wait, and never run ahead of a requested
  mutation.** Reads, mutations and reconciliation run one at a time, but
  `state()` and `snapshot()` are synchronous. A mutation is registered as
  pending when `mutate()` is called, before it reaches the head of the queue,
  so these calls report uncertainty for every requested mutation that has not
  settled. (A follow-up review reproduced the race this closes: a snapshot
  taken between `mutate()` and the start of its queued turn reported the
  pre-mutation state as consistent.)
- **Acknowledgements are validated before they are trusted.** An `applied`
  outcome whose acknowledgement cannot be recorded as valid evidence leaves
  the session uncertain.
- **Re-entrant provider calls fail fast.** A provider that calls back into its
  own session during an operation receives `session_reentry` instead of
  deadlocking the queue.

## Consequences

- Recovery is as reliable as the provider's token contract. A provider whose
  token does not change on every state change defeats detection.
- Providers are not trusted on this point: tokens are validated, and a
  rejection's claim of "no change" is checked against its token.
- The session assumes it is the only writer of provider state. An outside
  change is noticed on the next provider round trip, not on a cache hit.
- Snapshots record the verified token they describe.
