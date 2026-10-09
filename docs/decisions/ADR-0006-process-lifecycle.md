# ADR-0006: Child processes run in their own group with an enforced deadline

**Status:** accepted in Phase 3.6.

## Context

The first `runChild` implementation had two problems:

- **It killed only the direct child.** Descendants survived it.
- **It waited for the output pipes to close.** A grandchild that inherited
  stdout therefore held a 300 ms deadline open for over 3 seconds.

It also had no cancellation.

## Decision

- **Own process group (POSIX).** The child is started in a new process group.
  Deadline and cancellation (`AbortSignal`) send SIGTERM to that group, then
  SIGKILL after a grace period. Only that group is signalled.
- **One hard deadline.** `timeoutMs + killGraceMs + settleMs`, reported as
  `deadlineMs` and shortened by cancellation. Every phase stops at it:
  running, termination, collecting output after the child exits, and
  verifying the tree is gone. (Revised in the Phase 3.6 hardening pass. The
  earlier design ran verification for up to 500 ms *after* its final timer,
  so a run whose signals were denied took about 1.8 s against a 300 ms
  timeout.)
- **Bounded output collection.** After the child exits, output is collected
  for at most `drainMs`, never past the deadline. Remaining descendants are
  then killed, so pipes cannot extend the run.
- **Nothing in the group outlives the run.** Settling re-sends SIGKILL until
  the group is gone, then waits for the pipes to close, up to the deadline.
- **Escapes are reported, not hidden.** If the group is gone but the pipes
  are still held open 250 ms later, a descendant left the group. It is not
  signalled, and cleanup is reported as `failed` instead of `terminated`.
  (Measured on macOS under load: a cleanly terminated group's pipes close
  within 0.2 ms of the group disappearing.)
- **EPERM is not proof of failure on macOS.** While every member of a
  group is an unreaped zombie, `kill(-pgid, …)` returns EPERM rather than
  ESRCH. Revscope therefore treats EPERM from the group as unconfirmed and
  keeps polling. Only a group that still exists at the deadline after EPERM
  is reported as a termination failure. (Phase 4.1: treating EPERM as an
  immediate failure misreported clean terminations as `failed` in 40 of
  180 loaded runs.)
- **The result says what happened.** It reports why the run ended (`exited`,
  `timed-out` or `cancelled`) separately from cleanup (`not-needed`,
  `terminated` or `failed`, with a reason).
- **Windows.** Only the direct child is signalled, and the result says so
  (`scope: "direct-child-only"`). Killing a whole process tree there would
  need Job Objects or an external tool; both are deferred.

## Consequences

- A process that deliberately leaves the group (for example with `setsid`)
  escapes group termination. It is reported only if it still holds the
  output pipes.
- The group ID stays reserved while any member exists. Once the group is
  observed gone, Revscope stops signalling it. Between that observation and
  the previous signal, the ID can in theory be reused, and that is not
  defended against.
- Only macOS has been exercised. Linux uses the same POSIX mechanism but is
  unverified.
