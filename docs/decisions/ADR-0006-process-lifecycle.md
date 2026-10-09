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
- **Bounded output collection.** After the child exits, output is collected
  for a bounded drain period. Remaining descendants are then killed and the
  streams closed, so pipes cannot extend the deadline.
- **Nothing outlives the run.** When it finishes, any remaining group member
  is killed. The run then waits up to 500 ms for the group to disappear before
  reporting whether cleanup succeeded.
- **The result says what happened.** It reports why the run ended (`exited`,
  `timed-out` or `cancelled`) separately from cleanup (`not-needed`,
  `terminated` or `failed`, with a reason).
- **Windows.** Only the direct child is signalled, and the result says so
  (`scope: "direct-child-only"`). Killing a whole process tree there would
  need Job Objects or an external tool; both are deferred.

## Consequences

- A process that deliberately leaves the group (for example with `setsid`)
  escapes group termination. This is a documented limitation.
- Process IDs are not re-checked before signalling. The group ID stays
  reserved while any member exists, so signalling an exited group fails
  harmlessly. A full reuse of the ID within the verification window is
  theoretically possible and not defended against.
- Only macOS has been exercised. Linux uses the same POSIX mechanism but is
  unverified.
