# Architecture

Revscope is a layered TypeScript (ESM) application. Dependencies point inward,
and `tests/architecture/boundaries.test.ts` enforces it.

```
bin ──▶ interfaces ──▶ composition ──▶ infrastructure ──▶ application ──▶ domain
                 └────────────────────────────────────────▶ application ──▶ domain
```

| Layer | Directory | Owns | May import |
|---|---|---|---|
| Domain | `src/domain/` | Evidence model and label rules, capability semantics, error catalog and envelope, comparison, bundle validation, format sniffing, canonical JSON | `zod`, `node:crypto`, domain |
| Application | `src/application/` | Ports, the mutation-aware `AnalysisSession`, the tool registry and `executeTool` | domain, `zod`, `node:path`, `node:async_hooks` |
| Infrastructure | `src/infrastructure/` | File readers, stub provider, environment policy, child-process launcher, logger | domain, application ports, Node built-ins |
| Composition | `src/composition.ts` | Wires infrastructure into a `ToolContext` | everything except interfaces |
| Interfaces | `src/interfaces/` | CLI, MCP server, configuration, output and exit codes | everything above |
| Entry | `src/bin/revscope.ts` | Process I/O only | interfaces |

## One execution path

Every interface calls `executeTool(context, name, rawInput)`
(`src/application/tools/registry.ts`). It handles the whole request:

1. Looks up the tool. An unknown tool produces `unknown_tool`.
2. Validates the input with the tool's zod schema. A failure produces
   `invalid_input`, with the field paths and messages but never the rejected
   values.
3. Runs the tool, which returns a `Result`. Expected failures are values, not
   exceptions.
4. Re-validates the success output, including every evidence identifier.
5. Turns any unexpected exception into `internal_error` with a correlation ID.
   The exception class goes to the log; no message or stack trace reaches the
   caller.

The CLI only maps arguments onto tool input fields, resolving relative paths
against the working directory. The MCP server only frames JSON-RPC. Neither
validates tool input itself, so their error semantics cannot drift. The
conformance suite (`tests/conformance/errorConformance.test.ts`) checks this:
for each failure class, the application, CLI and MCP outputs must be
**identical**.

## Evidence semantics

Every result has a **result kind** from a closed list
(`RESULT_KINDS` in `src/domain/evidence.ts`). One central table,
`RESULT_KIND_SEMANTICS`, maps each kind to its labels and constraints:

| Result kind | Confidence | Authority | Allowed subjects | Produced by |
|---|---|---|---|---|
| `artifact-bytes` | observed | original-artifact | artifact | reads |
| `artifact-heuristic` | inferred | original-artifact | artifact | reads (must state its basis) |
| `engine-interpretation` | derived | analysis-engine | analysis state | reads |
| `state-observation` | observed | analysis-state | analysis state | reads |
| `mutation-acknowledgement` | reported | analysis-state | analysis state | mutations only |
| `derived-computation` | derived | revscope-computation | evidence set | reads |
| `unverified-assertion` | inferred | analyst-assertion | artifact or analysis state | reads (must state its basis) |

Capabilities declare only a result kind; a capability has no way to choose
confidence or authority. `createEvidence` takes no labels at all and computes
them from the kind. `parseEvidence` rejects any record whose labels differ
from the table, even if its identifier was recomputed. As a consequence:

- Decompiler output is `engine-interpretation`, which is never `observed` and
  never speaks for the original artifact.
- A mutation acknowledgement is `reported`: the provider's own account of a
  change it made. It is not an observation of the resulting state, which only
  a later read or state observation establishes. It only describes analysis
  state, and only mutating capabilities may produce one.

The checks run wherever evidence is made or accepted:

- **Provider declarations** are checked when a session opens, against the
  subject their results will describe (always analysis state). A provider
  cannot declare a kind that speaks for the original artifact, such as
  presenting decompiler output as `artifact-bytes`, cannot take the session's
  reserved `observe_state` operation, and must use operation names, effects
  and limitations that evidence can carry. The session refuses to open
  otherwise and lists the issues.
- **Built-in tools** create evidence through the same declarations.
- **Imported records** (`report-evidence`, `compare-evidence`) are checked by
  `parseEvidence` against the same table: labels, subject kind and basis.

A provider can still choose a wrong kind within those bounds, for example
`state-observation` for decompiler output; provider reviews must check each
declared kind against what the operation does.

### Consistency, not integrity or authenticity

The evidence identifier is an **unkeyed** SHA-256 of the record's canonical
JSON, labels included. A record whose content no longer matches its
identifier is rejected, which catches accidental corruption and careless
edits. It is not an integrity or authenticity mechanism. Anyone who edits a
record can recompute a matching identifier, so a record that passes is
consistent but may have been altered, and its producer field is a claim, not
a proof. Records loaded from files, such as the inputs to `report-evidence`
and `compare-evidence`, are therefore **unauthenticated**. Label rules still
apply to them, so an edited record cannot carry contradictory labels. A
future milestone may add signatures or a provenance chain. The error code
`evidence_integrity` names the failed consistency check; it does not imply
that passing records are protected.

## Mutation-aware session

`AnalysisSession` (`src/application/session.ts`) only trusts what it has
verified against a provider **state token**. A state token is an opaque
string that the provider must change whenever its analysis state changes.

- **Opening.** `AnalysisSession.open` checks every capability declaration,
  then calls `observeState()` to obtain the initial verified token. If that
  fails, the session does not open.
- **Reads** return the token they were made against. Cache entries are bound
  to the revision and token at which they were recorded. While the session is
  consistent, a read whose token differs from the verified one means the state
  changed outside the session; the session becomes uncertain.
- **Mutations** count as in progress from the moment `mutate()` is called,
  including while they wait behind earlier operations. From then until the
  outcome is recorded, `state()` reports `consistency: "uncertain"` and
  `mutation_in_progress: true`, and `snapshot()` refuses. The session also
  records itself as uncertain before the provider is called, and returns to
  consistent only after the outcome *and* its acknowledgement evidence have
  been validated.

| Mutation outcome | Possibly mutated | Session afterwards | Snapshot |
|---|---|---|---|
| Applied, with a valid new token and recordable acknowledgement | yes (known) | consistent at the new token; cache cleared | allowed |
| Applied, but the acknowledgement is not valid evidence | yes | **uncertain** | **refused** |
| Rejected, token unchanged | no (verified) | consistent; earlier cache kept | allowed |
| Rejected, but token changed | unknown | **uncertain** | **refused** |
| Partial (some items applied) | yes | **uncertain** | **refused** |
| Provider exception, or missing/invalid token | unknown | **uncertain** | **refused** |

While the session is uncertain:

- Reads go to the provider. They are not cached and carry a `session-state`
  unknown (`stateVerified: false`).
- Mutations are refused with `state_uncertain`.
- Snapshot export is refused with `state_uncertain`.
- **No ordinary read restores consistency**, not even one that lists every
  item.

Consistency returns only through `reconcile()`. It calls the provider's
`observeState()`, adopts the fresh token, starts a new revision and clears the
cache. The session stays uncertain if the observation fails, throws, returns
an invalid token, or is **stale**. An observation is stale when it reports a
token the session already knows was replaced since its last verified state:

- the token from before a mutation the provider reported as `partial` with
  `stateEffect: "changed"`;
- the verified token after a read reported a different one.

Under the single-writer assumption the state cannot legitimately return to
such a token without another change by this session. The cost is that a
provider which wrongly reports a change, and then truthfully reports the
old token, keeps the session uncertain until its token changes.

Reads, mutations and reconciliation run one at a time in call order.
`state()` and `snapshot()` are synchronous and never wait; they account for
every mutation that has been requested and not yet settled, not only the one
the provider is currently running. A read issued before a mutation still runs
first and describes the pre-mutation state.

Providers must not call back into the session that owns them: such a call
would queue behind the operation that made it and deadlock. The session marks
each operation's asynchronous context (`AsyncLocalStorage`), and a call that
arrives from inside it is refused immediately with `session_reentry`. The
check follows Node's asynchronous context propagation; a callback that a
provider routes through a mechanism that drops that context is not detected.

**Trust assumptions:** the session assumes it is the only writer of the
provider's state. A change made outside the session is detected on the next
provider round trip; a cached read is not re-checked until then. The token
contract is the provider's responsibility. A provider that returns the same
token for different states defeats detection.

## Environment policy and child processes

`buildChildEnvironment` (`src/infrastructure/envPolicy.ts`) builds a child's
environment from three explicit sources:

- a **baseline** allowlist: `PATH`, `LANG`, `LC_ALL`, `LC_CTYPE`, `TZ`;
- a deliberate **passthrough** list of names;
- explicit **set** values.

Nothing else reaches the child. The manifest records only names (approved,
inherited, absent, set), never values.

`runChild` (`src/infrastructure/childProcess.ts`) is the only code that
starts processes. It runs the child without a shell: an absolute executable
path, an argument vector, and NUL bytes rejected in the executable, the
working directory and the arguments.

**One deadline.** Every run has a hard deadline of
`timeoutMs + killGraceMs + settleMs` (defaults: 500 ms grace, 250 ms
settle), reported as `deadlineMs`. Cancellation shortens it to
`killGraceMs + settleMs` after the abort. Every phase, including
collecting output from descendants and verifying that the tree is gone,
stops at the deadline, so the run returns by then plus event-loop latency.
The tests allow 150 ms of latency.

**Lifecycle on POSIX (verified on macOS only):**

- The child leads a new process group. At `timeoutMs`, or on cancellation
  through an `AbortSignal`, the whole group receives SIGTERM, then SIGKILL
  after `killGraceMs`.
- Only that group is ever signalled. Once the group has been observed gone,
  it is never signalled again, so a later reuse of its ID is not hit.
- After the child exits, output still arriving from descendants is collected
  for at most `drainMs` (default 250 ms), never past the deadline. Then the
  run settles.
- Settling kills any remaining group member, including a descendant that
  closed its output, re-sending SIGKILL until the group is gone. It then
  waits for the output pipes to close, never past the deadline.

**Result:**

- `termination` says why the run ended: `exited`, `timed-out` or
  `cancelled`.
- The exit code and signal.
- `cleanup.status` says whether everything the run started is gone:
  - `not-needed`: the tree ended by itself.
  - `terminated`: Revscope signalled the tree and it is gone.
  - `failed`: a termination failure, with a reason. Signalling failed, group
    members were still running at the deadline, or the output pipes were
    still held open after the group ended.
- `outputComplete` is false when output was cut off.

**Escaped descendants.** A descendant that leaves the group (for example by
starting its own session) is not signalled, because Revscope cannot tell it
apart from an unrelated process without inspecting the system process table.
If it still holds the output pipes, cleanup is reported as `failed`. If it
also closed them, it is not detected.

**Measured on macOS** with `timeoutMs` 300, `killGraceMs` 500, `drainMs`
250, `settleMs` 250 (deadline 1050 ms):

| Scenario | Returned after | Cleanup |
|---|---|---|
| Normal exit | ~70 ms | not-needed |
| Grandchild holds the pipes | ~305 ms | terminated |
| Grandchild holds the pipes and ignores SIGTERM | ~570 ms | terminated |
| Grandchild escapes the group, holding the pipes | ~660 ms | failed |
| Child ignores SIGTERM | ~810 ms | terminated |
| Signalling denied (simulated EPERM) | ≤ 1050 ms + latency | failed |

**Windows:** only the direct child is signalled (`cleanup.scope:
"direct-child-only"`), and descendants are not tracked. If they keep the
output pipes open, cleanup is reported as `failed`. None of this has been
run on Windows. Linux uses the same POSIX mechanism but has not been run
either.

No tool in this milestone launches external programs. The lifecycle is tested
with the Node.js runtime running test-owned scripts.

## MCP implementation

The MCP layer is a small hand-written JSON-RPC server
(`src/interfaces/mcp.ts`), not an SDK server. Doing it this way lets input
validation failures use Revscope's own envelope. Tool schemas are generated
from the same zod schemas as draft-07 JSON Schema with an object root.

- **Framing:** each message is one line of at most 4 MiB. Lines are split
  from the byte stream directly, so an oversized line is discarded without
  being held in memory and answered with `resource_limit`.
- **Request ids:** every response, including a rejection of a malformed
  request or an internal error, carries the request's id when it is a valid
  JSON-RPC id (a string or an integer), and `null` otherwise.
- **Tool arguments** reach the tool exactly as parsed, so the tool's schema,
  not the transport, decides what is invalid. That keeps MCP envelopes
  identical to the CLI's and the application's.

**Paths at the tool boundary** must be non-empty, absolute and free of NUL
characters. The CLI resolves relative paths against its working directory,
but passes an empty value through unchanged, so `inspect-artifact ""` is
reported as `invalid_input` by every interface instead of silently naming
the working directory.

Compatibility is checked with the official MCP SDK client, a dev-only
dependency, in `tests/e2e/mcpSdk.test.ts`. That client validates every
`structuredContent` value against the advertised `outputSchema`.

See [decisions/](decisions/) for the reasoning behind each choice.
