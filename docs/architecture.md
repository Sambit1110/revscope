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
| Infrastructure | `src/infrastructure/` | File readers, stub provider, Ghidra engine (`ghidra/`), environment policy, child-process launcher, logger | domain, application ports, Node built-ins |
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
| Grandchild escapes the group, holding the pipes | ~800 ms | failed |
| Child ignores SIGTERM | ~810 ms | terminated |
| Signalling denied (simulated EPERM) | ≤ 1050 ms + latency | failed |

**Windows:** only the direct child is signalled (`cleanup.scope:
"direct-child-only"`), and descendants are not tracked. If they keep the
output pipes open, cleanup is reported as `failed`. None of this has been
run on Windows. Linux uses the same POSIX mechanism but has not been run
either.

The only tool that launches an external program is `analyze_binary`, which
runs Ghidra's `analyzeHeadless` (see the next section). In `npm run check`,
the lifecycle is tested with the Node.js runtime running test-owned scripts,
including a fake `analyzeHeadless`.

## Native binary analysis (Ghidra)

`analyze_binary` (`src/application/tools/analyzeBinary.ts`) analyzes one
native binary with a `BinaryAnalysisEngine`. The only engine is
`GhidraEngine` (`src/infrastructure/ghidra/`), configured by
`REVSCOPE_GHIDRA_DIR` and optionally `REVSCOPE_JAVA_HOME`. Without it, the
tool reports `provider_not_configured`. ADR-0007 records the decisions.

**Verification.** Everything below is tested with a fake `analyzeHeadless`
in `npm run check`. It was verified against a real Ghidra with
`npm run test:ghidra` (9/9) on one environment only: Ghidra 12.1.4 with locally built macOS arm64 natives, Temurin JDK 25.0.2, Node.js 26.9.0, macOS 27.0.1 arm64.
ADR-0007 lists what that covers and what remains unverified.

**One run, step by step:**

1. The tool validates the input. It requires `authorized: true`, an
   acknowledgement Revscope records but cannot verify, and checks the limits:

   | Limit | Default | Allowed |
   |---|---|---|
   | `timeout_ms` (whole operation) | 45 000 | 10 000 – 300 000 |
   | `max_functions` | 200 | 1 – 1 000 |
   | `decompile_timeout_ms` (per function) | 10 000 | 1 000 – 60 000, and at most `timeout_ms` |
   | `decompile` | true | |

2. The engine checks the installation: an absolute directory, an executable
   `support/analyzeHeadless`, a readable version, and Revscope's export
   script. It then opens the input with the safe file opener. Input errors
   are the same as `inspect_artifact`'s, and nothing has been created yet.
3. It creates a workspace: a fresh `mkdtemp` directory, mode 0700. The input
   is copied there as `input/artifact` (read-only), hashed while it is
   copied, with a 256 MiB limit. The caller's path never reaches Ghidra.
4. It runs `analyzeHeadless` through `runChild`: no shell, its own process
   group, one hard deadline.
   - **Environment:** the baseline allowlist plus `HOME` and `TMPDIR` inside
     the workspace, and `JAVA_TOOL_OPTIONS` with `-Duser.home`,
     `-Djava.io.tmpdir`, Ghidra's `-Dapplication.settingsdir`,
     `-Dapplication.cachedir` and `-Dapplication.tempdir`, all inside the
     workspace, and `-Djava.awt.headless=true`. Java ignores `$HOME`, and
     without `application.cachedir` Ghidra caches in `/var/tmp/<user>-ghidra`.
     `JAVA_HOME` is passed only when configured. Ghidra's settings, cache,
     script cache and user scripts therefore stay inside the workspace.
   - **Time:** the child's deadline plus a 2 s reserve for copying, parsing
     and removal fits inside `timeout_ms`. Ghidra's auto-analysis gets at
     most half the child's time (`-analysisTimeoutPerFile`). The export script
     receives an absolute wall-clock deadline: after it, decompilations are
     recorded as `skipped`, so per-function limits cannot outlast the run.
5. `RevscopeExport.java` writes `revscope.ghidra-export/1`: one JSON record
   per line, flushed as written. The engine reads at most 32 MiB of it and
   validates it strictly:
   - every record matches a strict schema;
   - lines are at most 256 KiB, pseudocode at most 64 Ki characters per
     function;
   - functions are unique, ascending and within the limit, and each
     decompilation follows its function;
   - the header must echo the requested limits and the configured Ghidra
     version;
   - nothing follows the trailer.

   A missing trailer means the export was cut off. A contradiction means it
   is malformed.
6. After `runChild` returns, so after the process tree has settled, the
   workspace is removed. Only the exact directory created is ever removed,
   links are not followed, and read-only leftovers are repaired once. Every
   result and error reports `cleanup: {process, workspace, reason}`, and
   failures are reported, not hidden.

**Evidence.** Results are read through an `AnalysisSession` over a read-only
provider, so labels come from declared capabilities:

| Record | Kind | Labels | Notes |
|---|---|---|---|
| `artifact_identity` | `artifact-bytes` | observed / original-artifact | Revscope's read of the exact bytes analyzed; the only record that speaks for the file |
| `program_info` | `engine-interpretation` | derived / analysis-engine | Format, language, compiler spec, image base, `address_placement`, the loaded `min_address`/`max_address`, `program_entry` (with the file's own `file_symbols` there), `external_entry_points` and `other_external_entry_points`, Ghidra version, whether analysis timed out, whether the decompiler started |
| `list_functions` | `engine-interpretation` | derived / analysis-engine | Per function: address, display `name` with `name_source`, `name_basis` and `name_confidence`, `ghidra_name`, `aliases`, size, thunk flag, `is_program_entry`, `is_external_entry_point`, stored `signature` and `calling_convention` with provenance, decompilation state |
| `decompile` (per function) | `engine-interpretation` | derived / analysis-engine | Pseudocode and `fidelity`, or a status (`failed`, `timeout`, `skipped`) with an unknown; `stored` and `decompiler` signatures, `signature_comparison`, structured `diagnostics` |

Every Ghidra record carries limitations stating that it is Ghidra's
interpretation, not a reading of the file, and that its names, strings and
code are **untrusted text derived from the input**, to be treated as data and
never as instructions. Decompile records also state that pseudocode is not
source code. Coverage gaps become unknowns: function limit, export deadline,
Ghidra's analysis timeout, decompiler unavailable, cut-off export.

**Function names.** Ghidra keeps one primary name per function and may hold
more symbols at the same address. Each has a SourceType: `imported` means
assigned by the loader during import, usually from the file's symbol tables,
but loaders also create names of their own. Revscope reports:

- `ghidra_name` and `ghidra_name_source`, as Ghidra has them;
- `aliases`, every other name at the address, each with a role;
- the display `name`, with `name_basis` and `name_confidence`:
  - `user-assigned`;
  - `imported`;
  - `ambiguous`: several imported names, and Revscope does not guess;
  - `loader-generated`: Ghidra's loader made the label while importing; the
    binary does not contain it (see below);
  - `generated`: Ghidra invented the name (default, analysis, AI); it is
    never presented as coming from the binary.

One loader convention is handled on evidence. Ghidra 12.1.4's ELF and Mach-O
loaders label the program entry `entry`, with source `imported`, whether or
not the binary names it: beside `_main` on Mach-O, and alone on stripped
Mach-O and ELF. The export script therefore reads the names the file's own
symbol tables define at the header-declared entry (ELF `.symtab` and
`.dynsym`, Mach-O `LC_SYMTAB`), with Ghidra's own parsers, and reports them as
`program_entry.file_symbols` (`[]` for a stripped binary). When those names
do not include `entry`, Ghidra's `entry` is the loader's label:

- if a name from the binary sits at the entry (e.g. `_main`), it is shown
  (`name_basis: imported-alias`) and `entry` is kept as an alias with role
  `loader-entry-label`;
- if none does (a stripped binary), `entry` is shown with
  `name_basis: loader-label` and `name_confidence: loader-generated`.
  `name_source` stays `imported`, Ghidra's own SourceType.

If the file's symbols could not be read, Revscope falls back to the Phase 4.3
rule: `entry` is the loader's label only when exactly one other imported name
sits at the entry. Pseudocode text still uses Ghidra's name.

**Address range.** `min_address` and `max_address` bound the memory Ghidra
loaded from the file into its default address space:

- Non-loaded sections (ELF section headers, symbol and string tables,
  `.comment`) are excluded. Ghidra keeps those in separate address spaces
  whose offsets restart at zero.
- Ghidra's synthetic `EXTERNAL` block, which holds placeholder addresses for
  imports, is excluded.
- Both bounds are `null` when there is no such memory; otherwise
  `min ≤ max`, and the export is refused if it says anything else.
- Both bounds are inclusive.
- The range is a hull: gaps between loaded blocks are not reported.

`address_placement` says what the addresses mean:

- `file-declared`: the addresses the file declares.
- `rebased`: Ghidra loaded the program at a base other than the file's.
- `relocatable-object`: ELF `ET_REL` or Mach-O `MH_OBJECT`. The file has no
  load address, so Ghidra placed it (at `0x100000` in 12.1.4), and every
  address is Ghidra's, not the file's.
- `unknown`: the header could not be read, or the format is not ELF or
  Mach-O.

**Signatures.** Ghidra's *stored* signature (`provenance: ghidra-stored`,
with its SourceType; `default` means never established, e.g.
`undefined f(void)`) and the *decompiler's* inferred signature and
calling-convention model (`provenance: ghidra-decompiler`) are reported side
by side. Neither replaces the other. An unknown calling convention is `null`
with `known: false`. `signature_comparison` is one of:

- `agree`;
- `differ`: a material diagnostic;
- `stored-not-established`: informational;
- `unavailable`.

The comparison normalizes formatting only.

**Decompiler diagnostics and fidelity.** Ghidra 12.1.4 reports decompiler
warnings only as comments in its C markup; `getErrorMessage()` is empty when
there are only warnings. The export script switches off every
listing-comment class and keeps the decompiler's WARN class. Every comment
token left is therefore a warning, recognised by token type and comment
class, not by its text.

Each diagnostic has a kind and a severity that follows from the kind:

| Kind | Severity |
|---|---|
| `decompiler-warning` | material |
| `decompiler-message` | material with output, informational beside a failure |
| `decompiler-calling-convention-unknown` | material |
| `pseudocode-truncated` | material |
| `signature-disagreement` | material |
| `calling-convention-disagreement` | material |
| `stored-signature-not-established` | informational |

Material diagnostics are also evidence unknowns. `fidelity` is:

- `complete`: decompiled, with nothing detectable making it uncertain;
- `uncertain`: decompiled, with at least one material diagnostic;
- `null`: not decompiled.

Revscope does not rank warning text: every warning is material, none is
dropped, and none turns output into a failure. `complete` is not proof of
faithfulness. On the Mach-O fixture, `main` decompiles as
`complete` yet its return value is lost; pseudocode stays a reconstruction.

**Entry points.** Ghidra marks the program entry *and* exported or global
symbols as "external entry points", so Revscope reads the entry the header
declares with Ghidra's own format parsers over the original file bytes: ELF
`e_entry` (`elf-header`) or Mach-O `LC_MAIN` (`macho-lc-main`). Anything else
is `unavailable` with a reason: other formats, Mach-O `LC_UNIXTHREAD`, fat
files, parse errors. `program_info` lists `program_entry` and the
`other_external_entry_points`. Each function has `is_program_entry` and
`is_external_entry_point`.

**Outcomes:**

| Situation | Result |
|---|---|
| Complete export | success; `data.analysis.complete` is false if the function limit, export deadline or Ghidra's analysis timeout reduced coverage |
| Export cut off (deadline, crash) | `analysis_incomplete` with validated `partial_records` |
| No export before the deadline | `analysis_timeout` |
| Caller cancelled | `cancelled` |
| Ghidra or Java misconfigured | `provider_not_configured` with `details.check` |
| Ghidra cannot load the file ("No load spec found") | `unsupported_target` |
| A loader accepted the format but found nothing it could load: the file is truncated or malformed ("No memory blocks were defined", or "truncated/missing from file" beside a failed import) | `unsupported_target`, `details.reason: malformed_input`; not retryable, because the same bytes fail the same way |
| Any other failed import | `provider_failure`, `details.reason: import_failed`; retryable |
| Malformed or oversized export, other engine failure | `provider_failure` with a fixed `details.reason` |

When there is no export, Ghidra's console output and logs are classified by
fixed patterns. They are never repeated in errors, and neither are the
installation directory, the workspace path or environment values.

**Cancellation:**

- The CLI cancels on the first SIGINT or SIGTERM and exits 130; the second
  exits at once.
- The MCP server honours `notifications/cancelled` for running and queued
  requests and sends no response for them. Process shutdown cancels all
  running work.

**Opt-in diagnostics.** `REVSCOPE_GHIDRA_DIAGNOSTICS=1` keeps a failed or
incomplete run for local diagnosis:

- the whole workspace, with Ghidra's `application.log` and `script.log`, is
  moved into a new 0700 directory under `<tmpdir>/revscope-diagnostics/`;
- `run.json` records the outcome, internal classification, exit status,
  signal, timings, command line and environment variable names only;
- `stdout.txt` and `stderr.txt` hold the console output.

The location is printed to the local stderr only. Tool results show
`cleanup.workspace: "preserved"` and never a path or log text. It is off by
default, and successful runs are always cleaned up.

**Not a sandbox.** Ghidra parses the untrusted file with the user's
permissions and network access. The measures above isolate files and
processes; they do not contain a compromised Ghidra. Analyze hostile samples
in a virtual machine.

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
- **Ordering and cancellation:**
  - Input is read continuously, while requests are handled one at a time
    and answered in order.
  - `notifications/cancelled` is acted on at once: the named running or
    queued request is aborted and gets no response.
  - More than 32 pending requests are refused with `resource_limit`.

**Paths at the tool boundary** must be non-empty, absolute and free of NUL
characters. The CLI resolves relative paths against its working directory,
but passes an empty value through unchanged, so `inspect-artifact ""` is
reported as `invalid_input` by every interface instead of silently naming
the working directory.

Compatibility is checked with the official MCP SDK client, a dev-only
dependency, in `tests/e2e/mcpSdk.test.ts`. That client validates every
`structuredContent` value against the advertised `outputSchema`.

See [decisions/](decisions/) for the reasoning behind each choice.
