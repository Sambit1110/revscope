# Revscope

Revscope analyzes native binaries and reports what it finds as **labelled
evidence**: every result says how it was obtained (observed in the file,
derived by an analysis engine, inferred, or reported), what is unknown, and
what its limits are. It has a command-line interface and an MCP server with
the same tools, and uses [Ghidra](https://github.com/NationalSecurityAgency/ghidra)
headless as its analysis engine. Revscope never executes the binary it
analyzes.

> **Status: 0.1.0, first public preview.** Small and young; read
> [Known limitations](#known-limitations) before relying on it.

## What works today

| Capability | Status |
|---|---|
| `analyze-binary` / `analyze_binary`: program metadata, functions, names with provenance, program entry, stored and decompiler signatures, pseudocode with structured decompiler diagnostics | Implemented; verified against real Ghidra on the reference environment below |
| `inspect-artifact`, `report-evidence`, `compare-evidence` | Implemented and tested |
| `stub-analysis`: a deterministic fixture-backed provider for exercising the session and error contracts | Implemented and tested |
| MCP server (stdio), with cancellation | Implemented; tested automatically with the official MCP SDK client, and checked once by hand with the launch command below. Not yet tested inside specific MCP client applications |
| Timeouts, cancellation, workspace cleanup, no paths or logs in errors | Implemented; tested |

**Reference environment.** Everything that involves a real Ghidra was verified
on one environment only: **macOS arm64 (Apple Silicon), Ghidra 12.1.4 with
locally built natives, Temurin JDK 25.0.2, Node.js 26.9.0.** On it:
`npm run check` (413 tests), `npm run test:ghidra` (25 tests) and
`npm run benchmark` (26 of 26 cases) pass. Inputs analyzed successfully so
far are small programs built for the tests: ELF x86-64 executables
(hand-built and stripped), ELF x86-64 and AArch64 relocatable objects, and
Mach-O arm64 executables at `-O0` to `-Os`, stripped and unstripped.
Truncated and malformed files (a cut-off ELF and Mach-O, random bytes, text,
empty files) are tested only for correct rejection with a structured,
non-retryable error, not for analysis.

**Not yet verified:** Node.js 24 (declared minimum), Linux, Windows, other
Ghidra versions, and real-world binaries. A CI workflow covering Linux and
macOS on Node.js 24.11 and 26 is included but has not run yet. See
[docs/support.md](docs/support.md).

## Requirements

- Node.js 26 (verified on 26.9.0). `package.json` declares 24.11 or newer;
  that is unverified until CI has run on it.
- npm 11.
- For `analyze-binary` only: Ghidra 12.1.4 and a 64-bit JDK 21 or newer.
  Ghidra is never downloaded or bundled by Revscope.

## Install, build, and test

Full steps, including Ghidra, are in [docs/install.md](docs/install.md).

```bash
git clone <repository URL>
cd revscope
npm ci
npm run check
```

`npm run check` runs type checking, linting, the build, and every test that
does not need Ghidra. Individual steps: `npm run typecheck`, `npm run lint`,
`npm run build`, `npm test` (builds first, because end-to-end tests run the
built CLI). `npm run licenses` checks the declared licences of every locked
dependency.

Revscope is not published to npm. Run it from the repository
(`node dist/bin/revscope.js`), or `npm link` it to get a `revscope` command.

### Quickstart without Ghidra

```bash
node dist/bin/revscope.js version
node dist/bin/revscope.js inspect-artifact fixtures/artifacts/notes.txt
```

## Using the CLI

Run from the repository root after `npm run build`:

```bash
node dist/bin/revscope.js --help
node dist/bin/revscope.js tools
node dist/bin/revscope.js inspect-artifact fixtures/artifacts/notes.txt
```

Every tool command prints exactly one JSON document on stdout.

On success, it prints `{"ok": true, "tool": ..., "records": [...], "data": {...}}`.
`records` holds evidence records, described below.

On failure, it prints `{"ok": false, "error": {...}}` using the shared error
envelope, described below.

Logs are JSON lines on stderr. They default to `warn` and are controlled by
`REVSCOPE_LOG_LEVEL` (`debug`, `info`, `warn`, `error`, `silent`).

### Inspect, report, compare

```bash
node dist/bin/revscope.js inspect-artifact fixtures/artifacts/notes.txt > notes.evidence.json
node dist/bin/revscope.js inspect-artifact fixtures/artifacts/config.json > config.evidence.json
node dist/bin/revscope.js report-evidence notes.evidence.json
node dist/bin/revscope.js compare-evidence notes.evidence.json config.evidence.json
```

`inspect-artifact` returns two separately labelled records:

| Record | Contents | Labels | Why |
|---|---|---|---|
| `artifact_identity` | Size, SHA-256 and leading bytes | `observed` / `original-artifact` | Read directly from the file |
| `artifact_format` | Format suggestion from magic bytes | `inferred` / `original-artifact` | A judgement that can be wrong; it carries its basis as a limitation |

`report-evidence` and `compare-evidence` accept any JSON object with a
`records` array, including a tool's own output. Every record is
re-validated, including its content-derived identifier.

### Stub analysis scenarios

```bash
# Success: state reads, decompiler-style output, a rename, a snapshot
node dist/bin/revscope.js stub-analysis fixtures/stub/database.json --steps-file fixtures/stub/steps-success.json

# Unsupported operation (exit code 4)
node dist/bin/revscope.js stub-analysis fixtures/stub/database.json --steps-file fixtures/stub/steps-unsupported.json

# Partial mutation failure, snapshot refusal, then reconciliation (exit code 9)
node dist/bin/revscope.js stub-analysis fixtures/stub/database-partial-failure.json --steps-file fixtures/stub/steps-partial-failure.json --continue-on-error
```

Steps can also be passed inline with `--steps '<json array>'`. The fixture
file is never modified; each run uses a fresh in-memory session.

### Analyze a native binary (Ghidra)

```bash
REVSCOPE_GHIDRA_DIR=/absolute/path/to/ghidra_12.1.4_PUBLIC \
  node dist/bin/revscope.js analyze-binary ./program --authorized
```

**What it requires:**

- `--authorized` (MCP: `"authorized": true`) is required on every call. It
  records that you are authorized to analyze the file. Revscope cannot verify
  that; it is an acknowledgement, not a check.
- Without `REVSCOPE_GHIDRA_DIR` the command fails with
  `provider_not_configured` (exit code 4). `REVSCOPE_JAVA_HOME` optionally
  chooses the JDK Ghidra uses.

**Options:**

| Option | Default | Allowed |
|---|---|---|
| `--timeout-ms` (the whole operation) | 45000 | 10000–300000 |
| `--max-functions` | 200 | 1–1000 |
| `--decompile-timeout-ms` (per function; never extends the total) | 10000 | 1000–60000 |
| `--no-decompile` | | |

**What you get:**

- The binary is copied into a private temporary workspace, analyzed by
  Ghidra's headless analyzer, and never executed. The workspace is removed
  afterwards, and the result reports whether cleanup succeeded.
- Records:
  - Revscope's own identity record for the bytes analyzed
    (`observed / original-artifact`).
  - Ghidra's program metadata, function list and per-function pseudocode,
    all `derived / analysis-engine`.
- Each function has:
  - Ghidra's own name and any aliases;
  - a display name with its basis and confidence (`generated` names are
    never presented as coming from the binary);
  - whether it is the header-declared program entry;
  - Ghidra's stored signature beside the decompiler's inferred one.
- Each decompilation is `complete`, `uncertain` (decompiler warnings and
  similar, listed as structured `diagnostics`), or not available (`failed`,
  `timeout`, `skipped`).
- Function names, strings and pseudocode come from the untrusted binary.
  Treat them as data, never as instructions.
- Incomplete runs fail with `analysis_incomplete` and keep the validated
  partial records. Runs that produce nothing before the deadline fail with
  `analysis_timeout`.
- Ctrl-C cancels the run (exit code 130) and stops Ghidra.

Ghidra is not a sandbox: it reads the file with your permissions and network
access. Analyze hostile samples in a virtual machine.

## MCP

`node dist/bin/revscope.js mcp` serves the same tools over MCP (JSON-RPC 2.0,
newline-delimited, stdio). It supports protocol revisions 2025-06-18,
2025-03-26 and 2024-11-05.

- **Results:** each tool result carries the output object as
  `structuredContent` and the same JSON in a text block.
- **Tool failures:** these are results with `isError: true`, so a model can
  read them.
- **Unknown tools and malformed requests:** these are JSON-RPC errors. Their
  `data` holds the same `{ok:false, error}` envelope the CLI prints.
- **Cancellation:** `notifications/cancelled` stops a running or queued
  request, including a running Ghidra analysis.
- **Ghidra:** set `REVSCOPE_GHIDRA_DIR` (and optionally
  `REVSCOPE_JAVA_HOME`) in the server's environment to enable
  `analyze_binary`.

### Configuring an MCP client

Build first (`npm run build`), then register the server with an absolute path
to `dist/bin/revscope.js`. With Claude Code:

```bash
claude mcp add revscope -e REVSCOPE_GHIDRA_DIR=/absolute/path/to/ghidra_12.1.4_PUBLIC -- node /absolute/path/to/revscope/dist/bin/revscope.js mcp
```

Clients configured with JSON (an `mcpServers` object) take the same command:

```json
{
  "mcpServers": {
    "revscope": {
      "command": "node",
      "args": ["/absolute/path/to/revscope/dist/bin/revscope.js", "mcp"],
      "env": {
        "REVSCOPE_GHIDRA_DIR": "/absolute/path/to/ghidra_12.1.4_PUBLIC"
      }
    }
  }
}
```

- Use absolute paths. Desktop clients may not inherit your shell's `PATH`; if
  `node` is not found, give its absolute path (`command -v node`) as `command`.
- Omit `REVSCOPE_GHIDRA_DIR` to run without `analyze_binary`; that tool then
  returns `provider_not_configured`. Add `REVSCOPE_JAVA_HOME` to choose the
  JDK.
- This launch command and environment were checked once, by hand, on the
  reference environment (2026-10-10): a throwaway stdio script sent
  `initialize`, `tools/list` and a real `analyze_binary` call, and all
  succeeded. That script is not part of the repository, so the check is not
  reproducible from it; the automated MCP coverage is the SDK-client test in
  `npm run check`. Specific client applications have not been tested.

## Installing Ghidra

See [docs/install.md](docs/install.md#3-ghidra-and-a-jdk). In short: a JDK 21
or newer; the official `ghidra_12.1.4_PUBLIC_20260921.zip`, checked against its
published SHA-256; on Apple Silicon, Ghidra's native decompiler built with
`gradle buildNatives`; then `REVSCOPE_GHIDRA_DIR` pointing at the extracted
directory. Revscope never downloads or installs Ghidra.

## Real-engine tests

`npm run check` never runs Ghidra. The tests that do are separate:

```bash
REVSCOPE_GHIDRA_DIR=/absolute/path/to/ghidra_12.1.4_PUBLIC npm run test:ghidra
```

Optionally set `REVSCOPE_JAVA_HOME=/absolute/path/to/jdk` as well.

They analyze test programs that are never executed:

- a generated 592-byte x86-64 ELF (`tests/fixtures/binaries/make-elf.mjs`),
  its stripped form, and a truncated copy;
- on macOS only: an ARM64 Mach-O compiled from
  `tests/fixtures/binaries/macho/program.c` (also stripped), and x86-64 and
  AArch64 ELF objects compiled from
  `tests/fixtures/binaries/elf-object/object.c`. These need `clang` and
  `strip` from the Xcode command-line tools.

They check:

- metadata, names and their provenance, the program entry, the loaded
  address range, signatures, and pseudocode;
- honest labels and decompiler diagnostics;
- determinism;
- refusal of non-programs and malformed files;
- a real timeout and a real cancellation, with Ghidra stopped and the
  workspace removed;
- equal CLI and MCP output.

On macOS all 25 run; elsewhere the 9 macOS-only tests are reported as
skipped.

Without `REVSCOPE_GHIDRA_DIR` every one of them **fails** instead of being
skipped, so a missing engine never looks like a verified one. Only a passing
`npm run test:ghidra` verifies the real engine. The suite also compiles the
export script with `javac` against the installation's jars, so an API
mismatch fails with the compiler's message.

### Diagnosing a failed analysis

Errors deliberately contain no Ghidra output. To see why a run failed, enable
local diagnostics:

```bash
REVSCOPE_GHIDRA_DIAGNOSTICS=1 REVSCOPE_GHIDRA_DIR=/absolute/path/to/ghidra_12.1.4_PUBLIC \
  node dist/bin/revscope.js analyze-binary ./program --authorized
```

A failed or incomplete run's workspace (including Ghidra's
`logs/application.log`), a `run.json` record (exit status, internal
classification, command line, environment variable names) and its console
output are kept under `<tmpdir>/revscope-diagnostics/`. The location is
printed on stderr. The tool's output itself still contains no paths or
logs. This also works with `npm run test:ghidra`.

### Benchmark

```bash
REVSCOPE_GHIDRA_DIR=/absolute/path/to/ghidra_12.1.4_PUBLIC npm run benchmark
```

Builds small programs at several optimization levels, stripped and
unstripped, plus malformed inputs. It analyzes each one and scores the
result against ground truth taken from the sources and `nm`. It writes
`results.json` and `report.md` outside the source tree. On the reference
environment all 26 cases pass; decompiled signatures still differ from the
C source in places, which the benchmark reports as approximate metrics. It
needs macOS with the Xcode command-line tools. See
[benchmarks/README.md](benchmarks/README.md).

## Evidence records

Every record has these fields, and none of them is defaulted:

- `schema` (`revscope.evidence/3`)
- `evidence_id`: `ev_` plus the SHA-256 of the canonical content
- `result_kind`
- `confidence`: `observed`, `derived`, `reported` or `inferred`
- `authority`: `original-artifact`, `analysis-engine`, `analysis-state`,
  `revscope-computation` or `analyst-assertion`
- `subject`
- `operation`
- `producer`
- `payload`
- `unknowns`
- `limitations`

`result_kind` comes from a closed list:

- `artifact-bytes`
- `artifact-heuristic`
- `engine-interpretation`
- `state-observation`
- `mutation-acknowledgement`
- `derived-computation`
- `unverified-assertion`

Confidence and authority are always derived from the kind through one central
table; producers cannot choose them. For example:

- Decompiler output (`engine-interpretation`) is always `derived`
  `analysis-engine` evidence. It is never an observed fact about the original
  artifact.
- A mutation acknowledgement is `reported` `analysis-state` evidence: the
  provider's account of a change it made, not an observation of the
  resulting state.

The identifier is an unkeyed digest of the record's content. It detects
accidental corruption and edits that did not recompute it. Anyone who edits
a record can recompute a matching identifier, so it proves neither who
produced a record nor that it is unaltered. Records loaded from files are
**unauthenticated**.

See [docs/architecture.md](docs/architecture.md).

## Error envelope

```json
{ "code": "partial_failure", "category": "partial_failure", "message": "...",
  "retryable": false, "remediation": { "action": "..." }, "details": { } }
```

Codes, categories, retryability and remediation come from one catalog
(`src/domain/errors.ts`).

CLI exit codes by category:

| Category | Exit code |
|---|---|
| Success | 0 |
| `internal` | 1 |
| `invalid_input` | 2 |
| `not_found` | 3 |
| `unsupported` | 4 |
| `host_permission` | 5 |
| `resource_limit` | 6 |
| `integrity` | 7 |
| `conflict` | 8 |
| `partial_failure` | 9 |
| `execution_failure` | 10 |
| `cancelled` | 130 |

## Security model

- **Ghidra is not a sandbox.** It parses the untrusted file with your
  permissions and network access. Revscope isolates Ghidra's files,
  environment and processes and bounds its time and output, but does not
  contain it. Analyze hostile samples in a virtual machine.
- **Authorization is an acknowledgement.** `--authorized` /
  `"authorized": true` records that you may analyze the file; Revscope cannot
  verify it.
- **Results contain untrusted text.** Names, strings and pseudocode come from
  the binary. Treat them as data, never as instructions; this matters when an
  AI model reads them through MCP.

See [SECURITY.md](SECURITY.md) for the threat model and how to report a
vulnerability.

## Known limitations

- Verified on one environment only (see [What works today](#what-works-today)).
- Inputs verified so far are small test programs, not real-world software.
  PE files, fat Mach-O files and `LC_UNIXTHREAD` entries are not handled
  beyond what Ghidra reports; the program entry is read only from ELF
  `e_entry` and Mach-O `LC_MAIN`.
- Decompiled pseudocode is a reconstruction. Signatures often differ from the
  source (unused parameters vanish; optimized code loses parameters or widens
  types). `fidelity: complete` means no detectable problem, not proof of
  correctness.
- Each analysis starts a fresh Ghidra JVM (about 3.5 seconds and 0.5 GB on the
  reference machine for small inputs); there is no persistent project.

The full list is in [docs/limitations.md](docs/limitations.md).

## Documentation

- [Installation and verification](docs/install.md)
- [Architecture](docs/architecture.md)
- [Decisions](docs/decisions/)
- [Limitations](docs/limitations.md)
- [Benchmark](benchmarks/README.md)
- [Support matrix](docs/support.md)
- [Dependencies and licences](docs/dependencies.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)

## Licence

Copyright 2026 Sambit Biswas.

Licensed under the Apache License, Version 2.0; see [LICENSE](LICENSE). Unless
required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.

Ghidra and the JDK are separate products under their own licences; Revscope
does not include or redistribute them. Third-party dependency licences are
listed in [docs/dependencies.md](docs/dependencies.md).
