# Revscope

Revscope is an evidence-first software analysis platform. This repository holds
its **pre-release foundation**: the result contract, the error contract, a
mutation-aware analysis session, a child-process environment policy, and a
small CLI and MCP interface over them.

> **Status:** Revscope reads file metadata, runs a deterministic **stub**
> provider from fixture files, and has a **Ghidra** provider
> (`analyze-binary`) for real native binaries. The Ghidra integration is
> verified against Ghidra 12.1.4 on one machine (macOS arm64, JDK 25) with a
> small ELF fixture; other platforms and real-world binaries are not yet
> verified. See [Real-engine tests](#real-engine-tests).

## Requirements

- Node.js 24.11 or newer (declared). Verified so far only on Node.js 26.9.0,
  macOS 27 arm64. See [docs/support.md](docs/support.md).
- npm 11.
- For `analyze-binary` only: Ghidra and a 64-bit JDK 21 or newer. See
  [Installing Ghidra](#installing-ghidra).

## Install, build, and test

```bash
npm ci
npm run check
```

`npm run check` runs type checking, linting, the build, and every test.
Individual steps: `npm run typecheck`, `npm run lint`, `npm run build`,
`npm test` (builds first, because end-to-end tests run the built CLI).

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

## Installing Ghidra

Revscope never downloads or installs Ghidra. These steps are for you to run,
and they reflect Ghidra **12.1.4**, the latest release on 2026-10-10. The
requirements below were checked in that release's published
`Ghidra/application.properties` and `GettingStarted.md`.

1. **JDK.** Ghidra 12.1.4 needs a 64-bit JDK (not just a runtime),
   version 21 or newer. It declares `application.java.min=21` and no maximum.
   Its documentation names Java 21. A newer JDK such as 25 is within the
   declared range but is not the documented version, so if Ghidra misbehaves
   on it, use a JDK 21 and point `REVSCOPE_JAVA_HOME` at it.
2. **Download** `ghidra_12.1.4_PUBLIC_*.zip` from the
   [official releases page](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.4_build).
   Check its SHA-256 against the value published on that page:

   ```bash
   shasum -a 256 ghidra_12.1.4_PUBLIC_*.zip
   ```

3. **macOS: clear quarantine** before extracting, as Ghidra's guide
   recommends:

   ```bash
   xattr -d com.apple.quarantine ghidra_12.1.4_PUBLIC_*.zip
   ```

4. **Extract** the zip to a new directory, for example
   `~/Applications/ghidra_12.1.4_PUBLIC`. Ghidra has no installer. Do not
   extract it over an existing installation.
5. **macOS arm64 (Apple Silicon): build the native components.** The release
   contains prebuilt natives only for Windows and Linux x86-64. Without them,
   analysis still runs but the decompiler cannot start, and Revscope reports
   every decompilation as unavailable. The build needs the Xcode command-line
   tools and Gradle 8.5 or newer (or the Gradle wrapper, which downloads
   Gradle):

   ```bash
   cd ~/Applications/ghidra_12.1.4_PUBLIC/support/gradle && gradle buildNatives
   ```

6. **Point Revscope at it:** `export REVSCOPE_GHIDRA_DIR=$HOME/Applications/ghidra_12.1.4_PUBLIC`.

## Real-engine tests

`npm run check` never runs Ghidra. The tests that do are separate:

```bash
REVSCOPE_GHIDRA_DIR=/absolute/path/to/ghidra_12.1.4_PUBLIC npm run test:ghidra
```

Optionally set `REVSCOPE_JAVA_HOME=/absolute/path/to/jdk` as well.

They analyze a generated 592-byte x86-64 ELF fixture
(`tests/fixtures/binaries/make-elf.mjs`, never executed) and check:

- metadata, imported function names and pseudocode;
- honest labels;
- determinism;
- refusal of non-programs;
- a real timeout and a real cancellation, with Ghidra stopped and the
  workspace removed;
- equal CLI and MCP output.

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

## Documentation

- [Architecture](docs/architecture.md)
- [Decisions](docs/decisions/)
- [Limitations](docs/limitations.md)
- [Support matrix](docs/support.md)
- [Dependencies and licences](docs/dependencies.md)

## Licence

No licence has been granted yet. `package.json` is marked `UNLICENSED` and
`private` until the owner chooses a licence.
