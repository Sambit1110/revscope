# Revscope

Revscope is an evidence-first software analysis platform. This repository holds
its **pre-release foundation**: the result contract, the error contract, a
mutation-aware analysis session, a child-process environment policy, and a
small CLI and MCP interface over them.

> **Status:** no real reverse-engineering provider exists yet. Revscope
> currently reads file metadata and runs a deterministic **stub** provider
> from fixture files. It does not disassemble, decompile, or otherwise
> analyze real binaries.

## Requirements

- Node.js 24.11 or newer (declared). Verified so far only on Node.js 26.9.0,
  macOS 27 arm64. See [docs/support.md](docs/support.md).
- npm 11.

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

The identifier detects accidental or partial modification. It is an unkeyed
digest, so it does **not** prove who produced a record.

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
