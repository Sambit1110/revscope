# Dependencies and licences

All versions are pinned exactly in `package.json` and locked in
`package-lock.json`.

## Runtime

| Package | Version | Licence | Purpose |
|---|---|---|---|
| zod | 4.6.5 | MIT | Runtime validation and JSON Schema generation |

`zod` is the only production dependency; the production tree contains no
transitive packages.

## Development only

| Package | Version | Licence | Purpose |
|---|---|---|---|
| typescript | 7.0.2 | Apache-2.0 | Type checking and build |
| vitest | 5.0.3 | MIT | Test runner |
| oxlint | 1.87.0 | MIT | Linting |
| @types/node | 24.19.1 | MIT | Node.js type definitions for the declared minimum runtime |
| @modelcontextprotocol/sdk | 1.32.1 | MIT | Independent MCP client used only in interoperability tests |

## Transitive development dependencies

Review date: 2026-10-09.

| Licence | Packages |
|---|---|
| MIT | 118 |
| ISC | 8 |
| Apache-2.0 | 4 |
| BSD-3-Clause | 3 |
| BSD-2-Clause | 1 |
| MPL-2.0 | 2: `lightningcss` and its platform binary, pulled in by Vite through Vitest |

MPL-2.0 is a file-level copyleft licence. It is used here only as an
unmodified build and test tool and is not redistributed with Revscope.

`fsevents` (optional, macOS only) is the only dependency with an install
script.

Re-run the review whenever the lockfile changes.
