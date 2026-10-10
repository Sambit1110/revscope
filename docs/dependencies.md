# Dependencies and licences

Revscope is licensed under Apache-2.0 (see [LICENSE](../LICENSE)). All npm
versions are pinned exactly in `package.json` and locked in
`package-lock.json`. `npm run licenses` checks the licence every locked
package declares (`scripts/check-licenses.ts`). It is configured to run in
CI (`.github/workflows/ci.yml`), but no CI job has run yet. It reads
declared metadata only and is not a legal review.

## Runtime

| Package | Version | Licence | Purpose |
|---|---|---|---|
| zod | 4.6.5 | MIT | Runtime validation and JSON Schema generation |

`zod` is the only production dependency; the production tree contains no
transitive packages. Revscope does not bundle or vendor it: npm installs it
from the registry with its own licence file.

## External requirements (not npm packages)

Only `analyze_binary` needs these; everything else works without them. They
are found through configuration and are never bundled, downloaded or
redistributed by Revscope.

| Requirement | Licence | Purpose | Configured by |
|---|---|---|---|
| Ghidra 12.1.4 | Apache-2.0 | Headless analysis and decompilation | `REVSCOPE_GHIDRA_DIR` |
| JDK 21 or newer, 64-bit | Per vendor (for example Eclipse Temurin: GPLv2 with the Classpath Exception) | Runs Ghidra and compiles the export script | `REVSCOPE_JAVA_HOME`, or Ghidra's own JDK discovery |

`ghidra-scripts/RevscopeExport.java` is Revscope's own code (Apache-2.0). It
runs inside Ghidra and uses Ghidra's public API; it contains no Ghidra source.

## Development only

| Package | Version | Licence | Purpose |
|---|---|---|---|
| typescript | 7.0.2 | Apache-2.0 | Type checking and build |
| vitest | 5.0.3 | MIT | Test runner |
| oxlint | 1.87.0 | MIT | Linting |
| @types/node | 24.19.1 | MIT | Node.js type definitions for the declared minimum runtime |
| @modelcontextprotocol/sdk | 1.32.1 | MIT | Independent MCP client used only in interoperability tests |

## Transitive packages in the lockfile

Review date: 2026-10-10 (`npm run licenses`). Counts are of every package
entry in `package-lock.json`, including optional per-platform binaries that
are installed only on matching hosts.

| Licence | Packages |
|---|---|
| MIT | 151 |
| Apache-2.0 | 23 |
| ISC | 8 |
| BSD-3-Clause | 3 |
| BSD-2-Clause | 1 |
| MPL-2.0 | 12: `lightningcss` and its per-platform binaries, pulled in by Vite through Vitest |

MPL-2.0 is a file-level copyleft licence. `lightningcss` is used only as an
unmodified test-time tool and is never distributed with Revscope; the licence
check allows MPL-2.0 for these development-only packages by name and rejects
it anywhere else.

`fsevents` (optional, macOS only) is the only dependency with an install
script.

## Obligations when distributing Revscope

- Keep `LICENSE` with any copy. The npm package always includes it.
- No `NOTICE` file is needed today: Revscope distributes no third-party code
  that carries one. Add one if that changes, for example when vendoring an
  Apache-2.0 component that ships a NOTICE.
- No REA code is included. A line-by-line comparison against REA 6.1.0's
  sources, tests, bridge and documentation on 2026-10-10 found only isolated
  stock idioms (at most four consecutive lines, a standard `Result` type).

Re-run `npm run licenses` and update this page whenever the lockfile changes.
