# Changelog

All notable changes to Revscope are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). Before 1.0.0, minor versions may
change the CLI, MCP tools, evidence schema and export format.

## [0.1.0] - Unreleased

First public preview.

### Added

- **Evidence contract** (`revscope.evidence/3`): every record states its
  result kind, with confidence (`observed`, `derived`, `reported`,
  `inferred`) and authority derived centrally from the kind, plus unknowns
  and limitations; identifiers are content digests.
- **One error envelope** for the CLI and MCP, with a fixed catalog of codes,
  categories, retryability, remediation and exit codes.
- **CLI** (`revscope`): `inspect-artifact`, `report-evidence`,
  `compare-evidence`, `stub-analysis`, `analyze-binary`, `tools`, `mcp`,
  `version`. Each tool command prints one JSON document.
- **MCP server** over stdio (protocol revisions 2025-06-18, 2025-03-26,
  2024-11-05) with the same tools and results as the CLI, and request
  cancellation.
- **Ghidra provider** (`analyze-binary` / `analyze_binary`), using Ghidra
  headless and Revscope's own export script (`revscope.ghidra-export/3`):
  - program metadata, the loaded address range with its placement basis, and
    the header-declared program entry (ELF `e_entry`, Mach-O `LC_MAIN`);
  - functions with Ghidra's name, aliases, and a display name with its basis
    and confidence (generated and loader-made names are never presented as
    coming from the binary);
  - Ghidra's stored signature beside the decompiler's inferred one;
  - pseudocode with structured decompiler diagnostics and a fidelity of
    `complete`, `uncertain` or none;
  - required authorization acknowledgement, one total deadline, function
    and size limits, cancellation, process-group termination, workspace
    cleanup, and errors free of host paths and logs;
  - opt-in local diagnostics for failed runs (`REVSCOPE_GHIDRA_DIAGNOSTICS`).
- **Real-engine tests** (`npm run test:ghidra`) and a **real-binary
  benchmark** (`npm run benchmark`) with predefined ground truth, plus an
  optional comparison script for REA's Ghidra provider.
- Apache-2.0 licence, security policy, contribution guide (DCO), installation
  guide, CI workflows (not yet run), and a dependency licence check
  (`npm run licenses`).

### Verified

On macOS 27.0.1 arm64, Ghidra 12.1.4 (locally built natives), Temurin JDK
25.0.2, Node.js 26.9.0: `npm run check`, `npm run test:ghidra` and
`npm run benchmark` pass. Node.js 24, Linux, Windows, other Ghidra versions
and real-world binaries are not yet verified. See
[docs/support.md](docs/support.md) and
[docs/limitations.md](docs/limitations.md).
