# ADR-0007: Ghidra headless as the first real analysis engine

**Status:** accepted for Phase 4. Verified against a real Ghidra in Phase 4.1
on one environment only (Ghidra 12.1.4 with locally built macOS arm64 natives, Temurin JDK 25.0.2, Node.js 26.9.0, macOS 27.0.1 arm64); see "Verification" below.

## Context

Until Phase 4, Revscope's only provider was a fixture-backed stub. The first
real engine had to:

- produce metadata, functions and decompiled pseudocode from a native binary;
- never execute the input;
- label its output honestly;
- report timeouts, cancellation and partial output through the common error
  contract;
- clean up after itself;
- behave identically through the CLI and MCP.

Ghidra is mature, open source (Apache-2.0), and has a supported headless
interface (`support/analyzeHeadless`) with post-analysis scripts.

## Decision

- **One engine run per request.** `analyze_binary` asks a
  `BinaryAnalysisEngine` port for one run. The Ghidra engine starts a fresh
  JVM per request. There is no long-lived project or server.
- **Revscope's own export script.** `ghidra-scripts/RevscopeExport.java`,
  written for Revscope, runs as a headless post-script. It writes
  `revscope.ghidra-export/1`: one JSON record per line, flushed as written,
  ending with a trailer. A missing trailer means the export is incomplete.
  Java was chosen over PyGhidra (needs Python packages) and Jython
  (deprecated).
- **The export is untrusted.** It comes from a large program that parsed an
  untrusted binary. Revscope validates it strictly: sizes, ordering,
  cross-references, and the limits it requested. A mismatch is a
  `provider_failure`, not a partial result.
- **Labels from declared capabilities.** The export is served by a read-only
  provider through the existing `AnalysisSession`. Every Ghidra result is
  `engine-interpretation` (`derived` / `analysis-engine`) and carries
  limitations saying it is Ghidra's interpretation, contains untrusted text,
  and (for pseudocode) is not source code. Only Revscope's own read of the
  copied bytes is `observed` / `original-artifact`.
- **Isolation, not sandboxing.**
  - The input is copied into a fresh 0700 workspace under a neutral name.
  - Ghidra's home, settings, cache, script cache and temporary files are
    redirected into the workspace (`JAVA_TOOL_OPTIONS` with `user.home`,
    `java.io.tmpdir` and Ghidra's own `application.settingsdir`,
    `application.cachedir` and `application.tempdir`; `HOME`, `TMPDIR`).
    Without `application.cachedir`, Ghidra puts its packed-database cache in
    `/var/tmp/<user>-ghidra`, outside the workspace; Phase 4.1 found and
    fixed this.
  - The environment is allowlisted.
  - Ghidra runs in its own process group with one hard deadline.
  - The workspace is removed after the process tree has settled.

  Ghidra still runs with the user's permissions and network access.
- **One deadline.** `timeout_ms` bounds the whole operation. The child's
  deadline plus a reserve for copying, parsing and removal fits inside it.
  The export script receives an absolute wall-clock deadline, so per-function
  decompilation limits cannot outlast the run.
- **Explicit authorization acknowledgement.** Every call must pass
  `authorized: true` (`--authorized` on the CLI). Revscope records the
  acknowledgement and cannot verify it.
- **Cancellation everywhere.**
  - The CLI cancels on SIGINT or SIGTERM.
  - The MCP server reads continuously, so `notifications/cancelled` reaches a
    running request.
  - Process shutdown cancels all running work.

## Consequences

- No new npm dependencies. Ghidra and a JDK are external requirements found
  through configuration (`REVSCOPE_GHIDRA_DIR`, optionally
  `REVSCOPE_JAVA_HOME`).
- Each call pays JVM start-up and import time; there is no persistent
  project yet.
- On macOS arm64, Ghidra 12.1.4 ships no prebuilt native decompiler; it must
  be built for the installation. Without it, the export reports the
  decompiler as unavailable.
- Failures without an export are classified from Ghidra's output by fixed
  patterns. The text is never reported to callers. For diagnosis,
  `REVSCOPE_GHIDRA_DIAGNOSTICS=1` keeps a failed run's workspace, logs and a
  run record locally (Phase 4.1).
- Functions outside the default address space (overlays, separate code
  spaces) are not exported.

## Verification

**Phase 4 (2026-10-10), from published sources only:**

- `application.java.min=21`, no maximum;
- the `analyzeHeadless` options used;
- post-scripts run after `-analysisTimeoutPerFile`;
- the `HeadlessScript`, `DecompileResults` and `TaskMonitor` methods used.

**Phase 4.1 (2026-10-10), real engine:** `npm run test:ghidra` passed 9/9,
twice, on Ghidra 12.1.4 with locally built macOS arm64 natives, Temurin JDK 25.0.2, Node.js 26.9.0, macOS 27.0.1 arm64.

The first real run failed. The export script called
`LanguageID.getIdString()`, which does not exist in 12.1.4 (the accessor is
`getIdAsString()`), so Ghidra skipped it and every analysis ended in
`export_script_failed`. The source check had missed that call. The suite
now compiles the script with `javac` against the installation's own jars
first.

Verified on that environment:

- the script compiles;
- import, analysis and export of the ELF fixture (names from the symbol
  table, pseudocode `return 0x2a;` and `return param_1 * 2;`);
- labels;
- identical evidence across two runs of the fixture;
- `unsupported_target` for a text file and for noise ("No load spec found");
- a real timeout and a real cancellation, with Ghidra stopped and the
  workspace removed;
- `java_home_invalid`;
- the cache staying out of `/var/tmp`;
- identical CLI and MCP output;
- JDK 25 running Ghidra 12.1.4.

**Phase 4.3 (2026-10-10), analysis fidelity:** `npm run test:ghidra` passed
19/19, twice, on the same environment. The new tests use the ELF fixture
and an ARM64 Mach-O compiled at test time from
`tests/fixtures/binaries/macho/program.c` (`clang -arch arm64 -O0`, never
run or committed).

Verified on that environment:

- the program entry from ELF `e_entry` and Mach-O `LC_MAIN`, apart from
  exported symbols;
- `_main` shown with `entry` as Ghidra's loader label;
- stored and decompiler signatures kept apart;
- the three decompiler warnings on the `_puts` stub captured structurally
  as material uncertainty, with the other functions complete;
- identical evidence across runs for both fixtures;
- identical CLI and MCP output.

The export schema was `revscope.ghidra-export/2`.

**Phase 4.4.1 (2026-10-10), benchmark-driven fixes:** the Phase 4.4 benchmark
found three defects. Export schema `revscope.ghidra-export/3` fixes them:

- `min_address`/`max_address` now bound the loaded memory in the default
  address space. Before, `Program.getMaxAddress()` could fall in a non-loaded
  section's space and read below the minimum on ELF.
- New `address_placement`.
- `program_entry.file_symbols`, so Ghidra's loader label `entry` on a
  stripped binary is no longer reported as an imported name.
- A truncated ELF ("No memory blocks were defined") is a non-retryable
  `unsupported_target` (`malformed_input`), no longer a retryable
  `provider_failure`.

The real-engine tests cover these on the same environment, using the
generated ELF, its stripped form, a truncated ELF, x86-64 and AArch64 ELF
objects, and the Mach-O fixture with and without its symbol table.

**Still unverified:**

- other Ghidra versions, Linux and Windows;
- binaries other than the two small fixtures (unoptimized, unstripped):
  real-world size, timing, and determinism beyond them;
- optimized or stripped binaries, Mach-O dylibs, fat binaries and
  `LC_UNIXTHREAD` entries, and PE files (program entry unavailable);
- the `java_runtime`, generic `import_failed` and `export_script_failed`
  classification patterns, beyond the one compile failure observed;
- Ghidra without built natives on macOS (decompiler unavailable).
