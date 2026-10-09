# ADR-0007: Ghidra headless as the first real analysis engine

**Status:** accepted for Phase 4. The integration is complete and tested
against a fake engine. **It has not yet been verified against a real Ghidra
installation**; see "Verification" below.

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
  - Ghidra's home, settings, script cache and temporary files are redirected
    into the workspace (`JAVA_TOOL_OPTIONS`, `HOME`, `TMPDIR`).
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
  patterns. The text is never reported, so diagnosis needs the patterns to
  match. The patterns follow Ghidra's documented messages and are unverified.
- Functions outside the default address space (overlays, separate code
  spaces) are not exported.

## Verification

Checked against Ghidra 12.1.4's published sources and documentation
(2026-10-10). None of it has been run:

- `application.java.min=21`, no maximum;
- the `analyzeHeadless` options used;
- post-scripts still run after `-analysisTimeoutPerFile` fires;
- `HeadlessScript.analysisTimeoutOccurred()`,
  `DecompileResults.decompileCompleted/isTimedOut/getDecompiledFunction`,
  and `TaskMonitor.isCancelled()` exist.

`npm run test:ghidra` is the verification step. Until it passes against an
installed Ghidra, real-engine compatibility, determinism and the failure
classification patterns are unverified.
