# Support matrix

A runtime, platform or Ghidra setup is **verified** only when the relevant
check has actually run there and passed. Anything declared or configured but
not yet run is **unverified**. CI workflows exist in `.github/workflows/`,
but no CI job has run yet (nothing has been pushed to the GitHub repository
yet); this page will be updated from their results.

## Runtime and platform

| Runtime / platform | Status | Evidence |
|---|---|---|
| Node.js 26.9.0, npm 11.19.1, macOS 27.0.1 arm64 | **Verified** locally | `npm run check` passes (413 tests), 2026-10-10 |
| Node.js 24.11+ (declared minimum in `engines`) | Unverified | Not available on the development host. The CI workflow tests 24.11.x on Linux and macOS |
| Node.js 26.x on Linux x64 (`ubuntu-24.04`) | Unverified | CI workflow prepared, not yet run |
| Node.js 26.x on macOS arm64 runners (`macos-26`) | Unverified on CI | Same OS family as the reference machine, but not yet run on CI |
| Windows | Unsupported for now | Never run. The tests assume POSIX in places, and the Windows process-tree and `O_NOFOLLOW` fallbacks have never executed |

## Analysis engine

| Setup | Status | Evidence |
|---|---|---|
| Fake `analyzeHeadless` (part of `npm run check`) | **Verified** | Process lifecycle, export validation, labels, errors, cleanup, CLI/MCP equivalence |
| Ghidra 12.1.4, macOS 27.0.1 arm64, locally built natives, Temurin JDK 25.0.2, Node.js 26.9.0 | **Verified** | `npm run test:ghidra` 25/25 and `npm run benchmark` 26/26, 2026-10-10 |
| Ghidra 12.1.4 on Linux x64 with Temurin JDK 21 | Unverified | Optional `ghidra.yml` workflow prepared (manual or weekly), not yet run. The 9 macOS-only real-engine tests are skipped there |
| Ghidra 12.1.4 on macOS arm64 without built natives | Unverified | Expected: analysis runs, every decompilation reported unavailable |
| Other Ghidra versions | Unverified | The export script is compiled and run against 12.1.4 only |
| Ghidra on Windows | Unsupported for now | Never run |

## Inputs

Verified against real Ghidra only on small programs built for the tests and
the benchmark, never on real-world software:

- ELF x86-64 executables: hand-built and stripped;
- ELF x86-64 and AArch64 relocatable objects (`clang -c`);
- Mach-O arm64 executables at `-O0`, `-O1`, `-O2` and `-Os`, stripped and
  unstripped;
- refusal (not analysis) of text, random bytes, empty files, truncated ELF
  and Mach-O files, directories, symbolic links and missing paths, each with
  the expected structured error.

Unverified: PE files, linked ELF executables from a real toolchain, fat
Mach-O files, dynamic libraries, firmware, large binaries.

## MCP clients

The server is tested automatically with the official MCP SDK client
(`@modelcontextprotocol/sdk`, in `npm run check`). The launch command in the
README was also checked once, by hand, with a throwaway stdio script that is
not in the repository (2026-10-10, reference environment); that check is a
one-off, not a reproducible test. Specific client applications have not been
tested.
