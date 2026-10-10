# Support matrix

A runtime, platform or Ghidra setup is **verified** only when the relevant
check has actually run there and passed. Anything declared or configured but
not yet run is **unverified**. GitHub Actions results below are from the
first runs of `.github/workflows/ci.yml` and `.github/workflows/ghidra.yml`
on commit `b7f4837`; later commits must pass again.

## Runtime and platform

| Runtime / platform | Status | Evidence |
|---|---|---|
| Node.js 26.9.0, npm 11.19.1, macOS 27.0.1 arm64 | **Verified** locally | `npm run check` passes (413 tests), 2026-10-10 |
| Node.js 24.11.x and 26.x on Linux x64 (`ubuntu-24.04`) | **Verified** on CI | `npm ci` and `npm run check` pass (`ci.yml`, commit `b7f4837`) |
| Node.js 24.11.x and 26.x on macOS arm64 (`macos-26`) | **Verified** on CI | `npm ci` and `npm run check` pass (`ci.yml`, commit `b7f4837`) |
| Node.js 24.11.x with a real Ghidra | Unverified | Real-engine tests and the benchmark have run on Node.js 26 only |
| Production dependency audit and licence check | **Passing** on CI | `npm audit --omit=dev` and `npm run licenses` (`ci.yml`, commit `b7f4837`) |
| Windows | Unsupported for now | Never run. The tests assume POSIX in places, and the Windows process-tree and `O_NOFOLLOW` fallbacks have never executed |

## Analysis engine

| Setup | Status | Evidence |
|---|---|---|
| Fake `analyzeHeadless` (part of `npm run check`) | **Verified** | Process lifecycle, export validation, labels, errors, cleanup, CLI/MCP equivalence |
| Ghidra 12.1.4, macOS 27.0.1 arm64, locally built natives, Temurin JDK 25.0.2, Node.js 26.9.0 | **Verified** | `npm run test:ghidra` 25/25 and `npm run benchmark` 26/26, 2026-10-10 |
| Ghidra 12.1.4 (prebuilt Linux natives), Linux x64 (`ubuntu-24.04`), Temurin JDK 21, Node.js 26.x | **Verified** on CI, partially | `npm run test:ghidra`: 16 passed, 9 skipped (`ghidra.yml`, commit `b7f4837`). The skipped tests are the macOS-only Mach-O and compiled-ELF-object tests. The benchmark has not run on Linux |
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
