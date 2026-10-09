# Support matrix

A platform or runtime is listed as **verified** only when the full check
(`npm ci && npm run check`) has actually run there. Declared support without
a verification run is labelled **unverified**.

| Runtime / platform | Status | Evidence |
|---|---|---|
| Node.js 26.9.0, macOS 27.0.1 arm64, npm 11.19.1 | Verified | Local runs of the full check during the foundation milestone and the Phase 3.6 hardening pass (`npm run check`, 219 tests) |
| Node.js 24.11+ (declared minimum in `engines`) | Unverified | Not available on the development host; needs a CI lane |
| Linux x64 / arm64 | Unverified | No run yet |
| Windows | Unverified | No run yet. The tests assume POSIX paths in places; expect work. The process-tree and `O_NOFOLLOW` fallbacks for Windows have never run |

| Provider | Status |
|---|---|
| Stub provider (fixtures) | Verified by the deterministic test suite |
| Ghidra integration against a fake `analyzeHeadless` | Verified by `npm run check` (process lifecycle, export validation, labels, errors, cleanup, CLI/MCP equivalence) |
| Ghidra 12.1.4, macOS 27.0.1 arm64, locally built natives, Temurin JDK 25.0.2 | **Verified** by `npm run test:ghidra` (9/9, two runs, Phase 4.1) on a 592-byte ELF fixture |
| Ghidra 12.1.4 on macOS arm64 without built natives | Unverified (expected: decompiler reported unavailable) |
| Other Ghidra versions | Unverified |
| Ghidra on Linux / Windows | Unverified |
