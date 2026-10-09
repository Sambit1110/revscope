# Support matrix

A platform or runtime is listed as **verified** only when the full check
(`npm ci && npm run check`) has actually run there. Declared support without
a verification run is labelled **unverified**.

| Runtime / platform | Status | Evidence |
|---|---|---|
| Node.js 26.9.0, macOS 27.0.1 arm64, npm 11.19.1 | Verified | Local run of the full check during the foundation milestone |
| Node.js 24.11+ (declared minimum in `engines`) | Unverified | Not available on the development host; needs a CI lane |
| Linux x64 / arm64 | Unverified | No run yet |
| Windows | Unverified | No run yet. The tests assume POSIX paths in places; expect work |

| Provider | Status |
|---|---|
| Stub provider (fixtures) | Verified by the deterministic test suite |
| Real binary-analysis providers | Not implemented |
