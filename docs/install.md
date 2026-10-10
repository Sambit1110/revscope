# Installation and verification

These steps install Revscope from a source checkout and verify it, step by
step. Each step says what result to expect. Commands that need a path you
choose use `/absolute/path/...`.

Verified end to end only on the reference environment: macOS arm64, Ghidra
12.1.4 with locally built natives, Temurin JDK 25.0.2, Node.js 26.9.0, npm
11. Parts are also verified in CI on Linux x64 and macOS arm64; everything
else is unverified (see [support.md](support.md)).

## 1. Prerequisites

- Node.js 24.11 or newer (`npm run check` passes on 24.11.x and 26.x in CI)
  and npm 11. The real-engine steps below have been verified on Node.js 26
  only.
- git.
- For `analyze-binary`: a 64-bit JDK 21 or newer, and Ghidra 12.1.4
  (step 3).
- For the macOS-only real-engine tests and the benchmark: the Xcode
  command-line tools (`clang`, `strip`, `nm`).

## 2. Get, build and check Revscope

```bash
git clone https://github.com/Sambit1110/revscope.git revscope
cd revscope
npm ci
npm run check
```

Expected: type checking and linting succeed and every test passes. No
network access or Ghidra is needed after `npm ci`.

Try it without Ghidra:

```bash
node dist/bin/revscope.js version
node dist/bin/revscope.js inspect-artifact fixtures/artifacts/notes.txt
```

Expected: `0.1.0`, then one JSON document with `"ok": true` and two records
(`artifact_identity`, `artifact_format`).

Optionally, `npm link` provides a `revscope` command for your user. Revscope
is not published to npm.

## 3. Ghidra and a JDK

Revscope never downloads or installs Ghidra or Java. These steps are yours to
run.

1. **JDK.** Install a 64-bit JDK (not only a runtime), version 21 or newer.
   Ghidra 12.1.4 declares `application.java.min=21` and no maximum, and its
   documentation names Java 21. The reference environment uses Temurin 25.0.2;
   if Ghidra misbehaves on a newer JDK, use 21. To choose a JDK explicitly,
   set `REVSCOPE_JAVA_HOME` to its home directory.
2. **Download** `ghidra_12.1.4_PUBLIC_20260921.zip` from the
   [official release](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.4_build)
   and check it. The SHA-256 published on that release is
   `ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db`:

   ```bash
   echo "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db  ghidra_12.1.4_PUBLIC_20260921.zip" | shasum -a 256 -c
   ```

   Expected: `ghidra_12.1.4_PUBLIC_20260921.zip: OK`. Do not continue
   otherwise.
3. **macOS: clear quarantine** before extracting, as Ghidra's guide
   recommends:

   ```bash
   xattr -d com.apple.quarantine ghidra_12.1.4_PUBLIC_20260921.zip
   ```

4. **Extract** it to a new directory, for example
   `~/Applications/ghidra_12.1.4_PUBLIC`. Ghidra has no installer; do not
   extract over an existing installation.
5. **macOS arm64 only: build Ghidra's native decompiler.** The release ships
   natives only for Windows and Linux x86-64. Without them, analysis still
   runs but every decompilation is reported as unavailable. Building needs
   the Xcode command-line tools and Gradle 8.5 or newer (or Gradle's wrapper,
   which downloads Gradle):

   ```bash
   cd ~/Applications/ghidra_12.1.4_PUBLIC/support/gradle && gradle buildNatives
   ```

6. **Point Revscope at it:**

   ```bash
   export REVSCOPE_GHIDRA_DIR="$HOME/Applications/ghidra_12.1.4_PUBLIC"
   ```

## 4. Verify the real engine

```bash
npm run test:ghidra
```

Expected on macOS: 25 tests pass. Elsewhere the 9 macOS-only tests (Mach-O
and compiled ELF objects) are reported as skipped. Without
`REVSCOPE_GHIDRA_DIR` every test fails, by design.

Then analyze the generated test program:

```bash
node tests/fixtures/binaries/make-elf.mjs /tmp/revscope-fixture.elf
node dist/bin/revscope.js analyze-binary /tmp/revscope-fixture.elf --authorized
```

Expected: `"ok": true`; functions `answer` (the program entry, `0x400080`)
and `twice`; pseudocode `return 0x2a;` and `return param_1 * 2;`;
`"workspace": "removed"`. The file is only read, never executed.

## 5. Optional: the benchmark (macOS)

```bash
npm run benchmark
```

Expected on the reference environment: 26 of 26 cases pass. It writes
`results.json` and `report.md` to a new directory under your temporary
directory and prints its location. See
[benchmarks/README.md](../benchmarks/README.md).

## 6. Optional: an MCP client

Register `node /absolute/path/to/revscope/dist/bin/revscope.js mcp` with
`REVSCOPE_GHIDRA_DIR` in its environment; the
[README](../README.md#configuring-an-mcp-client) has examples. Expected: the
client lists five tools (`inspect_artifact`, `report_evidence`,
`compare_evidence`, `stub_analysis`, `analyze_binary`).

## Uninstall

Remove the checkout, run `npm unlink -g revscope` if you linked it, and
delete the Ghidra directory if you no longer need it. Revscope's own
temporary workspaces are removed after every run. Diagnostics kept with
`REVSCOPE_GHIDRA_DIAGNOSTICS=1` stay under `<tmpdir>/revscope-diagnostics/`
until you remove them.
