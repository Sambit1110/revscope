# Limitations

## Scope

- **The Ghidra provider is verified on one environment and small test
  programs only.** `npm run test:ghidra` (25/25) and `npm run benchmark`
  (26/26) pass on macOS 27.0.1 arm64, Ghidra 12.1.4 with locally built
  natives, Temurin JDK 25.0.2 and Node.js 26.9.0, analyzing generated and
  locally compiled ELF and Mach-O test programs (see [support.md](support.md)).
  Still unverified:
  - Node.js 24, Linux and Windows, and other Ghidra versions (CI workflows
    are prepared but have not run);
  - real-world binaries (size, timing, determinism);
  - the `java_runtime`, `export_script_failed` and generic `import_failed`
    classification patterns.
- **Ghidra's default cache directory is left alone.** Revscope redirects
  Ghidra's packed-database cache into each run's private workspace, which is
  removed afterwards. Ghidra used on its own (outside Revscope) keeps that
  cache in `/var/tmp/<user>-ghidra`; Revscope never creates, reads or deletes
  that directory, so remove it yourself if you no longer need it.
- **Ghidra is not a sandbox.** It parses the untrusted file with the user's
  permissions and network access. Revscope isolates its files, environment
  and processes and bounds its time and output, but does not contain it.
  Analyze hostile samples in a virtual machine.
- **Authorization is an acknowledgement.** `analyze_binary` requires
  `authorized: true` (`--authorized`). Revscope records it and cannot verify
  that the caller may analyze the file.
- **Ghidra coverage is partial:**
  - The program entry is read only from ELF `e_entry` and Mach-O `LC_MAIN`.
    Other formats, `LC_UNIXTHREAD` and fat Mach-O files report it as
    unavailable.
  - Only Ghidra's loader label `entry` is recognised, and only at the
    header-declared program entry: it is checked against the names the
    file's own symbol tables define there (`program_entry.file_symbols`).
    Other names Ghidra's loaders create are still reported with Ghidra's
    `imported` source.
  - `min_address`/`max_address` are the hull of loaded memory in the default
    address space; gaps between loaded blocks are not reported. For
    relocatable objects (`address_placement: relocatable-object`) the
    addresses are Ghidra's placement, not the file's.
  - Every decompiler warning counts as material uncertainty; Revscope does
    not rank warning text. `fidelity: complete` means no detectable
    uncertainty, not a faithful reconstruction.
  - Signature comparison is textual after formatting normalization. Two
    signatures that mean the same but are written differently are reported
    as differing.
  - Only functions in the default address space are exported.
  - At most 1 000 functions.
  - Pseudocode is truncated at 64 Ki characters per function.
  - Failures without an export are classified from Ghidra's output by fixed
    patterns; an unrecognised message becomes a generic `provider_failure`.
- **macOS arm64 needs Ghidra's native decompiler built locally.** Ghidra
  12.1.4 ships no prebuilt natives for macOS. Without them, analysis runs
  but every decompilation is reported unavailable.
- **One JVM per call.** Each analysis pays Java start-up and import time.
  Some MCP clients cut off tool calls after about 60 s; the default 45 s
  timeout is set below that, and larger binaries may need more.
- **The stub provider remains.** `stub_analysis` still serves fixture data,
  and its "decompile" output is fixture text.
- **Format detection is a suggestion.** `artifact_format` looks only at the
  leading magic bytes and is labelled `inferred`. It does not parse or
  validate the file. Some signatures are ambiguous: `cafebabe` is reported as
  "Mach-O universal or Java class".
- **Only `analyze_binary` launches an external program** (Ghidra), through the
  environment policy and `runChild`.
- **Process-tree termination is POSIX-only.** It relies on process groups:
  - A descendant that leaves the group (for example with `setsid`) is not
    terminated. It is reported as a cleanup failure only while it holds the
    output pipes.
  - On Windows only the direct child is signalled; this is unverified.
  - Process-group behaviour has been exercised only on macOS.
- **Sessions do not persist.** Each `stub-analysis` invocation and each MCP
  `tools/call` uses a fresh in-memory session. Session state does not carry
  over between MCP calls.
- **Session consistency depends on the provider's state token.** A provider
  that does not change its token whenever its state changes defeats
  detection. The session also assumes it is the only writer of the provider's
  state; an outside change is noticed on the next provider round trip, not on
  a cache hit. Recovery refuses an observation that returns a token the
  session knows was replaced. A provider that reports a change it did not
  make therefore keeps the session uncertain until its token changes.
- **Evidence identifiers are consistency checks only.** They are unkeyed
  digests: they catch accidental corruption, but anyone can edit a record and
  recompute its identifier. They prove neither that a record is unaltered nor
  who produced it. Records loaded from files are unauthenticated.

## Interfaces

- **MCP coverage is minimal.** The server implements `initialize`, `ping`,
  `tools/list`, `tools/call` and `notifications/cancelled` over stdio. It has
  no resources, prompts, progress notifications, HTTP transport, or
  authentication.
- **CLI output is always JSON.** There is no human-oriented formatting.

## Inputs and resources

- **JSON inputs** (bundles, fixtures, steps files) are read into memory and
  are limited to 16 MiB.
- **JSON nesting is limited to 64 levels** wherever JSON enters: files, MCP
  tool arguments and CLI `--steps`. A deeper JSON file is refused with
  `resource_limit`; a deeper value inside tool input is refused as
  `invalid_input` by the tool's schema.
- **Object keys named `__proto__` are refused**, not silently dropped:
  JavaScript cannot hold such a key as ordinary data through validation.
- **MCP lines are limited to 4 MiB.** A longer line is discarded without
  being buffered and answered with a `resource_limit` error.
- **File opening.** Artifacts and JSON inputs are opened first and checked
  afterwards, on the opened descriptor, so a file swapped for a link, FIFO or
  device between check and use is still refused. Opening never blocks on a
  FIFO.
  - **Symbolic links** as the final path component are refused
    (`O_NOFOLLOW`); the caller must select the target file directly.
    **Symbolic links in parent directories are followed.**
  - On Windows, where `O_NOFOLLOW` does not exist, the path is checked with
    `lstat` and the opened file must have the same device and inode. This
    fallback has not been run on Windows.
  - This defends against swaps of the final component only. It is not a
    sandbox: Revscope reads any regular file the current user can read.
- **JSON inputs must be valid UTF-8.** Invalid bytes are refused instead of
  being replaced.
- **Comparison pairs records** by subject, operation and canonical
  parameters:
  - Analysis-state subjects are compared by artifact digest, ignoring the
    session and revision.
  - Several different records answering the same question are reported as
    `ambiguous` instead of being paired, unless both sides hold exactly the
    same records. Repeated records (same identifier) count once.
- **Artifact evidence is identified by content only.** The subject is the
  SHA-256 and size; the file name is reported in the tool's `data`, not in
  the evidence, so renaming or moving a file does not change its evidence.

## Verification

- **Platform coverage:** only Node.js 26.9.0 on macOS arm64 has been
  exercised. See [support.md](support.md).
- **Static scans:** the module-boundary test finds dependencies with patterns
  rather than a full parser. It covers static, side-effect and dynamic
  imports, re-exports and `require`, and flags imports it cannot read. Each
  form is pinned by a guard test, but an unusual form a pattern does not
  anticipate would go unseen.
- **Continuous integration is prepared but has never run.** The workflows
  in `.github/workflows/` run only once the repository is on GitHub. Until
  their results are recorded in [support.md](support.md), nothing they cover
  counts as verified.
- **Benchmark scope.** `npm run benchmark` covers:
  - small programs built locally, never real-world software;
  - Mach-O arm64 executables;
  - ELF relocatable objects only (this toolchain has no ELF linker);
  - two hand-built ELF executables.

  Three defects it found during development are fixed (see ADR-0007): the
  loader's `entry` label reported as an imported name on stripped binaries,
  an ELF address range whose maximum read below its minimum, and truncated
  ELF files reported as a retryable failure. It also measures this
  limitation, which remains:
  - decompiler signatures often differ from the source. Unused parameters
    vanish, and optimized code loses parameters and widens types (for
    example `ulong` for `unsigned`). The program entry decompiles as
    `entry` with the loader's signature.
- **The benchmark needs macOS** with the Xcode command-line tools, and its
  Mach-O `-O0` inputs are not byte-reproducible: the linker writes a random
  `LC_UUID` (and the ad hoc code signature covers it). Their code and
  symbols, and Revscope's analysis of them, are identical between builds.
