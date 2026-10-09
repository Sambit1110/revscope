# Limitations of the foundation milestone

## Scope

- **No real analysis provider.** The only provider is a deterministic stub
  loaded from fixture JSON. Its "decompile" output is fixture text. Revscope
  cannot yet disassemble, decompile or otherwise analyze real binaries.
- **Format detection is a suggestion.** `artifact_format` looks only at the
  leading magic bytes and is labelled `inferred`. It does not parse or
  validate the file. Some signatures are ambiguous: `cafebabe` is reported as
  "Mach-O universal or Java class".
- **No tool launches external programs yet.** The environment policy and
  `runChild` are implemented and tested, but no tool uses them.
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
  `tools/list` and `tools/call` over stdio. It has no resources, prompts,
  progress notifications, cancellation, HTTP transport, or authentication.
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
- **No continuous integration** is configured yet.
