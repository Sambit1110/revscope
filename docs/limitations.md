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
- **Evidence identifiers prove integrity, not authenticity.** They are
  unkeyed digests: anyone can edit a record and recompute its identifier.
  Records loaded from files are unauthenticated.

## Interfaces

- **MCP coverage is minimal.** The server implements `initialize`, `ping`,
  `tools/list` and `tools/call` over stdio. It has no resources, prompts,
  progress notifications, cancellation, HTTP transport, or authentication.
- **CLI output is always JSON.** There is no human-oriented formatting.

## Inputs and resources

- **JSON inputs** (bundles, fixtures, steps files) are read into memory and
  are limited to 16 MiB.
- **Symbolic links are not followed** by `inspect-artifact`; the caller must
  select the target file directly.
- **Comparison pairs records** by subject, operation and canonical
  parameters:
  - Analysis-state subjects are compared by artifact digest, ignoring the
    session and revision.
  - Several records answering the same question are reported as `ambiguous`
    instead of being paired.

## Verification

- **Platform coverage:** only Node.js 26.9.0 on macOS arm64 has been
  exercised. See [support.md](support.md).
- **Static scans:** the module-boundary test scans import statements with a
  pattern rather than a full parser. It guards its own pattern against
  becoming vacuous.
- **No continuous integration** is configured yet.
