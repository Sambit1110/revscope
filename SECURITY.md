# Security policy

## Reporting a vulnerability

Please report vulnerabilities **privately**, not in public issues, pull
requests or discussions.

Use GitHub's private vulnerability reporting for this repository: on the
repository page, open **Security**, then **Report a vulnerability**.

> **Not yet available.** The repository is not published yet. Private
> vulnerability reporting will be enabled when it is, and this note removed.
> Until then there is no public reporting channel.

Please include:

- the Revscope version or commit, your OS, Node.js, Ghidra and JDK versions;
- what an attacker controls (the analyzed file, MCP requests, environment);
- steps to reproduce, using an input you are allowed to share (ideally one
  you built for the purpose), and the impact you observed.

This is a volunteer project with no guaranteed response time. You should
receive an acknowledgement, and a fix or an explanation, as soon as
practical. Please allow time for a fix before disclosing publicly; you will
be credited unless you prefer otherwise.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x (latest) | Yes |
| Older | No |

## Threat model

Revscope analyzes files that may be hostile, and its results may be read by
an AI model through MCP.

**What Revscope defends against:**

- **Execution of the input.** Revscope never executes the analyzed file; it
  copies it into a private workspace (`0700`) and passes it to Ghidra's
  headless analyzer, which reads it.
- **Leaking host information through results.** Public errors never contain
  host paths, environment values, stack traces or Ghidra's logs. Opt-in local
  diagnostics (`REVSCOPE_GHIDRA_DIAGNOSTICS=1`) keep them on disk and print
  only their location.
- **Environment leakage into Ghidra.** The child process gets an allowlisted
  environment. Ghidra's home, settings, cache and temporary files are
  redirected into the run's workspace.
- **Runaway analysis.** Every run has one total deadline, bounded function
  counts and pseudocode size, and a bounded export; the process group is
  terminated on timeout or cancellation, and the workspace is removed. A
  cleanup failure is reported, never hidden.
- **Malformed engine output.** Ghidra's export is treated as untrusted: it is
  size-limited and strictly validated, and a mismatch is an error, not a
  partial result.
- **Symlink and special-file tricks on the input path.** Inputs must be
  regular files; symbolic links, directories and devices are refused.

**What Revscope does not defend against:**

- **Vulnerabilities in Ghidra or the JVM.** A crafted file that exploits
  Ghidra runs with your user's permissions and network access. Ghidra is
  **not** a sandbox and Revscope does not contain it. Analyze untrusted
  samples in a disposable virtual machine without credentials or sensitive
  data.
- **Prompt injection through results.** Function names, strings and
  pseudocode come from the binary and may contain text aimed at a model.
  Results are labelled as untrusted, but MCP clients and models must treat
  them as data, never as instructions.
- **Unauthorized analysis.** `authorized: true` (`--authorized`) is an
  acknowledgement Revscope records; it cannot verify that you may analyze a
  file.
- **Tampered evidence files.** Evidence identifiers are unkeyed content
  digests: they detect accidental corruption, not deliberate edits, and do
  not prove who produced a record.
- **A compromised local environment**, such as a modified Ghidra
  installation, JDK or Node.js, or hostile values in `REVSCOPE_*` variables.

**Scope notes.** Process-tree termination relies on POSIX process groups and
has been exercised only on macOS. Windows is unsupported. See
[docs/limitations.md](docs/limitations.md) for the full list.
