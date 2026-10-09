# ADR-0004: Child processes receive an allowlisted environment

**Status:** accepted for the foundation milestone.

## Context

Analysis tools often launch helpers or the target program itself. Passing the
host environment through by default exposes credentials and tokens to code
that may be untrusted.

## Decision

- The child environment is built only from:
  - a baseline allowlist (`PATH`, `LANG`, `LC_ALL`, `LC_CTYPE`, `TZ`);
  - an explicit passthrough list of names;
  - explicitly set values.
- A name cannot be both inherited and set. Names and values are validated.
- The manifest records names only, never values, whether inherited or set.
- Children are launched without a shell, by absolute path, with an argument
  vector, a deadline and bounded output capture.

## Consequences

- Each future provider must declare the host variables it needs, for example
  a Java home directory.
- Tests prove that a host-only canary does not reach the child unless it is
  allowlisted. The test host environment is synthetic, so no real variable is
  ever printed.
