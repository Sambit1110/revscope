# ADR-0002: One error envelope for every interface

**Status:** accepted for the foundation milestone.

## Context

When the CLI, the MCP server and the application layer each shape their own
errors, clients need several parsers. Validation failures produced by an
interface framework then lose the structured fields: code, category,
retryability and remediation.

## Decision

- There is one catalog (`ERROR_CATALOG`). It maps every stable code to a
  category, a retryability and a remediation.
- There is one envelope: `{code, category, message, retryable, remediation:
  {action}, details}`, wrapped as `{ok:false, error}`.
- There is one execution path (`executeTool`). It owns input validation, so
  adapters cannot produce a different validation error shape.
- On MCP:
  - Tool failures are tool results with `isError: true` and the envelope as
    `structuredContent` and as text.
  - Protocol-level failures (unknown tool, malformed request) are JSON-RPC
    errors that carry the same envelope in `data`.
- Messages and details never include stack traces, exception messages or
  environment values. Unexpected failures report only a correlation ID.

## Consequences

- A conformance test requires byte-identical envelopes from the application,
  CLI and MCP for each failure class.
- CLI exit codes are derived from the category, so they cannot disagree with
  the envelope.
