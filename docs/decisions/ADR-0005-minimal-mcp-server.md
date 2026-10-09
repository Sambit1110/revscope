# ADR-0005: Hand-written minimal MCP server; SDK used only as a test client

**Status:** accepted for the foundation milestone.

## Context

MCP server frameworks validate tool arguments themselves. In the requirements
study, those validation failures reached clients as plain text, outside the
structured error contract. The foundation needs only `initialize`, `ping`,
`tools/list` and `tools/call` over stdio.

## Decision

- Implement those methods directly in `src/interfaces/mcp.ts`.
- Delegate all tool behaviour to `executeTool`.
- Advertise draft-07 JSON Schemas generated from the same zod schemas.
- Use the official MCP SDK client only as a dev dependency, to check
  interoperability with the built executable.

## Consequences

- There is one runtime dependency (`zod`).
- Revscope owns its protocol coverage. Not implemented: resources, prompts,
  progress notifications, cancellation, and the streamable HTTP transport.
- Compatibility claims are limited to what the SDK test exercises.
