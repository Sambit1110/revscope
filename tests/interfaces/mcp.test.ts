import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";

import { TOOLS } from "../../src/application/tools/registry.js";
import { toolOutputSchema } from "../../src/application/tools/types.js";
import { createMcpHandler, listTools, serveMcp } from "../../src/interfaces/mcp.js";
import { fixturePath, testContext } from "../support/context.js";

const handler = () => createMcpHandler(testContext().context);

describe("MCP protocol handling", () => {
  it("negotiates a supported protocol version and falls back to the newest", async () => {
    const handle = handler();
    const known = await handle({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26" } });
    expect(known?.result).toMatchObject({ protocolVersion: "2025-03-26", serverInfo: { name: "revscope" } });
    const future = await handle({ jsonrpc: "2.0", id: 2, method: "initialize", params: { protocolVersion: "2099-01-01" } });
    expect(future?.result).toMatchObject({ protocolVersion: "2025-06-18" });
  });

  it("answers ping and ignores notifications", async () => {
    const handle = handler();
    expect((await handle({ jsonrpc: "2.0", id: "p", method: "ping" }))?.result).toEqual({});
    expect(await handle({ jsonrpc: "2.0", method: "notifications/initialized" })).toBeNull();
  });

  it("advertises every registry tool with object-rooted draft-07 schemas", () => {
    const tools = listTools();
    expect(tools.map(({ name }) => name)).toEqual(TOOLS.map(({ name }) => name));
    for (const tool of tools) {
      expect(tool.inputSchema["type"]).toBe("object");
      expect(tool.outputSchema["type"]).toBe("object");
      expect(JSON.stringify(tool)).not.toContain("2020-12");
      expect(tool.annotations).toMatchObject({ readOnlyHint: true, destructiveHint: false, openWorldHint: false });
    }
  });

  it("returns tool results with matching text and structured content", async () => {
    const response = await handler()({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "inspect_artifact", arguments: { path: fixturePath("artifacts", "notes.txt") } },
    });
    const result = response?.result as { isError: boolean; structuredContent: unknown; content: { text: string }[] };
    expect(result.isError).toBe(false);
    expect(toolOutputSchema.safeParse(result.structuredContent).success).toBe(true);
    expect(JSON.parse(result.content[0]?.text ?? "")).toEqual(result.structuredContent);
  });

  it.each([
    [[{ jsonrpc: "2.0", id: 1, method: "ping" }], -32600],
    [{ id: 1, method: "ping" }, -32600],
    [{ jsonrpc: "2.0", id: 1, method: "resources/list" }, -32601],
    [{ jsonrpc: "2.0", id: 1, method: "tools/call", params: { arguments: {} } }, -32602],
  ])("reports protocol error %# with an envelope in data", async (message, code) => {
    const response = await handler()(message);
    expect(response?.error?.code).toBe(code);
    expect(response?.error?.data).toMatchObject({ ok: false, error: { code: expect.any(String) } });
  });

  it("serves newline-delimited messages in order and reports unparseable lines", async () => {
    const stdin = new PassThrough();
    const lines: string[] = [];
    const served = serveMcp(testContext().context, stdin, (line) => lines.push(line));
    stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" })}\n`);
    stdin.write("not json\n\n");
    stdin.end(`${JSON.stringify({ jsonrpc: "2.0", id: 2, method: "ping" })}\n`);
    await served;
    const responses = lines.map((line) => JSON.parse(line) as { id: unknown; error?: { code: number } });
    expect(responses.map(({ id }) => id)).toEqual([1, null, 2]);
    expect(responses[1]?.error?.code).toBe(-32700);
  });
});
