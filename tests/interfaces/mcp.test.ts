import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";

import { TOOLS } from "../../src/application/tools/registry.js";
import { toolOutputSchema } from "../../src/application/tools/types.js";
import { MAX_PENDING_REQUESTS, createMcpHandler, listTools, serveMcp } from "../../src/interfaces/mcp.js";
import { WaitingEngine } from "../support/engine.js";
import { fixturePath, testContext } from "../support/context.js";

const handler = () => createMcpHandler(testContext().context);

interface Response {
  readonly id: unknown;
  readonly result?: { isError: boolean; structuredContent: { ok: boolean; error?: { code: string; details: Record<string, unknown> } } };
  readonly error?: { code: number; data: { error: { code: string; details: Record<string, unknown> } } };
}

/** Feed raw chunks to the stdio server and collect its responses. */
const serve = async (
  chunks: readonly (string | Buffer)[],
  options: Parameters<typeof serveMcp>[3] = {},
  context = testContext().context,
): Promise<Response[]> => {
  const stdin = new PassThrough();
  const lines: string[] = [];
  const served = serveMcp(context, stdin, (line) => lines.push(line), options);
  for (const chunk of chunks) stdin.write(chunk);
  stdin.end();
  await served;
  return lines.map((line) => JSON.parse(line) as Response);
};

const jsonLine = (message: unknown) => `${JSON.stringify(message)}\n`;

const analyzeCall = (id: number) =>
  jsonLine({ jsonrpc: "2.0", id, method: "tools/call", params: { name: "analyze_binary", arguments: { path: "/tmp/sample.bin", authorized: true } } });
const cancel = (requestId: number) => jsonLine({ jsonrpc: "2.0", method: "notifications/cancelled", params: { requestId, reason: "user" } });
const tick = () => new Promise((resolve) => setTimeout(resolve, 20));

const start = (engine: WaitingEngine, options: Parameters<typeof serveMcp>[3] = {}) => {
  const stdin = new PassThrough();
  const lines: string[] = [];
  const served = serveMcp(testContext({ binaryAnalysis: engine }).context, stdin, (text) => lines.push(text), options);
  return {
    stdin,
    served,
    responses: () => lines.map((text) => JSON.parse(text) as Response),
  };
};

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

  it("answers a rejected request under its own id when that id is valid", async () => {
    const responses = await serve([
      jsonLine({ jsonrpc: "2.0", id: 7, method: 5 }),
      jsonLine({ jsonrpc: "1.0", id: "abc", method: "ping" }),
      jsonLine({ jsonrpc: "2.0", id: 1.5, method: "ping" }),
      jsonLine({ jsonrpc: "2.0", id: 0, method: "ping" }),
    ]);
    expect(responses.map(({ id }) => id)).toEqual([7, "abc", null, 0]);
    expect(responses.slice(0, 3).map(({ error }) => error?.code)).toEqual([-32600, -32600, -32600]);
  });

  it("reports an internal failure under the request's id with a correlation id and no details", async () => {
    const { context, logs } = testContext({
      logger: {
        ...testContext().context.logger,
        info: () => {
          throw new Error("logger exploded at /Users/secret EXPLODE_SECRET");
        },
        error: (entry) => {
          logs.push(JSON.stringify(entry));
        },
      },
    });
    const [response] = await serve(
      [jsonLine({ jsonrpc: "2.0", id: "req-42", method: "tools/call", params: { name: "inspect_artifact", arguments: { path: fixturePath("artifacts", "notes.txt") } } })],
      {},
      context,
    );
    expect(response?.id).toBe("req-42");
    expect(response?.error?.code).toBe(-32603);
    expect(response?.error?.data.error).toMatchObject({ code: "internal_error", details: { correlation_id: "cor_test" } });
    expect(JSON.stringify(response)).not.toContain("EXPLODE_SECRET");
    expect(logs.join("")).toContain("mcp_internal_error");
  });

  it("rejects an oversized line without buffering it and keeps serving", async () => {
    const big = `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"pad":"${"x".repeat(300)}"}}`;
    const responses = await serve(
      [big.slice(0, 100), big.slice(100, 250), `${big.slice(250)}\n`, jsonLine({ jsonrpc: "2.0", id: 2, method: "ping" })],
      { maxLineBytes: 128 },
    );
    expect(responses).toHaveLength(2);
    expect(responses[0]?.error?.code).toBe(-32600);
    expect(responses[0]?.error?.data.error).toMatchObject({ code: "resource_limit", details: { limit_bytes: 128 } });
    expect(responses[1]).toMatchObject({ id: 2, result: {} });
  });

  it("accepts CRLF line endings, lines split across chunks, and a final line without a newline", async () => {
    const ping = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" });
    const responses = await serve([`${ping.slice(0, 10)}`, `${ping.slice(10)}\r\n`, JSON.stringify({ jsonrpc: "2.0", id: 2, method: "ping" })]);
    expect(responses.map(({ id }) => id)).toEqual([1, 2]);
  });

  it("hands tool arguments to the tool unchanged, so a __proto__ key is reported rather than dropped", async () => {
    const [response] = await serve([
      `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"inspect_artifact","arguments":{"__proto__":{"path":"${fixturePath("artifacts", "notes.txt")}"}}}}\n`,
    ]);
    expect(response?.result?.isError).toBe(true);
    expect(response?.result?.structuredContent.error?.code).toBe("invalid_input");
    expect(JSON.stringify(response?.result?.structuredContent.error?.details)).toContain("__proto__");
  });

  describe("cancellation", () => {
    it("aborts a running request when the client cancels it, and sends no response for it", async () => {
      const engine = new WaitingEngine();
      const server = start(engine);
      server.stdin.write(analyzeCall(1));
      await tick();
      expect(engine.started).toHaveLength(1);
      server.stdin.write(cancel(1));
      server.stdin.end(jsonLine({ jsonrpc: "2.0", id: 2, method: "ping" }));
      await server.served;
      expect(engine.cancelled).toHaveLength(1);
      expect(server.responses().map(({ id }) => id)).toEqual([2]);
    });

    it("cancels a queued request before it starts, without disturbing the running one", async () => {
      const engine = new WaitingEngine();
      const server = start(engine);
      server.stdin.write(analyzeCall(1));
      server.stdin.write(analyzeCall(2));
      await tick();
      server.stdin.write(cancel(2));
      await tick();
      engine.release();
      server.stdin.end();
      await server.served;
      expect(server.responses().map(({ id }) => id)).toEqual([1]);
      expect(engine.cancelled.map(({ signal }) => signal.aborted)).toEqual([true]);
    });

    it("ignores cancellations for unknown requests", async () => {
      const engine = new WaitingEngine();
      engine.release();
      const server = start(engine);
      server.stdin.write(cancel(99));
      server.stdin.end(analyzeCall(1));
      await server.served;
      expect(server.responses()).toMatchObject([{ id: 1, result: { isError: false } }]);
    });

    it("cancels running work on shutdown and still answers it", async () => {
      const engine = new WaitingEngine();
      const shutdown = new AbortController();
      const server = start(engine, { signal: shutdown.signal });
      server.stdin.write(analyzeCall(1));
      await tick();
      shutdown.abort();
      server.stdin.end();
      await server.served;
      expect(server.responses()).toMatchObject([{ id: 1, result: { isError: true, structuredContent: { error: { code: "cancelled" } } } }]);
    });

    it("refuses requests beyond the pending limit instead of queueing them without bound", async () => {
      const engine = new WaitingEngine();
      const server = start(engine);
      for (let id = 1; id <= MAX_PENDING_REQUESTS + 2; id += 1) server.stdin.write(analyzeCall(id));
      await tick();
      const refused = server.responses();
      expect(refused.map(({ id }) => id)).toEqual([MAX_PENDING_REQUESTS + 1, MAX_PENDING_REQUESTS + 2]);
      expect(refused[0]?.error?.data.error).toMatchObject({ code: "resource_limit" });
      engine.release();
      server.stdin.end();
      await server.served;
      expect(server.responses()).toHaveLength(MAX_PENDING_REQUESTS + 2);
    });
  });
});
