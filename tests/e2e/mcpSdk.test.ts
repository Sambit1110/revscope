import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { existsSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { failureOutputSchema } from "../../src/domain/errors.js";
import { toolOutputSchema } from "../../src/application/tools/types.js";
import { BIN, fixturePath } from "../support/context.js";

/**
 * Drives the built `revscope mcp` executable with the official MCP SDK client,
 * an implementation Revscope does not control. The SDK validates every
 * structuredContent value against the advertised outputSchema.
 */
describe("MCP compatibility with an independent client", () => {
  let client: Client;
  let transport: StdioClientTransport;

  beforeAll(async () => {
    if (!existsSync(BIN)) throw new Error("Build first: npm run build");
    transport = new StdioClientTransport({
      command: process.execPath,
      args: [BIN, "mcp"],
      // Only what the server needs; the test host environment is not forwarded.
      env: { PATH: "/usr/bin:/bin", REVSCOPE_LOG_LEVEL: "silent" },
      stderr: "pipe",
    });
    client = new Client({ name: "revscope-conformance", version: "1" });
    await client.connect(transport);
  });

  afterAll(async () => {
    await client.close();
  });

  it("lists the tools with schemas the client accepts", async () => {
    const { tools } = await client.listTools();
    expect(tools.map(({ name }) => name)).toEqual([
      "inspect_artifact",
      "report_evidence",
      "compare_evidence",
      "stub_analysis",
      "analyze_binary",
    ]);
    expect(client.getServerVersion()).toMatchObject({ name: "revscope" });
  });

  it("returns schema-valid structured evidence for a successful call", async () => {
    const result = await client.callTool({
      name: "inspect_artifact",
      arguments: { path: fixturePath("artifacts", "config.json") },
    });
    expect(result.isError).toBe(false);
    const output = toolOutputSchema.parse(result.structuredContent);
    expect(output.ok).toBe(true);
    if (output.ok) expect(output.records.map(({ confidence }) => confidence)).toEqual(["observed", "inferred"]);
  });

  it("returns schema-valid error envelopes for input validation failures", async () => {
    const result = await client.callTool({ name: "inspect_artifact", arguments: { path: "relative.txt" } });
    expect(result.isError).toBe(true);
    const output = failureOutputSchema.parse(result.structuredContent);
    expect(output.error.code).toBe("invalid_input");
    const text = (result.content as { type: string; text: string }[])[0]?.text ?? "";
    expect(JSON.parse(text)).toEqual(result.structuredContent);
  });

  it("reports partial failures and preserves partial observations", async () => {
    const result = await client.callTool({
      name: "stub_analysis",
      arguments: {
        fixture_path: fixturePath("stub", "database-partial-failure.json"),
        steps: [
          { action: "read", operation: "get_name", params: { address: "0x1000" } },
          { action: "mutate", operation: "rename", params: { names: { "0x1000": "entry", "0x2000": "util" } } },
        ],
      },
    });
    const output = failureOutputSchema.parse(result.structuredContent);
    expect(output.error.code).toBe("partial_failure");
    expect(output.error.details).toMatchObject({ possibly_mutated: true, failed_step: 1 });
    expect(output.error.details["partial_records"]).toHaveLength(1);
  });

  it("rejects an unknown tool with a protocol error whose data is the shared envelope", async () => {
    await expect(client.callTool({ name: "no_such_tool", arguments: {} })).rejects.toMatchObject({
      code: -32602,
      data: { ok: false, error: { code: "unknown_tool", category: "unsupported" } },
    });
  });
});
