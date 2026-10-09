import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { failureOutputSchema } from "../../src/domain/errors.js";
import { toolOutputSchema } from "../../src/application/tools/types.js";
import { BIN, REPO_ROOT, fixturePath } from "../support/context.js";
import { fakeGhidra } from "../support/fakeGhidra.js";
import { exportText } from "../support/ghidraExport.js";
import { makeElf } from "../fixtures/binaries/make-elf.mjs";

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

const alive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (cause: unknown) {
    return (cause as NodeJS.ErrnoException).code === "EPERM";
  }
};

describe("analyze_binary through the MCP SDK client (fake engine)", () => {
  let client: Client;
  let fake: Awaited<ReturnType<typeof fakeGhidra>>;
  let binary: string;
  /** Owned by this suite: the server process uses it across tests. */
  let directory: string;

  beforeAll(async () => {
    if (!existsSync(BIN)) throw new Error("Build first: npm run build");
    directory = await mkdtemp(join(tmpdir(), "revscope-mcp-ghidra-"));
    fake = await fakeGhidra({ mode: "success", export: exportText() }, "11.4", directory);
    binary = join(directory, "fixture.elf");
    await writeFile(binary, makeElf());
    client = new Client({ name: "revscope-ghidra-conformance", version: "1" });
    await client.connect(
      new StdioClientTransport({
        command: process.execPath,
        args: [BIN, "mcp"],
        env: { PATH: "/usr/bin:/bin", REVSCOPE_LOG_LEVEL: "silent", REVSCOPE_GHIDRA_DIR: fake.root },
        stderr: "pipe",
      }),
    );
  });

  afterAll(async () => {
    await client.close();
    await rm(directory, { recursive: true, force: true });
  });

  it("returns the same structured result as the CLI for the same request", async () => {
    await fake.setControl({ mode: "success", export: exportText() });
    const result = await client.callTool({ name: "analyze_binary", arguments: { path: binary, authorized: true } });
    expect(result.isError).toBe(false);
    const viaMcp = toolOutputSchema.parse(result.structuredContent);
    const cli = spawnSync(process.execPath, [BIN, "analyze-binary", binary, "--authorized"], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      env: { PATH: "/usr/bin:/bin", REVSCOPE_GHIDRA_DIR: fake.root },
    });
    expect(cli.status).toBe(0);
    expect(viaMcp).toEqual(toolOutputSchema.parse(JSON.parse(cli.stdout)));
  });

  it("rejects a call without the authorization acknowledgement as a tool error", async () => {
    const result = await client.callTool({ name: "analyze_binary", arguments: { path: binary } });
    expect(result.isError).toBe(true);
    expect(failureOutputSchema.parse(result.structuredContent).error).toMatchObject({ code: "invalid_input" });
  });

  it("stops the engine when the client cancels the call", async () => {
    await fake.setControl({ mode: "slow-success", delayMs: 30_000, export: exportText() });
    const controller = new AbortController();
    const call = client.callTool({ name: "analyze_binary", arguments: { path: binary, authorized: true } }, undefined, {
      signal: controller.signal,
      timeout: 60_000,
    });
    const started = performance.now();
    let engine: Awaited<ReturnType<typeof fake.lastRun>> | null = null;
    while (engine?.args.includes("-import") !== true && performance.now() - started < 20_000) {
      engine = await fake.lastRun().catch(() => null);
      // Ignore the record left by an earlier call in this suite.
      if (engine !== null && !alive(engine.pid)) engine = null;
      if (engine === null) await new Promise((resolve) => setTimeout(resolve, 50));
    }
    if (engine === null) throw new Error("the fake engine never started");
    controller.abort();
    await expect(call).rejects.toThrow();
    const deadline = performance.now() + 5_000;
    while (alive(engine.pid) && performance.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 50));
    expect(alive(engine.pid)).toBe(false);
    // The server keeps serving after a cancellation.
    await fake.setControl({ mode: "success", export: exportText() });
    expect((await client.callTool({ name: "analyze_binary", arguments: { path: binary, authorized: true } })).isError).toBe(false);
  }, 40_000);
});
