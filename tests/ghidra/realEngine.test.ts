/**
 * Real-engine verification: these tests run Ghidra itself. They are not part
 * of `npm run check`. Run them with:
 *
 *   REVSCOPE_GHIDRA_DIR=/absolute/path/to/ghidra_<version>_PUBLIC npm run test:ghidra
 *
 * optionally with REVSCOPE_JAVA_HOME=/absolute/path/to/jdk. Without
 * REVSCOPE_GHIDRA_DIR every test fails: a missing engine must never look
 * like a verified one.
 */
import { spawnSync } from "node:child_process";
import { readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";

import { executeTool } from "../../src/application/tools/registry.js";
import type { ToolOutput } from "../../src/application/tools/types.js";
import { createToolContext } from "../../src/composition.js";
import type { Evidence } from "../../src/domain/evidence.js";
import { GhidraEngine } from "../../src/infrastructure/ghidra/engine.js";
import { serveMcp } from "../../src/interfaces/mcp.js";
import { makeElf } from "../fixtures/binaries/make-elf.mjs";
import { BIN, REPO_ROOT, tempDir } from "../support/context.js";

const ghidraDir = process.env["REVSCOPE_GHIDRA_DIR"];
const javaHome = process.env["REVSCOPE_JAVA_HOME"];

const settings = () => {
  if (ghidraDir === undefined || ghidraDir === "")
    throw new Error(
      "Real-engine tests need an installed Ghidra: set REVSCOPE_GHIDRA_DIR to its absolute installation directory (see README, 'Real-engine tests'). They cannot pass without Ghidra.",
    );
  return { ghidraDir, ...(javaHome === undefined || javaHome === "" ? {} : { javaHome }) };
};

/** REVSCOPE_GHIDRA_DIAGNOSTICS=1 keeps failed runs for diagnosis, reported on this terminal only. */
const diagnostics =
  process.env["REVSCOPE_GHIDRA_DIAGNOSTICS"] === "1" ? { report: (line: string) => void process.stderr.write(line) } : null;

const context = () =>
  createToolContext({ logLevel: "silent", writeLog: () => undefined, ghidra: settings(), ghidraDiagnostics: diagnostics });

const fixture = async () => {
  const path = join(await tempDir(), "fixture.elf");
  await writeFile(path, makeElf());
  return path;
};

const analyze = async (path: string, extra: Record<string, unknown> = {}) =>
  executeTool(context(), "analyze_binary", { path, authorized: true, timeout_ms: 300_000, ...extra });

const success = (output: ToolOutput) => {
  if (!output.ok) throw new Error(JSON.stringify(output.error));
  return output;
};

const byOperation = (records: readonly Evidence[], name: string) => records.filter(({ operation }) => operation.name === name);

// Every test calls settings() itself, so a missing Ghidra fails each test
// instead of being reported as skipped.
describe("Ghidra real-engine verification", () => {
  it("analyzes the ELF fixture: metadata, named functions, and pseudocode, labelled as engine output", async () => {
    settings();
    const output = success(await analyze(await fixture()));
    const [identity, ...engine] = output.records;
    expect(identity).toMatchObject({ confidence: "observed", authority: "original-artifact" });
    for (const record of engine) expect(record).toMatchObject({ confidence: "derived", authority: "analysis-engine", producer: { id: "ghidra" } });
    const [info] = byOperation(output.records, "program_info");
    expect(info?.payload).toMatchObject({ language_id: expect.stringMatching(/^x86:LE:64/u), executable_format: expect.stringMatching(/ELF/u) });
    const [list] = byOperation(output.records, "list_functions");
    if (list === undefined) throw new Error("no function list");
    const { functions } = list.payload as { functions: { address: string; name: string; name_source: string }[] };
    expect(functions).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ address: "0x400080", name: "answer", name_source: "imported" }),
        expect.objectContaining({ address: "0x400090", name: "twice", name_source: "imported" }),
      ]),
    );
    const code = (address: string) =>
      byOperation(output.records, "decompile").find(({ payload }) => (payload as { address: string }).address === address)?.payload as { status: string; pseudocode: string };
    expect(code("0x400080")).toMatchObject({ status: "ok", pseudocode: expect.stringMatching(/0x2a|42/u) });
    expect(code("0x400090").pseudocode).toMatch(/\* 2|<< 1|\+ param_1|param_1 \+/u);
    expect(output.data).toMatchObject({ analysis: { export_complete: true }, cleanup: { process: "not-needed", workspace: "removed" } });
  });

  it("produces identical evidence for identical runs (determinism)", async () => {
    settings();
    const path = await fixture();
    const first = success(await analyze(path)).records.map(({ evidence_id }) => evidence_id);
    const second = success(await analyze(path)).records.map(({ evidence_id }) => evidence_id);
    expect(second).toEqual(first);
  });

  it("refuses files Ghidra cannot load", async () => {
    settings();
    const directory = await tempDir();
    const text = join(directory, "notes.txt");
    await writeFile(text, "plain text, not a program\n");
    const noise = join(directory, "noise.bin");
    await writeFile(noise, Buffer.from(Array.from({ length: 4096 }, (_, index) => (index * 7919) % 251)));
    for (const path of [text, noise]) {
      const output = await analyze(path);
      expect(output.ok ? "analyzed" : output.error.code, path).toBe("unsupported_target");
    }
  });

  it("times out a run that cannot finish, stopping Ghidra and removing the workspace", async () => {
    const tempParent = await tempDir();
    const engine = new GhidraEngine({ settings: settings(), tempParent, maxChildRunMs: 2_000 });
    const result = await engine.analyze({
      path: await fixture(),
      limits: { timeoutMs: 60_000, maxFunctions: 200, decompile: true, decompileTimeoutMs: 10_000 },
      signal: new AbortController().signal,
    });
    expect(result.ok ? "finished" : result.error.code).toMatch(/^analysis_(?:timeout|incomplete)$/u);
    if (!result.ok) expect(result.error.details["cleanup"]).toMatchObject({ process: "terminated", workspace: "removed" });
    expect(await readdir(tempParent)).toEqual([]);
  });

  it("cancels a running analysis", async () => {
    const tempParent = await tempDir();
    const engine = new GhidraEngine({ settings: settings(), tempParent });
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 3_000);
    const result = await engine.analyze({
      path: await fixture(),
      limits: { timeoutMs: 300_000, maxFunctions: 200, decompile: true, decompileTimeoutMs: 10_000 },
      signal: controller.signal,
    });
    if (result.ok) throw new Error("Ghidra finished within 3 s; cancellation was not exercised");
    expect(result.error).toMatchObject({ code: "cancelled", details: { cleanup: { workspace: "removed" } } });
    expect(await readdir(tempParent)).toEqual([]);
  });

  it("reports an invalid Java home as configuration, before starting Ghidra", async () => {
    const engine = new GhidraEngine({ settings: { ...settings(), javaHome: await tempDir() } });
    const result = await engine.analyze({
      path: await fixture(),
      limits: { timeoutMs: 60_000, maxFunctions: 200, decompile: true, decompileTimeoutMs: 10_000 },
      signal: new AbortController().signal,
    });
    expect(result.ok ? "analyzed" : result.error).toMatchObject({ code: "provider_not_configured", details: { check: "java_home_invalid" } });
  });

  it("gives the same result through the built CLI and MCP", async () => {
    settings();
    const path = await fixture();
    const cli = spawnSync(process.execPath, [BIN, "analyze-binary", path, "--authorized", "--timeout-ms", "300000"], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      env: { PATH: process.env["PATH"] ?? "/usr/bin:/bin", ...Object.fromEntries(Object.entries({ REVSCOPE_GHIDRA_DIR: ghidraDir, REVSCOPE_JAVA_HOME: javaHome }).filter(([, value]) => value !== undefined && value !== "")) },
      timeout: 320_000,
    });
    expect(cli.status).toBe(0);
    const stdin = new PassThrough();
    const lines: string[] = [];
    const served = serveMcp(context(), stdin, (line) => lines.push(line));
    stdin.end(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "analyze_binary", arguments: { path, authorized: true, timeout_ms: 300_000 } } })}\n`);
    await served;
    const mcp = (JSON.parse(lines[0] ?? "null") as { result: { structuredContent: unknown } }).result.structuredContent;
    expect(mcp).toEqual(JSON.parse(cli.stdout));
  });
});
