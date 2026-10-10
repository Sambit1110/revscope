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
import { chmod, readdir, stat, writeFile } from "node:fs/promises";
import { userInfo } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { executeTool } from "../../src/application/tools/registry.js";
import type { ToolOutput } from "../../src/application/tools/types.js";
import { createToolContext } from "../../src/composition.js";
import type { Evidence } from "../../src/domain/evidence.js";
import { DEFAULT_SCRIPT_DIR, GhidraEngine } from "../../src/infrastructure/ghidra/engine.js";
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

/**
 * Compile the Mach-O test program into a temporary directory with the Xcode
 * command-line tools. The binary is analyzed only, never run; execute
 * permission is removed.
 */
const MACHO_SOURCE = fileURLToPath(new URL("../fixtures/binaries/macho/program.c", import.meta.url));
const machoFixture = async () => {
  const path = join(await tempDir(), "program");
  const compiled = spawnSync("clang", ["-arch", "arm64", "-O0", "-o", path, MACHO_SOURCE], { encoding: "utf8", timeout: 120_000 });
  if (compiled.status !== 0)
    throw new Error(`The Mach-O fixture needs clang from the Xcode command-line tools: ${compiled.error?.message ?? compiled.stderr}`);
  await chmod(path, 0o644);
  return path;
};

interface FunctionEntry {
  readonly address: string;
  readonly name: string;
  readonly is_program_entry: boolean;
  readonly is_external_entry_point: boolean;
  readonly [field: string]: unknown;
}

/** The parts of a successful analysis the tests look at. */
const parts = (output: ToolOutput) => {
  const records = success(output).records;
  const info = byOperation(records, "program_info")[0]?.payload as Record<string, unknown>;
  const list = byOperation(records, "list_functions")[0];
  if (list === undefined) throw new Error("no function list");
  const { functions } = list.payload as { functions: FunctionEntry[] };
  const at = (address: string) => {
    const found = functions.find((entry) => entry.address === address);
    if (found === undefined) throw new Error(`no function at ${address}`);
    return found;
  };
  const decompiled = (address: string) =>
    byOperation(records, "decompile").find(({ payload }) => (payload as { address: string }).address === address);
  return { records, info, functions, at, decompiled };
};

const analyze = async (path: string, extra: Record<string, unknown> = {}) =>
  executeTool(context(), "analyze_binary", { path, authorized: true, timeout_ms: 300_000, ...extra });

const success = (output: ToolOutput) => {
  if (!output.ok) throw new Error(JSON.stringify(output.error));
  return output;
};

const byOperation = (records: readonly Evidence[], name: string) => records.filter(({ operation }) => operation.name === name);

/** Every file under a directory, recursively, with size and modification time; empty when absent. */
const snapshot = async (directory: string): Promise<Record<string, string>> => {
  const entries: Record<string, string> = {};
  const walk = async (path: string): Promise<void> => {
    const stats = await stat(path).catch(() => null);
    if (stats === null) return;
    entries[path] = `${String(stats.size)}:${String(stats.mtimeMs)}`;
    if (stats.isDirectory()) for (const name of await readdir(path)) await walk(join(path, name));
  };
  await walk(directory);
  return entries;
};

/** All of the installation's jars, the classpath Ghidra compiles scripts against. */
const ghidraJars = async (root: string): Promise<string[]> => {
  const jars: string[] = [];
  const walk = async (path: string): Promise<void> => {
    for (const entry of await readdir(path, { withFileTypes: true })) {
      const child = join(path, entry.name);
      if (entry.isDirectory()) await walk(child);
      else if (entry.name.endsWith(".jar") && path.endsWith(`${"/"}lib`)) jars.push(child);
    }
  };
  await walk(join(root, "Ghidra"));
  return jars;
};

// Every test calls settings() itself, so a missing Ghidra fails each test
// instead of being reported as skipped.
describe("Ghidra real-engine verification", () => {
  it("compiles Revscope's export script against the installed Ghidra's own classes", async () => {
    // Regression: the script called LanguageID.getIdString(), which does not exist in
    // Ghidra 12.1.4, so Ghidra skipped it and every analysis failed with export_script_failed.
    const { ghidraDir: root, javaHome: jdk } = settings();
    const javac = jdk === undefined ? "javac" : join(jdk, "bin", "javac");
    const out = await tempDir();
    const compiled = spawnSync(
      javac,
      ["-proc:none", "-nowarn", "-d", out, "-cp", (await ghidraJars(root)).join(":"), join(DEFAULT_SCRIPT_DIR, "RevscopeExport.java")],
      { encoding: "utf8", timeout: 120_000 },
    );
    expect(compiled.stderr).toBe("");
    expect(compiled.status).toBe(0);
  });

  it("keeps Ghidra's cache out of its default location outside the workspace", async () => {
    settings();
    const defaultCache = `/var/tmp/${userInfo().username}-ghidra`;
    const before = await snapshot(defaultCache);
    success(await analyze(await fixture()));
    expect(await snapshot(defaultCache)).toEqual(before);
  });

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

describe("Ghidra real-engine verification: function names (ELF)", () => {
  it("presents symbol-table names as imported, with no aliases", async () => {
    settings();
    const { at } = parts(await analyze(await fixture()));
    for (const [address, name] of [["0x400080", "answer"], ["0x400090", "twice"]] as const)
      expect(at(address)).toMatchObject({ name, ghidra_name: name, name_source: "imported", name_basis: "ghidra-name", name_confidence: "imported", aliases: [] });
  });
});

describe("Ghidra real-engine verification: signatures (ELF)", () => {
  it("keeps stored and decompiler signatures apart, and an unknown calling convention unknown", async () => {
    settings();
    const { at, decompiled } = parts(await analyze(await fixture()));
    // answer is the program entry: Ghidra's loader gives it the processEntry convention.
    expect(at("0x400080")).toMatchObject({
      signature: { text: "undefined answer(void)", source: "default", provenance: "ghidra-stored" },
      calling_convention: { name: "processEntry", known: true },
    });
    expect(at("0x400090")).toMatchObject({ calling_convention: { name: null, known: false } });
    expect(decompiled("0x400090")?.payload).toMatchObject({
      stored: { signature: { text: "undefined twice(void)", source: "default" } },
      decompiler: { signature: "int twice(int param_1)", provenance: "ghidra-decompiler" },
      signature_comparison: "stored-not-established",
    });
  });
});

describe("Ghidra real-engine verification: entry points (ELF)", () => {
  it("reports the header-declared entry separately from Ghidra's other external entry points", async () => {
    settings();
    const { info, at } = parts(await analyze(await fixture()));
    expect(info["program_entry"]).toEqual({ source: "elf-header", addresses: ["0x400080"], reason: null });
    expect(info["other_external_entry_points"]).toEqual(["0x400090"]);
    expect(at("0x400080")).toMatchObject({ name: "answer", is_program_entry: true, is_external_entry_point: true });
    // A global symbol Ghidra marks as an external entry point is not the program entry.
    expect(at("0x400090")).toMatchObject({ name: "twice", is_program_entry: false, is_external_entry_point: true });
  });
});

// The Mach-O fixture is compiled with the Xcode command-line tools, so it runs on macOS only.
describe.runIf(process.platform === "darwin")("Ghidra real-engine verification: ARM64 Mach-O fixture (macOS)", () => {
  it("identifies the format and architecture", async () => {
    settings();
    const { info } = parts(await analyze(await machoFixture()));
    expect(info).toMatchObject({ executable_format: "Mac OS X Mach-O", language_id: "AARCH64:LE:64:AppleSilicon", image_base: "0x100000000" });
  });

  it("names the program entry _main, keeping Ghidra's loader label `entry` as an identified alias", async () => {
    settings();
    const { at, decompiled } = parts(await analyze(await machoFixture()));
    expect(at("0x1000004e0")).toMatchObject({
      name: "_main",
      name_source: "imported",
      name_basis: "imported-alias",
      name_confidence: "imported",
      ghidra_name: "entry",
      aliases: [{ name: "entry", source: "imported", role: "loader-entry-label" }],
    });
    // The decompile record shows the same display name; the pseudocode keeps Ghidra's.
    expect(decompiled("0x1000004e0")?.payload).toMatchObject({ name: "_main", ghidra_name: "entry" });
    for (const [address, name] of [["0x100000460", "_add"], ["0x100000480", "_factorial"], ["0x100000514", "_greeting"]] as const)
      expect(at(address)).toMatchObject({ name, ghidra_name: name, name_confidence: "imported", aliases: [] });
  });

  it("keeps stored and decompiler signatures apart (_add, _factorial, _puts)", async () => {
    settings();
    const { at, decompiled } = parts(await analyze(await machoFixture()));
    for (const [address, stored, inferred] of [
      ["0x100000460", "undefined _add(void)", "int _add(int param_1,int param_2)"],
      ["0x100000480", "undefined _factorial(void)", "int _factorial(int param_1)"],
    ] as const) {
      // The stored signature is Ghidra's placeholder and is not replaced by the decompiler's inference.
      expect(at(address)).toMatchObject({ signature: { text: stored, source: "default" }, calling_convention: { name: null, known: false } });
      expect(decompiled(address)?.payload).toMatchObject({
        stored: { signature: { text: stored, source: "default" } },
        decompiler: { signature: inferred, calling_convention: { name: "__cdecl", known: true } },
        signature_comparison: "stored-not-established",
      });
    }
    // _puts's stored signature came from Ghidra's library type information and matches the decompiler's.
    expect(decompiled("0x100000520")?.payload).toMatchObject({
      stored: { signature: { text: "int _puts(char * param_1)", source: "imported" } },
      decompiler: { signature: "int _puts(char *param_1)", calling_convention: { name: null, known: false } },
      signature_comparison: "agree",
    });
  });

  it("reads the LC_MAIN entry and does not treat exported symbols or the header as entry points", async () => {
    settings();
    const { info, at, functions } = parts(await analyze(await machoFixture()));
    expect(info["program_entry"]).toEqual({ source: "macho-lc-main", addresses: ["0x1000004e0"], reason: null });
    // Exported symbols (_add, _factorial) and the Mach-O header symbol are external entry points, not program entries.
    expect(info["other_external_entry_points"]).toEqual(expect.arrayContaining(["0x100000000", "0x100000460", "0x100000480"]));
    expect(info["other_external_entry_points"]).not.toContain("0x1000004e0");
    expect(functions.filter(({ is_program_entry }) => is_program_entry).map(({ address }) => address)).toEqual(["0x1000004e0"]);
    expect(at("0x100000460")).toMatchObject({ is_program_entry: false, is_external_entry_point: true });
    // A file-local (non-exported) function is neither.
    expect(at("0x100000514")).toMatchObject({ is_program_entry: false, is_external_entry_point: false });
  });

  it("produces identical evidence for identical runs (determinism)", async () => {
    settings();
    const path = await machoFixture();
    const first = success(await analyze(path)).records.map(({ evidence_id }) => evidence_id);
    const second = success(await analyze(path)).records.map(({ evidence_id }) => evidence_id);
    expect(second).toEqual(first);
  });
});
