import { spawn, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";

import { toolOutputSchema } from "../../src/application/tools/types.js";
import { BIN, REPO_ROOT, tempDir } from "../support/context.js";
import { fakeGhidra } from "../support/fakeGhidra.js";
import { exportText } from "../support/ghidraExport.js";
import { makeElf } from "../fixtures/binaries/make-elf.mjs";

/** Run the built executable from the repository root, exactly as documented. */
const revscope = (...args: string[]) => {
  const run = spawnSync(process.execPath, [BIN, ...args], {
    cwd: REPO_ROOT,
    encoding: "utf8",
    env: { PATH: "/usr/bin:/bin" },
    timeout: 30_000,
  });
  return { status: run.status, stdout: run.stdout, stderr: run.stderr };
};

const json = (stdout: string) => toolOutputSchema.parse(JSON.parse(stdout));

describe("documented CLI usage against fixtures", () => {
  beforeAll(() => {
    if (!existsSync(BIN)) throw new Error("Build first: npm run build");
  });

  it("prints help, version, and the tool list", async () => {
    const help = revscope("--help");
    expect(help.status).toBe(0);
    expect(help.stdout).toContain("revscope inspect-artifact <file>");
    // The help must describe what exists: the Ghidra engine, and no "not yet" claims about it.
    expect(help.stdout).toContain("Ghidra headless as the engine");
    expect(help.stdout).not.toMatch(/no real binary analysis|pre-release foundation/u);
    const manifest = JSON.parse(await readFile(join(REPO_ROOT, "package.json"), "utf8")) as { version: string };
    expect(revscope("version").stdout.trim()).toBe(manifest.version);
    const tools = JSON.parse(revscope("tools").stdout) as { tools: { name: string; cli_command: string }[] };
    expect(tools.tools.map(({ cli_command }) => cli_command)).toEqual([
      "inspect-artifact",
      "report-evidence",
      "compare-evidence",
      "stub-analysis",
      "analyze-binary",
    ]);
  });

  it("inspects fixtures, reports, and compares the resulting evidence", async () => {
    const directory = await tempDir();
    const notes = revscope("inspect-artifact", "fixtures/artifacts/notes.txt");
    expect(notes.status).toBe(0);
    expect(notes.stderr).toBe("");
    const notesPath = join(directory, "notes.json");
    await writeFile(notesPath, notes.stdout);
    const config = revscope("inspect-artifact", "fixtures/artifacts/config.json");
    const configPath = join(directory, "config.json");
    await writeFile(configPath, config.stdout);

    const report = json(revscope("report-evidence", notesPath).stdout);
    expect(report.ok && report.data["report"]).toMatchObject({ valid_records: 2 });

    const compared = revscope("compare-evidence", notesPath, configPath);
    expect(compared.status).toBe(0);
    const comparison = json(compared.stdout);
    expect(comparison.ok && comparison.data["summary"]).toMatchObject({ added: 2, removed: 2 });
  });

  it("produces byte-identical output for repeated runs", () => {
    const first = revscope("inspect-artifact", "fixtures/artifacts/notes.txt").stdout;
    const second = revscope("inspect-artifact", "fixtures/artifacts/notes.txt").stdout;
    expect(second).toBe(first);
  });

  it("runs the stub success, unsupported-operation, and partial-failure scenarios", () => {
    const succeeded = revscope(
      "stub-analysis",
      "fixtures/stub/database.json",
      "--steps-file",
      "fixtures/stub/steps-success.json",
    );
    expect(succeeded.status).toBe(0);
    const success = json(succeeded.stdout);
    expect(success.ok && success.records.map(({ confidence }) => confidence)).toEqual([
      "observed",
      "derived",
      "observed",
      "reported",
      "observed",
    ]);

    const unsupported = revscope(
      "stub-analysis",
      "fixtures/stub/database.json",
      "--steps-file",
      "fixtures/stub/steps-unsupported.json",
    );
    expect(unsupported.status).toBe(4);
    const unsupportedOutput = json(unsupported.stdout);
    expect(!unsupportedOutput.ok && unsupportedOutput.error.code).toBe("unsupported_operation");

    const partial = revscope(
      "stub-analysis",
      "fixtures/stub/database-partial-failure.json",
      "--steps-file",
      "fixtures/stub/steps-partial-failure.json",
      "--continue-on-error",
    );
    expect(partial.status).toBe(9);
    const partialOutput = json(partial.stdout);
    expect(!partialOutput.ok && partialOutput.error.code).toBe("partial_failure");
    if (!partialOutput.ok) {
      const steps = partialOutput.error.details["steps"] as { error?: { code: string }; outcome: string }[];
      expect(steps.map((step) => step.error?.code ?? step.outcome)).toEqual([
        "ok",
        "partial_failure",
        "ok",
        "state_uncertain",
        "ok",
        "ok",
      ]);
    }
  });

  it("maps failure categories to documented exit codes and writes JSON to stdout", () => {
    expect(revscope("inspect-artifact", "fixtures/does-not-exist").status).toBe(3);
    expect(revscope("inspect-artifact", "fixtures").status).toBe(4);
    expect(revscope("inspect-artifact").status).toBe(2);
    const unknown = revscope("frobnicate");
    expect(unknown.status).toBe(4);
    expect(json(unknown.stdout).ok).toBe(false);
  });

  it("rejects invalid configuration with the shared envelope", () => {
    const run = spawnSync(process.execPath, [BIN, "tools"], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      env: { PATH: "/usr/bin:/bin", REVSCOPE_LOG_LEVEL: "chatty" },
    });
    expect(run.status).toBe(2);
    expect(JSON.parse(run.stdout)).toMatchObject({ ok: false, error: { code: "invalid_input" } });
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

const binary = async () => {
  const path = join(await tempDir(), "fixture.elf");
  await writeFile(path, makeElf());
  return path;
};
const withGhidra = (root: string, ...args: string[]) =>
  spawnSync(process.execPath, [BIN, ...args], {
    cwd: REPO_ROOT,
    encoding: "utf8",
    env: { PATH: "/usr/bin:/bin", REVSCOPE_GHIDRA_DIR: root },
    timeout: 60_000,
  });

describe("analyze-binary through the built CLI", () => {
  it("requires --authorized and reports a missing engine with the documented exit codes", async () => {
    const path = await binary();
    const unauthorized = revscope("analyze-binary", path);
    expect(unauthorized.status).toBe(2);
    expect(json(unauthorized.stdout)).toMatchObject({ ok: false, error: { code: "invalid_input", details: { issues: [{ path: "authorized" }] } } });
    const unconfigured = revscope("analyze-binary", path, "--authorized");
    expect(unconfigured.status).toBe(4);
    expect(json(unconfigured.stdout)).toMatchObject({ ok: false, error: { code: "provider_not_configured" } });
  });

  it("analyzes with a configured (fake) engine and labels engine output honestly", async () => {
    const fake = await fakeGhidra({ mode: "success", export: exportText() });
    const run = withGhidra(fake.root, "analyze-binary", await binary(), "--authorized");
    expect(run.status).toBe(0);
    expect(run.stderr).toBe("");
    const output = json(run.stdout);
    if (!output.ok) throw new Error(run.stdout);
    expect(output.records.map(({ confidence, authority }) => `${confidence}/${authority}`)).toEqual([
      "observed/original-artifact",
      "derived/analysis-engine",
      "derived/analysis-engine",
      "derived/analysis-engine",
      "derived/analysis-engine",
    ]);
    expect(output.data).toMatchObject({ authorization: "acknowledged-by-caller", cleanup: { workspace: "removed" } });
    expect(run.stdout).not.toContain(fake.root);
  });

  it("cancels on SIGINT, stops the engine, and exits 130", async () => {
    const fake = await fakeGhidra({ mode: "slow-success", delayMs: 30_000, export: exportText() });
    const child = spawn(process.execPath, [BIN, "analyze-binary", await binary(), "--authorized"], {
      cwd: REPO_ROOT,
      env: { PATH: "/usr/bin:/bin", REVSCOPE_GHIDRA_DIR: fake.root },
    });
    let stdout = "";
    child.stdout.on("data", (chunk: Buffer) => (stdout += chunk.toString("utf8")));
    const exited = new Promise<number | null>((resolve) => child.once("exit", (code) => resolve(code)));
    // Wait until the fake engine is running before interrupting.
    const started = performance.now();
    let engine: Awaited<ReturnType<typeof fake.lastRun>> | null = null;
    while (engine === null && performance.now() - started < 20_000) {
      engine = await fake.lastRun().catch(() => null);
      if (engine === null) await new Promise((resolve) => setTimeout(resolve, 50));
    }
    if (engine === null) throw new Error("the fake engine never started");
    const interrupted = performance.now();
    child.kill("SIGINT");
    expect(await exited).toBe(130);
    expect(performance.now() - interrupted).toBeLessThan(5_000);
    expect(JSON.parse(stdout)).toMatchObject({ ok: false, error: { code: "cancelled", details: { cleanup: { process: "terminated", workspace: "removed" } } } });
    expect(alive(engine.pid)).toBe(false);
  }, 40_000);
});
