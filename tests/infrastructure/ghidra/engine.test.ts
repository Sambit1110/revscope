import { createHash } from "node:crypto";
import { chmod, mkdir, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import type { BinaryAnalysisLimits, BinaryAnalysisRun } from "../../../src/application/ports.js";
import type { ErrorEnvelope } from "../../../src/domain/errors.js";
import type { Result } from "../../../src/domain/result.js";
import type { ProcessControl } from "../../../src/infrastructure/childProcess.js";
import { GhidraEngine } from "../../../src/infrastructure/ghidra/engine.js";
import { tempDir } from "../../support/context.js";
import { FAST_TIMING, LIMITS, fakeEngine, fakeGhidra, type FakeControl } from "../../support/fakeGhidra.js";
import { exportText } from "../../support/ghidraExport.js";

const posix = process.platform !== "win32";
/** Documented allowance for scheduling latency beyond a deadline. */
const TOLERANCE_MS = 250;
/** Long enough for the fake to start and write a partial export even in a loaded run. */
const PARTIAL_RUN_MS = 2_000;

const owned: number[] = [];
afterEach(() => {
  for (const pid of owned.splice(0))
    try {
      process.kill(pid, "SIGKILL");
    } catch {
      // Already gone.
    }
});

const alive = (pid: number | null | undefined): boolean => {
  if (pid === null || pid === undefined) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (cause: unknown) {
    return (cause as NodeJS.ErrnoException).code === "EPERM";
  }
};

const sampleInput = async (name = "sample.bin") => {
  const path = join(await tempDir(), name);
  const bytes = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0, ...Array.from({ length: 120 }, (_, index) => index)]);
  await writeFile(path, bytes);
  return { path, sha256: createHash("sha256").update(bytes).digest("hex") };
};

const analyze = async (
  control: FakeControl,
  options: { limits?: Partial<BinaryAnalysisLimits>; signal?: AbortSignal; engine?: Parameters<typeof fakeEngine>[1] } = {},
) => {
  const fake = await fakeGhidra(control);
  const engine = await fakeEngine(fake, options.engine);
  const input = await sampleInput();
  const before = performance.now();
  const result = await engine.analyze({
    path: input.path,
    limits: { ...LIMITS, ...options.limits },
    signal: options.signal ?? new AbortController().signal,
  });
  const wallMs = performance.now() - before;
  const run = await fake.lastRun().catch(() => null);
  if (run !== null) owned.push(run.pid, ...(run.grandchild === null ? [] : [run.grandchild]));
  return { result, wallMs, fake, input, run, workspaces: async () => readdir(join(run?.cwd ?? "/nonexistent", "..")).catch(() => []) };
};

const value = (result: Result<BinaryAnalysisRun, ErrorEnvelope>) => {
  if (!result.ok) throw new Error(JSON.stringify(result.error));
  return result.value;
};
const failure = (result: Result<BinaryAnalysisRun, ErrorEnvelope>) => {
  if (result.ok) throw new Error("expected failure");
  return result.error;
};

/** Analyze with an installation that `prepare` has broken; the error must not name the directory. */
const configured = async (prepare: (root: string) => Promise<void>, javaHome?: string) => {
  const fake = await fakeGhidra({ mode: "success", export: exportText() });
  await prepare(fake.root);
  const engine = new GhidraEngine({
    settings: { ghidraDir: fake.root, ...(javaHome === undefined ? {} : { javaHome }) },
    scriptDir: fake.scriptDir,
    tempParent: await tempDir(),
  });
  const error = failure(await engine.analyze({ path: (await sampleInput()).path, limits: LIMITS, signal: new AbortController().signal }));
  expect(JSON.stringify(error)).not.toContain(fake.root);
  return error;
};


const tryInput = async (path: string, engineOptions: Parameters<typeof fakeEngine>[1] = {}) => {
  const fake = await fakeGhidra({ mode: "success", export: exportText() });
  const tempParent = await tempDir();
  const engine = await fakeEngine(fake, { tempParent, ...engineOptions });
  const error = failure(await engine.analyze({ path, limits: LIMITS, signal: new AbortController().signal }));
  expect(await readdir(tempParent)).toEqual([]);
  expect(await fake.lastRun().catch(() => "never ran")).toBe("never ran");
  return error;
};


const noop = () => Promise.resolve();

describe.skipIf(!posix)("Ghidra engine with a fake analyzeHeadless", () => {
  describe("a successful run", () => {
    it("analyzes a private copy, serves the export, and removes the workspace", async () => {
      const { result, input, run, workspaces } = await analyze({ mode: "success", export: exportText() });
      const analyzed = value(result);
      expect(analyzed.artifact).toMatchObject({ sha256: input.sha256, sizeBytes: 128, displayName: "sample.bin" });
      expect(run?.inputSha256).toBe(input.sha256);
      expect(analyzed.coverage).toMatchObject({ exportComplete: true, stopped: "complete", functionsExported: 2 });
      expect(analyzed.cleanup).toEqual({ process: "not-needed", workspace: "removed", reason: null });
      expect(analyzed.provider.identity).toEqual({ id: "ghidra", version: "11.4" });
      expect(await workspaces()).toEqual([]);
    });

    it("invokes analyzeHeadless with the documented arguments, never the caller's path", async () => {
      const { run, input, fake } = await analyze({ mode: "success", export: exportText() });
      if (run === null) throw new Error("the fake did not run");
      const flagValue = (flag: string) => run.args[run.args.indexOf(flag) + 1];
      expect(run.args[0]).toBe(join(run.cwd, "project"));
      expect(flagValue("-import")).toBe(join(run.cwd, "input", "artifact"));
      expect(flagValue("-scriptPath")).toBe(fake.scriptDir);
      expect(run.args).toContain("-deleteProject");
      expect(Number(flagValue("-analysisTimeoutPerFile"))).toBeGreaterThanOrEqual(1);
      expect(flagValue("-max-cpu")).toBe("2");
      expect(JSON.stringify(run.args)).not.toContain(input.path);
      expect(run.script).toMatchObject({
        name: "RevscopeExport.java",
        exportPath: join(run.cwd, "out", "export.ndjson"),
        maxFunctions: "200",
        decompile: "true",
        decompileTimeout: "10",
        maxPseudocode: "65536",
      });
      expect(run.script.deadlineEpochMs).toBeGreaterThan(Date.now() - 60_000);
      expect(run.script.deadlineEpochMs).toBeLessThanOrEqual(Date.now() + LIMITS.timeoutMs);
    });

    it("gives Ghidra only allowlisted environment variables, with its home and temp inside the workspace", async () => {
      const canary = `REVSCOPE_CANARY_${String(Date.now())}`;
      const { run } = await analyze(
        { mode: "success", export: exportText() },
        { engine: { host: { PATH: "/usr/bin:/bin", LANG: "C", [canary]: "secret-value", JAVA_HOME: "/host/java" } } },
      );
      if (run === null) throw new Error("the fake did not run");
      expect(run.envNames).not.toContain(canary);
      expect(run.env.JAVA_HOME).toBeNull();
      expect(run.env.HOME).toBe(join(run.cwd, "home"));
      expect(run.env.TMPDIR).toBe(join(run.cwd, "tmp"));
      expect(run.env.JAVA_TOOL_OPTIONS).toBe(`-Duser.home=${join(run.cwd, "home")} -Djava.io.tmpdir=${join(run.cwd, "tmp")} -Djava.awt.headless=true`);
    });

    it("passes JAVA_HOME only when it is configured", async () => {
      const javaHome = await tempDir();
      await mkdir(join(javaHome, "bin"));
      await writeFile(join(javaHome, "bin", "java"), "#!/bin/sh\n");
      await chmod(join(javaHome, "bin", "java"), 0o755);
      const fake = await fakeGhidra({ mode: "success", export: exportText() });
      const engine = await fakeEngine(fake, { settings: { ghidraDir: fake.root, javaHome } });
      value(await engine.analyze({ path: (await sampleInput()).path, limits: LIMITS, signal: new AbortController().signal }));
      expect((await fake.lastRun()).env.JAVA_HOME).toBe(javaHome);
    });
  });

  describe("configuration", () => {
    it.each([
      ["a relative directory", () => new GhidraEngine({ settings: { ghidraDir: "ghidra" } }), "ghidra_dir_not_absolute"],
      ["a missing directory", () => new GhidraEngine({ settings: { ghidraDir: "/nonexistent/revscope-ghidra" } }), "ghidra_dir_missing"],
    ])("reports %s", async (_label, make, check) => {
      const error = failure(await make().analyze({ path: "/tmp/x", limits: LIMITS, signal: new AbortController().signal }));
      expect(error).toMatchObject({ code: "provider_not_configured", details: { check, cleanup: { process: "not-started", workspace: "not-created" } } });
    });

    it.each([
      ["no launcher", (root: string) => rm(join(root, "support", "analyzeHeadless")), "analyze_headless_missing"],
      ["a launcher that is not executable", (root: string) => chmod(join(root, "support", "analyzeHeadless"), 0o644), "analyze_headless_not_executable"],
      ["no version", (root: string) => writeFile(join(root, "Ghidra", "application.properties"), "application.name=Ghidra\n"), "version_unreadable"],
      ["an implausible version", (root: string) => writeFile(join(root, "Ghidra", "application.properties"), "application.version=1 2\n"), "version_unreadable"],
    ])("reports %s without naming the directory", async (_label, prepare, check) => {
      expect(await configured(prepare)).toMatchObject({ code: "provider_not_configured", details: { check } });
    });

    it("reports an invalid Java home", async () => {
      expect(await configured(noop, "java")).toMatchObject({ details: { check: "java_home_not_absolute" } });
      expect(await configured(noop, await tempDir())).toMatchObject({ details: { check: "java_home_invalid" } });
    });

    it("reports a missing export script", async () => {
      const fake = await fakeGhidra({ mode: "success", export: exportText() });
      const engine = await fakeEngine(fake, { scriptDir: await tempDir() });
      const error = failure(await engine.analyze({ path: (await sampleInput()).path, limits: LIMITS, signal: new AbortController().signal }));
      expect(error).toMatchObject({ code: "provider_not_configured", details: { check: "export_script_missing" } });
    });

    it("reports Ghidra failing to find Java", async () => {
      const { result } = await analyze({ mode: "say", stderr: "JDK 21+ (64-bit) could not be found and must be manually chosen!\nUnable to prompt user for JDK path, no TTY detected.\n", exitCode: 1 });
      expect(failure(result)).toMatchObject({ code: "provider_not_configured", details: { check: "java_runtime" } });
    });
  });

  describe("input", () => {
    it("refuses missing files, directories and links before creating anything", async () => {
      const directory = await tempDir();
      await writeFile(join(directory, "real"), "x");
      await symlink(join(directory, "real"), join(directory, "link"));
      expect(await tryInput(join(directory, "absent"))).toMatchObject({ code: "target_not_found", details: { path: join(directory, "absent") } });
      expect((await tryInput(directory)).code).toBe("unsupported_target");
      expect((await tryInput(join(directory, "link"))).code).toBe("unsupported_target");
    });

    it("refuses inputs over the size limit", async () => {
      const { path } = await sampleInput();
      expect(await tryInput(path, { maxInputBytes: 16 })).toMatchObject({ code: "resource_limit", details: { limit_bytes: 16, size_bytes: 128 } });
    });
  });

  describe("runs without a usable export", () => {
    it.each([
      ["an unrecognised file format", { mode: "say", stdout: "ERROR REPORT: No load spec found for import file: /private/input\n" }, "unsupported_target", null],
      ["a failing export script", { mode: "say", stdout: "ERROR REPORT: Failed to compile script RevscopeExport.java\n" }, "provider_failure", "export_script_failed"],
      ["a failed import", { mode: "say", stdout: "ERROR REPORT: Import failed for file\n", exitCode: 0 }, "provider_failure", "import_failed"],
      ["a silent crash", { mode: "say", exitCode: 3 }, "provider_failure", "engine_failed"],
    ] as const)("classifies %s", async (_label, control, code, reason) => {
      const { result } = await analyze(control);
      const error = failure(result);
      expect(error.code).toBe(code);
      if (reason !== null) expect(error.details["reason"]).toBe(reason);
      expect(error.details["cleanup"]).toMatchObject({ workspace: "removed" });
    });

    it("never repeats engine output, host paths or secrets in errors", async () => {
      const { result } = await analyze({ mode: "say", stdout: "/Users/someone/private/build SECRET_TOKEN=abc123\n", stderr: "at ghidra.Foo(Foo.java:12)\n", exitCode: 1 });
      const text = JSON.stringify(failure(result));
      for (const leaked of ["/Users/someone", "SECRET_TOKEN", "abc123", "Foo.java", "revscope-ghidra-"]) expect(text).not.toContain(leaked);
    });
  });

  describe("malformed exports", () => {
    it.each([
      ["garbage", { mode: "success", export: "garbage\n" }, "malformed_export"],
      ["different limits", { mode: "success", export: exportText({ maxFunctions: 5 }) }, "malformed_export"],
      ["a different Ghidra version", { mode: "success", export: exportText({ ghidraVersion: "10.0" }) }, "malformed_export"],
      ["an oversized export", { mode: "huge" }, "export_too_large"],
    ] as const)("refuses %s as a provider failure", async (_label, control, reason) => {
      const { result } = await analyze(control);
      expect(failure(result)).toMatchObject({ code: "provider_failure", details: { reason, cleanup: { workspace: "removed" } } });
    });
  });

  describe("timeouts, cancellation and partial output", () => {
    it("times out a hanging engine, kills its process group and removes the workspace", async () => {
      const { result, wallMs, run, workspaces } = await analyze({ mode: "hang", grandchild: true, ignoreTerm: true }, { engine: { maxChildRunMs: 400 } });
      const error = failure(result);
      expect(error).toMatchObject({ code: "analysis_timeout", category: "resource_limit", details: { cleanup: { process: "terminated", workspace: "removed" } } });
      expect(wallMs).toBeLessThan(400 + FAST_TIMING.killGraceMs + FAST_TIMING.settleMs + TOLERANCE_MS + 300);
      expect(alive(run?.pid)).toBe(false);
      expect(alive(run?.grandchild)).toBe(false);
      expect(await workspaces()).toEqual([]);
    });

    it("holds the whole operation to timeout_ms with the production timing", async () => {
      const fake = await fakeGhidra({ mode: "hang" });
      const engine = new GhidraEngine({ settings: { ghidraDir: fake.root }, scriptDir: fake.scriptDir, tempParent: await tempDir(), host: { PATH: "/usr/bin:/bin" } });
      const before = performance.now();
      const result = await engine.analyze({ path: (await sampleInput()).path, limits: { ...LIMITS, timeoutMs: 10_000 }, signal: new AbortController().signal });
      const wallMs = performance.now() - before;
      owned.push((await fake.lastRun()).pid);
      expect(failure(result).code).toBe("analysis_timeout");
      expect(wallMs).toBeLessThanOrEqual(10_000 + TOLERANCE_MS);
    }, 20_000);

    it("does not start the engine when too little time remains", async () => {
      const fake = await fakeGhidra({ mode: "success", export: exportText() });
      const engine = new GhidraEngine({ settings: { ghidraDir: fake.root }, scriptDir: fake.scriptDir, tempParent: await tempDir() });
      const error = failure(await engine.analyze({ path: (await sampleInput()).path, limits: { ...LIMITS, timeoutMs: 4_000 }, signal: new AbortController().signal }));
      expect(error).toMatchObject({ code: "analysis_timeout", details: { cleanup: { process: "not-started", workspace: "removed" } } });
      expect(await fake.lastRun().catch(() => "never ran")).toBe("never ran");
    });

    it("keeps a cut-off export as incomplete coverage when the deadline stops a slow decompilation", async () => {
      // The fake must start and write before the deadline; Node start-up under a loaded run can exceed 400 ms.
      const { result, wallMs } = await analyze({ mode: "partial-hang", export: exportText({ trailer: null }) }, { engine: { maxChildRunMs: PARTIAL_RUN_MS } });
      const analyzed = value(result);
      expect(analyzed.coverage).toEqual({ exportComplete: false, interruption: "timed-out", stopped: null, analysisTimedOut: false, functionsTotal: null, functionsExported: 2 });
      expect(analyzed.cleanup).toMatchObject({ process: "terminated", workspace: "removed" });
      expect(wallMs).toBeLessThan(PARTIAL_RUN_MS + FAST_TIMING.killGraceMs + FAST_TIMING.settleMs + TOLERANCE_MS + 300);
    });

    it("reports an engine that exits mid-export as incomplete", async () => {
      const { result } = await analyze({ mode: "partial-exit", export: exportText({ trailer: null }) });
      expect(value(result).coverage).toMatchObject({ exportComplete: false, interruption: "engine-exited" });
    });

    it("cancels a running analysis promptly", async () => {
      const controller = new AbortController();
      setTimeout(() => controller.abort(), 500);
      const { result, wallMs, run, workspaces } = await analyze({ mode: "slow-success", delayMs: 20_000, export: exportText() }, { signal: controller.signal });
      expect(failure(result)).toMatchObject({ code: "cancelled", details: { cleanup: { process: "terminated", workspace: "removed" } } });
      expect(wallMs).toBeLessThan(500 + FAST_TIMING.killGraceMs + FAST_TIMING.settleMs + TOLERANCE_MS + 300);
      expect(alive(run?.pid)).toBe(false);
      expect(await workspaces()).toEqual([]);
    });

    it("does not start when already cancelled", async () => {
      const controller = new AbortController();
      controller.abort();
      const { result, run } = await analyze({ mode: "success", export: exportText() }, { signal: controller.signal });
      expect(failure(result)).toMatchObject({ code: "cancelled", details: { cleanup: { process: "not-started", workspace: "not-created" } } });
      expect(run).toBeNull();
    });

    it("reports a process tree it could not terminate instead of claiming cleanup", async () => {
      const denied: ProcessControl = {
        platform: process.platform,
        kill: (pid, signal) => {
          if (signal === 0) {
            process.kill(pid, 0);
            return;
          }
          throw Object.assign(new Error("denied"), { code: "EPERM" });
        },
      };
      const { result, run } = await analyze({ mode: "hang" }, { engine: { maxChildRunMs: 300, control: denied } });
      const error = failure(result);
      expect(error.details["cleanup"]).toMatchObject({ process: "failed", reason: expect.stringContaining("EPERM") });
      expect(alive(run?.pid)).toBe(true);
    });
  });

  describe("opt-in diagnostics", () => {
    it("are off by default: a failed run's workspace is removed and nothing is reported", async () => {
      const { result, workspaces } = await analyze({ mode: "say", stdout: "Failed to compile script\n", exitCode: 0 });
      expect(failure(result).details["cleanup"]).toMatchObject({ workspace: "removed" });
      expect(await workspaces()).toEqual([]);
    });

    it("keep a failed run's workspace, logs and run record, and report the location only locally", async () => {
      const directory = join(await tempDir(), "diagnostics");
      const reported: string[] = [];
      const { result, run } = await analyze(
        { mode: "say", stdout: "INFO  REPORT: Failed to compile script RevscopeExport.java\n", stderr: "detail on stderr\n", exitCode: 3 },
        { engine: { diagnostics: { directory, report: (line) => reported.push(line) } } },
      );
      const error = failure(result);
      expect(error).toMatchObject({ code: "provider_failure", details: { reason: "export_script_failed", cleanup: { workspace: "preserved" } } });
      // Nothing about the location, the logs or the output reaches the caller.
      const text = JSON.stringify(error);
      for (const hidden of [directory, "Failed to compile", "detail on stderr", run?.cwd ?? "-"]) expect(text).not.toContain(hidden);
      expect(reported).toHaveLength(1);
      const [preserved] = (await readdir(directory)).map((name) => join(directory, name));
      expect(reported[0]).toContain(preserved);
      const record = JSON.parse(await readFile(join(preserved ?? "", "run.json"), "utf8")) as Record<string, unknown>;
      expect(record).toMatchObject({
        outcome: { code: "provider_failure" },
        internal: { classification: "export_script_failed" },
        process: { termination: "exited", exit_code: 3 },
      });
      expect(JSON.stringify(record)).not.toContain("PATH=");
      expect(await readFile(join(preserved ?? "", "stdout.txt"), "utf8")).toContain("Failed to compile");
      expect(await readdir(join(preserved ?? "", "workspace"))).toEqual(expect.arrayContaining(["input", "logs", "home", "out"]));
    });

    it("leave successful runs alone", async () => {
      const directory = join(await tempDir(), "diagnostics");
      const { result } = await analyze({ mode: "success", export: exportText() }, { engine: { diagnostics: { directory, report: () => undefined } } });
      expect(value(result).cleanup).toMatchObject({ workspace: "removed" });
      expect(await readdir(directory).catch(() => [])).toEqual([]);
    });
  });
});
