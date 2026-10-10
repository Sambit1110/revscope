/**
 * Revscope real-binary benchmark.
 *
 *   REVSCOPE_GHIDRA_DIR=/abs/ghidra npm run benchmark -- [--out <dir>] [--repeat <n>] [--only <regex>]
 *
 * Builds every input from source (or byte by byte) into a directory outside
 * the source tree, analyzes each with the built CLI under explicit limits,
 * scores the output against predefined ground truth, and writes
 * `results.json` (schema revscope.benchmark/1) and `report.md` there.
 * Nothing it builds is ever executed. A case that cannot run is reported as
 * not run, and the exit status is non-zero.
 */
import { spawnSync } from "node:child_process";
import { existsSync, statSync } from "node:fs";
import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { cpus, release, tmpdir, totalmem, userInfo } from "node:os";
import { join, relative } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import type { GhidraEngine as GhidraEngineType } from "../src/infrastructure/ghidra/engine.js";
import { CASES, type BenchmarkCase, type RejectionCase } from "./manifest.ts";
import { processesMentioning, runCli, runDirectories, minimalEnv, type EngineSettings, type RunLimits, type RunObservation } from "./lib/execute.ts";
import { buildCompiled, buildGeneratedElf, buildRejection, toolVersion, type BuiltInput } from "./lib/fixtures.ts";
import { computeMetrics, readSuccess, type CaseMetrics, type GroundTruth } from "./lib/metrics.ts";
import { HARNESS_VERSION, RESULTS_SCHEMA, renderReport, summarize, type CaseResult, type Environment, type Results } from "./lib/report.ts";

const REPO_ROOT = fileURLToPath(new URL("../", import.meta.url));
const BIN = join(REPO_ROOT, "dist", "bin", "revscope.js");

const say = (line: string) => void process.stdout.write(`${line}\n`);

const parseArgs = (argv: readonly string[]) => {
  const options = { out: null as string | null, repeat: 3, only: null as string | null };
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    const value = argv[index + 1];
    if (flag === "--out" && value !== undefined) options.out = value;
    else if (flag === "--repeat" && value !== undefined) options.repeat = Number(value);
    else if (flag === "--only" && value !== undefined) options.only = value;
    else throw new Error(`unknown or incomplete argument: ${String(flag)}`);
    index += 1;
  }
  if (!Number.isInteger(options.repeat) || options.repeat < 2 || options.repeat > 20)
    throw new Error("--repeat must be an integer from 2 to 20 (determinism needs at least two runs)");
  return options;
};

const LIMITS: RunLimits = { timeoutMs: 120_000, maxFunctions: 1_000, decompileTimeoutMs: 10_000 };

const firstLine = (text: string) => text.trim().split("\n")[0] ?? "";

const environmentOf = async (engine: EngineSettings | null): Promise<Environment> => {
  const pkg = JSON.parse(await readFile(join(REPO_ROOT, "package.json"), "utf8")) as { version: string };
  const git = (...args: string[]) => spawnSync("git", ["-C", REPO_ROOT, "--no-optional-locks", ...args], { encoding: "utf8" });
  const head = git("rev-parse", "HEAD");
  const status = git("status", "--porcelain");
  let ghidraVersion: string | null = null;
  if (engine !== null) {
    const properties = await readFile(join(engine.ghidraDir, "Ghidra", "application.properties"), "utf8").catch(() => "");
    ghidraVersion = /^application\.version=(.+)$/mu.exec(properties)?.[1]?.trim() ?? null;
  }
  const java = spawnSync(engine?.javaHome === null || engine === null ? "java" : join(engine.javaHome, "bin", "java"), ["-version"], {
    encoding: "utf8",
  });
  const [cpu] = cpus();
  return {
    os: { platform: process.platform, release: release(), arch: process.arch },
    cpu: { model: cpu?.model ?? "unknown", count: cpus().length },
    memory_bytes: totalmem(),
    node: process.version,
    revscope: {
      version: pkg.version,
      commit: head.status === 0 ? head.stdout.trim() : null,
      worktree_dirty: status.status === 0 ? status.stdout.trim() !== "" : null,
    },
    ghidra: { version: ghidraVersion, decompiler: null },
    java: java.status === 0 ? firstLine(`${java.stderr}${java.stdout}`) : null,
    clang: toolVersion("clang"),
    nm: toolVersion("nm"),
  };
};

const ghidraCacheDir = `/var/tmp/${userInfo().username}-ghidra`;
const cacheState = () => (existsSync(ghidraCacheDir) ? `present, modified ${statSync(ghidraCacheDir).mtime.toISOString()}` : "absent");

const runProblems = (run: RunObservation, index: number): string[] => {
  const problems: string[] = [];
  const at = `run ${String(index + 1)}`;
  if (run.harness_killed) problems.push(`${at}: exceeded the harness's hard limit and was killed`);
  if (run.leftovers.temp_entries > 0) problems.push(`${at}: ${String(run.leftovers.temp_entries)} entries left in the run's temp directory`);
  if (run.leftovers.home_entries > 0) problems.push(`${at}: ${String(run.leftovers.home_entries)} entries left in the run's home directory`);
  if (run.leftovers.processes > 0) problems.push(`${at}: ${String(run.leftovers.processes)} processes still running`);
  for (const leak of run.leaks) problems.push(`${at}: output contains a sensitive value (${leak})`);
  // "not-created" is correct for refusals before any workspace exists; "failed" and "preserved" are not clean.
  if (run.cleanup_reported !== null && !["removed", "not-created"].includes(run.cleanup_reported.workspace))
    problems.push(`${at}: cleanup reported workspace ${run.cleanup_reported.workspace}`);
  if (run.cleanup_reported !== null && run.cleanup_reported.process === "failed") problems.push(`${at}: cleanup reported the process stop failed`);
  return problems;
};

const inputRecord = (input: BuiltInput, out: string) => ({
  file: relative(out, input.path),
  sha256: input.sha256,
  size: input.size,
  recipe: input.recipe,
});

const expectedOf = (spec: BenchmarkCase, truth: GroundTruth | null): Record<string, unknown> => {
  if (spec.kind === "rejection") return { accept: spec.accept, reaches_engine: spec.reachesEngine };
  return {
    outcome: "ok",
    names: spec.names,
    recovery: truth?.recovery ?? null,
    address_mode: truth?.addressMode ?? null,
    entry: truth === null ? null : { source: truth.entry.source, addresses: truth.entry.addresses.map((address) => `0x${address.toString(16)}`) },
    functions: truth?.functions.map(({ symbol, address, expected }) => ({
      symbol,
      address: `0x${address.toString(16)}`,
      params: expected.params,
      returns: expected.returns,
    })),
  };
};

interface Context {
  readonly out: string;
  readonly engine: EngineSettings;
  readonly repeat: number;
}

const analyzeCase = async (
  context: Context,
  spec: BenchmarkCase & { kind: "compiled" | "generated-elf" },
  input: BuiltInput,
  truth: GroundTruth,
): Promise<CaseResult> => {
  const runs: RunObservation[] = [];
  let metrics: CaseMetrics | null = null;
  const problems: string[] = [];
  const outputs = new Set<string>();
  for (let index = 0; index < context.repeat; index += 1) {
    const result = await runCli({
      node: process.execPath,
      bin: BIN,
      engine: context.engine,
      runRoot: join(context.out, "runs", spec.id, String(index + 1)),
      inputPath: input.path,
      authorized: true,
      limits: LIMITS,
      cancelAfterStartMs: null,
    });
    await writeFile(join(context.out, "raw", `${spec.id}.${String(index + 1)}.json`), result.stdout);
    runs.push(result.observation);
    outputs.add(result.observation.stdout_sha256);
    problems.push(...runProblems(result.observation, index));
    if (result.observation.outcome !== "ok") {
      problems.push(`run ${String(index + 1)}: outcome ${result.observation.outcome}`);
      continue;
    }
    const read = readSuccess(result.document);
    if (!read.ok) problems.push(`run ${String(index + 1)}: ${read.problem}`);
    else metrics ??= computeMetrics(truth, read.observed);
    say(`  ${spec.id} run ${String(index + 1)}: ${result.observation.outcome} in ${String(result.observation.wall_ms)} ms`);
  }
  if (metrics !== null)
    for (const [name, check] of Object.entries(metrics.exact)) if (!check.pass) problems.push(`${name}: ${check.detail}`);
  const identical = outputs.size === 1;
  if (!identical) problems.push(`output differed across ${String(context.repeat)} runs (${String(outputs.size)} distinct)`);
  return {
    id: spec.id,
    kind: spec.kind,
    category: spec.category,
    description: spec.description,
    status: problems.length === 0 ? "pass" : "fail",
    problems,
    input: inputRecord(input, context.out),
    expected: expectedOf(spec, truth),
    runs,
    determinism: { runs: context.repeat, identical, distinct_outputs: outputs.size },
    metrics,
  };
};

const rejectionCase = async (context: Context, spec: RejectionCase, input: BuiltInput): Promise<CaseResult> => {
  const result = await runCli({
    node: process.execPath,
    bin: BIN,
    engine: context.engine,
    runRoot: join(context.out, "runs", spec.id, "1"),
    inputPath: input.path,
    authorized: spec.input !== "unauthorized",
    limits: LIMITS,
    cancelAfterStartMs: null,
  });
  await writeFile(join(context.out, "raw", `${spec.id}.1.json`), result.stdout);
  const run = result.observation;
  const problems = runProblems(run, 0);
  if (!spec.accept.includes(run.outcome)) problems.push(`outcome ${run.outcome}, expected one of ${spec.accept.join(", ")}`);
  if (run.outcome !== "ok" && run.exit_code === 0) problems.push("an error exited with status 0");
  say(`  ${spec.id}: ${run.outcome} in ${String(run.wall_ms)} ms`);
  return {
    id: spec.id,
    kind: "rejection",
    category: spec.category,
    description: spec.description,
    status: problems.length === 0 ? "pass" : "fail",
    problems,
    input: input.sha256 === "" ? null : inputRecord(input, context.out),
    expected: expectedOf(spec, null),
    runs: [run],
    determinism: null,
    metrics: null,
  };
};

/** A real timeout: the engine API with Ghidra capped at 2 s, as the real-engine test does. */
const timeoutCase = async (context: Context, input: BuiltInput): Promise<CaseResult> => {
  const engineModule = (await import(pathToFileURL(join(REPO_ROOT, "dist", "infrastructure", "ghidra", "engine.js")).href)) as {
    GhidraEngine: typeof GhidraEngineType;
  };
  const dirs = await runDirectories(join(context.out, "runs", "reliability-timeout", "1"));
  const engine = new engineModule.GhidraEngine({
    settings: { ghidraDir: context.engine.ghidraDir, ...(context.engine.javaHome === null ? {} : { javaHome: context.engine.javaHome }) },
    tempParent: dirs.temp,
    maxChildRunMs: 2_000,
    host: minimalEnv(context.engine, dirs),
  });
  const started = performance.now();
  const result = await engine.analyze({
    path: input.path,
    limits: { timeoutMs: 60_000, maxFunctions: 200, decompile: true, decompileTimeoutMs: 10_000 },
    signal: new AbortController().signal,
  });
  const wall = Math.round(performance.now() - started);
  await new Promise((resolve) => setTimeout(resolve, 500));
  const tempEntries = (await readdir(dirs.temp)).length;
  const processes = processesMentioning([dirs.temp, dirs.tempReal]);
  const code = result.ok ? "ok" : result.error.code;
  const cleanup = result.ok ? result.value.cleanup : (result.error.details["cleanup"] as Record<string, unknown> | undefined);
  const problems: string[] = [];
  if (code !== "analysis_timeout" && code !== "analysis_incomplete") problems.push(`outcome ${code}, expected analysis_timeout or analysis_incomplete`);
  if (cleanup?.["workspace"] !== "removed") problems.push(`cleanup reported workspace ${String(cleanup?.["workspace"])}`);
  if (tempEntries > 0) problems.push(`${String(tempEntries)} entries left in the temp directory`);
  if (processes > 0) problems.push(`${String(processes)} processes still running`);
  say(`  reliability-timeout: ${code} in ${String(wall)} ms`);
  return {
    id: "reliability-timeout",
    kind: "reliability",
    category: [],
    description: "Real timeout: engine API, Ghidra capped at 2 s (internal test cap; the CLI's minimum timeout is 10 s)",
    status: problems.length === 0 ? "pass" : "fail",
    problems,
    input: inputRecord(input, context.out),
    expected: { outcome: ["analysis_timeout", "analysis_incomplete"], workspace: "removed", leftovers: 0 },
    runs: [],
    determinism: null,
    metrics: null,
    observed: { outcome: code, wall_ms: wall, cleanup: cleanup ?? null, temp_entries: tempEntries, processes },
  };
};

/** A real cancellation: SIGINT to the CLI once Ghidra is running. */
const cancelCase = async (context: Context, input: BuiltInput): Promise<CaseResult> => {
  const result = await runCli({
    node: process.execPath,
    bin: BIN,
    engine: context.engine,
    runRoot: join(context.out, "runs", "reliability-cancel", "1"),
    inputPath: input.path,
    authorized: true,
    limits: LIMITS,
    cancelAfterStartMs: 1_500,
  });
  await writeFile(join(context.out, "raw", "reliability-cancel.1.json"), result.stdout);
  const run = result.observation;
  const problems = runProblems(run, 0);
  if (run.outcome !== "cancelled") problems.push(`outcome ${run.outcome}, expected cancelled`);
  if (run.cleanup_reported?.workspace !== "removed") problems.push("cleanup did not report the workspace removed");
  say(`  reliability-cancel: ${run.outcome} in ${String(run.wall_ms)} ms`);
  return {
    id: "reliability-cancel",
    kind: "reliability",
    category: [],
    description: "Real cancellation: SIGINT to the CLI 1.5 s after Ghidra's process appears",
    status: problems.length === 0 ? "pass" : "fail",
    problems,
    input: inputRecord(input, context.out),
    expected: { outcome: "cancelled", workspace: "removed", leftovers: 0 },
    runs: [run],
    determinism: null,
    metrics: null,
  };
};

const notRun = (spec: { id: string; kind: CaseResult["kind"]; category: readonly number[]; description: string }, reason: string): CaseResult => ({
  ...spec,
  status: "not-run",
  problems: [reason],
  input: null,
  expected: {},
  runs: [],
  determinism: null,
  metrics: null,
});

const main = async () => {
  const options = parseArgs(process.argv.slice(2));
  const startedAt = new Date().toISOString();
  const out = options.out ?? join(tmpdir(), "revscope-benchmark", startedAt.replaceAll(/[:.]/gu, "-"));
  if (!relative(REPO_ROOT, out).startsWith("..")) throw new Error("--out must be outside the Revscope source tree");
  if (existsSync(out)) throw new Error("--out must not exist yet");
  await mkdir(join(out, "bin"), { recursive: true });
  await mkdir(join(out, "raw"), { recursive: true });
  say(`Revscope benchmark → ${out}`);

  const ghidraDir = process.env["REVSCOPE_GHIDRA_DIR"] ?? "";
  const javaHome = process.env["REVSCOPE_JAVA_HOME"] ?? "";
  const engine: EngineSettings | null = ghidraDir === "" ? null : { ghidraDir, javaHome: javaHome === "" ? null : javaHome };
  const environment = await environmentOf(engine);
  const cacheBefore = cacheState();
  const selected = CASES.filter(({ id }) => options.only === null || new RegExp(options.only, "u").test(id));
  const cases: CaseResult[] = [];
  const binDir = join(out, "bin");

  if (!existsSync(BIN)) throw new Error("dist/ is missing: run `npm run build` first (npm run benchmark does)");
  let anyMacho: string | null = null;
  let elfInput: BuiltInput | null = null;
  let machoInput: BuiltInput | null = null;
  for (const spec of selected) {
    say(`${spec.id}`);
    if (engine === null) {
      cases.push(notRun(spec, "REVSCOPE_GHIDRA_DIR is not set; no analysis can run"));
      continue;
    }
    const context: Context = { out, engine, repeat: options.repeat };
    if (spec.kind === "rejection") {
      const built = await buildRejection(spec, binDir, anyMacho);
      cases.push(built.ok ? await rejectionCase(context, spec, built.input) : notRun(spec, built.reason));
      continue;
    }
    const built = spec.kind === "compiled" ? await buildCompiled(spec, binDir) : await buildGeneratedElf(spec, binDir);
    if (!built.ok) {
      cases.push(notRun(spec, built.reason));
      continue;
    }
    if (spec.kind === "compiled" && spec.target === "macho-arm64" && !spec.stripped) {
      anyMacho ??= built.input.path;
      if (spec.id === "macho-control-O0") machoInput = built.input;
    }
    if (spec.id === "elf-generated") elfInput = built.input;
    cases.push(await analyzeCase(context, spec, built.input, built.truth));
  }

  // Reliability: real timeout and cancellation, on the generated ELF and a compiled Mach-O.
  if (options.only === null || new RegExp(options.only, "u").test("reliability")) {
    const reliability = { kind: "reliability" as const, category: [] as number[] };
    if (engine === null) {
      cases.push(notRun({ id: "reliability-timeout", description: "Real timeout", ...reliability }, "REVSCOPE_GHIDRA_DIR is not set"));
      cases.push(notRun({ id: "reliability-cancel", description: "Real cancellation", ...reliability }, "REVSCOPE_GHIDRA_DIR is not set"));
    } else {
      const context: Context = { out, engine, repeat: options.repeat };
      say("reliability");
      cases.push(
        elfInput === null
          ? notRun({ id: "reliability-timeout", description: "Real timeout", ...reliability }, "needs the elf-generated case")
          : await timeoutCase(context, elfInput),
      );
      cases.push(
        machoInput === null
          ? notRun({ id: "reliability-cancel", description: "Real cancellation", ...reliability }, "needs the macho-control-O0 case")
          : await cancelCase(context, machoInput),
      );
    }
  }

  // The decompiler state as Ghidra reported it, from the first successful run.
  const firstInfo = cases.flatMap(({ metrics }) => (metrics === null ? [] : [metrics])).length > 0 ? await decompilerState(out) : null;
  const results: Results = {
    schema: RESULTS_SCHEMA,
    harness_version: HARNESS_VERSION,
    started_at: startedAt,
    finished_at: new Date().toISOString(),
    environment: { ...environment, ghidra: { ...environment.ghidra, decompiler: firstInfo } },
    settings: { repeat: options.repeat, limits: LIMITS, only: options.only },
    host_checks: {
      ghidra_default_cache: { before: cacheBefore, after: cacheState() },
      note: "Ghidra's default cache directory (/var/tmp/<user>-ghidra) must not be created or modified by a run.",
    },
    cases,
    summary: summarize(cases),
  };
  await writeFile(join(out, "results.json"), `${JSON.stringify(results, null, 2)}\n`);
  await writeFile(join(out, "report.md"), renderReport(results));
  const { pass, fail } = results.summary.cases;
  say(`\n${String(pass)} pass, ${String(fail)} fail, ${String(results.summary.cases["not-run"])} not run`);
  say(`results: ${join(out, "results.json")}\nreport:  ${join(out, "report.md")}`);
  process.exitCode = fail === 0 && results.summary.cases["not-run"] === 0 && cacheBefore === cacheState() ? 0 : 1;
};

interface RawDocument {
  readonly ok?: boolean;
  readonly records?: readonly { readonly operation: { readonly name: string }; readonly payload: { readonly decompiler?: string } }[];
}

/** Ghidra's decompiler availability, read from the first raw success document. */
const decompilerState = async (out: string): Promise<string | null> => {
  for (const name of (await readdir(join(out, "raw"))).toSorted()) {
    let document: RawDocument | null;
    try {
      document = JSON.parse(await readFile(join(out, "raw", name), "utf8")) as RawDocument | null;
    } catch {
      continue;
    }
    const info = document?.ok === true ? document.records?.find(({ operation }) => operation.name === "program_info") : undefined;
    if (info?.payload.decompiler !== undefined) return info.payload.decompiler;
  }
  return null;
};

await main();
