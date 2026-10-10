/**
 * Optional comparison with REA's Ghidra provider, under the same conditions.
 *
 *   REA_DIR=/abs/rea-checkout REVSCOPE_GHIDRA_DIR=/abs/ghidra REVSCOPE_JAVA_HOME=/abs/jdk \
 *     node benchmarks/compare-rea.ts --from <benchmark output dir> [--out <dir>] [--only <regex>] [--repeat <n>]
 *
 * Equivalence: both tools get the same Ghidra installation, the same JDK,
 * the exact input files the benchmark built (hashes re-checked), Ghidra's
 * default auto-analysis, and run one at a time on the same machine.
 *
 * REA is only run, never changed: it gets a private HOME and TMPDIR and a
 * minimal environment, and the script fails if any file in the REA checkout
 * is newer than its start marker afterwards. REA's code is not copied or
 * imported; only its CLI's JSON output is read.
 *
 * Engine differences (same Ghidra, so expected to be none) are kept apart
 * from orchestration differences (how each tool runs Ghidra and presents
 * its results).
 */
import { spawn, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

import { runCli, runDirectories, splitTimeReport, type EngineSettings, type RunLimits } from "./lib/execute.ts";
import { sha256 } from "./lib/fixtures.ts";
import { parseSignature } from "./lib/signature.ts";

const REPO_ROOT = fileURLToPath(new URL("../", import.meta.url));
const BIN = join(REPO_ROOT, "dist", "bin", "revscope.js");
const SCHEMA = "revscope.rea-comparison/1";
const LIMITS: RunLimits = { timeoutMs: 120_000, maxFunctions: 1_000, decompileTimeoutMs: 10_000 };
const REA_HARD_LIMIT_MS = 180_000;

const say = (line: string) => void process.stdout.write(`${line}\n`);

interface BenchmarkCaseRecord {
  readonly id: string;
  readonly status: string;
  readonly kind: string;
  readonly input: { readonly file: string; readonly sha256: string } | null;
  readonly expected: { readonly functions?: readonly { readonly symbol: string; readonly address: string }[]; readonly address_mode?: string };
}

interface ReaRun {
  readonly exit_code: number | null;
  readonly wall_ms: number;
  readonly peak_rss_bytes: number | null;
  readonly temp_entries_after: number;
  readonly ok: boolean;
  readonly result: unknown;
}

/** One REA CLI call: private HOME and TMPDIR, minimal environment, hard limit, peak RSS. */
const runRea = async (rea: { dir: string; javaHome: string; ghidraDir: string }, root: string, args: readonly string[]): Promise<ReaRun> => {
  const dirs = await runDirectories(root);
  const child = spawn("/usr/bin/time", ["-l", process.execPath, join(rea.dir, "scripts", "rea.mjs"), ...args, "--format", "json"], {
    env: {
      PATH: process.env["PATH"] ?? "/usr/bin:/bin",
      HOME: dirs.home,
      TMPDIR: dirs.temp,
      LANG: "C",
      GHIDRA_INSTALL_DIR: rea.ghidraDir,
      JAVA_HOME: rea.javaHome,
    },
    cwd: dirs.home,
    detached: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8").on("data", (chunk: string) => (stdout += chunk));
  child.stderr.setEncoding("utf8").on("data", (chunk: string) => (stderr += chunk));
  const started = performance.now();
  const limit = setTimeout(() => {
    try {
      if (child.pid !== undefined) process.kill(-child.pid, "SIGKILL");
    } catch {
      // Already gone.
    }
  }, REA_HARD_LIMIT_MS);
  const code = await new Promise<number | null>((resolve) => child.on("close", resolve));
  clearTimeout(limit);
  const wall = Math.round(performance.now() - started);
  let parsed: unknown = null;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    parsed = null;
  }
  const result = (parsed as { normalized_result?: unknown } | null)?.normalized_result ?? null;
  return {
    exit_code: code,
    wall_ms: wall,
    peak_rss_bytes: splitTimeReport(stderr).peakRss,
    temp_entries_after: (await readdir(dirs.temp).catch(() => [])).length,
    ok: code === 0 && result !== null,
    result,
  };
};

/** Files in a directory tree modified after a moment, found with find(1); read-only. */
const modifiedSince = (directory: string, marker: string): string[] => {
  const found = spawnSync("find", [directory, "-newer", marker], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  return (found.stdout ?? "").split("\n").filter((line) => line !== "").map((line) => relative(directory, line));
};

const sum = (values: readonly number[]) => values.reduce((total, value) => total + value, 0);
/** The signature line: the first line that is neither blank nor a decompiler comment (warnings precede it). */
const firstLine = (pseudocode: string): string =>
  pseudocode.split("\n").find((line) => line.trim() !== "" && !line.trim().startsWith("/*"))?.trim() ?? "";
const squash = (text: string): string => text.replaceAll(/\s+/gu, " ").trim();
const median = (values: readonly number[]) => {
  const sorted = values.toSorted((left, right) => left - right);
  return sorted.length === 0 ? null : (sorted[Math.floor(sorted.length / 2)] ?? null);
};

interface RevscopeView {
  readonly functions: Map<string, { name: string; ghidra_name: string }>;
  readonly decompiled: Map<string, { signature: string | null; pseudocode: string | null; fidelity: string | null }>;
}

const revscopeView = (document: unknown): RevscopeView | null => {
  const records = (document as { ok?: boolean; records?: { operation: { name: string }; payload: Record<string, unknown> }[] } | null)?.records;
  if (records === undefined) return null;
  const list = records.find(({ operation }) => operation.name === "list_functions")?.payload["functions"] as
    | { address: string; name: string; ghidra_name: string }[]
    | undefined;
  if (list === undefined) return null;
  const decompiled = new Map<string, { signature: string | null; pseudocode: string | null; fidelity: string | null }>();
  for (const { operation, payload } of records)
    if (operation.name === "decompile")
      decompiled.set(payload["address"] as string, {
        signature: (payload["decompiler"] as { signature?: string } | null)?.signature ?? null,
        pseudocode: (payload["pseudocode"] as string | null) ?? null,
        fidelity: (payload["fidelity"] as string | null) ?? null,
      });
  return { functions: new Map(list.map(({ address, name, ghidra_name: ghidraName }) => [address, { name, ghidra_name: ghidraName }])), decompiled };
};

const main = async () => {
  const argv = process.argv.slice(2);
  const option = (flag: string) => {
    const index = argv.indexOf(flag);
    return index < 0 ? null : (argv[index + 1] ?? null);
  };
  const from = option("--from");
  const only = option("--only");
  const repeat = Number(option("--repeat") ?? "2");
  const reaDir = process.env["REA_DIR"] ?? "";
  const ghidraDir = process.env["REVSCOPE_GHIDRA_DIR"] ?? "";
  const javaHome = process.env["REVSCOPE_JAVA_HOME"] ?? "";
  if (from === null) throw new Error("--from <benchmark output directory> is required");
  if (reaDir === "" || ghidraDir === "" || javaHome === "")
    throw new Error("REA_DIR, REVSCOPE_GHIDRA_DIR and REVSCOPE_JAVA_HOME must all be set, so both tools use the same Ghidra and JDK");
  if (!Number.isInteger(repeat) || repeat < 1 || repeat > 10) throw new Error("--repeat must be 1-10");
  const startedAt = new Date().toISOString();
  const out = option("--out") ?? join(tmpdir(), "revscope-rea-comparison", startedAt.replaceAll(/[:.]/gu, "-"));
  if (!relative(REPO_ROOT, out).startsWith("..")) throw new Error("--out must be outside the Revscope source tree");
  if (existsSync(out)) throw new Error("--out must not exist yet");
  await mkdir(join(out, "raw"), { recursive: true });

  const benchmark = JSON.parse(await readFile(join(from, "results.json"), "utf8")) as { cases: BenchmarkCaseRecord[] };
  const selected = benchmark.cases.filter(
    (entry) => entry.input !== null && (entry.kind === "compiled" || entry.kind === "generated-elf") && entry.status !== "not-run" && (only === null || new RegExp(only, "u").test(entry.id)),
  );
  const reaPackage = JSON.parse(await readFile(join(reaDir, "package.json"), "utf8")) as { name: string; version: string };
  const reaCommit = spawnSync("git", ["-C", reaDir, "--no-optional-locks", "rev-parse", "HEAD"], { encoding: "utf8" });
  const engine: EngineSettings = { ghidraDir, javaHome };
  const rea = { dir: reaDir, javaHome, ghidraDir };

  // Anything in the REA checkout newer than this marker means the run changed it.
  const marker = join(out, "rea-start-marker");
  await writeFile(marker, "");
  await new Promise((resolve) => setTimeout(resolve, 1_100));

  const cases: Record<string, unknown>[] = [];
  for (const entry of selected) {
    if (entry.input === null) continue;
    const path = join(from, entry.input.file);
    const bytes = await readFile(path);
    if (sha256(bytes) !== entry.input.sha256) throw new Error(`${entry.id}: input changed since the benchmark built it`);
    say(entry.id);
    const root = join(out, "runs", entry.id);

    // Revscope: full analysis (list + decompile everything) and list-only, `repeat` times each.
    const revscopeFull = [];
    const revscopeList = [];
    let revscopeDocument: unknown = null;
    for (let index = 0; index < repeat; index += 1) {
      const full = await runCli({ node: process.execPath, bin: BIN, engine, runRoot: join(root, `revscope-full-${String(index)}`), inputPath: path, authorized: true, limits: LIMITS, cancelAfterStartMs: null });
      revscopeFull.push(full.observation);
      revscopeDocument ??= full.document;
      const list = await runCli({ node: process.execPath, bin: BIN, engine, runRoot: join(root, `revscope-list-${String(index)}`), inputPath: path, authorized: true, limits: LIMITS, decompile: false, cancelAfterStartMs: null });
      revscopeList.push(list.observation);
    }
    await writeFile(join(out, "raw", `${entry.id}.revscope.json`), JSON.stringify(revscopeDocument));
    const view = revscopeView(revscopeDocument);

    // REA: list procedures `repeat` times, then decompile each function Revscope decompiled, once.
    const reaLists: ReaRun[] = [];
    for (let index = 0; index < repeat; index += 1)
      reaLists.push(await runRea(rea, join(root, `rea-list-${String(index)}`), ["search", path, "--kind", "procedures", "--mode", "regex", "--pattern", ".*", "--provider", "ghidra"]));
    const procedures = (reaLists[0]?.result as { address: string; value: string }[] | null) ?? [];
    const reaDeterministic = reaLists.every((run) => JSON.stringify(run.result) === JSON.stringify(reaLists[0]?.result));
    await writeFile(join(out, "raw", `${entry.id}.rea-procedures.json`), JSON.stringify(procedures));

    const defaultSpace = procedures.filter(({ address }) => /^0x[0-9a-f]+$/u.test(address));
    const reaNames = new Map(defaultSpace.map(({ address, value }) => [address, value]));
    const revscopeAddresses = new Set(view?.functions.keys() ?? []);
    const reaAddresses = new Set(reaNames.keys());

    const reaDecompiles: { address: string; run: ReaRun }[] = [];
    for (const address of view?.decompiled.keys() ?? [])
      reaDecompiles.push({ address, run: await runRea(rea, join(root, `rea-decompile-${address}`), ["decompile", path, address, "--provider", "ghidra"]) });

    const functionComparisons = [...(view?.functions.entries() ?? [])].map(([address, revscope]) => {
      const reaName = reaNames.get(address) ?? null;
      const ours = view?.decompiled.get(address);
      const theirs = reaDecompiles.find((item) => item.address === address)?.run;
      const reaPseudocode = typeof theirs?.result === "string" ? theirs.result : null;
      return {
        address,
        revscope_display_name: revscope.name,
        ghidra_name_via_revscope: revscope.ghidra_name,
        ghidra_name_via_rea: reaName,
        engine_name_agrees: reaName === revscope.ghidra_name,
        display_name_differs_from_ghidra_name: revscope.name !== revscope.ghidra_name,
        revscope_signature: ours?.signature ?? null,
        rea_signature_line: reaPseudocode === null ? null : firstLine(reaPseudocode),
        signature_agrees:
          ours?.signature !== null && ours?.signature !== undefined && reaPseudocode !== null && squash(ours.signature) === squash(firstLine(reaPseudocode)),
        pseudocode_agrees: ours?.pseudocode !== null && ours?.pseudocode !== undefined && reaPseudocode !== null && squash(ours.pseudocode) === squash(reaPseudocode),
        revscope_fidelity: ours?.fidelity ?? null,
        rea_decompile_ok: theirs?.ok ?? null,
        parsed_signature_agrees:
          ours?.signature === null || ours?.signature === undefined || reaPseudocode === null
            ? null
            : JSON.stringify(parseSignature(ours.signature, revscope.ghidra_name, null)) ===
              JSON.stringify(parseSignature(firstLine(reaPseudocode), revscope.ghidra_name, null)),
      };
    });

    const groundTruth = entry.expected.address_mode === "absolute" ? (entry.expected.functions ?? []) : [];
    cases.push({
      id: entry.id,
      input_sha256: entry.input.sha256,
      engine: {
        // Same Ghidra, same input: these should agree; any difference is reported, not explained away.
        function_addresses: {
          revscope: revscopeAddresses.size,
          rea_default_space: reaAddresses.size,
          rea_other_spaces: procedures.length - defaultSpace.length,
          only_revscope: [...revscopeAddresses].filter((address) => !reaAddresses.has(address)),
          only_rea: [...reaAddresses].filter((address) => !revscopeAddresses.has(address)),
        },
        ghidra_names_agree: functionComparisons.filter(({ engine_name_agrees: agree }) => agree).length,
        signatures_agree: functionComparisons.filter(({ signature_agrees: agree }) => agree).length,
        pseudocode_agrees: functionComparisons.filter(({ pseudocode_agrees: agree }) => agree).length,
        compared: functionComparisons.length,
      },
      ground_truth: groundTruth.length === 0
        ? null
        : {
            functions: groundTruth.length,
            revscope_display_name_matches: groundTruth.filter(({ symbol, address }) => view?.functions.get(address)?.name === symbol).length,
            rea_name_matches: groundTruth.filter(({ symbol, address }) => reaNames.get(address) === symbol).length,
            revscope_reports_symbol_somewhere: groundTruth.filter(({ symbol, address }) => {
              const found = revscopeDocument === null ? undefined : view?.functions.get(address);
              return found !== undefined && (found.name === symbol || found.ghidra_name === symbol);
            }).length,
          },
      orchestration: {
        revscope_full: { invocations: 1, wall_ms_median: median(revscopeFull.map(({ wall_ms: wall }) => wall)), peak_rss_bytes_max: Math.max(...revscopeFull.map(({ peak_rss_bytes: peak }) => peak ?? 0)), outcomes: revscopeFull.map(({ outcome }) => outcome) },
        revscope_list_only: { invocations: 1, wall_ms_median: median(revscopeList.map(({ wall_ms: wall }) => wall)), peak_rss_bytes_max: Math.max(...revscopeList.map(({ peak_rss_bytes: peak }) => peak ?? 0)) },
        rea_list: { invocations: 1, wall_ms_median: median(reaLists.map(({ wall_ms: wall }) => wall)), peak_rss_bytes_max: Math.max(...reaLists.map(({ peak_rss_bytes: peak }) => peak ?? 0)), ok: reaLists.every(({ ok }) => ok), deterministic: reaDeterministic },
        rea_list_plus_decompile_all: {
          invocations: 1 + reaDecompiles.length,
          wall_ms_total: (median(reaLists.map(({ wall_ms: wall }) => wall)) ?? 0) + sum(reaDecompiles.map(({ run }) => run.wall_ms)),
          decompile_failures: reaDecompiles.filter(({ run }) => !run.ok).length,
        },
        rea_temp_entries_left: sum([...reaLists, ...reaDecompiles.map(({ run }) => run)].map(({ temp_entries_after: left }) => left)),
        names_presented_differently: functionComparisons.filter(({ display_name_differs_from_ghidra_name: differs }) => differs).map(({ address, revscope_display_name: shown, ghidra_name_via_rea: reaName }) => `${address}: Revscope ${shown}, REA ${String(reaName)}`),
      },
      functions: functionComparisons,
    });
    say(`  revscope full ${String(median(revscopeFull.map(({ wall_ms: wall }) => wall)))} ms; rea list ${String(median(reaLists.map(({ wall_ms: wall }) => wall)))} ms + ${String(reaDecompiles.length)} decompile calls`);
  }

  const changed = modifiedSince(reaDir, marker);
  const results = {
    schema: SCHEMA,
    started_at: startedAt,
    finished_at: new Date().toISOString(),
    from_benchmark: relative(out, from),
    rea: { package: reaPackage.name, version: reaPackage.version, commit: reaCommit.status === 0 ? reaCommit.stdout.trim() : null, provider: "ghidra" },
    conditions: {
      same_ghidra_installation: true,
      same_java_home: true,
      same_input_files: "sha256 re-checked against the benchmark",
      analysis: "Ghidra default auto-analysis in both",
      sequential: true,
      repeat,
      revscope_limits: LIMITS,
      rea_limits: `no per-call limits exposed by its CLI; the harness kills a call after ${String(REA_HARD_LIMIT_MS)} ms`,
    },
    rea_checkout_unchanged: changed.length === 0,
    rea_checkout_changes: changed.slice(0, 50),
    cases,
  };
  await writeFile(join(out, "comparison.json"), `${JSON.stringify(results, null, 2)}\n`);
  say(`REA checkout unchanged: ${String(changed.length === 0)}`);
  say(`comparison: ${join(out, "comparison.json")}`);
  process.exitCode = changed.length === 0 ? 0 : 1;
};

await main();
