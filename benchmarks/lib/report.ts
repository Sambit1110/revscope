/** Results document types and the Markdown summary rendered from them. Pure. */
import type { CaseMetrics } from "./metrics.ts";
import type { RunLimits, RunObservation } from "./execute.ts";

export const RESULTS_SCHEMA = "revscope.benchmark/1";
export const HARNESS_VERSION = "1";

export type CaseStatus = "pass" | "fail" | "not-run";

export interface CaseResult {
  readonly id: string;
  readonly kind: "compiled" | "generated-elf" | "rejection" | "reliability";
  readonly category: readonly number[];
  readonly description: string;
  readonly status: CaseStatus;
  /** Every reason for fail or not-run; empty on pass. */
  readonly problems: readonly string[];
  readonly input: { readonly file: string; readonly sha256: string; readonly size: number; readonly recipe: Record<string, string | boolean> } | null;
  readonly expected: Record<string, unknown>;
  readonly runs: readonly RunObservation[];
  readonly determinism: { readonly runs: number; readonly identical: boolean; readonly distinct_outputs: number } | null;
  readonly metrics: CaseMetrics | null;
  /** Free-form measured facts for reliability cases. */
  readonly observed?: Record<string, unknown>;
}

export interface Environment {
  readonly os: { readonly platform: string; readonly release: string; readonly arch: string };
  readonly cpu: { readonly model: string; readonly count: number };
  readonly memory_bytes: number;
  readonly node: string;
  readonly revscope: { readonly version: string; readonly commit: string | null; readonly worktree_dirty: boolean | null };
  readonly ghidra: { readonly version: string | null; readonly decompiler: string | null };
  readonly java: string | null;
  readonly clang: string | null;
  readonly nm: string | null;
}

export interface Results {
  readonly schema: typeof RESULTS_SCHEMA;
  readonly harness_version: typeof HARNESS_VERSION;
  readonly started_at: string;
  readonly finished_at: string;
  readonly environment: Environment;
  readonly settings: { readonly repeat: number; readonly limits: RunLimits; readonly only: string | null };
  readonly host_checks: Record<string, unknown>;
  readonly cases: readonly CaseResult[];
  readonly summary: Summary;
}

export interface Summary {
  readonly cases: Record<CaseStatus, number>;
  readonly exact: {
    readonly recovery: { readonly expected: number; readonly recovered: number };
    readonly names: { readonly checked: number; readonly exact: number };
    readonly entry: { readonly checked: number; readonly correct: number };
    readonly address_range: { readonly checked: number; readonly well_formed: number };
    readonly export_complete: { readonly checked: number; readonly complete: number };
    readonly deterministic: { readonly checked: number; readonly identical: number };
    readonly clean_runs: { readonly checked: number; readonly clean: number };
  };
  readonly approximate: {
    readonly return_type: Record<string, number>;
    readonly param_count: Record<string, number>;
    readonly param_types: Record<string, number>;
  };
  readonly heuristic: { readonly checked: number; readonly present: number };
  readonly decompiler: { readonly decompiled: number; readonly complete: number; readonly uncertain: number; readonly warnings: number };
}

const add = (into: Record<string, number>, from: Readonly<Record<string, number>>) => {
  for (const [key, value] of Object.entries(from)) into[key] = (into[key] ?? 0) + value;
};

const isClean = (run: RunObservation) =>
  run.leftovers.temp_entries === 0 &&
  run.leftovers.home_entries === 0 &&
  run.leftovers.processes === 0 &&
  run.leaks.length === 0 &&
  !run.harness_killed;

export const summarize = (cases: readonly CaseResult[]): Summary => {
  const statuses: Record<CaseStatus, number> = { pass: 0, fail: 0, "not-run": 0 };
  const exact = {
    recovery: { expected: 0, recovered: 0 },
    names: { checked: 0, exact: 0 },
    entry: { checked: 0, correct: 0 },
    address_range: { checked: 0, well_formed: 0 },
    export_complete: { checked: 0, complete: 0 },
    deterministic: { checked: 0, identical: 0 },
    clean_runs: { checked: 0, clean: 0 },
  };
  const approximate = { return_type: {}, param_count: {}, param_types: {} };
  const heuristic = { checked: 0, present: 0 };
  const decompiler = { decompiled: 0, complete: 0, uncertain: 0, warnings: 0 };
  for (const result of cases) {
    statuses[result.status] += 1;
    for (const run of result.runs) {
      exact.clean_runs.checked += 1;
      if (isClean(run)) exact.clean_runs.clean += 1;
    }
    if (result.determinism !== null) {
      exact.deterministic.checked += 1;
      if (result.determinism.identical) exact.deterministic.identical += 1;
    }
    const { metrics } = result;
    if (metrics === null) continue;
    exact.recovery.expected += metrics.exact.recovery.expected;
    exact.recovery.recovered += metrics.exact.recovery.recovered;
    exact.names.checked += metrics.exact.names.checked;
    exact.names.exact += metrics.exact.names.exact;
    exact.entry.checked += 1;
    if (metrics.exact.entry.pass) exact.entry.correct += 1;
    exact.address_range.checked += 1;
    if (metrics.exact.address_range.pass) exact.address_range.well_formed += 1;
    exact.export_complete.checked += 1;
    if (metrics.exact.export.pass) exact.export_complete.complete += 1;
    add(approximate.return_type, metrics.approximate.return_type);
    add(approximate.param_count, metrics.approximate.param_count);
    add(approximate.param_types, metrics.approximate.param_types);
    heuristic.checked += metrics.heuristic.pseudocode_hints.checked;
    heuristic.present += metrics.heuristic.pseudocode_hints.present;
    decompiler.decompiled += metrics.decompiler.decompiled;
    decompiler.complete += metrics.decompiler.fidelity.complete;
    decompiler.uncertain += metrics.decompiler.fidelity.uncertain;
    decompiler.warnings += metrics.decompiler.warnings;
  }
  return { cases: statuses, exact, approximate, heuristic, decompiler };
};

const median = (values: readonly number[]): number | null => {
  if (values.length === 0) return null;
  const sorted = values.toSorted((left, right) => left - right);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 1 ? (sorted[middle] ?? null) : Math.round(((sorted[middle - 1] ?? 0) + (sorted[middle] ?? 0)) / 2);
};

const seconds = (ms: number | null) => (ms === null ? "—" : `${(ms / 1000).toFixed(1)} s`);
const mib = (bytes: number | null) => (bytes === null ? "—" : `${Math.round(bytes / 1024 / 1024)} MiB`);
const ratio = (part: number, whole: number) => (whole === 0 ? "—" : `${String(part)}/${String(whole)}`);
const cell = (text: string) => text.replaceAll("|", "\\|").replaceAll("\n", " ");

export const performanceOf = (runs: readonly RunObservation[]) => {
  const peaks = runs.map(({ peak_rss_bytes: peak }) => peak).filter((peak): peak is number => peak !== null);
  return {
    wall_ms_median: median(runs.map(({ wall_ms: wall }) => wall)),
    peak_rss_bytes_max: peaks.length === 0 ? null : Math.max(...peaks),
  };
};

export const renderReport = (results: Results): string => {
  const { summary, environment: env } = results;
  const lines: string[] = [];
  const push = (...more: string[]) => lines.push(...more);
  push(
    "# Revscope benchmark report",
    "",
    `Schema \`${results.schema}\`, harness ${results.harness_version}. Started ${results.started_at}, finished ${results.finished_at}.`,
    "",
    "## Environment",
    "",
    `- Revscope ${env.revscope.version} at ${env.revscope.commit ?? "unknown commit"}${env.revscope.worktree_dirty === true ? " (uncommitted changes present)" : ""}`,
    `- Ghidra ${env.ghidra.version ?? "unknown"}, decompiler ${env.ghidra.decompiler ?? "unknown"}; ${env.java ?? "java version unknown"}`,
    `- ${env.os.platform} ${env.os.release} ${env.os.arch}; ${env.cpu.model} × ${String(env.cpu.count)}; ${mib(env.memory_bytes)} RAM; Node.js ${env.node}`,
    `- ${env.clang ?? "clang unavailable"}; ${env.nm ?? "nm unavailable"}`,
    `- Limits: timeout ${String(results.settings.limits.timeoutMs)} ms, max functions ${String(results.settings.limits.maxFunctions)}, decompile timeout ${String(results.settings.limits.decompileTimeoutMs)} ms; ${String(results.settings.repeat)} runs per analyzed case`,
    "",
    "## Summary",
    "",
    `Cases: ${String(summary.cases.pass)} pass, ${String(summary.cases.fail)} fail, ${String(summary.cases["not-run"])} not run.`,
    "",
    "**Exact** (equality with ground truth):",
    "",
    `- Functions recovered at the ground-truth address: ${ratio(summary.exact.recovery.recovered, summary.exact.recovery.expected)}`,
    `- Display name equals the symbol-table name (unstripped inputs): ${ratio(summary.exact.names.exact, summary.exact.names.checked)}`,
    `- Program entry correct: ${ratio(summary.exact.entry.correct, summary.exact.entry.checked)}`,
    `- Program address range well formed (min ≤ max): ${ratio(summary.exact.address_range.well_formed, summary.exact.address_range.checked)}`,
    `- Export complete: ${ratio(summary.exact.export_complete.complete, summary.exact.export_complete.checked)}`,
    `- Byte-identical output across repeated runs: ${ratio(summary.exact.deterministic.identical, summary.exact.deterministic.checked)} cases`,
    `- Runs with nothing left behind and nothing sensitive in the output: ${ratio(summary.exact.clean_runs.clean, summary.exact.clean_runs.checked)}`,
    "",
    "**Approximate** (decompiler signatures against the C source; partial agreement is not counted as agreement):",
    "",
    `- Return type: ${Object.entries(summary.approximate.return_type).map(([key, value]) => `${key} ${String(value)}`).join(", ")}`,
    `- Parameter count: ${Object.entries(summary.approximate.param_count).map(([key, value]) => `${key} ${String(value)}`).join(", ")}`,
    `- Parameter types: ${Object.entries(summary.approximate.param_types).map(([key, value]) => `${key} ${String(value)}`).join(", ")}`,
    "",
    `**Heuristic** (expected token present in pseudocode; not evidence of correctness): ${ratio(summary.heuristic.present, summary.heuristic.checked)}`,
    "",
    `**Decompiler:** ${String(summary.decompiler.decompiled)} decompiled; fidelity complete ${String(summary.decompiler.complete)}, uncertain ${String(summary.decompiler.uncertain)}; ${String(summary.decompiler.warnings)} decompiler warnings.`,
    "",
    "## Cases",
    "",
    "| Case | Status | Outcome | Recovered | Names | Entry | Return / params (exact) | Uncertain | Deterministic | Median wall | Peak RSS |",
    "|---|---|---|---|---|---|---|---|---|---|---|",
  );
  for (const result of results.cases) {
    const metrics = result.metrics;
    const perf = performanceOf(result.runs);
    const outcomes = [...new Set(result.runs.map(({ outcome }) => outcome))].join(", ") || "—";
    const exactReturns = metrics?.approximate.return_type.exact ?? 0;
    const signatureCount = metrics?.approximate.per_function.length ?? 0;
    push(
      `| ${cell(result.id)} | ${result.status} | ${cell(outcomes)} | ${metrics === null ? "—" : ratio(metrics.exact.recovery.recovered, metrics.exact.recovery.expected)} | ${
        metrics === null ? "—" : metrics.exact.names.expectation === "symbol-table" ? ratio(metrics.exact.names.exact, metrics.exact.names.checked) : `${String(metrics.exact.names.generated)} generated`
      } | ${metrics === null ? "—" : metrics.exact.entry.pass ? "yes" : "no"} | ${
        metrics === null ? "—" : `${ratio(exactReturns, signatureCount)} / ${ratio(metrics.approximate.param_count.match, signatureCount)}`
      } | ${metrics === null ? "—" : String(metrics.decompiler.fidelity.uncertain)} | ${
        result.determinism === null ? "—" : result.determinism.identical ? `yes (${String(result.determinism.runs)})` : "no"
      } | ${seconds(perf.wall_ms_median)} | ${mib(perf.peak_rss_bytes_max)} |`,
    );
  }
  const problems = results.cases.filter(({ problems: list }) => list.length > 0);
  push("", "## Failures and cases not run", "");
  if (problems.length === 0) push("None.");
  for (const result of problems) push(`- **${result.id}** (${result.status}): ${result.problems.map(cell).join("; ")}`);
  push("", "## Host checks", "", "```json", JSON.stringify(results.host_checks, null, 2), "```", "");
  return lines.join("\n");
};
