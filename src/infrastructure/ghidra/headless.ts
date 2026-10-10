import type { BinaryAnalysisLimits } from "../../application/ports.js";
import type { EnvironmentPolicy } from "../envPolicy.js";
import { EXPORT_LIMITS } from "./exportFormat.js";
import type { GhidraInstallation } from "./installation.js";
import type { Workspace } from "./workspace.js";

export const EXPORT_SCRIPT = "RevscopeExport.java";

/**
 * How the total operation timeout is divided. The child's own deadline
 * (runChild: timeout + killGrace + settle) plus `reserveMs` for copying,
 * parsing and removal must fit inside the caller's timeout.
 */
export interface EngineTiming {
  /** SIGTERM to SIGKILL; Ghidra's JVM gets this long to exit cleanly. */
  readonly killGraceMs: number;
  /** runChild's final cleanup and verification window. */
  readonly settleMs: number;
  /** Work outside the child: copying the input, reading the export, removing the workspace. */
  readonly reserveMs: number;
  /** The script stops exporting this long before the child's deadline, to write its trailer and exit. */
  readonly scriptMarginMs: number;
  /** Below this, Ghidra is not started at all. */
  readonly minChildMs: number;
}

export const DEFAULT_TIMING: EngineTiming = {
  killGraceMs: 2_000,
  settleMs: 1_000,
  reserveMs: 2_000,
  scriptMarginMs: 3_000,
  minChildMs: 2_000,
};

export interface HeadlessPlan {
  readonly args: readonly string[];
  readonly environment: EnvironmentPolicy;
  readonly childTimeoutMs: number;
  readonly analysisTimeoutSeconds: number;
  readonly scriptDeadlineEpochMs: number;
}

/**
 * Plan one analyzeHeadless run, or return null when the remaining budget is
 * too small to start Ghidra. All paths are workspace paths; the caller's
 * path never reaches Ghidra.
 */
export const planHeadless = (options: {
  readonly installation: GhidraInstallation;
  readonly workspace: Workspace;
  readonly scriptDir: string;
  readonly limits: BinaryAnalysisLimits;
  /** performance.now() at which the whole operation must have returned. */
  readonly deadlineAt: number;
  readonly timing: EngineTiming;
  /** Optional cap on how long Ghidra itself may run. */
  readonly maxChildRunMs?: number;
}): HeadlessPlan | null => {
  const { installation, workspace, scriptDir, limits, timing } = options;
  const available = options.deadlineAt - performance.now() - timing.killGraceMs - timing.settleMs - timing.reserveMs;
  const childTimeoutMs = Math.floor(Math.min(available, options.maxChildRunMs ?? Number.POSITIVE_INFINITY));
  if (childTimeoutMs < timing.minChildMs) return null;
  // Auto-analysis gets at most half of the child's time; the rest is for import and export.
  const analysisTimeoutSeconds = Math.max(1, Math.floor(childTimeoutMs / 2 / 1000));
  // An absolute wall-clock deadline for the script, so per-function limits cannot outlast the run.
  const scriptDeadlineEpochMs = Date.now() + childTimeoutMs - timing.scriptMarginMs;
  const decompileTimeoutSeconds = Math.max(1, Math.ceil(limits.decompileTimeoutMs / 1000));
  const args = [
    workspace.project,
    "revscope",
    "-import",
    workspace.input,
    "-scriptPath",
    scriptDir,
    "-postScript",
    EXPORT_SCRIPT,
    workspace.exportPath,
    String(limits.maxFunctions),
    String(limits.decompile),
    String(decompileTimeoutSeconds),
    String(scriptDeadlineEpochMs),
    String(EXPORT_LIMITS.pseudocodeChars),
    "-analysisTimeoutPerFile",
    String(analysisTimeoutSeconds),
    "-max-cpu",
    "2",
    "-deleteProject",
    "-log",
    `${workspace.logs}/application.log`,
    "-scriptlog",
    `${workspace.logs}/script.log`,
  ];
  // Java ignores $HOME for user.home, so Ghidra's directories are redirected
  // into the workspace through JAVA_TOOL_OPTIONS. Ghidra's documented
  // overrides (support/launch.properties) are set explicitly: without
  // application.cachedir its packed-database cache goes to
  // /var/tmp/<user>-ghidra on macOS and Linux, outside the workspace.
  // Workspace paths contain no whitespace (see createWorkspace).
  const javaOptions = [
    `-Duser.home=${workspace.home}`,
    `-Djava.io.tmpdir=${workspace.tmp}`,
    `-Dapplication.settingsdir=${workspace.home}`,
    `-Dapplication.cachedir=${workspace.cache}`,
    `-Dapplication.tempdir=${workspace.tmp}`,
    "-Djava.awt.headless=true",
  ].join(" ");
  const environment: EnvironmentPolicy = {
    set: {
      HOME: workspace.home,
      TMPDIR: workspace.tmp,
      JAVA_TOOL_OPTIONS: javaOptions,
      ...(installation.javaHome === null ? {} : { JAVA_HOME: installation.javaHome }),
    },
  };
  return { args, environment, childTimeoutMs, analysisTimeoutSeconds, scriptDeadlineEpochMs };
};

/** Engine failures recognised from Ghidra's output. The text itself is never reported. */
export type HeadlessFailure =
  | "unsupported_format"
  | "malformed_input"
  | "java_runtime"
  | "export_script_failed"
  | "import_failed"
  | "engine_failed";

/**
 * Best-effort classification of a run that produced no export, from
 * Ghidra's console output and logs. These patterns follow Ghidra's
 * documented messages and are unverified until the real-engine tests run.
 */
export const classifyHeadlessOutput = (text: string): HeadlessFailure => {
  if (/No load spec found/iu.test(text)) return "unsupported_format";
  // A loader accepted the format but found nothing it could load from the
  // file: Ghidra 12.1.4 reports this for a truncated ELF ("No memory blocks
  // were defined", after "N of N program headers are truncated/missing from
  // file"). Both depend only on the file's bytes, so retrying cannot help.
  if (/No memory blocks were defined for file/iu.test(text) || (/truncated\/missing from file/iu.test(text) && /Import failed/iu.test(text)))
    return "malformed_input";
  if (/could not be found and must be manually chosen|Unable to prompt user for JDK path|Failed to find a supported JDK|unsupported JDK|not a supported JDK/iu.test(text))
    return "java_runtime";
  if (/Script not found|Failed to compile|Unable to compile|script error|GhidraScript.*(?:failed|error)/iu.test(text))
    return "export_script_failed";
  if (/Import failed|ERROR REPORT: Import/iu.test(text)) return "import_failed";
  return "engine_failed";
};
