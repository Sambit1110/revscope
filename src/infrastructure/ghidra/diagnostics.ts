import { mkdir, mkdtemp, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";

import type { ChildOutcome } from "../childProcess.js";
import type { HeadlessFailure } from "./headless.js";
import type { Workspace } from "./workspace.js";

/**
 * Opt-in developer diagnostics (REVSCOPE_GHIDRA_DIAGNOSTICS=1). When a run
 * fails or is incomplete, its workspace is kept, with Ghidra's logs, and a
 * run record is written beside it. Nothing here ever reaches a tool result:
 * callers see only `cleanup.workspace: "preserved"`, and the location is
 * reported through `report`, which the CLI wires to the local stderr.
 */
export interface DiagnosticsOptions {
  /** Parent directory for preserved runs, e.g. <tmpdir>/revscope-diagnostics. */
  readonly directory: string;
  /** Local developer output only; never part of a tool result. */
  readonly report: (line: string) => void;
}

/** What the engine learned about a run, for the diagnostic record. */
export interface RunTrace {
  args: readonly string[] | null;
  child: ChildOutcome | null;
  classification: HeadlessFailure | null;
  exportProblem: string | null;
}

export const emptyTrace = (): RunTrace => ({ args: null, child: null, classification: null, exportProblem: null });

/**
 * Move a failed run's workspace into the diagnostics directory and describe
 * the run. Returns "preserved", or "failed" when nothing could be kept (the
 * caller then removes the workspace as usual).
 */
export const preserveFailedRun = async (
  workspace: Workspace,
  record: {
    readonly ghidraVersion: string;
    readonly outcome: { readonly code: string; readonly details: unknown };
    readonly trace: RunTrace;
  },
  options: DiagnosticsOptions,
): Promise<"preserved" | "failed"> => {
  let runDirectory: string;
  try {
    await mkdir(options.directory, { recursive: true, mode: 0o700 });
    runDirectory = await mkdtemp(join(options.directory, `run-${new Date().toISOString().replaceAll(":", "-")}-`));
    await rename(workspace.root, join(runDirectory, "workspace"));
  } catch {
    return "failed";
  }
  const { child } = record.trace;
  const run = {
    note: "Local developer diagnostics for one failed Ghidra run. Paths in `args` refer to the workspace before it was moved into ./workspace.",
    created_at: new Date().toISOString(),
    engine: { id: "ghidra", version: record.ghidraVersion },
    outcome: record.outcome,
    internal: { classification: record.trace.classification, export_problem: record.trace.exportProblem },
    process:
      child === null
        ? null
        : {
            termination: child.termination,
            exit_code: child.exitCode,
            signal: child.signal,
            duration_ms: child.durationMs,
            deadline_ms: child.deadlineMs,
            cleanup: child.cleanup,
            output_truncated: child.outputTruncated,
            output_complete: child.outputComplete,
            // Names only; values are never recorded.
            environment_names: child.environment,
          },
    args: record.trace.args,
  };
  try {
    await writeFile(join(runDirectory, "run.json"), `${JSON.stringify(run, null, 2)}\n`, { mode: 0o600 });
    if (child !== null) {
      await writeFile(join(runDirectory, "stdout.txt"), child.stdout, { mode: 0o600 });
      await writeFile(join(runDirectory, "stderr.txt"), child.stderr, { mode: 0o600 });
    }
  } catch {
    // The workspace itself is preserved; the record is best effort.
  }
  options.report(`revscope: diagnostics for a failed Ghidra run were preserved at ${runDirectory}\n`);
  return "preserved";
};
