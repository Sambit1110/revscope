import { access } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import type {
  ArtifactFacts,
  BinaryAnalysisEngine,
  BinaryAnalysisRequest,
  BinaryAnalysisRun,
  EngineCleanup,
} from "../../application/ports.js";
import { makeError, type ErrorEnvelope } from "../../domain/errors.js";
import { sha256Hex } from "../../domain/json.js";
import { err, ok, type Result } from "../../domain/result.js";
import { runChild, type ChildOutcome, type ProcessControl } from "../childProcess.js";
import { openRegularFile, readChunks } from "../safeFile.js";
import { emptyTrace, preserveFailedRun, type DiagnosticsOptions, type RunTrace } from "./diagnostics.js";
import { EXPORT_LIMITS, parseGhidraExport } from "./exportFormat.js";
import { GhidraExportProvider, exportCoverage } from "./exportProvider.js";
import {
  DEFAULT_TIMING,
  EXPORT_SCRIPT,
  classifyHeadlessOutput,
  planHeadless,
  type EngineTiming,
} from "./headless.js";
import {
  locateGhidra,
  notConfigured,
  type GhidraInstallation,
  type GhidraSettings,
} from "./installation.js";
import { MAX_INPUT_BYTES, copyInput, createWorkspace, removeWorkspace, type Workspace } from "./workspace.js";

/** The Revscope-owned Ghidra scripts, shipped beside the compiled code (src/ or dist/ alike). */
export const DEFAULT_SCRIPT_DIR = fileURLToPath(new URL("../../../ghidra-scripts", import.meta.url));

/** Console and log text kept for classifying failures; it is never reported. */
const OUTPUT_LIMIT_BYTES = 1024 * 1024;

export interface GhidraEngineOptions {
  readonly settings: GhidraSettings;
  readonly scriptDir?: string;
  /** Parent of workspaces; defaults to the system temporary directory. */
  readonly tempParent?: string;
  readonly timing?: Partial<EngineTiming>;
  /** Cap on how long Ghidra itself may run, below what the timeout allows. */
  readonly maxChildRunMs?: number;
  readonly maxInputBytes?: number;
  /** Host environment the child's allowlist draws from; defaults to process.env. */
  readonly host?: Readonly<Record<string, string | undefined>>;
  readonly control?: ProcessControl;
  /** Opt-in: keep failed runs' workspaces and logs for local diagnosis. Off by default. */
  readonly diagnostics?: DiagnosticsOptions;
}

type Outcome = Result<
  { readonly artifact: ArtifactFacts; readonly provider: GhidraExportProvider; readonly coverage: BinaryAnalysisRun["coverage"] },
  ErrorEnvelope
>;

const cancelled = (): ErrorEnvelope => makeError("cancelled", "The analysis was cancelled", {});

/** Every engine error says what was left behind. */
const withCleanup = (error: ErrorEnvelope, cleanup: EngineCleanup): ErrorEnvelope => ({
  ...error,
  details: { ...error.details, cleanup: { ...cleanup } },
});

/** Read a workspace file up to a limit; null when absent. Over the limit returns "too_large". */
const readBounded = async (path: string, limit: number): Promise<Uint8Array | "too_large" | null> => {
  const opened = await openRegularFile(path);
  if (!opened.ok) return null;
  if (opened.value.size > limit) {
    await opened.value.handle.close();
    return "too_large";
  }
  const chunks: Uint8Array[] = [];
  let size = 0;
  for await (const chunk of readChunks(opened.value.handle)) {
    size += chunk.length;
    if (size > limit) return "too_large";
    chunks.push(chunk);
  }
  return new Uint8Array(Buffer.concat(chunks));
};

const logText = async (workspace: Workspace, child: ChildOutcome): Promise<string> => {
  const logs = await Promise.all(
    ["application.log", "script.log"].map((name) => readBounded(join(workspace.logs, name), OUTPUT_LIMIT_BYTES)),
  );
  const decoded = logs.map((log) => (log instanceof Uint8Array ? Buffer.from(log).toString("utf8") : ""));
  return [child.stdout, child.stderr, ...decoded].join("\n");
};

/**
 * Ghidra headless as a BinaryAnalysisEngine. Each request gets a fresh
 * workspace and JVM; the input is copied, never executed, and the workspace
 * is removed before the request returns. Ghidra runs with the user's
 * permissions: this is process and file isolation, not a sandbox.
 */
export class GhidraEngine implements BinaryAnalysisEngine {
  readonly #options: GhidraEngineOptions;
  readonly #timing: EngineTiming;

  constructor(options: GhidraEngineOptions) {
    this.#options = options;
    this.#timing = { ...DEFAULT_TIMING, ...options.timing };
  }

  async analyze(request: BinaryAnalysisRequest): Promise<Result<BinaryAnalysisRun, ErrorEnvelope>> {
    const deadlineAt = performance.now() + request.limits.timeoutMs;
    const notStarted: EngineCleanup = { process: "not-started", workspace: "not-created", reason: null };

    const installation = await locateGhidra(this.#options.settings);
    if (!installation.ok) return err(withCleanup(installation.error, notStarted));
    const scriptDir = this.#options.scriptDir ?? DEFAULT_SCRIPT_DIR;
    const scriptPresent = await access(join(scriptDir, EXPORT_SCRIPT)).then(
      () => true,
      () => false,
    );
    if (!scriptPresent)
      return err(withCleanup(notConfigured("export_script_missing", "Revscope's Ghidra export script is missing"), notStarted));
    if (request.signal.aborted) return err(withCleanup(cancelled(), notStarted));

    // Open and check the input before creating anything, so input errors match inspect_artifact's.
    const source = await openRegularFile(request.path);
    if (!source.ok) return err(withCleanup(source.error, notStarted));
    const maxInputBytes = this.#options.maxInputBytes ?? MAX_INPUT_BYTES;
    if (source.value.size > maxInputBytes) {
      await source.value.handle.close();
      return err(
        withCleanup(
          makeError("resource_limit", "The input is larger than the supported limit", {
            path: request.path,
            limit_bytes: maxInputBytes,
            size_bytes: source.value.size,
          }),
          notStarted,
        ),
      );
    }
    const workspace = await createWorkspace(this.#options.tempParent);
    if (!workspace.ok) {
      await source.value.handle.close();
      return err(withCleanup(workspace.error, notStarted));
    }

    const trace = emptyTrace();
    const outcome = await this.#run(request, installation.value, scriptDir, workspace.value, source.value, deadlineAt, trace).catch(
      (): Outcome => err(makeError("provider_failure", "The engine run failed unexpectedly", { engine: "ghidra", reason: "engine_failed" })),
    );
    // runChild has returned, so the process tree has been settled before the workspace goes.
    const failed = !outcome.ok || !outcome.value.coverage.exportComplete;
    const preserved =
      failed && this.#options.diagnostics !== undefined
        ? await preserveFailedRun(
            workspace.value,
            {
              ghidraVersion: installation.value.version,
              outcome: outcome.ok
                ? { code: "analysis_incomplete", details: { coverage: { ...outcome.value.coverage } } }
                : { code: outcome.error.code, details: outcome.error.details },
              trace,
            },
            this.#options.diagnostics,
          )
        : "failed";
    const removed = preserved === "preserved" ? "preserved" : await removeWorkspace(workspace.value);
    const settled = trace.child?.cleanup ?? null;
    // Both failures are reported when both happen; neither hides the other.
    const reasons = [
      settled?.reason ?? null,
      removed === "failed" ? "The temporary analysis workspace could not be removed completely." : null,
      removed === "preserved" ? "The workspace was preserved for local diagnostics (REVSCOPE_GHIDRA_DIAGNOSTICS)." : null,
    ].filter((reason): reason is string => reason !== null);
    const cleanup: EngineCleanup = {
      process: settled?.status ?? "not-started",
      workspace: removed,
      reason: reasons.length === 0 ? null : reasons.join(" "),
    };
    if (!outcome.ok) return err(withCleanup(outcome.error, cleanup));
    return ok({ ...outcome.value, cleanup });
  }

  async #run(
    request: BinaryAnalysisRequest,
    installation: GhidraInstallation,
    scriptDir: string,
    workspace: Workspace,
    source: Parameters<typeof copyInput>[0],
    deadlineAt: number,
    trace: RunTrace,
  ): Promise<Outcome> {
    const { limits } = request;
    const artifact = await copyInput(source, request.path, workspace, this.#options.maxInputBytes ?? MAX_INPUT_BYTES);
    if (!artifact.ok) return artifact;
    if (request.signal.aborted) return err(cancelled());
    const plan = planHeadless({
      installation,
      workspace,
      scriptDir,
      limits,
      deadlineAt,
      timing: this.#timing,
      ...(this.#options.maxChildRunMs === undefined ? {} : { maxChildRunMs: this.#options.maxChildRunMs }),
    });
    if (plan === null)
      return err(
        makeError("analysis_timeout", "Too little of the timeout remained to start the engine", {
          timeout_ms: limits.timeoutMs,
        }),
      );

    trace.args = plan.args;
    const launched = await runChild(
      {
        executable: installation.analyzeHeadless,
        args: plan.args,
        cwd: workspace.root,
        environment: plan.environment,
        timeoutMs: plan.childTimeoutMs,
        killGraceMs: this.#timing.killGraceMs,
        settleMs: this.#timing.settleMs,
        drainMs: 500,
        maxOutputBytes: OUTPUT_LIMIT_BYTES,
        signal: request.signal,
      },
      this.#options.host ?? globalThis.process.env,
      this.#options.control,
    );
    if (!launched.ok) {
      const code = launched.error.code;
      if (code === "target_not_found") return err(notConfigured("analyze_headless_missing", "Ghidra's analyzeHeadless launcher could not be started"));
      if (code === "access_denied") return err(notConfigured("analyze_headless_not_executable", "Ghidra's analyzeHeadless launcher could not be started"));
      if (code === "cancelled") return err(cancelled());
      return err(makeError("provider_failure", "The engine could not be started", { engine: "ghidra", reason: "engine_not_started" }));
    }
    const child = launched.value;
    trace.child = child;
    if (child.termination === "cancelled") return err(cancelled());

    const exported = await readBounded(workspace.exportPath, EXPORT_LIMITS.totalBytes);
    if (exported === "too_large")
      return err(makeError("provider_failure", "The engine's export exceeded its size limit", { engine: "ghidra", reason: "export_too_large" }));
    const parsed =
      exported === null
        ? err({ kind: "empty" as const })
        : parseGhidraExport(exported, { maxFunctions: limits.maxFunctions, decompile: limits.decompile, ghidraVersion: installation.version });
    if (parsed.ok && exported instanceof Uint8Array) {
      const provider = new GhidraExportProvider(parsed.value, {
        ghidraVersion: installation.version,
        artifactSha256: artifact.value.sha256,
        exportSha256: sha256Hex(exported),
      });
      return ok({
        artifact: artifact.value,
        provider,
        coverage: exportCoverage(parsed.value, child.termination === "timed-out" ? "timed-out" : "engine-exited"),
      });
    }
    if (!parsed.ok && parsed.error.kind !== "empty") {
      trace.exportProblem = parsed.error.kind === "malformed" ? `line ${String(parsed.error.line)}: ${parsed.error.reason}` : parsed.error.kind;
      return err(
        makeError("provider_failure", "The engine's export is malformed", {
          engine: "ghidra",
          reason: parsed.error.kind === "too_large" ? "export_too_large" : "malformed_export",
          ...(parsed.error.kind === "malformed" ? { line: parsed.error.line, problem: parsed.error.reason } : {}),
        }),
      );
    }
    // No usable export at all.
    if (child.termination === "timed-out")
      return err(makeError("analysis_timeout", "The engine produced no result before the deadline", { timeout_ms: limits.timeoutMs }));
    trace.classification = classifyHeadlessOutput(await logText(workspace, child));
    switch (trace.classification) {
      case "unsupported_format":
        return err(makeError("unsupported_target", "Ghidra could not recognize the file as a supported program", { path: request.path }));
      case "malformed_input":
        // Not a provider failure: the same bytes fail the same way, so the error is not retryable.
        return err(
          makeError("unsupported_target", "Ghidra recognized the file's format but could not load it; the file appears truncated or malformed", {
            path: request.path,
            reason: "malformed_input",
          }),
        );
      case "java_runtime":
        return err(notConfigured("java_runtime", "Ghidra could not find a Java runtime it supports"));
      case "export_script_failed":
        return err(makeError("provider_failure", "Revscope's Ghidra export script failed", { engine: "ghidra", reason: "export_script_failed" }));
      case "import_failed":
        return err(makeError("provider_failure", "Ghidra could not import the file", { engine: "ghidra", reason: "import_failed", exit_code: child.exitCode }));
      case "engine_failed":
        return err(makeError("provider_failure", "The engine exited without a result", { engine: "ghidra", reason: "engine_failed", exit_code: child.exitCode }));
    }
  }
}
