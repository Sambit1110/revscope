import { spawn } from "node:child_process";
import { isAbsolute } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

import { invalidInput, makeError, type ErrorEnvelope, type InputIssue } from "../domain/errors.js";
import { err, ok, type Result } from "../domain/result.js";
import {
  buildChildEnvironment,
  type EnvironmentManifest,
  type EnvironmentPolicy,
} from "./envPolicy.js";

/** An argument vector, never a shell command line. */
export interface ChildCommand {
  readonly executable: string;
  readonly args: readonly string[];
  readonly cwd?: string;
  readonly environment?: EnvironmentPolicy;
  /** Total time allowed before the process tree is terminated. */
  readonly timeoutMs: number;
  readonly maxOutputBytes: number;
  /** Time between SIGTERM and SIGKILL when terminating. Default 500 ms. */
  readonly killGraceMs?: number;
  /** Time to collect remaining output after the child exits. Default 250 ms. */
  readonly drainMs?: number;
  readonly signal?: AbortSignal;
}

/**
 * How termination reached the process tree:
 * - process-group: the child ran in its own POSIX process group, which is signalled as a whole;
 * - direct-child-only: only the direct child can be signalled (Windows); descendants are not tracked.
 */
export type TerminationScope = "process-group" | "direct-child-only";

export interface ChildCleanup {
  /**
   * - not-needed: the process tree ended by itself;
   * - terminated: Revscope signalled the tree and it is gone;
   * - failed: signalling failed or the tree survived termination.
   */
  readonly status: "not-needed" | "terminated" | "failed";
  readonly scope: TerminationScope;
  readonly reason: string | null;
}

export interface ChildOutcome {
  /** Why the run ended: normal exit, the deadline, or the caller's cancellation. */
  readonly termination: "exited" | "timed-out" | "cancelled";
  readonly exitCode: number | null;
  readonly signal: string | null;
  readonly cleanup: ChildCleanup;
  readonly stdout: string;
  readonly stderr: string;
  readonly outputTruncated: boolean;
  /** False when output streams were cut off because a descendant held them open. */
  readonly outputComplete: boolean;
  readonly durationMs: number;
  readonly environment: EnvironmentManifest;
}

/** Process control seam; tests substitute a failing `kill` to exercise termination failure. */
export interface ProcessControl {
  readonly platform: NodeJS.Platform;
  readonly kill: (pid: number, signal: NodeJS.Signals | 0) => void;
}

const defaultControl: ProcessControl = {
  platform: process.platform,
  kill: (pid, signal) => {
    process.kill(pid, signal);
  },
};

/** How long to wait for killed processes to disappear before declaring cleanup failed. */
const VERIFY_EXIT_MS = 500;

const errorCode = (cause: unknown): string =>
  typeof cause === "object" && cause !== null && "code" in cause ? String(cause.code) : "";

const validate = (command: ChildCommand): InputIssue[] => {
  const issues: InputIssue[] = [];
  if (!isAbsolute(command.executable))
    issues.push({ path: "executable", message: "Must be an absolute path; PATH lookup is not used" });
  command.args.forEach((arg, index) => {
    if (arg.includes("\0"))
      issues.push({ path: `args.${String(index)}`, message: "Arguments cannot contain NUL characters" });
  });
  for (const [field, value] of [
    ["timeoutMs", command.timeoutMs],
    ["maxOutputBytes", command.maxOutputBytes],
    ["killGraceMs", command.killGraceMs ?? 500],
    ["drainMs", command.drainMs ?? 250],
  ] as const)
    if (!Number.isInteger(value) || value <= 0)
      issues.push({ path: field, message: "Must be a positive integer" });
  return issues;
};

/**
 * Run one executable without a shell, with an allowlisted environment, a
 * deadline that holds even when descendants keep output pipes open, explicit
 * cancellation, and bounded output capture.
 *
 * On POSIX the child leads a new process group; termination signals that
 * group (SIGTERM, then SIGKILL), and any member left when the child finishes
 * is terminated too. Only processes in that group are signalled. On Windows
 * only the direct child is signalled and descendants are not tracked.
 */
export const runChild = async (
  command: ChildCommand,
  host: Readonly<Record<string, string | undefined>> = process.env,
  control: ProcessControl = defaultControl,
): Promise<Result<ChildOutcome, ErrorEnvelope>> => {
  const issues = validate(command);
  if (issues.length > 0) return err(invalidInput("The child command is invalid", issues));
  const environment = buildChildEnvironment(host, command.environment);
  if (!environment.ok) return environment;
  if (command.signal?.aborted === true)
    return err(makeError("cancelled", "The child process was cancelled before it started", {}));

  const killGraceMs = command.killGraceMs ?? 500;
  const drainMs = command.drainMs ?? 250;
  const usesGroup = control.platform !== "win32";
  const scope: TerminationScope = usesGroup ? "process-group" : "direct-child-only";
  const started = performance.now();

  return new Promise((resolve) => {
    const chunks = { stdout: [] as Buffer[], stderr: [] as Buffer[] };
    let captured = 0;
    let truncated = false;
    let termination: ChildOutcome["termination"] = "exited";
    let signalled = false;
    let cleanupFailure: string | null = null;
    let exit: { code: number | null; signal: string | null } | null = null;
    let finished = false;
    const timers: NodeJS.Timeout[] = [];
    const later = (ms: number, task: () => void) => {
      timers.push(setTimeout(task, ms));
    };

    const child = spawn(command.executable, [...command.args], {
      shell: false,
      env: { ...environment.value.env },
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
      detached: usesGroup,
      ...(command.cwd === undefined ? {} : { cwd: command.cwd }),
    });
    const pid = child.pid;

    /** Signal the whole group (POSIX) or the child (Windows). Returns false if it is already gone. */
    const signalTree = (signal: NodeJS.Signals): boolean => {
      if (pid === undefined) return false;
      try {
        if (usesGroup) control.kill(-pid, signal);
        else child.kill(signal);
        return true;
      } catch (cause: unknown) {
        if (errorCode(cause) === "ESRCH") return false;
        cleanupFailure = `Signalling the process ${usesGroup ? "group" : ""} failed (${errorCode(cause) || "unknown error"}).`;
        return true;
      }
    };
    const treeAlive = (): boolean => {
      if (pid === undefined) return false;
      if (!usesGroup) return exit === null;
      try {
        control.kill(-pid, 0);
        return true;
      } catch (cause: unknown) {
        return errorCode(cause) !== "ESRCH";
      }
    };

    const terminate = (reason: "timed-out" | "cancelled") => {
      if (finished || signalled) return;
      if (exit === null) termination = reason;
      signalled = true;
      if (!signalTree("SIGTERM")) return;
      later(killGraceMs, () => {
        if (treeAlive()) signalTree("SIGKILL");
      });
    };

    /** Signalled processes can linger briefly as zombies; poll until they are gone. */
    const settleTree = async (): Promise<boolean> => {
      // Nothing from this run may outlive it, including descendants that
      // closed their output and kept running.
      if (treeAlive()) {
        signalled = true;
        signalTree("SIGKILL");
      }
      if (!usesGroup) return false;
      const until = performance.now() + VERIFY_EXIT_MS;
      while (treeAlive() && performance.now() < until) await delay(10);
      return treeAlive();
    };

    const finish = (outputComplete: boolean) => {
      if (finished) return;
      finished = true;
      for (const timer of timers) clearTimeout(timer);
      command.signal?.removeEventListener("abort", onAbort);
      child.stdout.destroy();
      child.stderr.destroy();
      void settleTree().then((survived) => {
        const status: ChildCleanup["status"] =
          cleanupFailure !== null || survived ? "failed" : signalled ? "terminated" : "not-needed";
        resolve(
          ok({
            termination,
            exitCode: exit?.code ?? null,
            signal: exit?.signal ?? null,
            cleanup: {
              status,
              scope,
              reason: cleanupFailure ?? (survived ? "Processes in the group survived SIGKILL." : null),
            },
            stdout: Buffer.concat(chunks.stdout).toString("utf8"),
            stderr: Buffer.concat(chunks.stderr).toString("utf8"),
            outputTruncated: truncated,
            outputComplete,
            durationMs: Math.round(performance.now() - started),
            environment: environment.value.manifest,
          }),
        );
      });
    };

    const onAbort = () => terminate("cancelled");
    command.signal?.addEventListener("abort", onAbort, { once: true });

    const capture = (stream: "stdout" | "stderr") => (chunk: Buffer) => {
      const room = command.maxOutputBytes - captured;
      if (room <= 0) {
        truncated = true;
        return;
      }
      const kept = chunk.subarray(0, room);
      if (kept.length < chunk.length) truncated = true;
      captured += kept.length;
      chunks[stream].push(kept);
    };
    child.stdout.on("data", capture("stdout"));
    child.stderr.on("data", capture("stderr"));

    child.once("error", (cause: NodeJS.ErrnoException) => {
      if (finished) return;
      finished = true;
      for (const timer of timers) clearTimeout(timer);
      command.signal?.removeEventListener("abort", onAbort);
      resolve(
        err(
          cause.code === "ENOENT"
            ? makeError("target_not_found", "The executable does not exist", {})
            : cause.code === "EACCES"
              ? makeError("access_denied", "The executable cannot be run by the current user", {})
              : makeError("provider_failure", "The child process could not be started", {}),
        ),
      );
    });
    child.once("exit", (code, signal) => {
      exit = { code, signal };
      // Descendants may keep the pipes open; collect output briefly, then stop waiting.
      later(drainMs, () => finish(false));
    });
    child.once("close", () => finish(true));

    later(command.timeoutMs, () => terminate("timed-out"));
    // Absolute bound: even an unkillable tree cannot hold the caller past this
    // point plus VERIFY_EXIT_MS for the final check.
    later(command.timeoutMs + killGraceMs + drainMs + 250, () => finish(false));
  });
};
