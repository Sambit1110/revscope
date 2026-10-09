import { spawn, type ChildProcessByStdio } from "node:child_process";
import { isAbsolute } from "node:path";
import type { Readable } from "node:stream";
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
  /** How long the child may run before termination begins. */
  readonly timeoutMs: number;
  readonly maxOutputBytes: number;
  /** Time between SIGTERM and SIGKILL when terminating. Default 500 ms. */
  readonly killGraceMs?: number;
  /** After the child exits, time to collect output still arriving from descendants. Default 250 ms. */
  readonly drainMs?: number;
  /** Time after the kill grace reserved for final cleanup and verification. Default 250 ms. */
  readonly settleMs?: number;
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
   * - failed: signalling failed, the tree survived until the deadline, or a
   *   descendant outside the tracked scope still holds the output pipes.
   */
  readonly status: "not-needed" | "terminated" | "failed";
  readonly scope: TerminationScope;
  readonly reason: string | null;
}

export interface ChildOutcome {
  /** Why the run ended: normal exit, the timeout, or the caller's cancellation. */
  readonly termination: "exited" | "timed-out" | "cancelled";
  readonly exitCode: number | null;
  readonly signal: string | null;
  /** Whether everything the run started is gone; `failed` is a termination failure. */
  readonly cleanup: ChildCleanup;
  readonly stdout: string;
  readonly stderr: string;
  readonly outputTruncated: boolean;
  /** False when output streams were cut off because a descendant held them open. */
  readonly outputComplete: boolean;
  readonly durationMs: number;
  /**
   * The hard bound this run was held to, in milliseconds from its start:
   * timeoutMs + killGraceMs + settleMs, or less after cancellation. The run
   * returns by then, plus event-loop latency, whatever its descendants do.
   */
  readonly deadlineMs: number;
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

/** Poll interval while waiting for the tree to disappear and the pipes to close. */
const SETTLE_POLL_MS = 10;
/** After the group is gone, how long to wait for the kernel to close its pipes. */
const PIPE_CLOSE_GRACE_MS = 100;

const errorCode = (cause: unknown): string =>
  typeof cause === "object" && cause !== null && "code" in cause ? String(cause.code) : "";

const validate = (command: ChildCommand): InputIssue[] => {
  const issues: InputIssue[] = [];
  if (!isAbsolute(command.executable))
    issues.push({ path: "executable", message: "Must be an absolute path; PATH lookup is not used" });
  if (command.executable.includes("\0"))
    issues.push({ path: "executable", message: "Cannot contain NUL characters" });
  if (command.cwd?.includes("\0") === true)
    issues.push({ path: "cwd", message: "Cannot contain NUL characters" });
  command.args.forEach((arg, index) => {
    if (arg.includes("\0"))
      issues.push({ path: `args.${String(index)}`, message: "Arguments cannot contain NUL characters" });
  });
  for (const [field, value] of [
    ["timeoutMs", command.timeoutMs],
    ["maxOutputBytes", command.maxOutputBytes],
    ["killGraceMs", command.killGraceMs ?? 500],
    ["drainMs", command.drainMs ?? 250],
    ["settleMs", command.settleMs ?? 250],
  ] as const)
    if (!Number.isSafeInteger(value) || value <= 0)
      issues.push({ path: field, message: "Must be a positive integer" });
  return issues;
};

const spawnError = (cause: unknown): ErrorEnvelope => {
  const code = errorCode(cause);
  if (code === "ENOENT") return makeError("target_not_found", "The executable does not exist", {});
  if (code === "EACCES") return makeError("access_denied", "The executable cannot be run by the current user", {});
  return makeError("provider_failure", "The child process could not be started", {});
};

/**
 * Run one executable without a shell, with an allowlisted environment,
 * explicit cancellation, bounded output capture, and one hard deadline.
 *
 * Phases, all capped by the deadline (timeoutMs + killGraceMs + settleMs):
 * 1. The child runs for up to timeoutMs, or until the caller aborts.
 * 2. Termination: SIGTERM to the tree, then SIGKILL after killGraceMs.
 * 3. After the child exits, output from descendants is collected for up to
 *    drainMs; pipes held open longer cannot extend the run.
 * 4. Settling: anything left in the tree is killed, and the run waits for the
 *    tree to disappear and the pipes to close.
 *
 * On POSIX the child leads a new process group, and only that group is ever
 * signalled; once the group is observed gone it is never signalled again. A
 * descendant that leaves the group is not signalled, but if it still holds
 * the output pipes the cleanup is reported as failed. On Windows only the
 * direct child is signalled and descendants are not tracked.
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
  const settleMs = command.settleMs ?? 250;
  const usesGroup = control.platform !== "win32";
  const scope: TerminationScope = usesGroup ? "process-group" : "direct-child-only";
  const started = performance.now();
  let deadlineAt = started + command.timeoutMs + killGraceMs + settleMs;

  let child: ChildProcessByStdio<null, Readable, Readable>;
  try {
    child = spawn(command.executable, [...command.args], {
      shell: false,
      env: { ...environment.value.env },
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
      detached: usesGroup,
      ...(command.cwd === undefined ? {} : { cwd: command.cwd }),
    });
  } catch (cause: unknown) {
    return err(spawnError(cause));
  }
  const pid = child.pid;

  return new Promise((resolve) => {
    const chunks = { stdout: [] as Buffer[], stderr: [] as Buffer[] };
    let captured = 0;
    let truncated = false;
    let termination: ChildOutcome["termination"] = "exited";
    let exit: { code: number | null; signal: string | null } | null = null;
    let closed = false;
    let outputComplete = false;
    let signalled = false;
    let groupGone = false;
    let cleanupFailure: string | null = null;
    let settling = false;
    let resolved = false;
    const timers = new Set<NodeJS.Timeout>();
    let deadlineTimer: NodeJS.Timeout | undefined;

    /** Run a task at an absolute time; every timer is cleared when settling starts. */
    const at = (time: number, task: () => void): NodeJS.Timeout => {
      const timer = setTimeout(() => {
        timers.delete(timer);
        task();
      }, Math.max(0, time - performance.now()));
      timers.add(timer);
      return timer;
    };
    const clearTimers = () => {
      for (const timer of timers) clearTimeout(timer);
      timers.clear();
    };

    /** Signal the group (POSIX) or the child (Windows), never a group already observed gone. */
    const signalTree = (signal: NodeJS.Signals): void => {
      if (pid === undefined || groupGone) return;
      try {
        if (usesGroup) control.kill(-pid, signal);
        else child.kill(signal);
        signalled = true;
      } catch (cause: unknown) {
        if (errorCode(cause) === "ESRCH") {
          groupGone = true;
          return;
        }
        cleanupFailure ??= `Sending ${signal} to the process ${usesGroup ? "group" : "child"} failed (${errorCode(cause) || "unknown error"}).`;
      }
    };
    const treeAlive = (): boolean => {
      if (pid === undefined) return false;
      if (!usesGroup) return exit === null;
      if (groupGone) return false;
      try {
        control.kill(-pid, 0);
        return true;
      } catch (cause: unknown) {
        if (errorCode(cause) !== "ESRCH") return true;
        groupGone = true;
        return false;
      }
    };

    const finish = () => {
      if (resolved) return;
      resolved = true;
      clearTimers();
      if (deadlineTimer !== undefined) clearTimeout(deadlineTimer);
      child.stdout.destroy();
      child.stderr.destroy();
      const survived = treeAlive();
      const heldOpen = pid !== undefined && !closed && !survived;
      const failure =
        cleanupFailure ??
        (survived
          ? "Processes in the group were still running at the deadline."
          : heldOpen
            ? usesGroup
              ? "The process group ended, but its output pipes were still held open: a descendant that left the group is still running. It was not signalled."
              : "The child exited, but its output pipes were still held open by descendants, which are not tracked on this platform."
            : null);
      resolve(
        ok({
          termination,
          exitCode: exit?.code ?? null,
          signal: exit?.signal ?? null,
          cleanup: {
            status: failure !== null ? "failed" : signalled ? "terminated" : "not-needed",
            scope,
            reason: failure,
          },
          stdout: Buffer.concat(chunks.stdout).toString("utf8"),
          stderr: Buffer.concat(chunks.stderr).toString("utf8"),
          outputTruncated: truncated,
          outputComplete,
          durationMs: Math.round(performance.now() - started),
          deadlineMs: Math.round(deadlineAt - started),
          environment: environment.value.manifest,
        }),
      );
    };

    /** Kill whatever is left, then wait for the tree and its pipes to go, never past the deadline. */
    const settle = async (): Promise<void> => {
      let goneAt: number | null = null;
      // At least one pass, even when settling starts at the deadline itself.
      // The deadline timer may resolve the run while this loop waits.
      for (;;) {
        if (resolved) return;
        // Re-signal on every pass: a member forked during the previous SIGKILL is caught too.
        if (treeAlive()) signalTree("SIGKILL");
        else {
          goneAt ??= performance.now();
          if (closed || performance.now() - goneAt >= PIPE_CLOSE_GRACE_MS) return;
        }
        if (performance.now() >= deadlineAt) return;
        await delay(SETTLE_POLL_MS);
      }
    };

    const beginSettle = () => {
      if (settling) return;
      settling = true;
      clearTimers();
      command.signal?.removeEventListener("abort", onAbort);
      void settle().then(finish, finish);
    };

    const terminate = (reason: "timed-out" | "cancelled") => {
      if (settling) return;
      if (exit !== null) {
        // The child already exited; only lingering descendants remain.
        beginSettle();
        return;
      }
      if (termination !== "exited") return;
      termination = reason;
      signalTree("SIGTERM");
      at(performance.now() + killGraceMs, () => {
        if (!settling && treeAlive()) signalTree("SIGKILL");
      });
    };

    const armDeadline = () => {
      if (deadlineTimer !== undefined) clearTimeout(deadlineTimer);
      deadlineTimer = setTimeout(() => {
        beginSettle();
        // The settle loop stops at the deadline; this resolves even if it cannot run.
        finish();
      }, Math.max(0, deadlineAt - performance.now()));
    };

    const onAbort = () => {
      deadlineAt = Math.min(deadlineAt, performance.now() + killGraceMs + settleMs);
      armDeadline();
      terminate("cancelled");
    };
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
      if (pid !== undefined) {
        // The process exists; this is a signalling failure, not a start failure.
        cleanupFailure ??= `The child process reported an error (${cause.code ?? "unknown error"}).`;
        return;
      }
      if (resolved) return;
      resolved = true;
      clearTimers();
      if (deadlineTimer !== undefined) clearTimeout(deadlineTimer);
      command.signal?.removeEventListener("abort", onAbort);
      resolve(err(spawnError(cause)));
    });
    child.once("exit", (code, signal) => {
      exit = { code, signal };
      if (settling) return;
      // Descendants may keep the pipes open; collect their output briefly, then stop waiting.
      at(Math.min(performance.now() + drainMs, deadlineAt), beginSettle);
    });
    child.once("close", () => {
      closed = true;
      if (settling) return;
      outputComplete = true;
      beginSettle();
    });

    at(started + command.timeoutMs, () => terminate("timed-out"));
    armDeadline();
  });
};
