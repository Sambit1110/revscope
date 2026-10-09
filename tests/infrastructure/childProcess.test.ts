import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

import { runChild, type ChildCommand, type ProcessControl } from "../../src/infrastructure/childProcess.js";

const FAMILY = fileURLToPath(new URL("../fixtures/child/process-family.mjs", import.meta.url));
const posix = process.platform !== "win32";

/** Documented bound (see docs/architecture.md): a run returns by timeoutMs + killGraceMs + settleMs. */
const TIMEOUT_MS = 300;
const KILL_GRACE_MS = 500;
const DRAIN_MS = 250;
const SETTLE_MS = 250;
const DEADLINE_MS = TIMEOUT_MS + KILL_GRACE_MS + SETTLE_MS;
/** Documented tolerance for event-loop and process-scheduling latency beyond the deadline. */
const TOLERANCE_MS = 150;
const MAX_OVERRUN_MS = DEADLINE_MS - TIMEOUT_MS + TOLERANCE_MS;
/**
 * Tests that need the child's SIGTERM handler installed act only after this
 * long; under a loaded test run, Node can take well over 100 ms to start.
 */
const READY_MS = 1000;

/** Every pid a fixture reported; killed after each test so a failure cannot leak processes. */
const owned: number[] = [];
afterEach(() => {
  for (const pid of owned.splice(0))
    try {
      process.kill(pid, "SIGKILL");
    } catch {
      // Already gone.
    }
});

const alive = (pid: number): boolean => {
  try {
    process.kill(pid, 0);
    return true;
  } catch (cause: unknown) {
    return (cause as NodeJS.ErrnoException).code === "EPERM";
  }
};

const family = (mode: string, overrides: Partial<ChildCommand> = {}): ChildCommand => ({
  executable: process.execPath,
  args: [FAMILY, mode],
  timeoutMs: TIMEOUT_MS,
  killGraceMs: KILL_GRACE_MS,
  drainMs: DRAIN_MS,
  settleMs: SETTLE_MS,
  maxOutputBytes: 64 * 1024,
  ...overrides,
});

const pidsFrom = (stdout: string): { child: number; grandchild?: number } => {
  const pids = JSON.parse(stdout.split("\n")[0] ?? "{}") as { child: number; grandchild?: number };
  owned.push(pids.child, ...(pids.grandchild === undefined ? [] : [pids.grandchild]));
  return pids;
};

const run = async (command: ChildCommand, control?: ProcessControl) => {
  const before = performance.now();
  const outcome = await runChild(command, {}, control);
  if (!outcome.ok) throw new Error(JSON.stringify(outcome.error));
  // Measured by the caller, not taken from the outcome's own report.
  return { ...outcome.value, wallMs: performance.now() - before };
};

describe.skipIf(!posix)("process lifecycle on POSIX", () => {
  it("finishes promptly after a normal exit and reports no cleanup", async () => {
    const outcome = await run(family("quick", { timeoutMs: 10_000 }));
    pidsFrom(outcome.stdout);
    expect(outcome).toMatchObject({
      termination: "exited",
      exitCode: 0,
      outputComplete: true,
      cleanup: { status: "not-needed", scope: "process-group" },
    });
  });

  it("holds the deadline when a grandchild inherits stdout and stderr, and kills the whole group", async () => {
    const outcome = await run(family("linger"));
    const pids = pidsFrom(outcome.stdout);
    expect(outcome.termination).toBe("timed-out");
    expect(outcome.durationMs).toBeGreaterThanOrEqual(TIMEOUT_MS);
    expect(outcome.durationMs).toBeLessThan(TIMEOUT_MS + MAX_OVERRUN_MS);
    expect(outcome.cleanup).toMatchObject({ status: "terminated", scope: "process-group" });
    expect(alive(pids.child)).toBe(false);
    expect(alive(pids.grandchild ?? -1)).toBe(false);
  });

  it("does not wait for a grandchild that keeps the pipes open after the child exits", async () => {
    const outcome = await run(family("exit-early", { timeoutMs: 20_000 }));
    const pids = pidsFrom(outcome.stdout);
    expect(outcome).toMatchObject({ termination: "exited", exitCode: 0, outputComplete: false });
    expect(outcome.durationMs).toBeLessThan(DRAIN_MS + 1500);
    expect(outcome.cleanup.status).toBe("terminated");
    expect(alive(pids.grandchild ?? -1)).toBe(false);
  });

  it("terminates a detached-from-output descendant left behind by the child", async () => {
    const outcome = await run(family("daemon", { timeoutMs: 20_000 }));
    const pids = pidsFrom(outcome.stdout);
    expect(outcome.termination).toBe("exited");
    expect(outcome.cleanup.status).toBe("terminated");
    expect(alive(pids.grandchild ?? -1)).toBe(false);
  });

  it("escalates to SIGKILL when the child ignores SIGTERM", async () => {
    const outcome = await run(family("ignore-term", { timeoutMs: READY_MS }));
    const pids = pidsFrom(outcome.stdout);
    expect(outcome.termination).toBe("timed-out");
    expect(outcome.signal).toBe("SIGKILL");
    expect(outcome.durationMs).toBeGreaterThanOrEqual(READY_MS + KILL_GRACE_MS - 50);
    expect(outcome.wallMs).toBeLessThanOrEqual(outcome.deadlineMs + TOLERANCE_MS);
    expect(alive(pids.child)).toBe(false);
  });

  it("cancels through an AbortSignal and reports cancellation, not a timeout", async () => {
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 150);
    const outcome = await run(family("linger", { timeoutMs: 20_000, signal: controller.signal }));
    const pids = pidsFrom(outcome.stdout);
    expect(outcome.termination).toBe("cancelled");
    expect(outcome.durationMs).toBeLessThan(150 + MAX_OVERRUN_MS);
    expect(alive(pids.grandchild ?? -1)).toBe(false);
  });

  it("refuses to start when already cancelled", async () => {
    const controller = new AbortController();
    controller.abort();
    const outcome = await runChild(family("quick", { signal: controller.signal }), {});
    expect(outcome.ok ? "started" : outcome.error.code).toBe("cancelled");
  });

  it("leaves unrelated processes alone", async () => {
    const sentinel = spawn(process.execPath, ["-e", "setTimeout(() => {}, 60000)"], { stdio: "ignore" });
    if (sentinel.pid === undefined) throw new Error("sentinel did not start");
    owned.push(sentinel.pid);
    pidsFrom((await run(family("linger"))).stdout);
    expect(alive(sentinel.pid)).toBe(true);
  });

  it("holds the whole run to its deadline when a grandchild ignores SIGTERM and holds the pipes", async () => {
    const outcome = await run(family("stubborn"));
    const pids = pidsFrom(outcome.stdout);
    expect(outcome.deadlineMs).toBe(DEADLINE_MS);
    expect(outcome.wallMs).toBeLessThanOrEqual(DEADLINE_MS + TOLERANCE_MS);
    expect(outcome).toMatchObject({ termination: "timed-out", outputComplete: false, cleanup: { status: "terminated" } });
    expect(alive(pids.child)).toBe(false);
    expect(alive(pids.grandchild ?? -1)).toBe(false);
  });

  it("reports a grandchild that escaped the process group instead of claiming a clean termination", async () => {
    const outcome = await run(family("escape"));
    const pids = pidsFrom(outcome.stdout);
    expect(outcome.wallMs).toBeLessThanOrEqual(DEADLINE_MS + TOLERANCE_MS);
    expect(outcome.termination).toBe("timed-out");
    expect(outcome.cleanup.status).toBe("failed");
    expect(outcome.cleanup.reason).toContain("left the group");
    expect(alive(pids.child)).toBe(false);
    // Outside the group Revscope signals nothing, so the escaped process is still running.
    expect(alive(pids.grandchild ?? -1)).toBe(true);
  });

  it("shortens the deadline when cancelled and still escalates to SIGKILL", async () => {
    const controller = new AbortController();
    setTimeout(() => controller.abort(), READY_MS);
    const outcome = await run(family("ignore-term", { timeoutMs: 20_000, signal: controller.signal }));
    pidsFrom(outcome.stdout);
    expect(outcome.termination).toBe("cancelled");
    expect(outcome.signal).toBe("SIGKILL");
    expect(outcome.deadlineMs).toBeLessThanOrEqual(READY_MS + KILL_GRACE_MS + SETTLE_MS + TOLERANCE_MS);
    expect(outcome.wallMs).toBeLessThanOrEqual(outcome.deadlineMs + TOLERANCE_MS);
  });

  it("rejects NUL characters in the executable or working directory without throwing", async () => {
    for (const command of [family("quick", { executable: `${process.execPath}\0x` }), family("quick", { cwd: "/tmp\0x" })]) {
      const outcome = await runChild(command, {});
      expect(outcome.ok ? "started" : outcome.error.code).toBe("invalid_input");
    }
  });

  it("reports termination failure and still returns within the bound", async () => {
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
    const outcome = await run(family("linger"), denied);
    const pids = pidsFrom(outcome.stdout);
    expect(outcome.termination).toBe("timed-out");
    expect(outcome.cleanup.status).toBe("failed");
    expect(outcome.cleanup.reason).toContain("EPERM");
    expect(outcome.wallMs).toBeLessThanOrEqual(DEADLINE_MS + TOLERANCE_MS);
    // The real processes are still running because termination was denied.
    expect(alive(pids.child)).toBe(true);
    process.kill(-pids.child, "SIGKILL");
  });
});

describe("process lifecycle on Windows", () => {
  it("reports that only the direct child is tracked", async () => {
    const control: ProcessControl = { platform: "win32", kill: () => undefined };
    const outcome = await run(family("quick", { timeoutMs: 10_000 }), control);
    pidsFrom(outcome.stdout);
    // Simulated here; real Windows behaviour is unverified (docs/support.md).
    expect(outcome.cleanup.scope).toBe("direct-child-only");
  });
});
