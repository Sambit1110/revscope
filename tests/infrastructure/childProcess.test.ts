import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

import { runChild, type ChildCommand, type ProcessControl } from "../../src/infrastructure/childProcess.js";

const FAMILY = fileURLToPath(new URL("../fixtures/child/process-family.mjs", import.meta.url));
const posix = process.platform !== "win32";

/** Documented bounds (see docs/architecture.md): deadline + grace + drain + 250 ms + 500 ms verification. */
const TIMEOUT_MS = 300;
const KILL_GRACE_MS = 500;
const DRAIN_MS = 250;
const MAX_OVERRUN_MS = KILL_GRACE_MS + DRAIN_MS + 250 + 500;

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
  maxOutputBytes: 64 * 1024,
  ...overrides,
});

const pidsFrom = (stdout: string): { child: number; grandchild?: number } => {
  const pids = JSON.parse(stdout.split("\n")[0] ?? "{}") as { child: number; grandchild?: number };
  owned.push(pids.child, ...(pids.grandchild === undefined ? [] : [pids.grandchild]));
  return pids;
};

const run = async (command: ChildCommand, control?: ProcessControl) => {
  const outcome = await runChild(command, {}, control);
  if (!outcome.ok) throw new Error(JSON.stringify(outcome.error));
  return outcome.value;
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
    const outcome = await run(family("ignore-term"));
    const pids = pidsFrom(outcome.stdout);
    expect(outcome.termination).toBe("timed-out");
    expect(outcome.signal).toBe("SIGKILL");
    expect(outcome.durationMs).toBeGreaterThanOrEqual(TIMEOUT_MS + KILL_GRACE_MS - 50);
    expect(outcome.durationMs).toBeLessThan(TIMEOUT_MS + MAX_OVERRUN_MS);
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
    expect(outcome.durationMs).toBeLessThan(TIMEOUT_MS + MAX_OVERRUN_MS + 200);
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
