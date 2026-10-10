/**
 * Runs Revscope as a black box, one CLI process per run, with explicit
 * limits, a minimal environment, and checks for anything left behind.
 */
import { spawn, spawnSync } from "node:child_process";
import { mkdir, readdir, realpath } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

import { sha256 } from "./fixtures.ts";

export interface EngineSettings {
  readonly ghidraDir: string;
  readonly javaHome: string | null;
}

export interface RunLimits {
  readonly timeoutMs: number;
  readonly maxFunctions: number;
  readonly decompileTimeoutMs: number;
}

export interface RunObservation {
  /** "ok", an error code, or "no-json" when stdout was not one JSON document. */
  readonly outcome: string;
  readonly exit_code: number | null;
  readonly signal: string | null;
  readonly wall_ms: number;
  /** Peak resident set size of the largest process in the run's tree (from /usr/bin/time -l). */
  readonly peak_rss_bytes: number | null;
  readonly stdout_sha256: string;
  readonly stdout_bytes: number;
  /** Bytes Revscope wrote to stderr (the time report excluded). */
  readonly stderr_bytes: number;
  readonly cleanup_reported: { readonly process: string; readonly workspace: string } | null;
  readonly leftovers: { readonly temp_entries: number; readonly home_entries: number; readonly processes: number };
  /** Which sensitive values appeared in stdout or stderr (labels only, never the values). */
  readonly leaks: readonly string[];
  readonly harness_killed: boolean;
}

export interface RunResult {
  readonly observation: RunObservation;
  readonly document: unknown;
  readonly stdout: string;
}

/** A private temp and home directory per run, so leftovers are attributable to it. */
export const runDirectories = async (root: string) => {
  const temp = join(root, "tmp");
  const home = join(root, "home");
  await mkdir(temp, { recursive: true });
  await mkdir(home, { recursive: true });
  return { temp, home, tempReal: await realpath(temp) };
};

/** Only what Revscope and Ghidra need; nothing else from the host environment is passed on. */
export const minimalEnv = (engine: EngineSettings, dirs: { temp: string; home: string }): Record<string, string> => ({
  // PATH is passed on so Ghidra's launcher finds the same java as it does for the user.
  PATH: process.env["PATH"] ?? "/usr/bin:/bin:/usr/sbin:/sbin",
  HOME: dirs.home,
  TMPDIR: dirs.temp,
  LANG: "C",
  REVSCOPE_GHIDRA_DIR: engine.ghidraDir,
  ...(engine.javaHome === null ? {} : { REVSCOPE_JAVA_HOME: engine.javaHome }),
});

/** Processes whose command line mentions the run's private directory. */
export const processesMentioning = (fragments: readonly string[]): number => {
  const ps = spawnSync("ps", ["-axo", "pid=,command="], { encoding: "utf8" });
  return (ps.stdout ?? "").split("\n").filter((line) => fragments.some((fragment) => line.includes(fragment))).length;
};

const entries = async (directory: string): Promise<number> => (await readdir(directory).catch(() => [])).length;

const sensitiveValues = (engine: EngineSettings, dirs: { temp: string; home: string; tempReal: string }) => [
  { label: "ghidra-dir", value: engine.ghidraDir },
  ...(engine.javaHome === null ? [] : [{ label: "java-home", value: engine.javaHome }]),
  { label: "user-home", value: homedir() },
  { label: "run-temp", value: dirs.temp },
  { label: "run-temp", value: dirs.tempReal },
  { label: "run-home", value: dirs.home },
];

/** Labels of sensitive values in the text, after removing the input path the caller supplied. */
export const findLeaks = (text: string, inputPath: string, values: readonly { label: string; value: string }[]): string[] => {
  const scrubbed = inputPath === "" ? text : text.replaceAll(inputPath, "<input>");
  return [...new Set(values.filter(({ value }) => value !== "" && scrubbed.includes(value)).map(({ label }) => label))];
};

/** Read `/usr/bin/time -l`'s peak RSS line and remove its report from stderr. */
export const splitTimeReport = (stderr: string): { stderr: string; peakRss: number | null } => {
  const marker = /^\s+\d+\.\d+ real\s+\d+\.\d+ user\s+\d+\.\d+ sys$/mu.exec(stderr);
  if (marker === null) return { stderr, peakRss: null };
  const report = stderr.slice(marker.index);
  const rss = /^\s*(\d+)\s+maximum resident set size$/mu.exec(report);
  return { stderr: stderr.slice(0, marker.index), peakRss: rss?.[1] === undefined ? null : Number(rss[1]) };
};

const outcomeOf = (document: unknown): string => {
  if (typeof document !== "object" || document === null) return "no-json";
  const { ok, error } = document as { ok?: unknown; error?: { code?: unknown } };
  if (ok === true) return "ok";
  return typeof error?.code === "string" ? error.code : "no-json";
};

const cleanupOf = (document: unknown): RunObservation["cleanup_reported"] => {
  const value = document as { data?: { cleanup?: unknown }; error?: { details?: { cleanup?: unknown } } } | null;
  const cleanup = (value?.data?.cleanup ?? value?.error?.details?.cleanup) as { process?: unknown; workspace?: unknown } | undefined;
  return typeof cleanup?.process === "string" && typeof cleanup.workspace === "string"
    ? { process: cleanup.process, workspace: cleanup.workspace }
    : null;
};

export interface CliRun {
  readonly node: string;
  readonly bin: string;
  readonly engine: EngineSettings;
  readonly runRoot: string;
  readonly inputPath: string;
  readonly authorized: boolean;
  readonly limits: RunLimits;
  /** False passes --no-decompile. */
  readonly decompile?: boolean;
  /** Send SIGINT once Ghidra is running plus this delay; null runs to completion. */
  readonly cancelAfterStartMs: number | null;
}

/** One CLI analysis, bounded by the requested timeout plus a fixed margin the harness enforces itself. */
export const runCli = async (run: CliRun): Promise<RunResult> => {
  const dirs = await runDirectories(run.runRoot);
  const args = [
    run.bin,
    "analyze-binary",
    run.inputPath,
    ...(run.authorized ? ["--authorized"] : []),
    "--timeout-ms",
    String(run.limits.timeoutMs),
    "--max-functions",
    String(run.limits.maxFunctions),
    "--decompile-timeout-ms",
    String(run.limits.decompileTimeoutMs),
    ...(run.decompile === false ? ["--no-decompile"] : []),
  ];
  // /usr/bin/time ignores SIGINT, so a cancellation run starts Node directly.
  const timed = run.cancelAfterStartMs === null;
  const command = timed ? "/usr/bin/time" : run.node;
  const child = spawn(command, timed ? ["-l", run.node, ...args] : args, {
    env: minimalEnv(run.engine, dirs),
    cwd: dirs.home,
    detached: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const started = performance.now();
  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8").on("data", (chunk: string) => (stdout += chunk));
  child.stderr.setEncoding("utf8").on("data", (chunk: string) => (stderr += chunk));

  let harnessKilled = false;
  const killGroup = () => {
    harnessKilled = true;
    try {
      if (child.pid !== undefined) process.kill(-child.pid, "SIGKILL");
    } catch {
      // Already gone.
    }
  };
  const hardLimit = setTimeout(killGroup, run.limits.timeoutMs + 60_000);
  const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) =>
    child.on("close", (code, signal) => resolve({ code, signal })),
  );

  if (run.cancelAfterStartMs !== null) {
    const cancelAt = (async () => {
      const deadline = Date.now() + 60_000;
      while (Date.now() < deadline && processesMentioning([dirs.temp, dirs.tempReal]) === 0)
        await new Promise((resolve) => setTimeout(resolve, 100));
      await new Promise((resolve) => setTimeout(resolve, run.cancelAfterStartMs ?? 0));
      if (child.exitCode === null && child.pid !== undefined) child.kill("SIGINT");
    })();
    await Promise.race([cancelAt, exited]);
  }
  const { code, signal } = await exited;
  clearTimeout(hardLimit);
  const wallMs = Math.round(performance.now() - started);

  // Give a just-killed tree a moment to disappear before looking for leftovers.
  await new Promise((resolve) => setTimeout(resolve, 500));
  const { stderr: revscopeStderr, peakRss } = timed ? splitTimeReport(stderr) : { stderr, peakRss: null };
  let document: unknown = null;
  try {
    document = JSON.parse(stdout);
  } catch {
    document = null;
  }
  const values = sensitiveValues(run.engine, dirs);
  return {
    document,
    stdout,
    observation: {
      outcome: outcomeOf(document),
      exit_code: code,
      signal,
      wall_ms: wallMs,
      peak_rss_bytes: peakRss,
      stdout_sha256: sha256(Buffer.from(stdout)),
      stdout_bytes: Buffer.byteLength(stdout),
      stderr_bytes: Buffer.byteLength(revscopeStderr),
      cleanup_reported: cleanupOf(document),
      leftovers: {
        temp_entries: await entries(dirs.temp),
        home_entries: await entries(dirs.home),
        processes: processesMentioning([dirs.temp, dirs.tempReal]),
      },
      leaks: findLeaks(`${stdout}\n${revscopeStderr}`, run.inputPath, values),
      harness_killed: harnessKilled,
    },
  };
};
