import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import type { BinaryAnalysisLimits } from "../../src/application/ports.js";
import { GhidraEngine, type GhidraEngineOptions } from "../../src/infrastructure/ghidra/engine.js";
import { tempDir } from "./context.js";

const FAKE = fileURLToPath(new URL("../fixtures/ghidra/fake-analyzeHeadless.mjs", import.meta.url));

export interface FakeControl {
  readonly mode: "success" | "slow-success" | "partial-hang" | "partial-exit" | "hang" | "say" | "huge";
  readonly export?: string;
  readonly delayMs?: number;
  readonly grandchild?: boolean;
  readonly ignoreTerm?: boolean;
  readonly stdout?: string;
  readonly stderr?: string;
  readonly exitCode?: number;
}

export interface LastRun {
  readonly args: string[];
  readonly cwd: string;
  readonly pid: number;
  readonly grandchild: number | null;
  readonly envNames: string[];
  readonly env: Record<"HOME" | "TMPDIR" | "JAVA_TOOL_OPTIONS" | "JAVA_HOME", string | null>;
  readonly script: { name: string; exportPath: string; maxFunctions: string; decompile: string; decompileTimeout: string; deadlineEpochMs: number; maxPseudocode: string };
  readonly inputSha256: string;
}

/**
 * A fake Ghidra installation: support/analyzeHeadless is an executable Node.js
 * script (absolute interpreter path, no shell) that loads the fake.
 */
export const fakeGhidra = async (control: FakeControl, version = "11.4") => {
  const root = await tempDir();
  await mkdir(join(root, "support"));
  await mkdir(join(root, "Ghidra"));
  const launcher = join(root, "support", "analyzeHeadless");
  await writeFile(launcher, `#!${process.execPath}\nimport(${JSON.stringify(pathToFileURL(FAKE).href)});\n`);
  await chmod(launcher, 0o755);
  await writeFile(join(root, "Ghidra", "application.properties"), `application.name=Ghidra\napplication.version=${version}\n`);
  await writeFile(join(root, "fake-control.json"), JSON.stringify(control));
  const scriptDir = join(root, "scripts");
  await mkdir(scriptDir);
  await writeFile(join(scriptDir, "RevscopeExport.java"), "// placeholder for the fake engine\n");
  return {
    root,
    scriptDir,
    setControl: (next: FakeControl) => writeFile(join(root, "fake-control.json"), JSON.stringify(next)),
    lastRun: async (): Promise<LastRun> => JSON.parse(await readFile(join(root, "last-run.json"), "utf8")) as LastRun,
  };
};

/** Short phases, so fake-engine timeouts take a fraction of a second. */
export const FAST_TIMING = { killGraceMs: 200, settleMs: 200, reserveMs: 300, scriptMarginMs: 100, minChildMs: 100 } as const;

export const fakeEngine = async (
  fake: Awaited<ReturnType<typeof fakeGhidra>>,
  options: Partial<GhidraEngineOptions> = {},
) =>
  new GhidraEngine({
    settings: { ghidraDir: fake.root },
    scriptDir: fake.scriptDir,
    tempParent: await tempDir(),
    timing: FAST_TIMING,
    host: { PATH: "/usr/bin:/bin" },
    ...options,
  });

export const LIMITS: BinaryAnalysisLimits = { timeoutMs: 45_000, maxFunctions: 200, decompile: true, decompileTimeoutMs: 10_000 };
