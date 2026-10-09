import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach } from "vitest";

import type { ToolContext } from "../../src/application/tools/types.js";
import { createToolContext } from "../../src/composition.js";

export const REPO_ROOT = fileURLToPath(new URL("../../", import.meta.url));
export const fixturePath = (...parts: string[]) => join(REPO_ROOT, "fixtures", ...parts);
export const BIN = join(REPO_ROOT, "dist", "bin", "revscope.js");

/** Production wiring with captured logs, optionally overriding dependencies. */
export const testContext = (overrides: Partial<ToolContext> = {}) => {
  const logs: string[] = [];
  const context: ToolContext = {
    ...createToolContext({ logLevel: "debug", writeLog: (line) => logs.push(line) }),
    newCorrelationId: () => "cor_test",
    ...overrides,
  };
  return { context, logs };
};

/** A context whose artifact reader throws, to provoke the internal-error path. */
export const exploding = (message = "boom /Users/secret/path EXPLODE_SECRET") =>
  testContext({
    artifactReader: {
      read: () => Promise.reject(new Error(message)),
    },
  });

const created: string[] = [];
afterEach(async () => {
  await Promise.all(created.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

/** A temporary directory removed after the current test. */
export const tempDir = async (): Promise<string> => {
  const path = await mkdtemp(join(tmpdir(), "revscope-test-"));
  created.push(path);
  return path;
};
