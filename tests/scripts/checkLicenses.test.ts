import { spawnSync } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { REPO_ROOT, tempDir } from "../support/context.js";

const SCRIPT = join(REPO_ROOT, "scripts", "check-licenses.ts");

const check = async (packages: Record<string, { license?: string; dev?: boolean }>) => {
  const path = join(await tempDir(), "package-lock.json");
  await writeFile(path, JSON.stringify({ lockfileVersion: 3, packages: { "": {}, ...packages } }));
  return spawnSync(process.execPath, [SCRIPT, path], { encoding: "utf8" });
};

describe("dependency licence check", () => {
  it("passes the repository's own lockfile", () => {
    const result = spawnSync(process.execPath, [SCRIPT], { encoding: "utf8" });
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("Licence check passed.");
  });

  it("accepts permissive production licences and listed development-only exceptions", async () => {
    const result = await check({
      "node_modules/zod": { license: "MIT" },
      "node_modules/lightningcss": { license: "MPL-2.0", dev: true },
      "node_modules/lightningcss-linux-x64-gnu": { license: "MPL-2.0", dev: true },
    });
    expect(result.status, result.stderr).toBe(0);
  });

  it.each([
    ["a copyleft production dependency", { "node_modules/lib": { license: "GPL-3.0-only" } }, "lib: GPL-3.0-only (production)"],
    ["an MPL-2.0 production dependency, even if it is on the development exception list", { "node_modules/lightningcss": { license: "MPL-2.0" } }, "lightningcss: MPL-2.0 (production)"],
    ["an unlisted development-only exception", { "node_modules/other": { license: "MPL-2.0", dev: true } }, "other: MPL-2.0 (development only"],
    ["a package without a licence", { "node_modules/mystery": {} }, "mystery: no licence declared"],
  ])("fails on %s", async (_label, packages, message) => {
    const result = await check(packages);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(message);
  });
});
