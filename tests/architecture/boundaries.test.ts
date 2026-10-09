import { readdir, readFile } from "node:fs/promises";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";

import { REPO_ROOT } from "../support/context.js";

const SRC = join(REPO_ROOT, "src");

const sourceFiles = async (directory: string): Promise<string[]> => {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(
    entries.map((entry) =>
      entry.isDirectory()
        ? sourceFiles(join(directory, entry.name))
        : Promise.resolve(entry.name.endsWith(".ts") ? [join(directory, entry.name)] : []),
    ),
  );
  return nested.flat();
};

/** Every way a module can name a dependency with a literal specifier. */
const DEPENDENCY_PATTERNS: readonly RegExp[] = [
  // import x from "m"; import type { T } from "m"; export * from "m"; export { x } from "m"
  /(?:^|[\n;])\s*(?:import|export)\s[^;]*?\bfrom\s*["']([^"']+)["']/gu,
  // import "m"; (side effects only)
  /(?:^|[\n;])\s*import\s*["']([^"']+)["']/gu,
  // await import("m")
  /\bimport\s*\(\s*["']([^"']+)["']\s*\)/gu,
  // require("m"), including through createRequire
  /\brequire\s*\(\s*["']([^"']+)["']\s*\)/gu,
];

/** Dynamic imports or requires whose target is not a literal cannot be checked. */
const UNANALYZABLE = /\b(?:import|require)\s*\(\s*(?!["'][^"']+["']\s*\))[^)]/gu;

const specifiers = (source: string): string[] =>
  DEPENDENCY_PATTERNS.flatMap((pattern) => [...source.matchAll(pattern)].map((match) => match[1] ?? ""));

const unanalyzable = (source: string): number => [...source.matchAll(UNANALYZABLE)].length;

const layerOf = (file: string): string => relative(SRC, file).split("/")[0] ?? "";

/** Allowed internal dependencies per layer; dependencies point inward only. */
const ALLOWED: Readonly<Record<string, readonly string[]>> = {
  domain: ["domain"],
  application: ["domain", "application"],
  infrastructure: ["domain", "application", "infrastructure"],
  interfaces: ["domain", "application", "infrastructure", "interfaces", "composition.ts"],
  "composition.ts": ["domain", "application", "infrastructure"],
  bin: ["interfaces"],
};

/** Third-party and Node built-ins each layer may use. */
const EXTERNAL: Readonly<Record<string, RegExp>> = {
  domain: /^(?:zod|node:crypto)$/u,
  // node:async_hooks lets the session detect providers calling back into it.
  application: /^(?:zod|node:path|node:async_hooks)$/u,
  infrastructure: /^(?:zod|node:.+)$/u,
  interfaces: /^(?:zod|node:.+)$/u,
  // node:os and node:path locate the opt-in diagnostics directory.
  "composition.ts": /^(?:zod|node:crypto|node:os|node:path)$/u,
  bin: /^$/u,
};

describe("module boundaries", () => {
  it("keeps every import within its layer's allowed dependencies", async () => {
    const violations: string[] = [];
    for (const file of await sourceFiles(SRC)) {
      const layer = layerOf(file);
      const source = await readFile(file, "utf8");
      if (unanalyzable(source) > 0) violations.push(`${relative(REPO_ROOT, file)} (non-literal import or require)`);
      for (const specifier of specifiers(source)) {
        if (specifier.startsWith(".")) {
          const target = relative(SRC, join(file, "..", specifier)).split("/")[0] ?? "";
          const targetLayer = target.replace(/\.js$/u, ".ts");
          if (!(ALLOWED[layer] ?? []).includes(targetLayer))
            violations.push(`${relative(REPO_ROOT, file)} -> ${specifier}`);
        } else if (!(EXTERNAL[layer] ?? /^$/u).test(specifier))
          violations.push(`${relative(REPO_ROOT, file)} -> ${specifier} (external)`);
      }
    }
    expect(violations).toEqual([]);
  });

  it.each([
    ['import x from "node:fs";', ["node:fs"]],
    ["import x from 'node:fs';", ["node:fs"]],
    ['import type { A } from "../interfaces/cli.js";', ["../interfaces/cli.js"]],
    ['export * from "node:fs";', ["node:fs"]],
    ['export { a } from "./a.js";', ["./a.js"]],
    ['import "node:fs";', ["node:fs"]],
    ['const fs = await import("node:fs");', ["node:fs"]],
    ['const r = require("node:fs");', ["node:fs"]],
    ['import {\n  a,\n  b,\n} from "./multi.js";', ["./multi.js"]],
  ])("detects the dependency in %s", (source, expected) => {
    expect(specifiers(source)).toEqual(expected);
  });

  it("flags imports and requires whose target it cannot read", () => {
    expect(unanalyzable("const m = await import(name);")).toBe(1);
    expect(unanalyzable("const r = require(`node:${x}`);")).toBe(1);
    expect(unanalyzable('const m = await import("node:fs");')).toBe(0);
    // Not calls: a property or word that merely contains the name.
    expect(unanalyzable("const imported = 1; obj.required(1);")).toBe(0);
  });

  it("finds imports in every source file it checks", async () => {
    // Guards the scanner itself: a broken pattern would make the test above vacuous.
    const files = await sourceFiles(SRC);
    expect(files.length).toBeGreaterThan(0);
    const withImports = await Promise.all(
      files.map(async (file) => specifiers(await readFile(file, "utf8")).length > 0),
    );
    expect(withImports.filter(Boolean).length).toBeGreaterThan(files.length / 2);
  });
});
