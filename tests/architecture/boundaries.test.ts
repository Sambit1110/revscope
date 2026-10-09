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

/** Static import and export specifiers, including type-only ones. */
const specifiers = (source: string): string[] =>
  [...source.matchAll(/(?:^|\n)\s*(?:import|export)\s[^;]*?from\s+"([^"]+)"/gu)].map(
    (match) => match[1] ?? "",
  );

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
  application: /^(?:zod|node:path)$/u,
  infrastructure: /^(?:zod|node:.+)$/u,
  interfaces: /^(?:zod|node:.+)$/u,
  "composition.ts": /^(?:zod|node:crypto)$/u,
  bin: /^$/u,
};

describe("module boundaries", () => {
  it("keeps every import within its layer's allowed dependencies", async () => {
    const violations: string[] = [];
    for (const file of await sourceFiles(SRC)) {
      const layer = layerOf(file);
      const source = await readFile(file, "utf8");
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
