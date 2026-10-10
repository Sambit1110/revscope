/**
 * Dependency licence check, from package-lock.json alone (offline and
 * deterministic):
 *
 *   npm run licenses            (or: node scripts/check-licenses.ts <package-lock.json>)
 *
 * - Every package must declare a licence in the lockfile.
 * - Production packages (installed for users) must use a permissive licence
 *   compatible with distributing Revscope under Apache-2.0.
 * - Development-only packages may also use the licences listed in
 *   DEV_ONLY_EXCEPTIONS, each named explicitly with the reason it is accepted.
 *
 * Exits non-zero, listing every violation. It checks declared licence
 * metadata only; it is not a legal review.
 */
import { readFileSync } from "node:fs";

const PERMISSIVE = new Set(["MIT", "ISC", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "0BSD"]);

/**
 * MPL-2.0 is file-level copyleft. lightningcss (and its per-platform binaries)
 * reaches the tree through Vitest's Vite dependency; it is run unmodified at
 * test time and never distributed with Revscope.
 */
const DEV_ONLY_EXCEPTIONS: ReadonlyMap<string, string> = new Map([["MPL-2.0", "^lightningcss(-[a-z0-9-]+)?$"]]);

interface LockPackage {
  readonly license?: string;
  readonly dev?: boolean;
}

// An optional path argument checks another lockfile (used by the tests).
const lockPath = process.argv[2] ?? new URL("../package-lock.json", import.meta.url);
const lock = JSON.parse(readFileSync(lockPath, "utf8")) as {
  readonly packages: Readonly<Record<string, LockPackage>>;
};

const violations: string[] = [];
const counts = new Map<string, number>();
let production = 0;
for (const [path, entry] of Object.entries(lock.packages)) {
  if (path === "") continue; // Revscope itself.
  const name = path.replace(/^.*node_modules\//u, "");
  const licence = entry.license;
  if (licence === undefined || licence === "") {
    violations.push(`${name}: no licence declared`);
    continue;
  }
  counts.set(licence, (counts.get(licence) ?? 0) + 1);
  if (PERMISSIVE.has(licence)) {
    if (entry.dev !== true) production += 1;
    continue;
  }
  const allowed = DEV_ONLY_EXCEPTIONS.get(licence);
  if (entry.dev === true && allowed !== undefined && new RegExp(allowed, "u").test(name)) continue;
  violations.push(`${name}: ${licence}${entry.dev === true ? " (development only, not on the exception list)" : " (production)"}`);
}

const summary = [...counts].toSorted(([left], [right]) => left.localeCompare(right)).map(([licence, count]) => `${licence} ${String(count)}`);
process.stdout.write(`Lockfile packages by licence: ${summary.join(", ")}. Production packages: ${String(production)}.\n`);
if (violations.length > 0) {
  process.stderr.write(`Licence check failed:\n${violations.map((line) => `  - ${line}`).join("\n")}\n`);
  process.exitCode = 1;
} else process.stdout.write("Licence check passed.\n");
