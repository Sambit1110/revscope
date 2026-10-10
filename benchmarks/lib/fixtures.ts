/**
 * Builds every benchmark input into a directory outside the source tree.
 * Nothing built here is ever executed: compiled programs lose their execute
 * permission and are only read, by `nm` and by Revscope.
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, copyFile, mkdir, readFile, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { BASE, FUNCTIONS, makeElf } from "../../tests/fixtures/binaries/make-elf.mjs";
import {
  GENERATED_ELF_ENTRY,
  GENERATED_ELF_FUNCTIONS,
  SOURCES,
  symbolPrefix,
  type CompiledCase,
  type GeneratedElfCase,
  type RejectionCase,
} from "../manifest.ts";
import { parseNm, textSymbols, type GroundTruth, type TruthFunction } from "./metrics.ts";

const SOURCE_DIRS = {
  benchmarks: fileURLToPath(new URL("../cases/", import.meta.url)),
  fixture: fileURLToPath(new URL("../../tests/fixtures/binaries/macho/", import.meta.url)),
};

export const sha256 = (bytes: Uint8Array): string => createHash("sha256").update(bytes).digest("hex");

/** Run a build tool; its output is kept short and never includes the environment. */
const tool = (command: string, args: readonly string[]) => {
  const result = spawnSync(command, args, { encoding: "utf8", timeout: 120_000 });
  return {
    ok: result.status === 0,
    stdout: result.stdout ?? "",
    problem: result.error?.message ?? (result.stderr ?? "").trim().split("\n").slice(-3).join(" "),
  };
};

export const toolVersion = (command: string, args: readonly string[] = ["--version"]): string | null => {
  const result = spawnSync(command, args, { encoding: "utf8", timeout: 30_000 });
  if (result.status !== 0) return null;
  return `${result.stdout}${result.stderr}`.trim().split("\n")[0] ?? null;
};

export interface BuiltInput {
  readonly path: string;
  readonly sha256: string;
  readonly size: number;
  /** Exactly how the input was produced. */
  readonly recipe: Record<string, string | boolean>;
}

export type Built<T> = { ok: true; input: BuiltInput; truth: T } | { ok: false; reason: string };

const finish = async (path: string, recipe: Record<string, string | boolean>): Promise<BuiltInput> => {
  await chmod(path, 0o644);
  const bytes = await readFile(path);
  return { path, sha256: sha256(bytes), size: bytes.length, recipe };
};

const TARGET_ARGS: Record<CompiledCase["target"], readonly string[]> = {
  "macho-arm64": ["-arch", "arm64"],
  "elf-x86_64-object": ["-target", "x86_64-unknown-linux-gnu", "-c", "-ffreestanding", "-fno-pic"],
  "elf-aarch64-object": ["-target", "aarch64-unknown-linux-gnu", "-c", "-ffreestanding", "-fno-pic"],
};

/** Compile a case and read its ground truth from the unstripped binary's symbol table. */
export const buildCompiled = async (spec: CompiledCase, directory: string): Promise<Built<GroundTruth>> => {
  const source = join(SOURCE_DIRS[spec.sourceDir], spec.source);
  const unstripped = join(directory, `${spec.id}.full`);
  const args = [...TARGET_ARGS[spec.target], spec.optimization, "-o", unstripped, source];
  const compiled = tool("clang", args);
  if (!compiled.ok) return { ok: false, reason: `clang failed: ${compiled.problem}` };
  await chmod(unstripped, 0o644);

  const nmFull = tool("nm", ["-n", unstripped]);
  if (!nmFull.ok) return { ok: false, reason: `nm failed: ${nmFull.problem}` };
  const full = parseNm(nmFull.stdout);
  const prefix = symbolPrefix(spec.target);
  const symbolsAtFull = textSymbols(full.defined);
  const addressOf = new Map<string, bigint>();
  for (const [address, names] of symbolsAtFull) for (const name of names) addressOf.set(name, address);

  const functions: TruthFunction[] = [];
  for (const expected of SOURCES[spec.source]) {
    const symbol = `${prefix}${expected.name}`;
    const address = addressOf.get(symbol);
    // A function the compiler removed is not in the binary, so it is not ground truth.
    if (address !== undefined) functions.push({ symbol, address, expected });
  }

  let path = unstripped;
  let symbolNames = full.names;
  let symbolsAt = symbolsAtFull;
  if (spec.stripped) {
    path = join(directory, spec.id);
    const stripped = tool("strip", ["-o", path, unstripped]);
    if (!stripped.ok) return { ok: false, reason: `strip failed: ${stripped.problem}` };
    const nmStripped = tool("nm", ["-n", path]);
    // nm reports "no symbols" with a non-zero status on some versions; an empty table is the expected result.
    const strippedTable = parseNm(nmStripped.stdout);
    symbolNames = strippedTable.names;
    symbolsAt = textSymbols(strippedTable.defined);
  } else {
    path = join(directory, spec.id);
    await copyFile(unstripped, path);
  }

  let entry: GroundTruth["entry"] = { source: "unavailable", addresses: [] };
  if (spec.entry.source === "macho-lc-main") {
    const main = addressOf.get(spec.entry.symbol);
    if (main === undefined) return { ok: false, reason: "the entry symbol is not in the symbol table" };
    entry = { source: spec.entry.source, addresses: [main] };
  } else if (spec.entry.source === "elf-header") entry = { source: spec.entry.source, addresses: [BigInt(spec.entry.address)] };

  const input = await finish(path, {
    compiler: "clang",
    source: spec.source,
    source_sha256: sha256(await readFile(source)),
    target: spec.target,
    optimization: spec.optimization,
    flags: args.filter((arg) => arg !== unstripped && arg !== source && arg !== "-o").join(" "),
    stripped: spec.stripped,
  });
  return {
    ok: true,
    input,
    truth: {
      addressMode: spec.target === "macho-arm64" ? "absolute" : "relative",
      names: spec.names,
      recovery: spec.stripped ? "measured" : "all",
      functions,
      // Name checks compare against the analyzed binary; addresses come from the unstripped build.
      symbolsAt: spec.stripped ? symbolsAtFull : symbolsAt,
      symbolNames,
      entry,
    },
  };
};

const SECTION_HEADERS_LAYOUT = [0, 1, 4]; // null, .text, .shstrtab

/**
 * Strip the generated ELF the way `strip` would: drop .symtab and .strtab,
 * keep .text and .shstrtab. Code, program header and entry are unchanged.
 */
export const stripGeneratedElf = (full: Buffer): Buffer => {
  const SECTION_HEADERS = 0x110;
  const header = (index: number) => full.subarray(SECTION_HEADERS + index * 64, SECTION_HEADERS + (index + 1) * 64);
  const out = Buffer.alloc(SECTION_HEADERS + 3 * 64);
  full.copy(out, 0, 0, SECTION_HEADERS);
  out.fill(0, 0x98, SECTION_HEADERS); // .symtab and .strtab contents
  SECTION_HEADERS_LAYOUT.forEach((from, to) => header(from).copy(out, SECTION_HEADERS + to * 64));
  out.writeUInt16LE(3, 60); // e_shnum
  out.writeUInt16LE(2, 62); // e_shstrndx: .shstrtab is now section 2
  // .shstrtab still names the removed sections; strip would rewrite it, but unused names are harmless.
  return out;
};
export const buildGeneratedElf = async (spec: GeneratedElfCase, directory: string): Promise<Built<GroundTruth>> => {
  const path = join(directory, spec.id);
  const full = makeElf();
  await writeFile(path, spec.stripped ? stripGeneratedElf(full) : full);
  const functions: TruthFunction[] = FUNCTIONS.map(({ name, offset }, index) => ({
    symbol: name,
    address: BASE + BigInt(offset),
    expected: GENERATED_ELF_FUNCTIONS[index] ?? { name, params: [], returns: "int" },
  }));
  const symbolsAt = new Map(functions.map(({ symbol, address }) => [address, [symbol]]));
  return {
    ok: true,
    input: await finish(path, { generator: "tests/fixtures/binaries/make-elf.mjs", stripped: spec.stripped }),
    truth: {
      addressMode: "absolute",
      names: spec.names,
      recovery: spec.stripped ? "measured" : "all",
      functions,
      symbolsAt,
      symbolNames: spec.stripped ? new Set() : new Set(functions.map(({ symbol }) => symbol)),
      entry: { source: "elf-header", addresses: [BigInt(GENERATED_ELF_ENTRY)] },
    },
  };
};

/** Deterministic bytes from a fixed seed (xorshift32), so the random case is reproducible. */
export const seededBytes = (length: number, seed = 0x5eed_1234): Buffer => {
  const out = Buffer.alloc(length);
  let state = seed >>> 0;
  for (let index = 0; index < length; index += 1) {
    state ^= state << 13;
    state >>>= 0;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    out[index] = state & 0xff;
  }
  return out;
};

/** Build a rejection input; `machoPath` is any compiled Mach-O to truncate. */
export const buildRejection = async (spec: RejectionCase, directory: string, machoPath: string | null): Promise<Built<null>> => {
  const path = join(directory, spec.id);
  const recipe: Record<string, string | boolean> = { input: spec.input };
  switch (spec.input) {
    case "text":
      await writeFile(path, "This is a plain text file, not a program.\n".repeat(20));
      break;
    case "random":
      await writeFile(path, seededBytes(4096));
      recipe["seed"] = "0x5eed1234 xorshift32";
      break;
    case "empty":
      await writeFile(path, "");
      break;
    case "truncated-elf":
      await writeFile(path, makeElf().subarray(0, 100));
      break;
    case "truncated-macho":
      if (machoPath === null) return { ok: false, reason: "no compiled Mach-O to truncate" };
      await writeFile(path, (await readFile(machoPath)).subarray(0, 512));
      break;
    case "directory":
      await mkdir(path);
      return { ok: true, input: { path, sha256: "", size: 0, recipe }, truth: null };
    case "symlink":
      await writeFile(`${path}.target`, makeElf());
      await symlink(`${path}.target`, path);
      return { ok: true, input: { path, sha256: sha256(makeElf()), size: 0, recipe }, truth: null };
    case "missing":
      return { ok: true, input: { path, sha256: "", size: 0, recipe }, truth: null };
    case "unauthorized":
      await writeFile(path, makeElf());
      break;
    default:
      return { ok: false, reason: "unknown rejection input" };
  }
  return { ok: true, input: await finish(path, recipe), truth: null };
};
