import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { DEFAULT_SCRIPT_DIR } from "../../../src/infrastructure/ghidra/engine.js";
import { GHIDRA_EXPORT_SCHEMA } from "../../../src/infrastructure/ghidra/exportFormat.js";
import { EXPORT_SCRIPT, planHeadless, DEFAULT_TIMING } from "../../../src/infrastructure/ghidra/headless.js";
import { BASE, FUNCTIONS, makeElf } from "../../fixtures/binaries/make-elf.mjs";

/** Pinned so any change to the fixture is deliberate and reviewed. */
const ELF_SHA256 = "92d2dbdfdd2d95bf26a269ce66b733a795475f9cd093858585aeb715733e9306";

/** An independent minimal ELF64 reader, so the generator is not checked against itself. */
const readElf = (file: Buffer) => {
  const sectionHeaders = Number(file.readBigUInt64LE(40));
  const count = file.readUInt16LE(60);
  const sections = Array.from({ length: count }, (_, index) => {
    const at = sectionHeaders + index * 64;
    return {
      type: file.readUInt32LE(at + 4),
      offset: Number(file.readBigUInt64LE(at + 24)),
      size: Number(file.readBigUInt64LE(at + 32)),
      link: file.readUInt32LE(at + 40),
      entsize: Number(file.readBigUInt64LE(at + 56)),
    };
  });
  const symtab = sections.find(({ type }) => type === 2);
  if (symtab === undefined) throw new Error("no symbol table");
  const strtab = sections[symtab.link];
  if (strtab === undefined) throw new Error("no string table");
  const symbols = Array.from({ length: symtab.size / symtab.entsize }, (_, index) => {
    const at = symtab.offset + index * symtab.entsize;
    const nameStart = strtab.offset + file.readUInt32LE(at);
    return {
      name: file.toString("latin1", nameStart, file.indexOf(0, nameStart)),
      info: file[at + 4],
      section: file.readUInt16LE(at + 6),
      value: file.readBigUInt64LE(at + 8),
      size: Number(file.readBigUInt64LE(at + 16)),
    };
  });
  return {
    magic: file.toString("latin1", 0, 4),
    elfClass: file[4],
    data: file[5],
    type: file.readUInt16LE(16),
    machine: file.readUInt16LE(18),
    entry: file.readBigUInt64LE(24),
    load: { type: file.readUInt32LE(0x40), flags: file.readUInt32LE(0x44), offset: file.readBigUInt64LE(0x48), vaddr: file.readBigUInt64LE(0x50), size: Number(file.readBigUInt64LE(0x60)) },
    symbols,
  };
};

describe("the generated ELF fixture", () => {
  it("is deterministic and pinned", () => {
    expect(createHash("sha256").update(makeElf()).digest("hex")).toBe(ELF_SHA256);
    expect(makeElf()).toEqual(makeElf());
  });

  it("is a well-formed little-endian x86-64 executable with two named functions", () => {
    const file = makeElf();
    const elf = readElf(file);
    expect(elf).toMatchObject({ magic: "\x7fELF", elfClass: 2, data: 1, type: 2, machine: 62, entry: BASE + 0x80n });
    expect(elf.load).toEqual({ type: 1, flags: 5, offset: 0n, vaddr: BASE, size: 0x94 });
    expect(elf.symbols.slice(1).map(({ name, info, section, value, size }) => ({ name, info, section, value, size }))).toEqual([
      { name: "answer", info: 0x12, section: 1, value: BASE + 0x80n, size: 6 },
      { name: "twice", info: 0x12, section: 1, value: BASE + 0x90n, size: 4 },
    ]);
    for (const { offset, bytes } of FUNCTIONS) expect([...file.subarray(offset, offset + bytes.length)]).toEqual(bytes);
  });
});

const script = () => readFile(join(DEFAULT_SCRIPT_DIR, EXPORT_SCRIPT), "utf8");

describe("Revscope's Ghidra export script", () => {
  it("is shipped where the engine looks for it", async () => {
    expect((await script()).length).toBeGreaterThan(0);
  });

  it("writes the schema the parser accepts and takes the arguments the runner sends", async () => {
    const text = await script();
    expect(text).toContain(`SCHEMA = "${GHIDRA_EXPORT_SCHEMA}"`);
    const plan = planHeadless({
      installation: { root: "/g", analyzeHeadless: "/g/support/analyzeHeadless", version: "11.4", javaHome: null },
      workspace: { parent: "/t", root: "/t/w", input: "/t/w/input/artifact", project: "/t/w/project", exportPath: "/t/w/out/export.ndjson", home: "/t/w/home", tmp: "/t/w/tmp", cache: "/t/w/cache", logs: "/t/w/logs" },
      scriptDir: DEFAULT_SCRIPT_DIR,
      limits: { timeoutMs: 45_000, maxFunctions: 200, decompile: true, decompileTimeoutMs: 10_000 },
      deadlineAt: performance.now() + 45_000,
      timing: DEFAULT_TIMING,
    });
    if (plan === null) throw new Error("no plan");
    const start = plan.args.indexOf("-postScript") + 2;
    const scriptArgs = plan.args.slice(start, plan.args.findIndex((arg, index) => index >= start && arg.startsWith("-")));
    expect(text).toContain(`args.length != ${String(scriptArgs.length)}`);
  });

  it("declares the checked exception that analysisTimeoutOccurred() throws (Ghidra 12.1.4 API)", async () => {
    // Without a Java compiler in this environment, this guards the one known compile hazard.
    expect(await script()).toMatch(/private String header\([^)]*\)\s*throws Exception \{/u);
  });

  it("reads language and compiler ids with the accessor Ghidra 12.1.4 provides (getIdAsString)", async () => {
    // Regression: LanguageID has no getIdString() in Ghidra 12.1.4; the script failed to compile.
    const text = await script();
    expect(text).toContain("getLanguageID().getIdAsString()");
    expect(text).toContain("getCompilerSpecID().getIdAsString()");
    expect(text).not.toContain("getIdString(");
  });

  it("starts no processes and touches no files except the export", async () => {
    const text = await script();
    for (const forbidden of ["Runtime.getRuntime", "ProcessBuilder", "exec(", "Files.delete", "java.net", "runScript(", "Emulator"])
      expect(text, forbidden).not.toContain(forbidden);
    expect(text.match(/new FileOutputStream\(/gu)).toHaveLength(1);
  });
});
