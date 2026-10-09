import { describe, expect, it } from "vitest";

import { EXPORT_LIMITS, parseGhidraExport } from "../../../src/infrastructure/ghidra/exportFormat.js";
import {
  exportBytes,
  exportRecords,
  functionRecord,
  headerRecord,
  linesToBytes,
} from "../../support/ghidraExport.js";

const expectations = { maxFunctions: 200, decompile: true, ghidraVersion: "11.4" };

const problem = (bytes: Uint8Array, expected = expectations) => {
  const parsed = parseGhidraExport(bytes, expected);
  if (parsed.ok) throw new Error("expected a problem");
  return parsed.error;
};

const recordsToBytes = (records: readonly object[]) => linesToBytes(records.map((record) => JSON.stringify(record)));

describe("parsing a Ghidra export", () => {
  it("accepts a complete export and keeps functions in order", () => {
    const parsed = parseGhidraExport(exportBytes(), expectations);
    if (!parsed.ok) throw new Error(JSON.stringify(parsed.error));
    expect(parsed.value.functions.map(({ name }) => name)).toEqual(["answer", "twice"]);
    expect(parsed.value.decompilations.get("0x401000")?.status).toBe("ok");
    expect(parsed.value.trailer).toMatchObject({ stopped: "complete", functions_exported: 2 });
  });

  it("treats a missing trailer, or a line cut off mid-write, as an incomplete export", () => {
    const cut = parseGhidraExport(exportBytes({ trailer: null }), expectations);
    expect(cut.ok && cut.value.trailer).toBeNull();
    const full = exportBytes();
    // Drop the trailer's newline and half its text: the engine was killed while writing it.
    const midWrite = full.subarray(0, full.length - 20);
    const parsed = parseGhidraExport(midWrite, expectations);
    expect(parsed.ok && parsed.value.trailer).toBeNull();
    expect(parsed.ok && parsed.value.functions).toHaveLength(2);
  });

  it("reports an export with no complete line as empty", () => {
    expect(problem(new Uint8Array())).toEqual({ kind: "empty" });
    expect(problem(new TextEncoder().encode('{"type":"hea'))).toEqual({ kind: "empty" });
  });

  it("refuses exports beyond the size limit", () => {
    expect(problem(new Uint8Array(EXPORT_LIMITS.totalBytes + 1))).toEqual({ kind: "too_large" });
  });

  const records = exportRecords();
  const [header = {}, answer = {}, answerDecompiled = {}, twice = {}] = records;
  const trailer = records.at(-1) ?? {};
  const bad: [string, () => Uint8Array, number][] = [
    ["garbage", () => linesToBytes([JSON.stringify(header), "not json"]), 2],
    ["invalid UTF-8", () => new Uint8Array([...linesToBytes([JSON.stringify(header)]), 0xff, 0x0a]), 2],
    ["a first record that is not the header", () => recordsToBytes([answer, header]), 1],
    ["a second header", () => recordsToBytes([header, header]), 2],
    ["a wrong schema", () => recordsToBytes([{ ...headerRecord(), schema: "other/1" }]), 1],
    ["different limits", () => recordsToBytes([headerRecord({ maxFunctions: 5 })]), 1],
    ["a different Ghidra version", () => recordsToBytes([headerRecord({ ghidraVersion: "9.0" })]), 1],
    ["a decompiler state contradicting the request", () => recordsToBytes([headerRecord({ decompiler: "not-requested" })]), 1],
    ["an unknown field", () => recordsToBytes([header, { ...functionRecord("0x1", "f"), extra: 1 }]), 2],
    ["an unknown record type", () => recordsToBytes([header, { type: "comment" }]), 2],
    ["a duplicate function", () => recordsToBytes([header, answer, answer]), 3],
    ["functions out of order", () => recordsToBytes([header, twice, answer]), 3],
    ["a decompilation before its function", () => recordsToBytes([header, answerDecompiled]), 2],
    ["two decompilations of one function", () => recordsToBytes([header, answer, answerDecompiled, answerDecompiled]), 4],
    ["ok without pseudocode", () => recordsToBytes([header, answer, { ...answerDecompiled, pseudocode: null }]), 3],
    ["pseudocode with a failed status", () => recordsToBytes([header, answer, { ...answerDecompiled, status: "failed" }]), 3],
    ["pseudocode beyond the limit", () => recordsToBytes([header, answer, { ...answerDecompiled, pseudocode: "x".repeat(EXPORT_LIMITS.pseudocodeChars + 1) }]), 3],
    ["a name beyond the limit", () => recordsToBytes([header, functionRecord("0x1", "n".repeat(EXPORT_LIMITS.nameChars + 1))]), 2],
    ["a line beyond the limit", () => linesToBytes([JSON.stringify(header), " ".repeat(EXPORT_LIMITS.lineBytes + 1)]), 2],
    ["an uppercase address", () => recordsToBytes([header, functionRecord("0x40100A", "f")]), 2],
    ["a trailer count that disagrees", () => recordsToBytes([header, answer, trailer]), 3],
    ["a record after the trailer", () => recordsToBytes([...records, answer]), records.length + 1],
    ["a lossy __proto__ key", () => linesToBytes([JSON.stringify(header), '{"type":"function","__proto__":{}}']), 2],
  ];
  it.each(bad)("refuses %s, naming the line but echoing nothing", (_label, bytes, line) => {
    const found = problem(bytes());
    expect(found).toMatchObject({ kind: "malformed", line });
    expect(JSON.stringify(found)).not.toContain("answer");
  });

  it("refuses more functions than the limit, and decompilation that was not requested", () => {
    const three = exportRecords({ functions: [{ address: "0x1", name: "a" }, { address: "0x2", name: "b" }, { address: "0x3", name: "c" }], maxFunctions: 2, trailer: null });
    expect(problem(recordsToBytes(three), { ...expectations, maxFunctions: 2 })).toMatchObject({ kind: "malformed", line: 4 });
    const withDecompilation = exportRecords({ decompile: false }).toSpliced(2, 0, answerDecompiled);
    expect(problem(recordsToBytes(withDecompilation), { ...expectations, decompile: false })).toMatchObject({ kind: "malformed", line: 3 });
  });

  it("refuses a function-limit stop below the limit", () => {
    expect(problem(exportBytes({ trailer: { stopped: "function-limit" } }))).toMatchObject({ kind: "malformed" });
    const atLimit = parseGhidraExport(exportBytes({ maxFunctions: 2, trailer: { stopped: "function-limit", functionsTotal: 9 } }), { ...expectations, maxFunctions: 2 });
    expect(atLimit.ok).toBe(true);
  });
});
