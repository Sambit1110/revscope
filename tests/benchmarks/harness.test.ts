/**
 * Unit tests for the benchmark harness's pure parts: ground-truth parsing,
 * signature reading, scoring, stripping, and output checks. The benchmark
 * itself runs Ghidra and is not part of `npm run check`.
 */
import { describe, expect, it } from "vitest";

import { CASES, SOURCES } from "../../benchmarks/manifest.ts";
import { findLeaks, splitTimeReport } from "../../benchmarks/lib/execute.ts";
import { seededBytes, stripGeneratedElf } from "../../benchmarks/lib/fixtures.ts";
import {
  computeMetrics,
  matchFunctions,
  parseNm,
  readSuccess,
  textSymbols,
  type GroundTruth,
  type Observed,
  type ObservedDecompilation,
  type ObservedFunction,
} from "../../benchmarks/lib/metrics.ts";
import { renderReport, summarize, type CaseResult, type Results } from "../../benchmarks/lib/report.ts";
import { compareType, parseSignature } from "../../benchmarks/lib/signature.ts";
import { BASE, FUNCTIONS, makeElf } from "../fixtures/binaries/make-elf.mjs";

const fn = (address: string, name: string, extra: Partial<ObservedFunction> = {}): ObservedFunction => ({
  address,
  name,
  name_source: "imported",
  name_confidence: "imported",
  ghidra_name: name,
  aliases: [],
  is_thunk: false,
  is_program_entry: false,
  decompilation: "ok",
  ...extra,
});

const decompiled = (address: string, ghidraName: string, signature: string, extra: Partial<ObservedDecompilation> = {}): ObservedDecompilation => ({
  address,
  ghidra_name: ghidraName,
  status: "ok",
  pseudocode: `\n${signature}\n{\n  return param_1 + param_2;\n}\n`,
  decompiler: { signature, calling_convention: { name: "__cdecl" } },
  signature_comparison: "stored-not-established",
  fidelity: "complete",
  diagnostics: [],
  ...extra,
});

const observed = (functions: ObservedFunction[], decompilations: ObservedDecompilation[], entry: string[] = ["0x1000"]): Observed => ({
  programInfo: {
    min_address: "0x1000",
    max_address: "0x1fff",
    program_entry: { source: "macho-lc-main", addresses: entry },
    external_entry_points: entry,
    ghidra_version: "12.1.4",
    decompiler: "available",
  },
  functions,
  decompilations,
  analysis: {
    complete: true,
    export_complete: true,
    functions_total: functions.length,
    functions_exported: functions.length,
    decompiled: decompilations.length,
    decompiled_with_uncertainty: 0,
  },
  cleanup: { process: "not-needed", workspace: "removed" },
});

const truth = (overrides: Partial<GroundTruth> = {}): GroundTruth => ({
  addressMode: "absolute",
  names: "symbol-table",
  recovery: "all",
  functions: [
    { symbol: "_add", address: 0x1000n, expected: { name: "add", params: ["int", "int"], returns: "int", pseudocodeHint: "+" } },
    { symbol: "_gcd", address: 0x1020n, expected: { name: "gcd", params: ["unsigned", "unsigned"], returns: "unsigned", pseudocodeHint: "%" } },
  ],
  symbolsAt: new Map([
    [0x1000n, ["_add"]],
    [0x1020n, ["_gcd"]],
  ]),
  symbolNames: new Set(["_add", "_gcd", "_puts"]),
  entry: { source: "macho-lc-main", addresses: [0x1000n] },
  ...overrides,
});

describe("signature reading", () => {
  it("separates return type, calling convention and parameters", () => {
    expect(parseSignature("undefined8 processEntry answer(void)", "answer", "processEntry")).toEqual({ returns: "undefined8", params: [], varargs: false });
    expect(parseSignature("int twice(int param_1)", "twice", "__stdcall")).toEqual({ returns: "int", params: ["int"], varargs: false });
    expect(parseSignature("int main(int argc,char **argv)", "main", null)).toEqual({ returns: "int", params: ["int", "char **"], varargs: false });
    expect(parseSignature("int printf(char *fmt, ...)", "printf", null)).toEqual({ returns: "int", params: ["char *"], varargs: true });
  });

  it("returns null instead of guessing when the name is not where expected", () => {
    expect(parseSignature("int other(int a)", "twice", null)).toBeNull();
    expect(parseSignature("twice(int a)", "twice", null)).toBeNull();
  });

  it("keeps partial type agreement apart from exact agreement", () => {
    expect(compareType("int", "int")).toBe("exact");
    expect(compareType("int", "uint")).toBe("sign-differs");
    expect(compareType("int", "undefined4")).toBe("unknown-same-width");
    expect(compareType("int", "undefined8")).toBe("mismatch");
    expect(compareType("int", "void")).toBe("mismatch");
    expect(compareType("unsigned", "uint")).toBe("exact");
    expect(compareType("char-pointer-pointer", "char **")).toBe("exact");
    expect(compareType("char-pointer-pointer", "long *")).toBe("pointer-differs");
    expect(compareType("const-char-pointer", "char *")).toBe("exact");
    expect(compareType("const-char-pointer", "undefined8")).toBe("unknown-same-width");
  });
});

describe("ground truth from nm", () => {
  it("reads defined and undefined symbols and groups code symbols by address", () => {
    const table = parseNm(
      ["0000000100000000 T __mh_execute_header", "0000000100000460 T _add", "0000000100000460 t _add_alias", "                 U _puts", "0000000100008000 d _data"].join("\n"),
    );
    expect(table.names).toEqual(new Set(["__mh_execute_header", "_add", "_add_alias", "_puts", "_data"]));
    expect(textSymbols(table.defined).get(0x1_0000_0460n)).toEqual(["_add", "_add_alias"]);
    expect(textSymbols(table.defined).has(0x1_0000_8000n)).toBe(false);
  });
});

describe("scoring", () => {
  it("scores a faithful result as exact on every check", () => {
    const metrics = computeMetrics(
      truth(),
      observed(
        [fn("0x1000", "_add", { is_program_entry: true }), fn("0x1020", "_gcd"), fn("0x1040", "_puts", { is_thunk: true })],
        [decompiled("0x1000", "_add", "int _add(int param_1,int param_2)"), decompiled("0x1020", "_gcd", "uint _gcd(uint param_1,uint param_2)"), decompiled("0x1040", "_puts", "int _puts(char *s)")],
      ),
    );
    for (const check of Object.values(metrics.exact)) expect(check.pass, check.detail).toBe(true);
    expect(metrics.exact.recovery).toMatchObject({ expected: 2, recovered: 2, other_functions: 1 });
    expect(metrics.approximate.return_type.exact).toBe(2);
    expect(metrics.approximate.param_count.match).toBe(2);
    // gcd's pseudocode lacks "%": recorded as an absent hint, never as a failure.
    expect(metrics.heuristic.pseudocode_hints).toEqual({ checked: 2, present: 1, absent: ["_gcd: %"] });
  });

  it("fails names, recovery and entry exactly, and keeps aliases and imported claims honest", () => {
    const metrics = computeMetrics(
      truth({ symbolsAt: new Map([[0x1000n, ["_add", "_add2"]], [0x1020n, ["_gcd"]]]) }),
      observed([fn("0x1000", "FUN_00001000", { name_confidence: "generated", name_source: "default" }), fn("0x2000", "made_up")], [], ["0x2000"]),
    );
    expect(metrics.exact.recovery).toMatchObject({ pass: false, missing: ["_gcd"] });
    expect(metrics.exact.names.pass).toBe(false);
    expect(metrics.exact.names.mismatches).toEqual([{ expected: "_add | _add2", observed: "FUN_00001000" }]);
    expect(metrics.exact.names.symbols_missing_from_aliases).toEqual(["_add", "_add2"]);
    expect(metrics.exact.names.imported_claims_not_in_symbol_table).toEqual(["made_up@0x2000"]);
    expect(metrics.exact.entry.pass).toBe(false);
    expect(metrics.exact.export.pass).toBe(false); // functions marked decompiled have no records
  });

  it("accepts a symbol-table name shown with the loader's entry label as an alias", () => {
    const metrics = computeMetrics(
      truth(),
      observed(
        [fn("0x1000", "_add", { ghidra_name: "entry", aliases: [{ name: "entry", source: "imported", role: "loader-entry-label" }] }), fn("0x1020", "_gcd")],
        [decompiled("0x1000", "entry", "void entry(void)"), decompiled("0x1020", "_gcd", "uint _gcd(uint a,uint b)")],
      ),
    );
    expect(metrics.exact.names.pass).toBe(true);
    // The decompiler's view of the entry is scored on its own terms: a void return is a mismatch.
    expect(metrics.approximate.per_function[0]).toMatchObject({ function: "_add", returns: "mismatch", params: "mismatch" });
  });

  it("measures stripped recovery without failing it, and flags names claiming a missing symbol table", () => {
    const stripped = truth({ names: "not-recoverable", recovery: "measured", symbolNames: new Set() });
    const metrics = computeMetrics(stripped, observed([fn("0x1000", "entry")], [decompiled("0x1000", "entry", "int entry(int a,int b)")]));
    expect(metrics.exact.recovery).toMatchObject({ pass: true, recovered: 1, missing: ["_gcd"] });
    expect(metrics.exact.names).toMatchObject({ pass: false, checked: 0, imported_claims_not_in_symbol_table: ["entry@0x1000"] });
  });

  it("compares relocatable objects by offset from the lowest address", () => {
    const relative = truth({ addressMode: "relative", symbolsAt: new Map([[0n, ["add"]], [0x20n, ["gcd"]]]) });
    const shifted = { ...relative, functions: relative.functions.map((entry, index) => ({ ...entry, address: BigInt(index * 0x20) })) };
    const { delta, pairs } = matchFunctions(shifted, [fn("0x100000", "add"), fn("0x100020", "gcd")]);
    expect(delta).toBe(0x100000n);
    expect(pairs.every(({ observed: found }) => found !== null)).toBe(true);
  });

  it("fails an address range whose maximum lies below its minimum", () => {
    // Seen on ELF inputs: Ghidra's maximum is in a non-loaded section space, printed without the space name.
    const base = observed([fn("0x1000", "_add"), fn("0x1020", "_gcd")], []);
    const metrics = computeMetrics(truth(), { ...base, programInfo: { ...base.programInfo, min_address: "0x400000", max_address: "0x13f" } });
    expect(metrics.exact.address_range).toMatchObject({ pass: false, min_address: "0x400000", max_address: "0x13f" });
  });

  it("rejects a success document whose shape it does not recognize", () => {
    expect(readSuccess({ ok: true, records: [] })).toMatchObject({ ok: false });
    expect(readSuccess({ ok: false })).toMatchObject({ ok: false });
  });
});

describe("generated inputs", () => {
  it("strips the generated ELF's symbol table and nothing else", () => {
    const full = makeElf();
    const stripped = stripGeneratedElf(full);
    expect(stripped.readUInt16LE(60)).toBe(3);
    expect(stripped.readUInt16LE(62)).toBe(2);
    expect(stripped.readBigUInt64LE(24)).toBe(full.readBigUInt64LE(24)); // entry
    // Everything but the section count and string-table index is unchanged: ELF header, program header, .text.
    expect(stripped.subarray(0, 60)).toEqual(full.subarray(0, 60));
    expect(stripped.subarray(64, 0x98)).toEqual(full.subarray(64, 0x98));
    // The function names are gone (.shstrtab still holds the unused section names).
    for (const name of ["answer", "twice"]) expect(stripped.includes(Buffer.from(name))).toBe(false);
    const sectionTypes = [0, 1, 2].map((index) => stripped.readUInt32LE(0x110 + index * 64 + 4));
    expect(sectionTypes).toEqual([0, 1, 3]); // null, PROGBITS, STRTAB
    expect(FUNCTIONS.map(({ offset }) => BASE + BigInt(offset))).toEqual([0x400080n, 0x400090n]);
  });

  it("generates the same pseudo-random bytes every time", () => {
    expect(seededBytes(64)).toEqual(seededBytes(64));
    expect(seededBytes(64)).not.toEqual(seededBytes(64, 1));
  });

  it("has unique case ids and ground truth for every source", () => {
    const ids = CASES.map(({ id }) => id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const spec of CASES) if (spec.kind === "compiled") expect(SOURCES[spec.source].length).toBeGreaterThan(0);
  });
});

describe("run checks", () => {
  it("reports sensitive values by label only, ignoring the caller's own input path", () => {
    const values = [
      { label: "ghidra-dir", value: "/opt/ghidra" },
      { label: "user-home", value: "/Users/someone" },
    ];
    expect(findLeaks('{"path":"/Users/someone/bin/x"}', "/Users/someone/bin/x", values)).toEqual([]);
    expect(findLeaks("failed under /opt/ghidra/support", "/x", values)).toEqual(["ghidra-dir"]);
  });

  it("reads peak RSS from /usr/bin/time -l and removes its report", () => {
    const stderr = "warning from revscope\n        3.40 real         2.10 user         0.50 sys\n           592314368  maximum resident set size\n                   0  average shared memory size\n";
    expect(splitTimeReport(stderr)).toEqual({ stderr: "warning from revscope\n", peakRss: 592_314_368 });
    expect(splitTimeReport("no report")).toEqual({ stderr: "no report", peakRss: null });
  });
});

describe("report", () => {
  it("summarizes and renders failures and not-run cases visibly", () => {
    const cases: CaseResult[] = [
      { id: "a", kind: "rejection", category: [7], description: "", status: "pass", problems: [], input: null, expected: {}, runs: [], determinism: null, metrics: null },
      { id: "b", kind: "compiled", category: [1], description: "", status: "not-run", problems: ["clang failed"], input: null, expected: {}, runs: [], determinism: null, metrics: null },
    ];
    const summary = summarize(cases);
    expect(summary.cases).toEqual({ pass: 1, fail: 0, "not-run": 1 });
    const results: Results = {
      schema: "revscope.benchmark/1",
      harness_version: "1",
      started_at: "t0",
      finished_at: "t1",
      environment: {
        os: { platform: "darwin", release: "x", arch: "arm64" },
        cpu: { model: "cpu", count: 1 },
        memory_bytes: 1024,
        node: "v26",
        revscope: { version: "0.1.0", commit: "abc", worktree_dirty: false },
        ghidra: { version: "12.1.4", decompiler: "available" },
        java: null,
        clang: null,
        nm: null,
      },
      settings: { repeat: 2, limits: { timeoutMs: 1, maxFunctions: 1, decompileTimeoutMs: 1 }, only: null },
      host_checks: {},
      cases,
      summary,
    };
    expect(renderReport(results)).toContain("- **b** (not-run): clang failed");
  });
});
