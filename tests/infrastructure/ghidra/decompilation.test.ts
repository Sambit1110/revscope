import { describe, expect, it } from "vitest";

import {
  compareSignatures,
  decompilerDiagnostics,
  fidelityOf,
  normalizeSignature,
} from "../../../src/infrastructure/ghidra/decompilation.js";

describe("comparing stored and decompiler signatures", () => {
  it("normalizes formatting only", () => {
    expect(normalizeSignature("int _puts(char * param_1)", null)).toBe(normalizeSignature("int _puts(char *param_1);", null));
    expect(normalizeSignature("undefined8 processEntry answer(void)", "processEntry")).toBe("undefined8 answer(void)");
    // Types and names are compared as written: nothing semantic is guessed.
    expect(normalizeSignature("int f(int a)", null)).not.toBe(normalizeSignature("long f(int a)", null));
  });

  it("reports agreement only when the stored signature was established", () => {
    expect(compareSignatures({ text: "int _puts(char * param_1)", source: "imported", callingConvention: null }, { text: "int _puts(char *param_1)", callingConvention: null })).toEqual({
      comparison: "agree",
      diagnostics: [],
    });
  });

  it("does not treat Ghidra's placeholder signature as a disagreement (_add, _factorial)", () => {
    for (const [stored, inferred] of [["undefined _add(void)", "int _add(int param_1,int param_2)"], ["undefined _factorial(void)", "int _factorial(int param_1)"]] as const) {
      const result = compareSignatures({ text: stored, source: "default", callingConvention: null }, { text: inferred, callingConvention: "__cdecl" });
      expect(result.comparison).toBe("stored-not-established");
      expect(result.diagnostics).toEqual([expect.objectContaining({ kind: "stored-signature-not-established", severity: "informational" })]);
    }
  });

  it("surfaces a real disagreement as material, without replacing either signature", () => {
    const result = compareSignatures({ text: "int f(int a)", source: "imported", callingConvention: null }, { text: "void f(void)", callingConvention: null });
    expect(result).toEqual({ comparison: "differ", diagnostics: [expect.objectContaining({ kind: "signature-disagreement", severity: "material" })] });
  });

  it("flags calling conventions that disagree when both are known", () => {
    const result = compareSignatures({ text: "int f(int a)", source: "analysis", callingConvention: "__stdcall" }, { text: "int f(int a)", callingConvention: "__cdecl" });
    expect(result.diagnostics.map(({ kind, severity }) => `${kind}:${severity}`)).toEqual(["calling-convention-disagreement:material"]);
    // An unknown stored convention is not a disagreement: it is simply unknown.
    expect(compareSignatures({ text: "int f(int a)", source: "analysis", callingConvention: null }, { text: "int f(int a)", callingConvention: "__cdecl" }).diagnostics).toEqual([]);
  });

  it("has nothing to compare without a decompiler signature", () => {
    expect(compareSignatures({ text: "int f(void)", source: "imported", callingConvention: null }, null)).toEqual({ comparison: "unavailable", diagnostics: [] });
  });
});

const base = { status: "ok" as const, warnings: [], errorMessage: null, decompilerCallingConvention: "__cdecl", truncated: false };

describe("decompiler diagnostics and fidelity", () => {
  it("calls a clean decompilation complete", () => {
    const diagnostics = decompilerDiagnostics(base);
    expect(diagnostics).toEqual([]);
    expect(fidelityOf("ok", diagnostics)).toBe("complete");
  });

  it("never represents warning-bearing output as complete, and never as failed", () => {
    const diagnostics = decompilerDiagnostics({ ...base, warnings: ["WARNING: Could not recover jumptable at 0x100000528. Too many branches"] });
    expect(diagnostics).toEqual([{ kind: "decompiler-warning", severity: "material", message: "WARNING: Could not recover jumptable at 0x100000528. Too many branches" }]);
    expect(fidelityOf("ok", diagnostics)).toBe("uncertain");
  });

  it("treats every structural uncertainty signal as material", () => {
    expect(decompilerDiagnostics({ ...base, decompilerCallingConvention: null }).map(({ kind }) => kind)).toEqual(["decompiler-calling-convention-unknown"]);
    expect(decompilerDiagnostics({ ...base, errorMessage: "Low-level Error: overlapping input varnodes" })[0]).toMatchObject({ kind: "decompiler-message", severity: "material" });
    expect(decompilerDiagnostics({ ...base, truncated: true }).map(({ kind }) => kind)).toEqual(["pseudocode-truncated"]);
  });

  it("keeps failures distinct: no fidelity, and the error message only explains the failure", () => {
    const diagnostics = decompilerDiagnostics({ ...base, status: "failed", decompilerCallingConvention: null, errorMessage: "Decompiler process died" });
    expect(diagnostics).toEqual([{ kind: "decompiler-message", severity: "informational", message: "Decompiler process died" }]);
    for (const status of ["failed", "timeout", "skipped", "not-exported"]) expect(fidelityOf(status, diagnostics)).toBeNull();
  });

  it("does not let informational notes lower fidelity", () => {
    expect(fidelityOf("ok", [{ kind: "stored-signature-not-established", severity: "informational", message: "x" }])).toBe("complete");
  });
});
