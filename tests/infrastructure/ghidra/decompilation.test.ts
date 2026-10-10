import { describe, expect, it } from "vitest";

import { compareSignatures, normalizeSignature } from "../../../src/infrastructure/ghidra/decompilation.js";

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
