import { describe, expect, it } from "vitest";

import { classifyHeader } from "../../src/domain/artifactFormat.js";
import { MAX_JSON_DEPTH, canonicalJson, jsonShapeIssue, jsonValueSchema } from "../../src/domain/json.js";

const bytes = (...values: number[]) => Uint8Array.from(values);

describe("header classification", () => {
  it.each([
    ["elf", bytes(0x7f, 0x45, 0x4c, 0x46, 2, 1)],
    ["mach-o", bytes(0xcf, 0xfa, 0xed, 0xfe, 7, 0)],
    ["mach-o-universal-or-java-class", bytes(0xca, 0xfe, 0xba, 0xbe)],
    ["pe-or-dos-mz", bytes(0x4d, 0x5a, 0x90, 0x00)],
    ["zip", bytes(0x50, 0x4b, 0x03, 0x04)],
    ["png", bytes(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a)],
  ])("suggests %s from its magic bytes", (label, header) => {
    expect(classifyHeader(header).label).toBe(label);
  });

  it("recognizes UTF-8 text, including a multi-byte character cut by a truncated sample", () => {
    const text = new TextEncoder().encode("héllo wörld");
    expect(classifyHeader(text).label).toBe("utf8-text");
    const cut = new TextEncoder().encode("hello wö").subarray(0, -1);
    expect(classifyHeader(cut, { truncated: true }).label).toBe("utf8-text");
  });

  it("does not call invalid UTF-8 text", () => {
    const hello = [...new TextEncoder().encode("hello")];
    // A byte that is never valid UTF-8, at the end of a complete file or of a sample.
    expect(classifyHeader(Uint8Array.from([...hello, 0xff])).label).toBe("unknown");
    expect(classifyHeader(Uint8Array.from([...hello, 0xff]), { truncated: true }).label).toBe("unknown");
    // A complete file cannot end inside a character.
    expect(classifyHeader(Uint8Array.from([...hello, 0xc3])).label).toBe("unknown");
    // An overlong encoding and a lone continuation byte are invalid anywhere.
    expect(classifyHeader(Uint8Array.from([...hello, 0xc0, 0xaf, ...hello]), { truncated: true }).label).toBe("unknown");
    expect(classifyHeader(Uint8Array.from([...hello, 0x80, ...hello])).label).toBe("unknown");
  });

  it("returns unknown for empty input and binary noise", () => {
    expect(classifyHeader(bytes()).label).toBe("unknown");
    expect(classifyHeader(bytes(0x00, 0x01, 0x02, 0xff)).label).toBe("unknown");
  });
});

describe("canonical JSON", () => {
  it("sorts keys recursively and rejects non-finite numbers", () => {
    expect(canonicalJson({ b: [{ d: 1, c: 2 }], a: null })).toBe(
      '{"a":null,"b":[{"c":2,"d":1}]}',
    );
    expect(() => canonicalJson(Number.NaN)).toThrow(TypeError);
  });
});

const nested = (depth: number): unknown => {
  let value: unknown = 1;
  for (let level = 0; level < depth; level += 1) value = [value];
  return value;
};

describe("JSON shape limits", () => {
  it("accepts nesting up to the limit and rejects deeper input without exhausting the stack", () => {
    expect(jsonValueSchema.safeParse(nested(MAX_JSON_DEPTH)).success).toBe(true);
    expect(jsonShapeIssue(nested(MAX_JSON_DEPTH + 1))).toMatchObject({ kind: "too_deep" });
    // Far deeper than the recursive schema could survive; rejected by the iterative check first.
    const parsed = jsonValueSchema.safeParse(nested(50_000));
    expect(parsed.success).toBe(false);
    expect(parsed.error?.issues[0]?.message).toContain("nesting exceeds");
  });

  it("rejects __proto__ keys anywhere instead of silently dropping them", () => {
    const value = JSON.parse('{"a": [{"b": {"__proto__": {"x": 1}}}]}') as unknown;
    expect(jsonShapeIssue(value)).toEqual({ kind: "lossy_key", path: "$.a.0.b.__proto__" });
    expect(jsonValueSchema.safeParse(value).success).toBe(false);
    // An array index is never a key, and an ordinary key named like it is fine.
    expect(jsonShapeIssue({ proto: 1, list: ["__proto__"] })).toBeNull();
  });
});
