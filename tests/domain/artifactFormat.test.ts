import { describe, expect, it } from "vitest";

import { classifyHeader } from "../../src/domain/artifactFormat.js";
import { canonicalJson } from "../../src/domain/json.js";

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

  it("recognizes UTF-8 text, including a multi-byte character cut at the end", () => {
    const text = new TextEncoder().encode("héllo wörld");
    expect(classifyHeader(text).label).toBe("utf8-text");
    expect(classifyHeader(text.subarray(0, text.length - 1)).label).toBe("utf8-text");
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
