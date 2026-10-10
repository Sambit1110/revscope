import type { SourceType } from "../manifest.ts";

/** A decompiler signature taken apart; null when it cannot be read reliably. */
export interface ParsedSignature {
  readonly returns: string;
  readonly params: readonly string[];
  readonly varargs: boolean;
}

/** Split on commas that are not nested in parentheses or brackets. */
const splitTopLevel = (text: string): string[] => {
  const parts: string[] = [];
  let depth = 0;
  let current = "";
  for (const char of text) {
    if (char === "(" || char === "[") depth += 1;
    if (char === ")" || char === "]") depth -= 1;
    if (char === "," && depth === 0) {
      parts.push(current);
      current = "";
    } else current += char;
  }
  parts.push(current);
  return parts.map((part) => part.trim()).filter((part) => part !== "");
};

/** The type part of one parameter declaration (`int param_1` -> `int`, `char **argv` -> `char **`). */
const parameterType = (declaration: string): string => {
  const match = /^(?<type>.*?)(?<name>[A-Za-z_][\w$]*)$/u.exec(declaration);
  const type = match?.groups?.["type"]?.trim() ?? "";
  // A bare type without a name (e.g. `int`) has no separate name to drop.
  return type === "" ? declaration.trim() : type;
};

/**
 * Read the return type and parameter types from a Ghidra decompiler
 * signature such as `undefined8 processEntry answer(void)`. The function's
 * Ghidra name and calling convention locate the parts; anything unexpected
 * yields null rather than a guess.
 */
export const parseSignature = (text: string, ghidraName: string, callingConvention: string | null): ParsedSignature | null => {
  const open = text.lastIndexOf(`${ghidraName}(`);
  const close = text.lastIndexOf(")");
  if (open < 0 || close < open) return null;
  let prefix = text.slice(0, open).trim();
  if (callingConvention !== null && prefix.endsWith(` ${callingConvention}`))
    prefix = prefix.slice(0, -callingConvention.length - 1).trim();
  if (prefix === "") return null;
  const inside = text.slice(open + ghidraName.length + 1, close).trim();
  const declarations = inside === "" || inside === "void" ? [] : splitTopLevel(inside);
  const varargs = declarations.at(-1) === "...";
  return {
    returns: prefix,
    params: (varargs ? declarations.slice(0, -1) : declarations).map(parameterType),
    varargs,
  };
};

/**
 * How a recovered type compares with the source type. Approximate by nature:
 * - exact: the same C type (Ghidra spells `unsigned int` as `uint`);
 * - sign-differs: same width, other signedness;
 * - pointer-differs: a pointer, to another type;
 * - unknown-same-width: Ghidra's untyped `undefinedN` of the right width;
 * - mismatch: anything else (other width, void, a non-pointer for a pointer).
 */
export type TypeAgreement = "exact" | "sign-differs" | "pointer-differs" | "unknown-same-width" | "mismatch";

const squash = (type: string): string =>
  type
    .replaceAll(/\bconst\b/gu, "")
    .replaceAll(/\s+/gu, " ")
    .replaceAll(/\s*\*/gu, " *")
    .trim();

export const compareType = (expected: SourceType, recovered: string): TypeAgreement => {
  const type = squash(recovered);
  switch (expected) {
    case "int":
      if (type === "int") return "exact";
      if (type === "uint" || type === "unsigned int") return "sign-differs";
      return type === "undefined4" ? "unknown-same-width" : "mismatch";
    case "unsigned":
      if (type === "uint" || type === "unsigned int") return "exact";
      if (type === "int") return "sign-differs";
      return type === "undefined4" ? "unknown-same-width" : "mismatch";
    case "char-pointer-pointer":
      if (type === "char * *") return "exact";
      if (type.endsWith("*")) return "pointer-differs";
      return type === "undefined8" ? "unknown-same-width" : "mismatch";
    case "const-char-pointer":
      if (type === "char *") return "exact";
      if (type.endsWith("*")) return "pointer-differs";
      return type === "undefined8" ? "unknown-same-width" : "mismatch";
    default:
      return "mismatch";
  }
};
