import { createHash } from "node:crypto";
import { z } from "zod";

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue =
  | JsonPrimitive
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue };
export type JsonObject = { readonly [key: string]: JsonValue };

/**
 * Deepest nesting accepted anywhere JSON enters Revscope. Validation and
 * canonical serialization recurse, so unbounded depth would exhaust the stack.
 */
export const MAX_JSON_DEPTH = 64;

/**
 * Assigning a `__proto__` key replaces an object's prototype instead of
 * creating a property, so such a key would be silently dropped by validation
 * and could not be represented faithfully. It is rejected instead.
 */
const LOSSY_KEY = "__proto__";

export interface JsonShapeIssue {
  readonly kind: "too_deep" | "lossy_key";
  /** Dotted path to the offending value; `$` for the root. */
  readonly path: string;
}

/**
 * Check a parsed JSON value's shape without recursion: nesting depth and
 * lossy keys. Values are never inspected beyond their structure.
 */
export const jsonShapeIssue = (value: unknown, maxDepth = MAX_JSON_DEPTH): JsonShapeIssue | null => {
  interface Node {
    readonly value: unknown;
    readonly depth: number;
    readonly key: string;
    readonly parent: Node | null;
  }
  const pathOf = (node: Node | null, key?: string): string => {
    const parts = key === undefined ? [] : [key];
    for (let at = node; at !== null && at.parent !== null; at = at.parent) parts.unshift(at.key);
    return ["$", ...parts].join(".");
  };
  const stack: Node[] = [{ value, depth: 0, key: "$", parent: null }];
  for (let node = stack.pop(); node !== undefined; node = stack.pop()) {
    if (typeof node.value !== "object" || node.value === null) continue;
    const depth = node.depth + 1;
    if (depth > maxDepth) return { kind: "too_deep", path: pathOf(node) };
    const isArray = Array.isArray(node.value);
    const entries: [string, unknown][] = isArray
      ? (node.value as unknown[]).map((entry, index) => [String(index), entry])
      : Object.entries(node.value);
    for (const [key, entry] of entries) {
      if (!isArray && key === LOSSY_KEY) return { kind: "lossy_key", path: pathOf(node, key) };
      stack.push({ value: entry, depth, key, parent: node });
    }
  }
  return null;
};

export const jsonShapeMessage = (issue: JsonShapeIssue): string =>
  issue.kind === "too_deep"
    ? `JSON nesting exceeds ${String(MAX_JSON_DEPTH)} levels`
    : `Object keys named ${LOSSY_KEY} are not supported`;

/** Finite JSON values only; NaN and Infinity have no JSON representation. */
const jsonTreeSchema: z.ZodType<JsonValue> = z.lazy(() =>
  z.union([
    z.string(),
    z.number().refine(Number.isFinite, "Number must be finite"),
    z.boolean(),
    z.null(),
    z.array(jsonTreeSchema),
    z.record(z.string(), jsonTreeSchema),
  ]),
);

/** Reject excessive depth and lossy keys once, before the recursive schema runs. */
const shapeGuard = z.unknown().superRefine((value, context) => {
  const issue = jsonShapeIssue(value);
  if (issue !== null) context.addIssue({ code: "custom", message: jsonShapeMessage(issue), fatal: true });
});

export const jsonValueSchema: z.ZodType<JsonValue> = shapeGuard.pipe(jsonTreeSchema);

export const jsonObjectSchema: z.ZodType<JsonObject> = shapeGuard.pipe(
  z.record(z.string(), jsonTreeSchema),
);

/**
 * Serialize with recursively sorted object keys so equal values always hash
 * identically, independent of property insertion order.
 */
export const canonicalJson = (value: JsonValue): string => {
  if (value === null || typeof value !== "object") {
    if (typeof value === "number" && !Number.isFinite(value))
      throw new TypeError("Canonical JSON cannot represent non-finite numbers");
    return JSON.stringify(value);
  }
  if (Array.isArray(value))
    return `[${value.map((entry: JsonValue) => canonicalJson(entry)).join(",")}]`;
  const record = value as { readonly [key: string]: JsonValue };
  const keys = Object.keys(record).toSorted();
  return `{${keys
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key] ?? null)}`)
    .join(",")}}`;
};

/** Lowercase hexadecimal SHA-256 of UTF-8 text or raw bytes. */
export const sha256Hex = (input: string | Uint8Array): string =>
  createHash("sha256").update(input).digest("hex");
