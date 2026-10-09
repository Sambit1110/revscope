import { createHash } from "node:crypto";
import { z } from "zod";

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue =
  | JsonPrimitive
  | readonly JsonValue[]
  | { readonly [key: string]: JsonValue };
export type JsonObject = { readonly [key: string]: JsonValue };

/** Finite JSON values only; NaN and Infinity have no JSON representation. */
export const jsonValueSchema: z.ZodType<JsonValue> = z.lazy(() =>
  z.union([
    z.string(),
    z.number().refine(Number.isFinite, "Number must be finite"),
    z.boolean(),
    z.null(),
    z.array(jsonValueSchema),
    z.record(z.string(), jsonValueSchema),
  ]),
);

export const jsonObjectSchema: z.ZodType<JsonObject> = z.record(
  z.string(),
  jsonValueSchema,
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
