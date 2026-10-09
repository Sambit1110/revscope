import { z } from "zod";

import { parseEvidence, type Evidence } from "./evidence.js";
import type { JsonObject, JsonValue } from "./json.js";

/**
 * Any JSON object with a `records` array is accepted as an evidence bundle,
 * including a successful Revscope tool output.
 */
export const bundleSchema = z.looseObject({ records: z.array(z.unknown()) });

export interface RecordFailure {
  readonly index: number;
  readonly code: string;
  readonly issues: JsonValue;
}

export interface ParsedBundle {
  readonly valid: readonly Evidence[];
  readonly invalid: readonly RecordFailure[];
}

/** Validate every record independently so one bad record does not hide the rest. */
export const parseBundleRecords = (records: readonly unknown[]): ParsedBundle => {
  const valid: Evidence[] = [];
  const invalid: RecordFailure[] = [];
  records.forEach((record, index) => {
    const parsed = parseEvidence(record);
    if (parsed.ok) valid.push(parsed.value);
    else
      invalid.push({
        index,
        code: parsed.error.code,
        issues: parsed.error.details["issues"] ?? [],
      });
  });
  return { valid, invalid };
};

const countBy = (values: readonly string[]): JsonObject => {
  const counts: Record<string, number> = {};
  for (const value of [...values].toSorted()) counts[value] = (counts[value] ?? 0) + 1;
  return counts;
};

/** Structured report of what a bundle claims and how strongly. */
export const summarizeBundle = (parsed: ParsedBundle): JsonObject => ({
  total_records: parsed.valid.length + parsed.invalid.length,
  valid_records: parsed.valid.length,
  invalid_records: parsed.invalid.map((failure) => ({
    index: failure.index,
    code: failure.code,
    issues: failure.issues,
  })),
  by_confidence: countBy(parsed.valid.map(({ confidence }) => confidence)),
  by_authority: countBy(parsed.valid.map(({ authority }) => authority)),
  by_operation: countBy(parsed.valid.map(({ operation }) => operation.name)),
  unknowns: parsed.valid.flatMap((record) =>
    record.unknowns.map((unknown) => ({
      evidence_id: record.evidence_id,
      scope: unknown.scope,
      reason: unknown.reason,
    })),
  ),
  limitations: [...new Set(parsed.valid.flatMap(({ limitations }) => limitations))].toSorted(),
});
