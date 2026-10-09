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

export interface DuplicateRecord {
  readonly index: number;
  readonly evidence_id: string;
}

export interface ParsedBundle {
  readonly total: number;
  /** Valid records, each evidence identifier once, in first-seen order. */
  readonly valid: readonly Evidence[];
  /** Later occurrences of an identifier already seen; identical content by construction. */
  readonly duplicates: readonly DuplicateRecord[];
  readonly invalid: readonly RecordFailure[];
}

/**
 * Validate every record independently so one bad record does not hide the
 * rest, and keep each evidence identifier once. Equal identifiers mean equal
 * content, so a repeated record adds no information and is only reported.
 */
export const parseBundleRecords = (records: readonly unknown[]): ParsedBundle => {
  const valid: Evidence[] = [];
  const seen = new Set<string>();
  const duplicates: DuplicateRecord[] = [];
  const invalid: RecordFailure[] = [];
  records.forEach((record, index) => {
    const parsed = parseEvidence(record);
    if (!parsed.ok)
      invalid.push({
        index,
        code: parsed.error.code,
        issues: parsed.error.details["issues"] ?? [],
      });
    else if (seen.has(parsed.value.evidence_id))
      duplicates.push({ index, evidence_id: parsed.value.evidence_id });
    else {
      seen.add(parsed.value.evidence_id);
      valid.push(parsed.value);
    }
  });
  return { total: records.length, valid, duplicates, invalid };
};

const countBy = (values: readonly string[]): JsonObject => {
  const counts: Record<string, number> = {};
  for (const value of [...values].toSorted()) counts[value] = (counts[value] ?? 0) + 1;
  return counts;
};

/** Structured report of what a bundle claims and how strongly. */
export const summarizeBundle = (parsed: ParsedBundle): JsonObject => ({
  total_records: parsed.total,
  valid_records: parsed.valid.length,
  duplicate_records: parsed.duplicates.map((duplicate) => ({ ...duplicate })),
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
