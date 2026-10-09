import { canonicalJson, type JsonObject } from "./json.js";
import { evidenceKey, type Evidence } from "./evidence.js";

export type ComparisonStatus =
  | "added"
  | "removed"
  | "unchanged"
  | "changed"
  | "relabelled"
  | "ambiguous";

interface LabelSet {
  readonly result_kind: string;
  readonly confidence: string;
  readonly authority: string;
}

export interface ComparisonEntry {
  readonly key: string;
  readonly status: ComparisonStatus;
  readonly left_ids: readonly string[];
  readonly right_ids: readonly string[];
  /** Present when the result kind, and so the labels, differ for the same question. */
  readonly label_change: {
    readonly left: LabelSet;
    readonly right: LabelSet;
  } | null;
}

export interface EvidenceComparison {
  readonly summary: Readonly<Record<ComparisonStatus, number>>;
  readonly entries: readonly ComparisonEntry[];
}

/** Group distinct records by question; a repeated identifier is kept once. */
const groupByKey = (records: readonly Evidence[]): Map<string, Evidence[]> => {
  const groups = new Map<string, Evidence[]>();
  const seen = new Set<string>();
  for (const record of records) {
    if (seen.has(record.evidence_id)) continue;
    seen.add(record.evidence_id);
    const key = evidenceKey(record);
    const group = groups.get(key);
    if (group === undefined) groups.set(key, [record]);
    else group.push(record);
  }
  return groups;
};

const labels = (evidence: Evidence): LabelSet => ({
  result_kind: evidence.result_kind,
  confidence: evidence.confidence,
  authority: evidence.authority,
});

/** Sorted distinct identifiers; duplicates of one record count once. */
const ids = (records: readonly Evidence[] | undefined): string[] =>
  [...new Set((records ?? []).map(({ evidence_id }) => evidence_id))].toSorted();

const sameIds = (left: readonly Evidence[], right: readonly Evidence[]): boolean => {
  const a = ids(left);
  const b = ids(right);
  return a.length === b.length && a.every((id, index) => id === b[index]);
};

const classify = (
  left: readonly Evidence[] | undefined,
  right: readonly Evidence[] | undefined,
): Pick<ComparisonEntry, "status" | "label_change"> => {
  if (left === undefined) return { status: "added", label_change: null };
  if (right === undefined) return { status: "removed", label_change: null };
  // The same records on both sides are unchanged however many there are, so
  // comparing a bundle with itself never reports ambiguity.
  if (sameIds(left, right)) return { status: "unchanged", label_change: null };
  const [before] = left;
  const [after] = right;
  // Several records answering the same question on one side cannot be paired
  // without guessing, so the comparison reports them instead of choosing one.
  if (left.length !== 1 || right.length !== 1 || !before || !after)
    return { status: "ambiguous", label_change: null };
  const labelsDiffer =
    before.result_kind !== after.result_kind ||
    before.confidence !== after.confidence ||
    before.authority !== after.authority;
  const payloadDiffers =
    canonicalJson(before.payload) !== canonicalJson(after.payload);
  const label_change = labelsDiffer
    ? { left: labels(before), right: labels(after) }
    : null;
  if (payloadDiffers) return { status: "changed", label_change };
  if (labelsDiffer) return { status: "relabelled", label_change };
  return { status: "unchanged", label_change: null };
};

/** Pair records by subject, operation, and parameters, then classify each pair. */
export const compareEvidence = (
  left: readonly Evidence[],
  right: readonly Evidence[],
): EvidenceComparison => {
  const leftGroups = groupByKey(left);
  const rightGroups = groupByKey(right);
  const keys = [...new Set([...leftGroups.keys(), ...rightGroups.keys()])].toSorted();
  const summary: Record<ComparisonStatus, number> = {
    added: 0,
    removed: 0,
    unchanged: 0,
    changed: 0,
    relabelled: 0,
    ambiguous: 0,
  };
  const entries = keys.map((key): ComparisonEntry => {
    const before = leftGroups.get(key);
    const after = rightGroups.get(key);
    const classified = classify(before, after);
    summary[classified.status] += 1;
    return {
      key,
      ...classified,
      left_ids: ids(before),
      right_ids: ids(after),
    };
  });
  return { summary, entries };
};

/** JSON projection of a comparison for evidence payloads. */
export const comparisonPayload = (comparison: EvidenceComparison): JsonObject => ({
  summary: { ...comparison.summary },
  entries: comparison.entries.map((entry) => ({
    key: entry.key,
    status: entry.status,
    left_ids: [...entry.left_ids],
    right_ids: [...entry.right_ids],
    label_change:
      entry.label_change === null
        ? null
        : {
            left: { ...entry.label_change.left },
            right: { ...entry.label_change.right },
          },
  })),
});
