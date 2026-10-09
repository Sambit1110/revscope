import { describe, expect, it } from "vitest";

import { compareEvidence } from "../../src/domain/comparison.js";
import { createEvidence, type Evidence, type EvidenceDraft } from "../../src/domain/evidence.js";
import { parseBundleRecords, summarizeBundle } from "../../src/domain/bundle.js";
import { artifactDraft } from "../support/evidence.js";

const create = (overrides: Partial<EvidenceDraft> = {}): Evidence => {
  const created = createEvidence(artifactDraft(overrides));
  if (!created.ok) throw new Error(JSON.stringify(created.error));
  return created.value;
};

describe("evidence comparison", () => {
  it("classifies added, removed, unchanged, changed, and relabelled records", () => {
    const identity = create();
    const format = create({
      result_kind: "artifact-heuristic",
      operation: { name: "artifact_format", parameters: {} },
      payload: { label: "elf" },
      limitations: ["magic bytes only"],
    });
    const removed = create({ operation: { name: "only_left", parameters: {} } });
    const added = create({ operation: { name: "only_right", parameters: {} } });
    const changedRight = create({ payload: { size_bytes: 99 } });
    const relabelledRight = create({
      result_kind: "artifact-bytes",
      operation: { name: "artifact_format", parameters: {} },
      payload: { label: "elf" },
    });

    const unchanged = compareEvidence([identity], [identity]);
    expect(unchanged.summary.unchanged).toBe(1);

    const result = compareEvidence([identity, format, removed], [changedRight, relabelledRight, added]);
    expect(result.summary).toEqual({
      added: 1,
      removed: 1,
      unchanged: 0,
      changed: 1,
      relabelled: 1,
      ambiguous: 0,
    });
    const relabelled = result.entries.find(({ status }) => status === "relabelled");
    expect(relabelled?.label_change).toEqual({
      left: { result_kind: "artifact-heuristic", confidence: "inferred", authority: "original-artifact" },
      right: { result_kind: "artifact-bytes", confidence: "observed", authority: "original-artifact" },
    });
  });

  it("reports duplicate answers to one question as ambiguous instead of guessing", () => {
    const first = create({ payload: { size_bytes: 1 } });
    const second = create({ payload: { size_bytes: 2 } });
    const result = compareEvidence([first, second], [first]);
    expect(result.summary.ambiguous).toBe(1);
  });

  it("orders entries deterministically", () => {
    const a = create({ operation: { name: "a_op", parameters: {} } });
    const b = create({ operation: { name: "b_op", parameters: {} } });
    expect(compareEvidence([b, a], []).entries.map(({ key }) => key)).toEqual(
      compareEvidence([a, b], []).entries.map(({ key }) => key),
    );
  });
});

describe("bundle report", () => {
  it("validates records independently and summarizes labels and unknowns", () => {
    const valid = create({
      result_kind: "artifact-heuristic",
      unknowns: [{ scope: "format", reason: "unrecognized" }],
    });
    const parsed = parseBundleRecords([valid, { ...valid, payload: "tampered" }, 42]);
    expect(parsed.valid).toHaveLength(1);
    expect(parsed.invalid.map(({ index }) => index)).toEqual([1, 2]);
    const summary = summarizeBundle(parsed);
    expect(summary["by_confidence"]).toEqual({ inferred: 1 });
    expect(summary["unknowns"]).toEqual([
      { evidence_id: valid.evidence_id, scope: "format", reason: "unrecognized" },
    ]);
  });
});
