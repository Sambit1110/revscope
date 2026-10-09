import { describe, expect, it } from "vitest";

import {
  RESULT_KINDS,
  RESULT_KIND_SEMANTICS,
  createEvidence,
  parseEvidence,
  type Evidence,
  type EvidenceDraft,
} from "../../src/domain/evidence.js";
import { canonicalJson, sha256Hex, type JsonValue } from "../../src/domain/json.js";
import { artifactDraft, stateSubject } from "../support/evidence.js";

const create = (draft: EvidenceDraft): Evidence => {
  const created = createEvidence(draft);
  if (!created.ok) throw new Error(JSON.stringify(created.error));
  return created.value;
};

const issuePaths = (value: unknown): string[] => {
  const parsed = parseEvidence(value);
  if (parsed.ok) return [];
  const issues = parsed.error.details["issues"];
  return Array.isArray(issues)
    ? issues.map((issue) => (issue as { path: string }).path)
    : [];
};

const rejected = (draft: EvidenceDraft, fragment: string) => {
  const created = createEvidence(draft);
  expect(created.ok).toBe(false);
  if (!created.ok) expect(JSON.stringify(created.error.details)).toContain(fragment);
};

/** Re-derive the identifier the way a forger would, to isolate label validation. */
const withRecomputedId = (record: Record<string, unknown>) => {
  const { evidence_id: _id, ...body } = record;
  return { ...body, evidence_id: `ev_${sha256Hex(canonicalJson(body as JsonValue))}` };
};

describe("evidence creation", () => {
  it("creates a record whose labels come from its result kind", () => {
    const evidence = create(artifactDraft());
    expect(evidence.schema).toBe("revscope.evidence/3");
    expect(evidence.evidence_id).toMatch(/^ev_[0-9a-f]{64}$/u);
    expect(evidence.confidence).toBe("observed");
    expect(evidence.authority).toBe("original-artifact");
    expect(parseEvidence(evidence)).toEqual({ ok: true, value: evidence });
  });

  it("refuses a payload with a __proto__ key rather than recording it without that key", () => {
    const payload = JSON.parse('{"__proto__": {"admin": true}, "size_bytes": 12}') as EvidenceDraft["payload"];
    expect(createEvidence(artifactDraft({ payload })).ok).toBe(false);
  });

  it("produces identical identifiers regardless of property order", () => {
    const first = create(artifactDraft({ payload: { a: 1, b: 2 } }));
    const second = create(artifactDraft({ payload: { b: 2, a: 1 } }));
    expect(first.evidence_id).toBe(second.evidence_id);
  });

  it("does not accept labels from the producer", () => {
    const created = createEvidence({
      ...artifactDraft(),
      confidence: "inferred",
    } as unknown as EvidenceDraft);
    expect(created.ok).toBe(false);
  });

  it.each([
    "result_kind",
    "subject",
    "operation",
    "producer",
    "payload",
    "unknowns",
    "limitations",
  ] as const)("rejects a draft without %s instead of defaulting it", (field) => {
    const draft: Record<string, unknown> = { ...artifactDraft() };
    delete draft[field];
    const created = createEvidence(draft as EvidenceDraft);
    expect(created.ok).toBe(false);
    if (!created.ok) {
      expect(created.error.code).toBe("evidence_integrity");
      expect(JSON.stringify(created.error.details)).toContain(field);
    }
  });

  it.each([
    ["result_kind", { result_kind: "observed-fact" }],
    ["subject.sha256", { subject: { kind: "artifact", sha256: "XYZ", size_bytes: 1 } }],
    ["operation.name", { operation: { name: "Bad Name", parameters: {} } }],
    ["payload", { payload: Number.POSITIVE_INFINITY }],
  ])("rejects malformed %s", (_field, override) => {
    const created = createEvidence({
      ...artifactDraft(),
      ...(override as Partial<EvidenceDraft>),
    });
    expect(created.ok).toBe(false);
  });
});

describe("result kinds", () => {
  it("maps every kind to exactly one label pair, centrally", () => {
    expect(Object.keys(RESULT_KIND_SEMANTICS).toSorted()).toEqual([...RESULT_KINDS].toSorted());
  });

  it("labels decompiler output as derived engine interpretation, never observed", () => {
    const evidence = create(
      artifactDraft({
        result_kind: "engine-interpretation",
        subject: stateSubject(),
        operation: { name: "decompile", parameters: { address: "0x1000" } },
      }),
    );
    expect(evidence.confidence).toBe("derived");
    expect(evidence.authority).toBe("analysis-engine");
    expect(Object.values(RESULT_KIND_SEMANTICS).some(
      ({ authority, confidence }) => authority === "analysis-engine" && confidence === "observed",
    )).toBe(false);
  });

  it("refuses decompiler output presented as an observed fact about the original artifact", () => {
    // The only kinds that speak for the original artifact require an artifact subject
    // and are produced by reading bytes, so engine output cannot reach them by relabelling.
    const decompiled = create(
      artifactDraft({
        result_kind: "engine-interpretation",
        subject: stateSubject(),
        operation: { name: "decompile", parameters: {} },
      }),
    );
    const forged = withRecomputedId({ ...decompiled, confidence: "observed", authority: "original-artifact" });
    expect(parseEvidence(forged).ok).toBe(false);
    rejected(
      artifactDraft({ result_kind: "engine-interpretation", operation: { name: "decompile", parameters: {} } }),
      "cannot describe a subject of kind artifact",
    );
  });

  it("refuses a mutation acknowledgement as proof of artifact state", () => {
    rejected(
      artifactDraft({ result_kind: "mutation-acknowledgement", operation: { name: "rename", parameters: {} } }),
      "cannot describe a subject of kind artifact",
    );
    const ack = create(
      artifactDraft({
        result_kind: "mutation-acknowledgement",
        subject: stateSubject(1),
        operation: { name: "rename", parameters: {} },
      }),
    );
    expect(ack.authority).toBe("analysis-state");
    const relabelled = withRecomputedId({ ...ack, authority: "original-artifact" });
    expect(issuePaths(relabelled)).toContain("result_kind");
  });

  it("never labels a mutation acknowledgement as an observation of the resulting state", () => {
    const ack = create(
      artifactDraft({
        result_kind: "mutation-acknowledgement",
        subject: stateSubject(1),
        operation: { name: "rename", parameters: {} },
      }),
    );
    expect(ack.confidence).toBe("reported");
    // Presenting the acknowledgement as a state observation is rejected even with a recomputed identifier.
    expect(issuePaths(withRecomputedId({ ...ack, confidence: "observed" }))).toContain("result_kind");
    for (const [kind, semantics] of Object.entries(RESULT_KIND_SEMANTICS))
      if (semantics.effect === "mutate") expect(semantics.confidence, kind).not.toBe("observed");
  });

  it("requires heuristic and assertion results to state their basis", () => {
    rejected(artifactDraft({ result_kind: "artifact-heuristic" }), "must state their basis");
    rejected(artifactDraft({ result_kind: "unverified-assertion" }), "must state their basis");
    expect(
      createEvidence(
        artifactDraft({
          result_kind: "artifact-heuristic",
          unknowns: [{ scope: "format", reason: "magic bytes only" }],
        }),
      ).ok,
    ).toBe(true);
  });

  it("requires Revscope computations to describe an evidence set", () => {
    rejected(artifactDraft({ result_kind: "derived-computation" }), "cannot describe a subject of kind artifact");
  });
});

describe("untrusted record parsing", () => {
  it("detects tampering with the payload", () => {
    const evidence = create(artifactDraft());
    const parsed = parseEvidence({ ...evidence, payload: { size_bytes: 13 } });
    expect(parsed.ok).toBe(false);
    if (!parsed.ok) {
      expect(parsed.error.code).toBe("evidence_integrity");
      expect(parsed.error.message).toContain("identifier");
    }
  });

  it("detects relabelling even when the identifier is recomputed", () => {
    const evidence = create(
      artifactDraft({ result_kind: "artifact-heuristic", limitations: ["header only"] }),
    );
    expect(parseEvidence({ ...evidence, confidence: "observed" }).ok).toBe(false);
    expect(parseEvidence(withRecomputedId({ ...evidence, confidence: "observed" })).ok).toBe(false);
  });

  it("accepts a recomputed identifier for consistent content: the digest is not a signature", () => {
    const evidence = create(artifactDraft());
    const edited = withRecomputedId({ ...evidence, payload: { size_bytes: 999 } });
    // Integrity consistency only; authenticity is out of scope (see docs/architecture.md).
    expect(parseEvidence(edited).ok).toBe(true);
  });

  it("reports which fields are missing from a record", () => {
    const evidence = create(artifactDraft());
    const { confidence: _confidence, ...withoutConfidence } = evidence;
    expect(issuePaths(withoutConfidence)).toContain("confidence");
  });

  it("rejects non-objects", () => {
    expect(parseEvidence(null).ok).toBe(false);
    expect(parseEvidence("ev").ok).toBe(false);
  });
});
