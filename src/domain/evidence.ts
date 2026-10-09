import { z } from "zod";

import {
  issuesFromZod,
  makeError,
  type ErrorEnvelope,
  type InputIssue,
} from "./errors.js";
import {
  canonicalJson,
  jsonObjectSchema,
  jsonValueSchema,
  sha256Hex,
  type JsonValue,
} from "./json.js";
import { err, ok, type Result } from "./result.js";

export const EVIDENCE_SCHEMA = "revscope.evidence/2";

/**
 * How directly the claim was established:
 * - observed: read directly from the subject without interpretation;
 * - derived: computed deterministically from observations or by a modelling engine;
 * - inferred: a judgement that may be wrong; it must state its basis.
 */
export const CONFIDENCE_LEVELS = ["observed", "derived", "inferred"] as const;
export type Confidence = (typeof CONFIDENCE_LEVELS)[number];

/**
 * What the claim speaks for:
 * - original-artifact: the bytes or metadata of the artifact as supplied;
 * - analysis-engine: an engine's model of the artifact (for example decompiler output);
 * - analysis-state: the mutable state of an analysis session or database;
 * - revscope-computation: Revscope's own computation over other evidence;
 * - analyst-assertion: a claim made by a person or agent.
 */
export const AUTHORITIES = [
  "original-artifact",
  "analysis-engine",
  "analysis-state",
  "revscope-computation",
  "analyst-assertion",
] as const;
export type Authority = (typeof AUTHORITIES)[number];

export const SUBJECT_KINDS = [
  "artifact",
  "analysis-state",
  "evidence-set",
] as const;
export type SubjectKind = (typeof SUBJECT_KINDS)[number];

/**
 * The closed set of things a result can be. Producers choose a kind; the
 * confidence and authority labels are always derived from it.
 */
export const RESULT_KINDS = [
  "artifact-bytes",
  "artifact-heuristic",
  "engine-interpretation",
  "state-observation",
  "mutation-acknowledgement",
  "derived-computation",
  "unverified-assertion",
] as const;
export type ResultKind = (typeof RESULT_KINDS)[number];

export interface ResultKindSemantics {
  readonly confidence: Confidence;
  readonly authority: Authority;
  /** Subjects this kind of result may describe. */
  readonly subjectKinds: readonly SubjectKind[];
  /** Whether the operation producing it reads or mutates. */
  readonly effect: "read" | "mutate";
  /** Inferred results must say what they are based on. */
  readonly requiresBasis: boolean;
}

/** The single place where result kinds map to evidence labels. */
export const RESULT_KIND_SEMANTICS: Readonly<Record<ResultKind, ResultKindSemantics>> = {
  // Bytes, size, digest: read directly from the supplied artifact.
  "artifact-bytes": {
    confidence: "observed",
    authority: "original-artifact",
    subjectKinds: ["artifact"],
    effect: "read",
    requiresBasis: false,
  },
  // A judgement about the artifact from partial evidence, such as magic bytes.
  "artifact-heuristic": {
    confidence: "inferred",
    authority: "original-artifact",
    subjectKinds: ["artifact"],
    effect: "read",
    requiresBasis: true,
  },
  // An engine's model of the program: decompilation, disassembly, recovered types.
  "engine-interpretation": {
    confidence: "derived",
    authority: "analysis-engine",
    subjectKinds: ["analysis-state"],
    effect: "read",
    requiresBasis: false,
  },
  // A value read directly from analysis state, such as a label at an address.
  "state-observation": {
    confidence: "observed",
    authority: "analysis-state",
    subjectKinds: ["analysis-state"],
    effect: "read",
    requiresBasis: false,
  },
  // A provider's report that it changed analysis state. Never a fact about the artifact.
  "mutation-acknowledgement": {
    confidence: "observed",
    authority: "analysis-state",
    subjectKinds: ["analysis-state"],
    effect: "mutate",
    requiresBasis: false,
  },
  // Revscope's own deterministic computation over other evidence.
  "derived-computation": {
    confidence: "derived",
    authority: "revscope-computation",
    subjectKinds: ["evidence-set"],
    effect: "read",
    requiresBasis: false,
  },
  // A claim by a person or agent that Revscope has not verified.
  "unverified-assertion": {
    confidence: "inferred",
    authority: "analyst-assertion",
    subjectKinds: ["artifact", "analysis-state"],
    effect: "read",
    requiresBasis: true,
  },
};

export const sha256Schema = z
  .string()
  .regex(/^[0-9a-f]{64}$/, "Must be 64 lowercase hexadecimal characters");
export const evidenceIdSchema = z
  .string()
  .regex(/^ev_[0-9a-f]{64}$/, "Must be ev_ followed by 64 hexadecimal characters");
export const sessionIdSchema = z
  .string()
  .regex(/^ses_[0-9a-f]{16}$/, "Must be ses_ followed by 16 hexadecimal characters");
/** Opaque provider identifier for one exact analysis state. */
export const stateTokenSchema = z.string().min(1).max(256);

export const subjectSchema = z.discriminatedUnion("kind", [
  z.strictObject({
    kind: z.literal("artifact"),
    sha256: sha256Schema,
    size_bytes: z.number().int().nonnegative(),
    display_name: z.string().min(1).max(255),
  }),
  z.strictObject({
    kind: z.literal("analysis-state"),
    artifact_sha256: sha256Schema,
    session_id: sessionIdSchema,
    state_revision: z.number().int().nonnegative(),
    /** The provider's token for the state this observation was made against. */
    state_token: stateTokenSchema,
  }),
  z.strictObject({
    kind: z.literal("evidence-set"),
    evidence_ids: z.array(evidenceIdSchema).min(1),
  }),
]);
export type Subject = z.infer<typeof subjectSchema>;

export const unknownSchema = z.strictObject({
  scope: z.string().min(1),
  reason: z.string().min(1),
});
export type EvidenceUnknown = z.infer<typeof unknownSchema>;

const draftShape = {
  result_kind: z.enum(RESULT_KINDS),
  subject: subjectSchema,
  operation: z.strictObject({
    name: z
      .string()
      .regex(/^[a-z][a-z0-9_]*$/, "Must be a lowercase snake_case operation name"),
    parameters: jsonObjectSchema,
  }),
  producer: z.strictObject({
    id: z.string().min(1),
    version: z.string().min(1),
  }),
  payload: jsonValueSchema,
  unknowns: z.array(unknownSchema),
  limitations: z.array(z.string().min(1)),
};

/** Problems with a result kind applied to a subject, independent of labels. */
export const kindIssues = (record: {
  readonly result_kind: ResultKind;
  readonly subject: Subject;
  readonly unknowns: readonly EvidenceUnknown[];
  readonly limitations: readonly string[];
}): string[] => {
  const semantics = RESULT_KIND_SEMANTICS[record.result_kind];
  const issues: string[] = [];
  if (!semantics.subjectKinds.includes(record.subject.kind))
    issues.push(
      `${record.result_kind} results cannot describe a subject of kind ${record.subject.kind}`,
    );
  if (
    semantics.requiresBasis &&
    record.unknowns.length === 0 &&
    record.limitations.length === 0
  )
    issues.push(`${record.result_kind} results must state their basis in limitations or unknowns`);
  return issues;
};

const labelMismatches = (record: {
  readonly result_kind: ResultKind;
  readonly confidence: Confidence;
  readonly authority: Authority;
}): string[] => {
  const semantics = RESULT_KIND_SEMANTICS[record.result_kind];
  const issues: string[] = [];
  if (record.confidence !== semantics.confidence)
    issues.push(
      `${record.result_kind} results are ${semantics.confidence}, not ${record.confidence}`,
    );
  if (record.authority !== semantics.authority)
    issues.push(
      `${record.result_kind} results speak for ${semantics.authority}, not ${record.authority}`,
    );
  return issues;
};

/** The producer-supplied part of a record. Labels are not part of it. */
export const evidenceDraftSchema = z
  .strictObject(draftShape)
  .superRefine((draft, context) => {
    for (const message of kindIssues(draft))
      context.addIssue({ code: "custom", path: ["result_kind"], message });
  });
export type EvidenceDraft = z.infer<typeof evidenceDraftSchema>;

export const evidenceSchema = z
  .strictObject({
    schema: z.literal(EVIDENCE_SCHEMA),
    evidence_id: evidenceIdSchema,
    confidence: z.enum(CONFIDENCE_LEVELS),
    authority: z.enum(AUTHORITIES),
    ...draftShape,
  })
  .superRefine((record, context) => {
    for (const message of [...kindIssues(record), ...labelMismatches(record)])
      context.addIssue({ code: "custom", path: ["result_kind"], message });
  });
export type Evidence = z.infer<typeof evidenceSchema>;

type EvidenceBody = Omit<Evidence, "evidence_id">;

/** Every semantic field, labels included, participates in identity. */
const computeEvidenceId = (body: EvidenceBody): string =>
  `ev_${sha256Hex(canonicalJson(body as unknown as JsonValue))}`;

const integrityError = (
  message: string,
  issues: readonly InputIssue[],
): ErrorEnvelope =>
  makeError("evidence_integrity", message, {
    issues: issues.map(({ path, message: text }) => ({ path, message: text })),
  });

/**
 * Create evidence from a complete draft. The labels are derived from the
 * result kind; there is no way to supply or default them.
 */
export const createEvidence = (
  draft: EvidenceDraft,
): Result<Evidence, ErrorEnvelope> => {
  const parsed = evidenceDraftSchema.safeParse(draft);
  if (!parsed.success)
    return err(
      integrityError(
        "Evidence metadata is missing, malformed, or inconsistent",
        issuesFromZod(parsed.error),
      ),
    );
  const semantics = RESULT_KIND_SEMANTICS[parsed.data.result_kind];
  const body: EvidenceBody = {
    schema: EVIDENCE_SCHEMA,
    confidence: semantics.confidence,
    authority: semantics.authority,
    ...parsed.data,
  };
  return ok({ ...body, evidence_id: computeEvidenceId(body) });
};

/**
 * Validate a record's structure, labels, and identifier.
 *
 * The identifier is an unkeyed digest: it detects accidental or partial
 * modification, but anyone can recompute it after editing a record. It does
 * not prove who produced the record.
 */
export const parseEvidence = (
  value: unknown,
): Result<Evidence, ErrorEnvelope> => {
  const parsed = evidenceSchema.safeParse(value);
  if (!parsed.success)
    return err(
      integrityError(
        "Evidence record is missing, malformed, or inconsistent",
        issuesFromZod(parsed.error),
      ),
    );
  const { evidence_id: evidenceId, ...body } = parsed.data;
  if (computeEvidenceId(body) !== evidenceId)
    return err(
      integrityError("Evidence identifier does not match its content", [
        { path: "evidence_id", message: "Does not match the record content" },
      ]),
    );
  return ok(parsed.data);
};

/** Comparison key: what the evidence is about and which question it answers. */
export const evidenceKey = (evidence: Evidence): string => {
  const subject = evidence.subject;
  const subjectKey =
    subject.kind === "artifact"
      ? `artifact:${subject.sha256}`
      : subject.kind === "analysis-state"
        ? `analysis-state:${subject.artifact_sha256}`
        : `evidence-set:${[...subject.evidence_ids].toSorted().join(",")}`;
  return `${subjectKey}|${evidence.operation.name}|${canonicalJson(
    evidence.operation.parameters,
  )}`;
};
