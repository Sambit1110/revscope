import type { CapabilityDescriptor } from "../../domain/capability.js";

export const PRODUCT_VERSION = "0.1.0";
export const REVSCOPE_PRODUCER = { id: "revscope", version: PRODUCT_VERSION } as const;

/** Bytes and size as read; a direct observation of the supplied artifact. */
export const ARTIFACT_IDENTITY: CapabilityDescriptor = {
  operation: "artifact_identity",
  description: "Size, SHA-256 digest, and leading bytes of a local file.",
  effect: "read",
  resultKind: "artifact-bytes",
  limitations: [
    "Describes the file bytes at the time they were read; later changes are not reflected.",
  ],
};

/** A format suggestion from magic bytes is a judgement about the artifact, not an observation. */
export const ARTIFACT_FORMAT: CapabilityDescriptor = {
  operation: "artifact_format",
  description: "Suggested file format from leading magic bytes.",
  effect: "read",
  resultKind: "artifact-heuristic",
  limitations: [
    "Suggested from leading magic bytes only; the rest of the file is not parsed or validated.",
  ],
};

/** Comparisons speak for Revscope's computation over evidence, not for any artifact. */
export const EVIDENCE_COMPARISON: CapabilityDescriptor = {
  operation: "compare_evidence",
  description: "Pair two evidence sets and classify differences.",
  effect: "read",
  resultKind: "derived-computation",
  limitations: [
    "Records are paired by subject, operation, and parameters; payloads are compared by canonical JSON equality.",
  ],
};

export const BUILTIN_CAPABILITIES: readonly CapabilityDescriptor[] = [
  ARTIFACT_IDENTITY,
  ARTIFACT_FORMAT,
  EVIDENCE_COMPARISON,
];
