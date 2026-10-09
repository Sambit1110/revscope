import type { EvidenceDraft } from "../../src/domain/evidence.js";

export const ARTIFACT_SHA = "a".repeat(64);

/** A complete, internally consistent draft for tests to vary one field at a time. */
export const artifactDraft = (
  overrides: Partial<EvidenceDraft> = {},
): EvidenceDraft => ({
  result_kind: "artifact-bytes",
  subject: {
    kind: "artifact",
    sha256: ARTIFACT_SHA,
    size_bytes: 12,
  },
  operation: { name: "artifact_identity", parameters: {} },
  producer: { id: "test", version: "1" },
  payload: { size_bytes: 12 },
  unknowns: [],
  limitations: [],
  ...overrides,
});

export const stateSubject = (revision = 0, stateToken = "token-0") =>
  ({
    kind: "analysis-state",
    artifact_sha256: ARTIFACT_SHA,
    session_id: "ses_0123456789abcdef",
    state_revision: revision,
    state_token: stateToken,
  }) as const;
