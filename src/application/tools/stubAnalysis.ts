import { z } from "zod";

import type { ErrorEnvelope } from "../../domain/errors.js";
import type { Evidence } from "../../domain/evidence.js";
import { jsonObjectSchema, sha256Hex, type JsonObject } from "../../domain/json.js";
import { err, ok, type Result } from "../../domain/result.js";
import { AnalysisSession } from "../session.js";
import { absolutePathSchema, defineTool, toJson } from "./types.js";

const MAX_STEPS = 100;

const stepSchema = z.discriminatedUnion("action", [
  z.strictObject({
    action: z.literal("read"),
    operation: z.string().min(1),
    params: jsonObjectSchema.optional(),
  }),
  z.strictObject({
    action: z.literal("mutate"),
    operation: z.string().min(1),
    params: jsonObjectSchema.optional(),
  }),
  z.strictObject({ action: z.literal("reconcile") }),
  z.strictObject({ action: z.literal("snapshot") }),
]);
type Step = z.infer<typeof stepSchema>;

interface StepRecord {
  readonly summary: JsonObject;
  readonly error: ErrorEnvelope | null;
}

const runStep = async (
  session: AnalysisSession,
  step: Step,
  index: number,
  records: Evidence[],
  snapshots: JsonObject[],
): Promise<StepRecord> => {
  const base = {
    index,
    action: step.action,
    ...("operation" in step ? { operation: step.operation } : {}),
  };
  const failed = (error: ErrorEnvelope): StepRecord => ({
    summary: { ...base, outcome: "error", error: toJson(error) },
    error,
  });
  switch (step.action) {
    case "read": {
      const result = await session.read(step.operation, step.params ?? {});
      if (!result.ok) return failed(result.error);
      records.push(result.value.evidence);
      return {
        summary: {
          ...base,
          outcome: "ok",
          evidence_id: result.value.evidence.evidence_id,
          cache: result.value.cache,
          state_verified: result.value.stateVerified,
        },
        error: null,
      };
    }
    case "reconcile": {
      const result = await session.reconcile();
      if (!result.ok) return failed(result.error);
      records.push(result.value.evidence);
      return {
        summary: {
          ...base,
          outcome: "ok",
          evidence_id: result.value.evidence.evidence_id,
          state_token: result.value.stateToken,
          revision: result.value.revision,
        },
        error: null,
      };
    }
    case "mutate": {
      const result = await session.mutate(step.operation, step.params ?? {});
      if (!result.ok) return failed(result.error);
      records.push(result.value.evidence);
      return {
        summary: { ...base, outcome: "ok", evidence_id: result.value.evidence.evidence_id },
        error: null,
      };
    }
    case "snapshot": {
      const result = session.snapshot();
      if (!result.ok) return failed(result.error);
      snapshots.push(toJson(result.value) as JsonObject);
      return {
        summary: { ...base, outcome: "ok", snapshot_id: result.value.snapshot_id },
        error: null,
      };
    }
  }
};

export const stubAnalysisTool = defineTool({
  name: "stub_analysis",
  title: "Run a stub analysis session",
  description:
    "Run read, mutate, reconcile, and snapshot steps against a deterministic stub provider loaded from a fixture file, in one fresh session. Demonstrates evidence labelling, unsupported operations, partial mutation failures, cache invalidation, and snapshot refusal. The stub does not analyze real binaries, and the fixture file is never modified.",
  readOnly: true,
  input: z.strictObject({
    fixture_path: absolutePathSchema,
    steps: z.array(stepSchema).min(1).max(MAX_STEPS),
    continue_on_error: z.boolean().optional(),
  }),
  run: async (input, context): Promise<Result<{ records: Evidence[]; data: JsonObject }, ErrorEnvelope>> => {
    const fixture = await context.jsonReader.read(input.fixture_path);
    if (!fixture.ok) return fixture;
    const provider = context.createStubProvider(fixture.value);
    if (!provider.ok) return provider;
    const sessionId = `ses_${sha256Hex(
      `${provider.value.identity.id}:${provider.value.artifactSha256}`,
    ).slice(0, 16)}`;
    const session = await AnalysisSession.open(provider.value, sessionId, context.logger);
    if (!session.ok) return session;

    const records: Evidence[] = [];
    const snapshots: JsonObject[] = [];
    const summaries: JsonObject[] = [];
    let firstFailure: { index: number; error: ErrorEnvelope } | null = null;
    for (const [index, step] of input.steps.entries()) {
      const outcome = await runStep(session.value, step, index, records, snapshots);
      summaries.push(outcome.summary);
      if (outcome.error !== null) {
        firstFailure ??= { index, error: outcome.error };
        if (input.continue_on_error !== true) break;
      }
    }
    const state = toJson(session.value.state());
    if (firstFailure !== null)
      return err({
        ...firstFailure.error,
        details: {
          ...firstFailure.error.details,
          failed_step: firstFailure.index,
          steps: summaries,
          // Observations made before and after the failure are preserved.
          partial_records: toJson(records),
          final_state: state,
        },
      });
    return ok({
      records,
      data: {
        session_id: sessionId,
        steps: summaries,
        final_state: state,
        snapshots,
      },
    });
  },
});
