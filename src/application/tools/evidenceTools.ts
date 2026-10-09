import { z } from "zod";

import { bundleSchema, parseBundleRecords, summarizeBundle, type ParsedBundle } from "../../domain/bundle.js";
import { evidenceFromCapability } from "../../domain/capability.js";
import { compareEvidence, comparisonPayload } from "../../domain/comparison.js";
import {
  invalidInput,
  issuesFromZod,
  makeError,
  type ErrorEnvelope,
} from "../../domain/errors.js";
import { err, ok, type Result } from "../../domain/result.js";
import type { JsonFileReader } from "../ports.js";
import { EVIDENCE_COMPARISON, REVSCOPE_PRODUCER } from "./builtinCapabilities.js";
import { absolutePathSchema, defineTool } from "./types.js";

const readBundle = async (
  reader: JsonFileReader,
  path: string,
  field: string,
): Promise<Result<ParsedBundle, ErrorEnvelope>> => {
  const raw = await reader.read(path);
  if (!raw.ok) return err({ ...raw.error, details: { ...raw.error.details, field } });
  const bundle = bundleSchema.safeParse(raw.value);
  if (!bundle.success)
    return err(
      invalidInput(
        "The file is not an evidence bundle: expected an object with a records array",
        issuesFromZod(bundle.error, field),
      ),
    );
  return ok(parseBundleRecords(bundle.data.records));
};

export const reportEvidenceTool = defineTool({
  name: "report_evidence",
  title: "Report evidence bundle",
  description:
    "Validate every record in an evidence bundle (any JSON object with a records array, including Revscope tool output) and report counts by confidence, authority, and operation, together with unknowns, limitations, and the records that failed validation.",
  readOnly: true,
  input: z.strictObject({ path: absolutePathSchema }),
  run: async ({ path }, context) => {
    const parsed = await readBundle(context.jsonReader, path, "path");
    if (!parsed.ok) return parsed;
    return ok({ records: [], data: { path, report: summarizeBundle(parsed.value) } });
  },
});

export const compareEvidenceTool = defineTool({
  name: "compare_evidence",
  title: "Compare evidence bundles",
  description:
    "Pair records from two evidence bundles by subject, operation, and parameters, and classify each pair as added, removed, unchanged, changed, relabelled (same payload, different confidence or authority), or ambiguous. Refuses bundles containing records that fail validation.",
  readOnly: true,
  input: z.strictObject({ left_path: absolutePathSchema, right_path: absolutePathSchema }),
  run: async ({ left_path: leftPath, right_path: rightPath }, context) => {
    const left = await readBundle(context.jsonReader, leftPath, "left_path");
    if (!left.ok) return left;
    const right = await readBundle(context.jsonReader, rightPath, "right_path");
    if (!right.ok) return right;
    if (left.value.invalid.length > 0 || right.value.invalid.length > 0)
      return err(
        makeError("evidence_integrity", "A bundle contains records that failed validation", {
          left_invalid_indexes: left.value.invalid.map(({ index }) => index),
          right_invalid_indexes: right.value.invalid.map(({ index }) => index),
        }),
      );
    const ids = [
      ...new Set([...left.value.valid, ...right.value.valid].map(({ evidence_id }) => evidence_id)),
    ].toSorted();
    if (ids.length === 0)
      return err(
        invalidInput("Both bundles are empty; there is nothing to compare", [
          { path: "left_path", message: "Bundle has no records" },
          { path: "right_path", message: "Bundle has no records" },
        ]),
      );
    const comparison = compareEvidence(left.value.valid, right.value.valid);
    const evidence = evidenceFromCapability(EVIDENCE_COMPARISON, {
      subject: { kind: "evidence-set", evidence_ids: ids },
      parameters: {},
      payload: comparisonPayload(comparison),
      producer: REVSCOPE_PRODUCER,
      unknowns: [],
      limitations: [],
    });
    if (!evidence.ok) return evidence;
    return ok({
      records: [evidence.value],
      data: { left_path: leftPath, right_path: rightPath, summary: { ...comparison.summary } },
    });
  },
});
