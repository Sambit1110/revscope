import { z } from "zod";

import { classifyHeader } from "../../domain/artifactFormat.js";
import { evidenceFromCapability } from "../../domain/capability.js";
import type { Subject } from "../../domain/evidence.js";
import { ok } from "../../domain/result.js";
import {
  ARTIFACT_FORMAT,
  ARTIFACT_IDENTITY,
  REVSCOPE_PRODUCER,
} from "./builtinCapabilities.js";
import { absolutePathSchema, defineTool } from "./types.js";

const LEADING_BYTES_SHOWN = 16;

const hex = (bytes: Uint8Array): string =>
  [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");

export const inspectArtifactTool = defineTool({
  name: "inspect_artifact",
  title: "Inspect artifact metadata",
  description:
    "Read one local regular file without executing it. Returns observed identity evidence (size, SHA-256, leading bytes) and separately labelled inferred format evidence from magic bytes. It does not parse or reverse-engineer the file.",
  readOnly: true,
  input: z.strictObject({ path: absolutePathSchema }),
  run: async ({ path }, context) => {
    const facts = await context.artifactReader.read(path);
    if (!facts.ok) return facts;
    const { displayName, sizeBytes, sha256, header } = facts.value;
    const subject: Subject = { kind: "artifact", sha256, size_bytes: sizeBytes };
    const identity = evidenceFromCapability(ARTIFACT_IDENTITY, {
      subject,
      parameters: {},
      payload: {
        size_bytes: sizeBytes,
        sha256,
        leading_bytes_hex: hex(header.subarray(0, LEADING_BYTES_SHOWN)),
      },
      producer: REVSCOPE_PRODUCER,
      unknowns: [],
      limitations: [],
    });
    if (!identity.ok) return identity;
    const classification = classifyHeader(header, { truncated: header.length < sizeBytes });
    const format = evidenceFromCapability(ARTIFACT_FORMAT, {
      subject,
      parameters: {},
      payload: { ...classification },
      producer: REVSCOPE_PRODUCER,
      unknowns:
        classification.label === "unknown"
          ? [{ scope: "format", reason: "No known signature matched the leading bytes." }]
          : [],
      limitations: [],
    });
    if (!format.ok) return format;
    return ok({
      records: [identity.value, format.value],
      data: { path, display_name: displayName },
    });
  },
});
