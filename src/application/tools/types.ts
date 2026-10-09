import { isAbsolute } from "node:path";
import { z } from "zod";

import {
  failureOutputSchema,
  invalidInput,
  issuesFromZod,
  type ErrorEnvelope,
} from "../../domain/errors.js";
import { evidenceSchema, type Evidence } from "../../domain/evidence.js";
import { jsonObjectSchema, type JsonObject, type JsonValue } from "../../domain/json.js";
import { err, type Result } from "../../domain/result.js";
import type {
  AnalysisProvider,
  ArtifactReader,
  JsonFileReader,
  Logger,
} from "../ports.js";

/** Dependencies every tool may use; supplied by composition or by tests. */
export interface ToolContext {
  readonly artifactReader: ArtifactReader;
  readonly jsonReader: JsonFileReader;
  /** Validate a stub fixture document and build a provider from it. */
  readonly createStubProvider: (
    fixture: unknown,
  ) => Result<AnalysisProvider, ErrorEnvelope>;
  readonly logger: Logger;
  readonly newCorrelationId: () => string;
}

export interface ToolSuccess {
  readonly records: readonly Evidence[];
  readonly data: JsonObject;
}

export const successOutputSchema = z.strictObject({
  ok: z.literal(true),
  tool: z.string().min(1),
  records: z.array(evidenceSchema),
  data: jsonObjectSchema,
});
export type SuccessOutput = z.infer<typeof successOutputSchema>;
export type FailureOutput = z.infer<typeof failureOutputSchema>;
export type ToolOutput = SuccessOutput | FailureOutput;

/** Every tool output, success or failure, as one discriminated schema. */
export const toolOutputSchema = z.discriminatedUnion("ok", [
  successOutputSchema,
  failureOutputSchema,
]);

export interface ToolDefinition {
  readonly name: string;
  readonly title: string;
  readonly description: string;
  /** True when the tool cannot change anything outside its own process. */
  readonly readOnly: boolean;
  readonly inputSchema: z.ZodType;
  /** Validate raw input with the tool's schema, then run it. */
  invoke(raw: unknown, context: ToolContext): Promise<Result<ToolSuccess, ErrorEnvelope>>;
}

/** Bind a typed input schema to its implementation so validation cannot be skipped. */
export const defineTool = <Input>(spec: {
  readonly name: string;
  readonly title: string;
  readonly description: string;
  readonly readOnly: boolean;
  readonly input: z.ZodType<Input>;
  readonly run: (
    input: Input,
    context: ToolContext,
  ) => Promise<Result<ToolSuccess, ErrorEnvelope>>;
}): ToolDefinition => ({
  name: spec.name,
  title: spec.title,
  description: spec.description,
  readOnly: spec.readOnly,
  inputSchema: spec.input,
  invoke: async (raw, context) => {
    const parsed = spec.input.safeParse(raw);
    if (!parsed.success)
      return err(
        invalidInput(`Input for ${spec.name} is invalid`, issuesFromZod(parsed.error)),
      );
    return spec.run(parsed.data, context);
  },
});

/**
 * Local paths must be absolute at the tool boundary; adapters resolve relative
 * paths first but pass empty values through, so every interface reports them
 * identically.
 */
export const absolutePathSchema = z
  .string()
  .min(1, "Must not be empty")
  .refine((path) => !path.includes("\0"), "Must not contain NUL characters")
  .refine((path) => path === "" || isAbsolute(path), "Must be an absolute path");

/** Round-trip structured values into plain JSON for output payloads. */
export const toJson = (value: unknown): JsonValue =>
  JSON.parse(JSON.stringify(value)) as JsonValue;
