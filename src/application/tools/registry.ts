import { makeError, type ErrorEnvelope } from "../../domain/errors.js";
import { parseEvidence } from "../../domain/evidence.js";
import { compareEvidenceTool, reportEvidenceTool } from "./evidenceTools.js";
import { inspectArtifactTool } from "./inspectArtifact.js";
import { stubAnalysisTool } from "./stubAnalysis.js";
import {
  successOutputSchema,
  toJson,
  type ToolContext,
  type ToolDefinition,
  type ToolOutput,
} from "./types.js";

/** The canonical tool inventory; CLI commands and MCP tools are both derived from it. */
export const TOOLS: readonly ToolDefinition[] = [
  inspectArtifactTool,
  reportEvidenceTool,
  compareEvidenceTool,
  stubAnalysisTool,
];

export const findTool = (name: string): ToolDefinition | undefined =>
  TOOLS.find((tool) => tool.name === name);

const failure = (error: ErrorEnvelope): ToolOutput => ({ ok: false, error });

/** Construct the unknown-tool error once so every interface reports it identically. */
export const unknownToolError = (name: string): ErrorEnvelope =>
  makeError("unknown_tool", `No tool is named ${name}`, {
    tool: name,
    available_tools: TOOLS.map((tool) => tool.name),
  });

const internalError = (
  context: ToolContext,
  tool: string,
  errorClass: string,
): ErrorEnvelope => {
  const correlationId = context.newCorrelationId();
  context.logger.error({
    event: "tool_internal_error",
    tool,
    error_class: errorClass,
    correlation_id: correlationId,
  });
  return makeError("internal_error", "The tool failed unexpectedly", {
    correlation_id: correlationId,
  });
};

/**
 * The single execution path for every interface: lookup, input validation,
 * execution, output verification, and error projection.
 */
export const executeTool = async (
  context: ToolContext,
  name: string,
  raw: unknown,
): Promise<ToolOutput> => {
  const tool = findTool(name);
  if (tool === undefined) return failure(unknownToolError(name));
  const started = performance.now();
  let output: ToolOutput;
  try {
    const result = await tool.invoke(raw ?? {}, context);
    if (!result.ok) output = failure(result.error);
    else {
      const candidate = {
        ok: true as const,
        tool: name,
        records: [...result.value.records],
        data: result.value.data,
      };
      const verified =
        successOutputSchema.safeParse(toJson(candidate)).success &&
        candidate.records.every((record) => parseEvidence(record).ok);
      output = verified
        ? candidate
        : failure(internalError(context, name, "OutputContractViolation"));
    }
  } catch (cause: unknown) {
    output = failure(
      internalError(context, name, cause instanceof Error ? cause.name : typeof cause),
    );
  }
  context.logger.info({
    event: "tool_completed",
    tool: name,
    outcome: output.ok ? "ok" : "error",
    ...(output.ok ? {} : { error_code: output.error.code }),
    duration_ms: Math.round(performance.now() - started),
  });
  return output;
};
