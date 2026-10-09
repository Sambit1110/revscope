import { z } from "zod";

import { PRODUCT_VERSION } from "../application/tools/builtinCapabilities.js";
import { TOOLS, executeTool, findTool, unknownToolError } from "../application/tools/registry.js";
import { toolOutputSchema, type ToolContext, type ToolOutput } from "../application/tools/types.js";
import {
  invalidInput,
  issuesFromZod,
  makeError,
  type ErrorEnvelope,
} from "../domain/errors.js";
import type { JsonObject } from "../domain/json.js";

/** Protocol revisions this server implements, newest first. */
export const SUPPORTED_PROTOCOL_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"] as const;

const JSONRPC = {
  parseError: -32700,
  invalidRequest: -32600,
  methodNotFound: -32601,
  invalidParams: -32602,
  internalError: -32603,
} as const;

type Id = string | number | null;

/** Longest accepted JSON-RPC line. Tool arguments are paths and small step lists. */
export const MAX_MCP_LINE_BYTES = 4 * 1024 * 1024;

/**
 * The request's id when it is a valid JSON-RPC id, so even a rejected request
 * is answered under its own id; null when no valid id can be found.
 */
export const requestId = (message: unknown): Id => {
  if (typeof message !== "object" || message === null || Array.isArray(message) || !("id" in message))
    return null;
  const { id } = message;
  return typeof id === "string" || (typeof id === "number" && Number.isInteger(id)) ? id : null;
};

interface RpcResponse {
  readonly jsonrpc: "2.0";
  readonly id: Id;
  readonly result?: unknown;
  readonly error?: { readonly code: number; readonly message: string; readonly data?: unknown };
}

const requestSchema = z.object({
  jsonrpc: z.literal("2.0"),
  id: z.union([z.string(), z.number().int()]).optional(),
  method: z.string().min(1),
  params: z.unknown().optional(),
});

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const callParamsSchema = z.object({
  name: z.string().min(1),
  // Passed through untouched: rebuilding the object (as z.record does) would
  // silently drop keys such as __proto__ that the tool's own schema reports.
  arguments: z.custom<Record<string, unknown>>(isPlainObject, "Must be an object").optional(),
});

const initializeParamsSchema = z.object({ protocolVersion: z.string() });

/** Project a schema as draft-07 JSON Schema with an object root, as MCP requires. */
export const projectSchema = (schema: z.ZodType, io: "input" | "output"): JsonObject => {
  const { $schema: _dialect, ...rest } = z.toJSONSchema(schema, {
    target: "draft-7",
    io,
    unrepresentable: "throw",
  }) as Record<string, unknown>;
  return { type: "object", ...rest } as JsonObject;
};

const OUTPUT_SCHEMA = projectSchema(toolOutputSchema, "output");

/** The advertised catalog, derived entirely from the shared tool registry. */
export const listTools = () =>
  TOOLS.map((tool) => ({
    name: tool.name,
    title: tool.title,
    description: tool.description,
    inputSchema: projectSchema(tool.inputSchema, "input"),
    outputSchema: OUTPUT_SCHEMA,
    annotations: {
      title: tool.title,
      readOnlyHint: tool.readOnly,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
  }));

const failureData = (error: ErrorEnvelope) => ({ ok: false, error });

const rpcError = (id: Id, code: number, message: string, error: ErrorEnvelope): RpcResponse => ({
  jsonrpc: "2.0",
  id,
  error: { code, message, data: failureData(error) },
});

/** Tool outcomes, including tool failures, are results so the model can read them. */
export const toCallToolResult = (output: ToolOutput) => ({
  content: [{ type: "text", text: JSON.stringify(output) }],
  structuredContent: output,
  isError: !output.ok,
});

/**
 * Handle one JSON-RPC message. Returns null for notifications. Errors that
 * prevent a tool from being identified are protocol errors; their `data`
 * carries the same envelope the CLI prints.
 */
export const createMcpHandler =
  (context: ToolContext) =>
  async (message: unknown): Promise<RpcResponse | null> => {
    if (Array.isArray(message))
      return rpcError(
        null,
        JSONRPC.invalidRequest,
        "Batch requests are not supported",
        invalidInput("Send one JSON-RPC message per line", [{ path: "$", message: "Batches are not supported" }]),
      );
    const request = requestSchema.safeParse(message);
    if (!request.success)
      return rpcError(
        requestId(message),
        JSONRPC.invalidRequest,
        "Invalid request",
        invalidInput("The message is not a JSON-RPC 2.0 request", issuesFromZod(request.error)),
      );
    const { id, method, params } = request.data;
    if (id === undefined) return null; // Notifications need no response.

    switch (method) {
      case "initialize": {
        const parsed = initializeParamsSchema.safeParse(params);
        if (!parsed.success)
          return rpcError(
            id,
            JSONRPC.invalidParams,
            "Invalid params",
            invalidInput("initialize requires protocolVersion", issuesFromZod(parsed.error, "params")),
          );
        const requested = parsed.data.protocolVersion;
        const protocolVersion = (SUPPORTED_PROTOCOL_VERSIONS as readonly string[]).includes(requested)
          ? requested
          : SUPPORTED_PROTOCOL_VERSIONS[0];
        return {
          jsonrpc: "2.0",
          id,
          result: {
            protocolVersion,
            capabilities: { tools: { listChanged: false } },
            serverInfo: { name: "revscope", version: PRODUCT_VERSION },
            instructions:
              "Revscope tools return evidence records whose confidence and authority state how directly each claim was established. Evidence identifiers are unkeyed digests: they detect accidental changes but do not authenticate records loaded from files. Tool failures use one error envelope: {ok:false, error:{code, category, message, retryable, remediation, details}}. The stub_analysis tool uses fixture data only.",
          },
        };
      }
      case "ping":
        return { jsonrpc: "2.0", id, result: {} };
      case "tools/list":
        return { jsonrpc: "2.0", id, result: { tools: listTools() } };
      case "tools/call": {
        const parsed = callParamsSchema.safeParse(params);
        if (!parsed.success)
          return rpcError(
            id,
            JSONRPC.invalidParams,
            "Invalid params",
            invalidInput("tools/call requires a tool name and optional arguments object", issuesFromZod(parsed.error, "params")),
          );
        if (findTool(parsed.data.name) === undefined)
          return rpcError(id, JSONRPC.invalidParams, "Unknown tool", unknownToolError(parsed.data.name));
        const output = await executeTool(context, parsed.data.name, parsed.data.arguments ?? {});
        return { jsonrpc: "2.0", id, result: toCallToolResult(output) };
      }
      default:
        return rpcError(
          id,
          JSONRPC.methodNotFound,
          "Method not found",
          makeError("unsupported_operation", `Method ${method} is not supported`, {
            operation: method,
            available_operations: ["initialize", "ping", "tools/call", "tools/list"],
          }),
        );
    }
  };

type Line = { readonly text: string } | { readonly oversized: true };

/**
 * Split a byte stream into lines without ever holding more than `maxBytes` of
 * one line. An oversized line is discarded up to its newline and reported once.
 */
async function* readLines(input: NodeJS.ReadableStream, maxBytes: number): AsyncGenerator<Line> {
  let parts: Buffer[] = [];
  let size = 0;
  let discarding = false;
  for await (const chunk of input) {
    let buffer = typeof chunk === "string" ? Buffer.from(chunk, "utf8") : chunk;
    for (;;) {
      const newline = buffer.indexOf(0x0a);
      const piece = buffer.subarray(0, newline === -1 ? buffer.length : newline);
      if (!discarding && size + piece.length > maxBytes) {
        discarding = true;
        parts = [];
        size = 0;
      }
      if (!discarding) {
        parts.push(piece);
        size += piece.length;
      }
      if (newline === -1) break;
      yield discarding ? { oversized: true } : { text: Buffer.concat(parts).toString("utf8") };
      discarding = false;
      parts = [];
      size = 0;
      buffer = buffer.subarray(newline + 1);
    }
  }
  if (discarding) yield { oversized: true };
  else if (size > 0) yield { text: Buffer.concat(parts).toString("utf8") };
}

/** Serve newline-delimited JSON-RPC on the given streams until input ends. */
export const serveMcp = async (
  context: ToolContext,
  input: NodeJS.ReadableStream,
  write: (line: string) => void,
  options: { readonly maxLineBytes?: number } = {},
): Promise<void> => {
  const handle = createMcpHandler(context);
  const maxLineBytes = options.maxLineBytes ?? MAX_MCP_LINE_BYTES;
  const send = (response: RpcResponse) => {
    write(`${JSON.stringify(response)}\n`);
  };
  for await (const line of readLines(input, maxLineBytes)) {
    if ("oversized" in line) {
      send(
        rpcError(null, JSONRPC.invalidRequest, "Request too large", makeError("resource_limit", "The message is longer than the supported line length", { limit_bytes: maxLineBytes })),
      );
      continue;
    }
    const text = line.text.endsWith("\r") ? line.text.slice(0, -1) : line.text;
    if (text.trim().length === 0) continue;
    let message: unknown;
    try {
      message = JSON.parse(text) as unknown;
    } catch {
      send(rpcError(null, JSONRPC.parseError, "Parse error", invalidInput("The line is not valid JSON", [{ path: "$", message: "Invalid JSON" }])));
      continue;
    }
    let response: RpcResponse | null;
    try {
      response = await handle(message);
    } catch (cause: unknown) {
      const correlationId = context.newCorrelationId();
      context.logger.error({
        event: "mcp_internal_error",
        error_class: cause instanceof Error ? cause.name : typeof cause,
        correlation_id: correlationId,
      });
      response = rpcError(
        requestId(message),
        JSONRPC.internalError,
        "Internal error",
        makeError("internal_error", "The server failed unexpectedly", { correlation_id: correlationId }),
      );
    }
    if (response !== null) send(response);
  }
};
