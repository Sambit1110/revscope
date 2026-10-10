import { resolve } from "node:path";
import { parseArgs, type ParseArgsConfig } from "node:util";

import { TOOLS, executeTool, unknownToolError } from "../application/tools/registry.js";
import { PRODUCT_VERSION } from "../application/tools/builtinCapabilities.js";
import {
  uncancellableCall,
  type ToolCall,
  type ToolContext,
  type ToolOutput,
} from "../application/tools/types.js";
import { invalidInput, type InputIssue } from "../domain/errors.js";
import { exitCodeFor, renderJson } from "./output.js";

export interface CliIo {
  readonly stdout: (text: string) => void;
  readonly cwd: string;
}

/** How a command-line option sets a tool input field. */
type FlagMapping =
  | { readonly field: string; readonly kind: "set-true" | "set-false" }
  | { readonly field: string; readonly kind: "integer" };

interface CommandSpec {
  readonly tool: string;
  /** Positional arguments in order, each mapped to a tool input field. */
  readonly positionals: readonly string[];
  readonly usage: string;
  readonly options?: ParseArgsConfig["options"];
  /** Options mapped directly onto tool input fields; the tool validates the values. */
  readonly flags?: Readonly<Record<string, FlagMapping>>;
}

/** CLI commands are thin aliases for tools; validation happens in the tool layer. */
export const COMMANDS: Readonly<Record<string, CommandSpec>> = {
  "inspect-artifact": {
    tool: "inspect_artifact",
    positionals: ["path"],
    usage: "revscope inspect-artifact <file>",
  },
  "report-evidence": {
    tool: "report_evidence",
    positionals: ["path"],
    usage: "revscope report-evidence <bundle.json>",
  },
  "compare-evidence": {
    tool: "compare_evidence",
    positionals: ["left_path", "right_path"],
    usage: "revscope compare-evidence <left.json> <right.json>",
  },
  "stub-analysis": {
    tool: "stub_analysis",
    positionals: ["fixture_path"],
    usage:
      "revscope stub-analysis <fixture.json> (--steps <json> | --steps-file <steps.json>) [--continue-on-error]",
    options: {
      steps: { type: "string" },
      "steps-file": { type: "string" },
      "continue-on-error": { type: "boolean" },
    },
  },
  "analyze-binary": {
    tool: "analyze_binary",
    positionals: ["path"],
    usage:
      "revscope analyze-binary <binary> --authorized [--timeout-ms <ms>] [--max-functions <n>] [--decompile-timeout-ms <ms>] [--no-decompile]",
    options: {
      authorized: { type: "boolean" },
      "timeout-ms": { type: "string" },
      "max-functions": { type: "string" },
      "decompile-timeout-ms": { type: "string" },
      "no-decompile": { type: "boolean" },
    },
    flags: {
      authorized: { field: "authorized", kind: "set-true" },
      "timeout-ms": { field: "timeout_ms", kind: "integer" },
      "max-functions": { field: "max_functions", kind: "integer" },
      "decompile-timeout-ms": { field: "decompile_timeout_ms", kind: "integer" },
      "no-decompile": { field: "decompile", kind: "set-false" },
    },
  },
};

/**
 * A decimal integer becomes a number; anything else is passed through as
 * text, so the tool's schema reports it exactly as it would over MCP.
 */
const integerOption = (text: string): number | string => (/^-?\d{1,15}$/u.test(text) ? Number(text) : text);

/** Input fields that hold local paths; relative values are resolved against the working directory. */
const PATH_FIELDS = new Set(["path", "left_path", "right_path", "fixture_path"]);

/**
 * Resolve a relative path against the working directory. An empty value is
 * passed through unchanged: resolving it would silently name the working
 * directory, where MCP would report the same input as invalid.
 */
const resolvePath = (cwd: string, value: string): string => (value === "" ? value : resolve(cwd, value));

export const usage = (): string =>
  [
    `Revscope ${PRODUCT_VERSION}: evidence-labelled binary analysis (CLI and MCP; Ghidra headless as the engine)`,
    "",
    "Usage:",
    ...Object.values(COMMANDS).map(({ usage: line }) => `  ${line}`),
    "  revscope tools          List tools as JSON",
    "  revscope mcp            Serve the same tools over MCP (stdio)",
    "  revscope version",
    "",
    "analyze-binary needs a Ghidra installation (REVSCOPE_GHIDRA_DIR; optionally REVSCOPE_JAVA_HOME) and --authorized, which records",
    "that you are authorized to analyze the file; Revscope cannot verify it. The binary is never executed.",
    "",
    "Tool commands print one JSON document on stdout: {\"ok\": true, ...} or {\"ok\": false, \"error\": {...}}.",
    "",
  ].join("\n");

const usageError = (issues: readonly InputIssue[]): ToolOutput => ({
  ok: false,
  error: invalidInput("The command line is invalid", issues),
});

const parseArgsIssue = (cause: unknown): InputIssue => {
  const code =
    typeof cause === "object" && cause !== null && "code" in cause ? String(cause.code) : "";
  const message =
    code === "ERR_PARSE_ARGS_UNKNOWN_OPTION"
      ? "Unknown option"
      : code === "ERR_PARSE_ARGS_INVALID_OPTION_VALUE"
        ? "Option value is missing or invalid"
        : "Arguments could not be parsed";
  return { path: "$argv", message };
};

const buildInput = async (
  spec: CommandSpec,
  args: readonly string[],
  io: CliIo,
  context: ToolContext,
): Promise<{ input: Record<string, unknown> } | { output: ToolOutput }> => {
  let parsed;
  try {
    parsed = parseArgs({
      args: [...args],
      allowPositionals: true,
      strict: true,
      options: spec.options ?? {},
    });
  } catch (cause: unknown) {
    return { output: usageError([parseArgsIssue(cause)]) };
  }
  const extra = parsed.positionals.slice(spec.positionals.length);
  if (extra.length > 0)
    return {
      output: usageError(
        extra.map((_, index) => ({
          path: `$argv.${String(spec.positionals.length + index)}`,
          message: "Unexpected argument",
        })),
      ),
    };
  const input: Record<string, unknown> = {};
  spec.positionals.forEach((field, index) => {
    const value = parsed.positionals[index];
    if (value !== undefined) input[field] = PATH_FIELDS.has(field) ? resolvePath(io.cwd, value) : value;
  });

  const values = parsed.values as Record<string, string | boolean | undefined>;
  for (const [option, mapping] of Object.entries(spec.flags ?? {})) {
    const given = values[option];
    if (given === undefined) continue;
    if (mapping.kind === "set-true") input[mapping.field] = true;
    else if (mapping.kind === "set-false") input[mapping.field] = false;
    else if (typeof given === "string") input[mapping.field] = integerOption(given);
  }

  if (spec.tool === "stub_analysis") {
    const inline = values["steps"];
    const file = values["steps-file"];
    if (typeof inline === "string" && typeof file === "string")
      return { output: usageError([{ path: "steps", message: "Use either --steps or --steps-file, not both" }]) };
    if (typeof inline === "string") {
      // Depth and lossy keys are checked by the tool's schema, as for MCP arguments.
      try {
        input["steps"] = JSON.parse(inline) as unknown;
      } catch {
        return { output: usageError([{ path: "steps", message: "Not valid JSON" }]) };
      }
    } else if (typeof file === "string") {
      if (file === "") return { output: usageError([{ path: "steps-file", message: "Must not be empty" }]) };
      const steps = await context.jsonReader.read(resolve(io.cwd, file));
      if (!steps.ok) return { output: { ok: false, error: steps.error } };
      input["steps"] = steps.value;
    }
    if (values["continue-on-error"] === true) input["continue_on_error"] = true;
  }
  return { input };
};

/** Run one CLI invocation and return its exit status. */
export const runCli = async (
  argv: readonly string[],
  io: CliIo,
  context: ToolContext,
  call: ToolCall = uncancellableCall(),
): Promise<number> => {
  const [command, ...args] = argv;
  if (command === undefined || command === "help" || command === "--help" || command === "-h") {
    io.stdout(usage());
    return 0;
  }
  if (command === "version" || command === "--version") {
    io.stdout(`${PRODUCT_VERSION}\n`);
    return 0;
  }
  if (command === "tools") {
    const commandFor = (tool: string) =>
      Object.entries(COMMANDS).find(([, spec]) => spec.tool === tool)?.[0] ?? null;
    io.stdout(
      renderJson({
        tools: TOOLS.map((tool) => ({
          name: tool.name,
          cli_command: commandFor(tool.name),
          title: tool.title,
          description: tool.description,
        })),
      }),
    );
    return 0;
  }
  const spec = COMMANDS[command];
  const output: ToolOutput =
    spec === undefined
      ? { ok: false, error: unknownToolError(command) }
      : await (async () => {
          const built = await buildInput(spec, args, io, context);
          return "output" in built ? built.output : executeTool(context, spec.tool, built.input, call);
        })();
  io.stdout(renderJson(output));
  return exitCodeFor(output);
};
