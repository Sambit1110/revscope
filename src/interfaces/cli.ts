import { resolve } from "node:path";
import { parseArgs, type ParseArgsConfig } from "node:util";

import { TOOLS, executeTool, unknownToolError } from "../application/tools/registry.js";
import { PRODUCT_VERSION } from "../application/tools/builtinCapabilities.js";
import type { ToolContext, ToolOutput } from "../application/tools/types.js";
import { invalidInput, type InputIssue } from "../domain/errors.js";
import { exitCodeFor, renderJson } from "./output.js";

export interface CliIo {
  readonly stdout: (text: string) => void;
  readonly cwd: string;
}

interface CommandSpec {
  readonly tool: string;
  /** Positional arguments in order, each mapped to a tool input field. */
  readonly positionals: readonly string[];
  readonly usage: string;
  readonly options?: ParseArgsConfig["options"];
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
};

/** Input fields that hold local paths; relative values are resolved against the working directory. */
const PATH_FIELDS = new Set(["path", "left_path", "right_path", "fixture_path"]);

export const usage = (): string =>
  [
    `Revscope ${PRODUCT_VERSION} (pre-release foundation; no real binary analysis provider yet)`,
    "",
    "Usage:",
    ...Object.values(COMMANDS).map(({ usage: line }) => `  ${line}`),
    "  revscope tools          List tools as JSON",
    "  revscope mcp            Serve the same tools over MCP (stdio)",
    "  revscope version",
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
    if (value !== undefined) input[field] = PATH_FIELDS.has(field) ? resolve(io.cwd, value) : value;
  });

  if (spec.tool === "stub_analysis") {
    const values = parsed.values as Record<string, string | boolean | undefined>;
    const inline = values["steps"];
    const file = values["steps-file"];
    if (typeof inline === "string" && typeof file === "string")
      return { output: usageError([{ path: "steps", message: "Use either --steps or --steps-file, not both" }]) };
    if (typeof inline === "string") {
      try {
        input["steps"] = JSON.parse(inline) as unknown;
      } catch {
        return { output: usageError([{ path: "steps", message: "Not valid JSON" }]) };
      }
    } else if (typeof file === "string") {
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
          return "output" in built ? built.output : executeTool(context, spec.tool, built.input);
        })();
  io.stdout(renderJson(output));
  return exitCodeFor(output);
};
