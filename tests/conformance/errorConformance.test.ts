import { PassThrough } from "node:stream";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { executeTool } from "../../src/application/tools/registry.js";
import type { ToolContext, ToolOutput } from "../../src/application/tools/types.js";
import { failureOutputSchema, type ErrorCode } from "../../src/domain/errors.js";
import { runCli } from "../../src/interfaces/cli.js";
import { serveMcp } from "../../src/interfaces/mcp.js";
import { EXIT_CODES } from "../../src/interfaces/output.js";
import { exploding, fixturePath, tempDir, testContext } from "../support/context.js";
import { fakeEngine, fakeGhidra, type FakeControl } from "../support/fakeGhidra.js";
import { exportText } from "../support/ghidraExport.js";
import { makeElf } from "../fixtures/binaries/make-elf.mjs";
import { GhidraEngine } from "../../src/infrastructure/ghidra/engine.js";

/** One failure scenario expressed for every interface. */
interface Case {
  readonly label: string;
  readonly code: ErrorCode;
  readonly tool: string;
  readonly input: Record<string, unknown>;
  readonly argv: readonly string[];
  readonly context?: () => ToolContext;
}

const viaApplication = (context: ToolContext, tool: string, input: unknown) =>
  executeTool(context, tool, input);

const viaCli = async (context: ToolContext, argv: readonly string[]) => {
  let stdout = "";
  const exitCode = await runCli(argv, { stdout: (text) => (stdout += text), cwd: "/" }, context);
  return { output: JSON.parse(stdout) as ToolOutput, exitCode };
};

/** Drive the stdio MCP server in-process and return the envelope it carries. */
const viaMcp = async (context: ToolContext, tool: string, input: unknown) => {
  const stdin = new PassThrough();
  const lines: string[] = [];
  const served = serveMcp(context, stdin, (line) => lines.push(line));
  stdin.end(
    `${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: tool, arguments: input } })}\n`,
  );
  await served;
  const response = JSON.parse(lines[0] ?? "null") as {
    result?: { isError: boolean; structuredContent: unknown; content: { text: string }[] };
    error?: { code: number; data: unknown };
  };
  if (response.result !== undefined) {
    // The text block carries exactly the structured envelope.
    expect(JSON.parse(response.result.content[0]?.text ?? "null")).toEqual(response.result.structuredContent);
    expect(response.result.isError).toBe(true);
    return response.result.structuredContent;
  }
  return response.error?.data;
};

const nested = (depth: number): unknown => {
  let value: unknown = 1;
  for (let level = 0; level < depth; level += 1) value = [value];
  return value;
};

/** A tool context whose engine is a fake Ghidra installation behaving as `control` says. */
const fakeGhidraContext = async (control: FakeControl, maxChildRunMs?: number) => {
  const fake = await fakeGhidra(control);
  const engine = await fakeEngine(fake, maxChildRunMs === undefined ? {} : { maxChildRunMs });
  return testContext({ binaryAnalysis: engine }).context;
};

/** The structured result of a successful MCP tool call, checked against its text block. */
const viaMcpSuccess = async (context: ToolContext, tool: string, input: unknown) => {
  const stdin = new PassThrough();
  const lines: string[] = [];
  const served = serveMcp(context, stdin, (line) => lines.push(line));
  stdin.end(`${JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: tool, arguments: input } })}\n`);
  await served;
  const response = JSON.parse(lines[0] ?? "null") as { result: { isError: boolean; structuredContent: unknown; content: { text: string }[] } };
  expect(response.result.isError).toBe(false);
  expect(JSON.parse(response.result.content[0]?.text ?? "null")).toEqual(response.result.structuredContent);
  return response.result.structuredContent;
};

const cases = async (): Promise<Case[]> => {
  const directory = await tempDir();
  const tampered = join(directory, "tampered.json");
  const healthy = join(directory, "healthy.json");
  const inspected = await executeTool(testContext().context, "inspect_artifact", {
    path: fixturePath("artifacts", "notes.txt"),
  });
  if (!inspected.ok) throw new Error("fixture inspection failed");
  await writeFile(healthy, JSON.stringify(inspected));
  await writeFile(
    tampered,
    JSON.stringify({ records: [{ ...inspected.records[0], payload: { size_bytes: 0 } }] }),
  );
  const notJson = join(directory, "broken.json");
  await writeFile(notJson, "{not json");
  const absent = join(directory, "absent.bin");
  const unsupportedSteps = [{ action: "read", operation: "trace_calls" }];
  const deepFile = join(directory, "deep.json");
  await writeFile(deepFile, JSON.stringify({ records: nested(100) }));
  const lossyFile = join(directory, "lossy.json");
  await writeFile(lossyFile, '{"records": [], "meta": {"__proto__": {"polluted": true}}}');
  const deepSteps = [{ action: "read", operation: "get_name", params: { deep: nested(100) } }];
  const lossySteps = JSON.parse('[{"action": "read", "operation": "list_names", "params": {"__proto__": {"x": 1}}}]') as unknown[];
  const partialSteps = [
    { action: "mutate", operation: "rename", params: { names: { "0x1000": "entry", "0x2000": "util" } } },
  ];
  const binary = join(directory, "fixture.elf");
  await writeFile(binary, makeElf());
  const analysisContexts = {
    unsupported: await fakeGhidraContext({ mode: "say", stdout: "ERROR REPORT: No load spec found for import file\n" }),
    timeout: await fakeGhidraContext({ mode: "hang" }, 300),
    // Long enough for the fake to start and write its partial export even in a loaded run.
    incomplete: await fakeGhidraContext({ mode: "partial-hang", export: exportText({ trailer: null }) }, 2_000),
    success: await fakeGhidraContext({ mode: "success", export: exportText() }),
    misconfigured: testContext({ binaryAnalysis: new GhidraEngine({ settings: { ghidraDir: "relative/ghidra" } }) }).context,
  };
  const analysis = (extra: Record<string, unknown> = {}) => ({ path: binary, authorized: true, ...extra });
  const analysisArgv = (...extra: string[]) => ["analyze-binary", binary, "--authorized", ...extra];
  return [
    {
      label: "analysis without the authorization acknowledgement",
      code: "invalid_input",
      tool: "analyze_binary",
      input: { path: binary },
      argv: ["analyze-binary", binary],
      context: () => analysisContexts.success,
    },
    {
      label: "analysis limit out of range",
      code: "invalid_input",
      tool: "analyze_binary",
      input: analysis({ timeout_ms: 5 }),
      argv: analysisArgv("--timeout-ms", "5"),
      context: () => analysisContexts.success,
    },
    {
      label: "analysis limit that is not a number",
      code: "invalid_input",
      tool: "analyze_binary",
      input: analysis({ max_functions: "many" }),
      argv: analysisArgv("--max-functions", "many"),
      context: () => analysisContexts.success,
    },
    {
      label: "analysis engine not configured",
      code: "provider_not_configured",
      tool: "analyze_binary",
      input: analysis(),
      argv: analysisArgv(),
    },
    {
      label: "invalid Ghidra configuration",
      code: "provider_not_configured",
      tool: "analyze_binary",
      input: analysis(),
      argv: analysisArgv(),
      context: () => analysisContexts.misconfigured,
    },
    {
      label: "analysis of a missing binary",
      code: "target_not_found",
      tool: "analyze_binary",
      input: analysis({ path: absent }),
      argv: ["analyze-binary", absent, "--authorized"],
      context: () => analysisContexts.success,
    },
    {
      label: "binary format the engine does not recognise",
      code: "unsupported_target",
      tool: "analyze_binary",
      input: analysis(),
      argv: analysisArgv(),
      context: () => analysisContexts.unsupported,
    },
    {
      label: "analysis timeout",
      code: "analysis_timeout",
      tool: "analyze_binary",
      input: analysis(),
      argv: analysisArgv(),
      context: () => analysisContexts.timeout,
    },
    {
      label: "incomplete analysis with partial results",
      code: "analysis_incomplete",
      tool: "analyze_binary",
      input: analysis(),
      argv: analysisArgv(),
      context: () => analysisContexts.incomplete,
    },
    {
      label: "missing required input",
      code: "invalid_input",
      tool: "inspect_artifact",
      input: {},
      argv: ["inspect-artifact"],
    },
    {
      label: "malformed JSON input file",
      code: "invalid_input",
      tool: "report_evidence",
      input: { path: notJson },
      argv: ["report-evidence", notJson],
    },
    {
      label: "missing target",
      code: "target_not_found",
      tool: "inspect_artifact",
      input: { path: absent },
      argv: ["inspect-artifact", absent],
    },
    {
      label: "unsupported target (directory)",
      code: "unsupported_target",
      tool: "inspect_artifact",
      input: { path: directory },
      argv: ["inspect-artifact", directory],
    },
    {
      label: "unsupported provider operation",
      code: "unsupported_operation",
      tool: "stub_analysis",
      input: { fixture_path: fixturePath("stub", "database.json"), steps: unsupportedSteps },
      argv: ["stub-analysis", fixturePath("stub", "database.json"), "--steps", JSON.stringify(unsupportedSteps)],
    },
    {
      label: "partial mutation failure",
      code: "partial_failure",
      tool: "stub_analysis",
      input: { fixture_path: fixturePath("stub", "database-partial-failure.json"), steps: partialSteps },
      argv: [
        "stub-analysis",
        fixturePath("stub", "database-partial-failure.json"),
        "--steps",
        JSON.stringify(partialSteps),
      ],
    },
    {
      label: "evidence integrity failure",
      code: "evidence_integrity",
      tool: "compare_evidence",
      input: { left_path: healthy, right_path: tampered },
      argv: ["compare-evidence", healthy, tampered],
    },
    {
      label: "internal failure",
      code: "internal_error",
      tool: "inspect_artifact",
      input: { path: fixturePath("artifacts", "notes.txt") },
      argv: ["inspect-artifact", fixturePath("artifacts", "notes.txt")],
      context: () => exploding().context,
    },
    {
      label: "empty path",
      code: "invalid_input",
      tool: "inspect_artifact",
      input: { path: "" },
      argv: ["inspect-artifact", ""],
    },
    {
      label: "path containing NUL",
      code: "invalid_input",
      tool: "inspect_artifact",
      input: { path: "/tmp/revscope\0probe" },
      argv: ["inspect-artifact", "/tmp/revscope\0probe"],
    },
    {
      label: "JSON file nested beyond the limit",
      code: "resource_limit",
      tool: "report_evidence",
      input: { path: deepFile },
      argv: ["report-evidence", deepFile],
    },
    {
      label: "JSON file with a lossy __proto__ key",
      code: "invalid_input",
      tool: "report_evidence",
      input: { path: lossyFile },
      argv: ["report-evidence", lossyFile],
    },
    {
      label: "inline steps nested beyond the limit",
      code: "invalid_input",
      tool: "stub_analysis",
      input: { fixture_path: fixturePath("stub", "database.json"), steps: deepSteps },
      argv: ["stub-analysis", fixturePath("stub", "database.json"), "--steps", JSON.stringify(deepSteps)],
    },
    {
      label: "inline steps with a lossy __proto__ key",
      code: "invalid_input",
      tool: "stub_analysis",
      input: { fixture_path: fixturePath("stub", "database.json"), steps: lossySteps },
      argv: ["stub-analysis", fixturePath("stub", "database.json"), "--steps", JSON.stringify(lossySteps)],
    },
    {
      label: "unknown tool",
      code: "unknown_tool",
      tool: "no_such_tool",
      input: {},
      argv: ["no_such_tool"],
    },
  ];
};

describe("one error contract across interfaces", () => {
  it("produces the same envelope from the application, CLI, and MCP for every failure class", async () => {
    const scenarios = await cases();
    for (const scenario of scenarios) {
      const context = scenario.context?.() ?? testContext().context;
      const application = await viaApplication(context, scenario.tool, scenario.input);
      const cli = await viaCli(context, scenario.argv);
      const mcp = await viaMcp(context, scenario.tool, scenario.input);

      for (const [surface, value] of [
        ["application", application],
        ["cli", cli.output],
        ["mcp", mcp],
      ] as const) {
        const parsed = failureOutputSchema.safeParse(value);
        expect(parsed.success, `${scenario.label} via ${surface}`).toBe(true);
        expect(parsed.data?.error.code, `${scenario.label} via ${surface}`).toBe(scenario.code);
      }
      // Identical envelopes, not just identical codes.
      expect(cli.output, scenario.label).toEqual(application);
      expect(mcp, scenario.label).toEqual(application);
      if (!application.ok) expect(cli.exitCode, scenario.label).toBe(EXIT_CODES[application.error.category]);
    }
  });

  it("produces the same successful analysis from the application, CLI, and MCP", async () => {
    // The export must declare the limits that were requested; a mismatch is refused as malformed.
    const context = await fakeGhidraContext({ mode: "success", export: exportText({ maxFunctions: 50 }) });
    const binary = join(await tempDir(), "fixture.elf");
    await writeFile(binary, makeElf());
    const input = { path: binary, authorized: true, max_functions: 50 };
    const application = await viaApplication(context, "analyze_binary", input);
    const cli = await viaCli(context, ["analyze-binary", binary, "--authorized", "--max-functions", "50"]);
    const mcp = await viaMcpSuccess(context, "analyze_binary", input);
    expect(application.ok).toBe(true);
    expect(cli.exitCode).toBe(0);
    expect(cli.output).toEqual(application);
    expect(mcp).toEqual(application);
  });

  it("never exposes stack traces, internal messages, or host paths from unexpected failures", async () => {
    const context = exploding().context;
    const outputs = [
      await viaApplication(context, "inspect_artifact", { path: fixturePath("artifacts", "notes.txt") }),
      (await viaCli(context, ["inspect-artifact", fixturePath("artifacts", "notes.txt")])).output,
      await viaMcp(context, "inspect_artifact", { path: fixturePath("artifacts", "notes.txt") }),
    ];
    for (const output of outputs) {
      const text = JSON.stringify(output);
      expect(text).not.toContain("EXPLODE_SECRET");
      expect(text).not.toContain("/Users/secret");
      expect(text).not.toContain("Error:");
      expect(text).not.toMatch(/\bat .+:\d+:\d+/u);
    }
  });

  it("reports CLI-only usage problems with the same envelope schema", async () => {
    const { context } = testContext();
    for (const argv of [
      ["inspect-artifact", "a", "b"],
      ["inspect-artifact", "--deep", "a"],
      ["stub-analysis", "f.json", "--steps", "{"],
      ["stub-analysis", "f.json", "--steps", "[]", "--steps-file", "s.json"],
      ["stub-analysis", "f.json", "--steps-file", ""],
      ["analyze-binary", "/tmp/x", "--authorized=yes"],
      ["analyze-binary", "/tmp/x", "--timeout-ms"],
    ]) {
      const { output, exitCode } = await viaCli(context, argv);
      const parsed = failureOutputSchema.safeParse(output);
      expect(parsed.success, argv.join(" ")).toBe(true);
      expect(parsed.data?.error.code).toBe("invalid_input");
      expect(exitCode).toBe(EXIT_CODES.invalid_input);
    }
  });
});
