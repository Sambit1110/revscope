import { describe, expect, it } from "vitest";

import { executeTool } from "../../src/application/tools/registry.js";
import type { ToolOutput } from "../../src/application/tools/types.js";
import { makeError } from "../../src/domain/errors.js";
import { parseEvidence } from "../../src/domain/evidence.js";
import { memoryRun, ScriptedEngine, err, ok } from "../support/engine.js";
import { testContext } from "../support/context.js";

const success = (output: ToolOutput) => {
  if (!output.ok) throw new Error(JSON.stringify(output.error));
  return output;
};
const failure = (output: ToolOutput) => {
  if (output.ok) throw new Error("expected failure");
  return output.error;
};

const input = (extra: Record<string, unknown> = {}) => ({ path: "/tmp/sample.bin", authorized: true, ...extra });

describe("analyze_binary without an engine", () => {
  it("reports provider_not_configured after validating the input", async () => {
    const { context } = testContext();
    const error = failure(await executeTool(context, "analyze_binary", input()));
    expect(error).toMatchObject({ code: "provider_not_configured", category: "unsupported", details: { check: "not_configured" } });
    // Invalid input is reported first, so callers can fix it before configuring an engine.
    expect(failure(await executeTool(context, "analyze_binary", { path: "relative" })).code).toBe("invalid_input");
  });
});

const engine = () => new ScriptedEngine(() => ok(memoryRun()));

describe("analyze_binary input", () => {
  it("requires an explicit authorization acknowledgement", async () => {
    for (const authorized of [undefined, false, "true", 1]) {
      const scripted = engine();
      const { context } = testContext({ binaryAnalysis: scripted });
      const raw = authorized === undefined ? { path: "/tmp/a" } : { path: "/tmp/a", authorized };
      const error = failure(await executeTool(context, "analyze_binary", raw));
      expect(error.code).toBe("invalid_input");
      expect(error.details["issues"]).toEqual([{ path: "authorized", message: expect.stringContaining("cannot verify") }]);
      expect(scripted.requests).toHaveLength(0);
    }
  });

  it("applies the documented defaults", async () => {
    const scripted = engine();
    const { context } = testContext({ binaryAnalysis: scripted });
    success(await executeTool(context, "analyze_binary", input()));
    expect(scripted.requests[0]?.limits).toEqual({ timeoutMs: 45_000, maxFunctions: 200, decompile: true, decompileTimeoutMs: 10_000 });
  });

  it.each([
    [{ timeout_ms: 9_999 }, "timeout_ms"],
    [{ timeout_ms: 300_001 }, "timeout_ms"],
    [{ timeout_ms: 10_000.5 }, "timeout_ms"],
    [{ max_functions: 0 }, "max_functions"],
    [{ max_functions: 1_001 }, "max_functions"],
    [{ decompile_timeout_ms: 999 }, "decompile_timeout_ms"],
    [{ decompile_timeout_ms: 60_001 }, "decompile_timeout_ms"],
    [{ timeout_ms: 10_000, decompile_timeout_ms: 20_000 }, "decompile_timeout_ms"],
    [{ decompile: "yes" }, "decompile"],
    [{ unexpected: 1 }, "$"],
  ])("rejects %j", async (extra, field) => {
    const scripted = engine();
    const { context } = testContext({ binaryAnalysis: scripted });
    const error = failure(await executeTool(context, "analyze_binary", input(extra)));
    expect(error.code).toBe("invalid_input");
    expect(JSON.stringify(error.details["issues"])).toContain(field === "$" ? "unexpected" : field);
    expect(scripted.requests).toHaveLength(0);
  });

  it("passes the caller's cancellation signal to the engine", async () => {
    const scripted = engine();
    const { context } = testContext({ binaryAnalysis: scripted });
    const controller = new AbortController();
    success(await executeTool(context, "analyze_binary", input(), { signal: controller.signal }));
    expect(scripted.requests[0]?.signal).toBe(controller.signal);
  });
});

const serializedRun = async () => {
  const { context } = testContext({ binaryAnalysis: engine() });
  return JSON.stringify(await executeTool(context, "analyze_binary", input()));
};

describe("analyze_binary results", () => {
  it("labels only Revscope's read of the bytes as observed; everything from the engine is derived engine output", async () => {
    const { context } = testContext({ binaryAnalysis: new ScriptedEngine(() => ok(memoryRun())) });
    const output = success(await executeTool(context, "analyze_binary", input()));
    const [identity, ...engineRecords] = output.records;
    expect(identity).toMatchObject({ operation: { name: "artifact_identity" }, confidence: "observed", authority: "original-artifact" });
    expect(engineRecords.map(({ operation }) => operation.name)).toEqual(["program_info", "list_functions", "decompile", "decompile"]);
    for (const record of engineRecords) {
      expect(record).toMatchObject({ result_kind: "engine-interpretation", confidence: "derived", authority: "analysis-engine" });
      expect(record.subject.kind).toBe("analysis-state");
      expect(parseEvidence(record).ok).toBe(true);
    }
    expect(output.records.filter(({ authority }) => authority === "original-artifact")).toHaveLength(1);
    expect(output.data).toMatchObject({
      authorization: "acknowledged-by-caller",
      analysis: { complete: true, export_complete: true, functions_exported: 2, decompiled: 1 },
      cleanup: { process: "not-needed", workspace: "removed" },
    });
  });

  it("skips decompilation reads when decompilation is off", async () => {
    const { context } = testContext({ binaryAnalysis: new ScriptedEngine(() => ok(memoryRun())) });
    const output = success(await executeTool(context, "analyze_binary", input({ decompile: false })));
    expect(output.records.map(({ operation }) => operation.name)).toEqual(["artifact_identity", "program_info", "list_functions"]);
  });

  it("reports a complete export with limited coverage as success that is not complete", async () => {
    const run = memoryRun({
      coverage: { exportComplete: true, interruption: null, stopped: "deadline", analysisTimedOut: true, functionsTotal: 9, functionsExported: 2 },
    });
    const { context } = testContext({ binaryAnalysis: new ScriptedEngine(() => ok(run)) });
    const output = success(await executeTool(context, "analyze_binary", input()));
    expect(output.data["analysis"]).toMatchObject({ complete: false, stopped: "deadline", analysis_timed_out: true, functions_total: 9 });
  });

  it("fails an incomplete export with analysis_incomplete and keeps the validated partial records", async () => {
    const run = memoryRun({
      coverage: { exportComplete: false, interruption: "timed-out", stopped: null, analysisTimedOut: null, functionsTotal: null, functionsExported: 2 },
      cleanup: { process: "terminated", workspace: "removed", reason: null },
    });
    const { context } = testContext({ binaryAnalysis: new ScriptedEngine(() => ok(run)) });
    const error = failure(await executeTool(context, "analyze_binary", input()));
    expect(error).toMatchObject({
      code: "analysis_incomplete",
      category: "partial_failure",
      details: { interruption: "timed-out", cleanup: { process: "terminated", workspace: "removed" } },
    });
    const partial = error.details["partial_records"] as unknown[];
    expect(partial).toHaveLength(5);
    for (const record of partial) expect(parseEvidence(record).ok).toBe(true);
  });

  it("passes engine errors through unchanged", async () => {
    const engineError = makeError("analysis_timeout", "The engine produced nothing before the deadline", {
      cleanup: { process: "terminated", workspace: "removed", reason: null },
    });
    const { context } = testContext({ binaryAnalysis: new ScriptedEngine(() => err(engineError)) });
    expect(failure(await executeTool(context, "analyze_binary", input()))).toEqual(engineError);
  });

  it("produces identical output for identical runs", async () => {
    expect(await serializedRun()).toBe(await serializedRun());
  });
});
