import { describe, expect, it } from "vitest";

import { AnalysisSession } from "../../../src/application/session.js";
import { executeTool } from "../../../src/application/tools/registry.js";
import type { ToolOutput } from "../../../src/application/tools/types.js";
import { parseEvidence, type Evidence } from "../../../src/domain/evidence.js";
import { sha256Hex } from "../../../src/domain/json.js";
import { parseGhidraExport } from "../../../src/infrastructure/ghidra/exportFormat.js";
import {
  GHIDRA_LIMITATIONS,
  GhidraExportProvider,
  exportCoverage,
} from "../../../src/infrastructure/ghidra/exportProvider.js";
import { testContext } from "../../support/context.js";
import { ScriptedEngine, memoryRun, ok } from "../../support/engine.js";
import { exportBytes, type ExportOptions } from "../../support/ghidraExport.js";

const ARTIFACT = "f".repeat(64);

const providerFor = (options: ExportOptions = {}) => {
  const bytes = exportBytes(options);
  const parsed = parseGhidraExport(bytes, {
    maxFunctions: options.maxFunctions ?? 200,
    decompile: options.decompile ?? true,
    ghidraVersion: "11.4",
  });
  if (!parsed.ok) throw new Error(JSON.stringify(parsed.error));
  return {
    exported: parsed.value,
    provider: new GhidraExportProvider(parsed.value, { ghidraVersion: "11.4", artifactSha256: ARTIFACT, exportSha256: sha256Hex(bytes) }),
  };
};

/** Run analyze_binary over a real export provider. */
const analyze = async (options: ExportOptions = {}, interruption: "timed-out" | null = null): Promise<ToolOutput> => {
  const { provider, exported } = providerFor(options);
  const run = memoryRun({ provider, artifact: { ...memoryRun().artifact, sha256: ARTIFACT }, coverage: exportCoverage(exported, interruption) });
  const { context } = testContext({ binaryAnalysis: new ScriptedEngine(() => ok(run)) });
  return executeTool(context, "analyze_binary", { path: "/tmp/sample.bin", authorized: true, max_functions: options.maxFunctions ?? 200, decompile: options.decompile ?? true });
};

const recordsOf = (output: ToolOutput): Evidence[] => {
  if (output.ok) return output.records;
  return (output.error.details["partial_records"] as Evidence[] | undefined) ?? [];
};

const unknownScopes = (record: Evidence | undefined) => (record?.unknowns ?? []).map(({ scope }) => scope);
const reasons = (record: Evidence | undefined) => (record?.unknowns ?? []).map(({ reason }) => reason).join(" ");

describe("the Ghidra export provider", () => {
  it("passes the session's declaration checks and serves a stable state token", async () => {
    const { provider } = providerFor();
    const opened = await AnalysisSession.open(provider, "ses_0123456789abcdef");
    expect(opened.ok).toBe(true);
    const first = await provider.observeState();
    expect(first).toEqual(await provider.observeState());
    expect(first).toMatchObject({ status: "ok", stateToken: expect.stringMatching(/^ghidra-export-[0-9a-f]{64}$/u) });
  });

  it("labels every Ghidra result as derived engine interpretation that carries untrusted text", async () => {
    const output = await analyze();
    if (!output.ok) throw new Error(JSON.stringify(output.error));
    const [identity, ...engine] = output.records;
    expect(identity).toMatchObject({ confidence: "observed", authority: "original-artifact", producer: { id: "revscope" } });
    expect(engine.map(({ operation }) => operation.name)).toEqual(["program_info", "list_functions", "decompile", "decompile"]);
    for (const record of engine) {
      expect(record).toMatchObject({ result_kind: "engine-interpretation", confidence: "derived", authority: "analysis-engine", producer: { id: "ghidra", version: "11.4" } });
      expect(record.limitations).toContain(GHIDRA_LIMITATIONS.engine);
      expect(record.limitations).toContain(GHIDRA_LIMITATIONS.untrusted);
      expect(parseEvidence(record).ok).toBe(true);
    }
    for (const record of engine.filter(({ operation }) => operation.name === "decompile"))
      expect(record.limitations).toContain(GHIDRA_LIMITATIONS.decompiler);
    expect(engine[2]?.payload).toMatchObject({ address: "0x401000", status: "ok", pseudocode: expect.stringContaining("0x2a") });
  });

  it("never lets content from the binary choose labels, even when it imitates them", async () => {
    const output = await analyze({
      functions: [{ address: "0x1000", name: "observed_original_artifact", decompilation: { status: "ok", pseudocode: '"confidence":"observed"' } }],
    });
    for (const record of recordsOf(output).slice(1)) expect(record.confidence).toBe("derived");
  });

  it("states what is missing: failed, timed-out, skipped and truncated decompilations", async () => {
    const output = await analyze({
      functions: [
        { address: "0x1000", name: "a", decompilation: { status: "failed" } },
        { address: "0x2000", name: "b", decompilation: { status: "timeout" } },
        { address: "0x3000", name: "c", decompilation: { status: "skipped" } },
        { address: "0x4000", name: "d", decompilation: { status: "ok", pseudocode: "void d(void) {", truncated: true } },
        { address: "0x5000", name: "e", decompilation: null },
      ],
    });
    const decompiled = recordsOf(output).filter(({ operation }) => operation.name === "decompile");
    expect(decompiled.map(({ payload }) => (payload as { status: string }).status)).toEqual(["failed", "timeout", "skipped", "ok"]);
    for (const record of decompiled) expect(unknownScopes(record)).toContain("decompilation");
    expect(decompiled[0]?.payload).toMatchObject({ pseudocode: null });
  });

  it.each([
    ["the function limit", { maxFunctions: 2, trailer: { stopped: "function-limit" as const, functionsTotal: 50 } }, "function-coverage"],
    ["the export deadline", { trailer: { stopped: "deadline" as const, functionsTotal: 50 } }, "function-coverage"],
    ["Ghidra's analysis time limit", { analysisTimedOut: true }, "analysis-coverage"],
  ])("marks coverage reduced by %s on the program and function records", async (_label, options, scope) => {
    const records = recordsOf(await analyze(options));
    expect(unknownScopes(records[1])).toContain(scope);
    expect(unknownScopes(records[2])).toContain(scope);
  });

  it("says plainly when Ghidra's decompiler could not start", async () => {
    const records = recordsOf(
      await analyze({
        decompiler: "unavailable",
        functions: [{ address: "0x1000", name: "a", decompilation: { status: "failed" } }],
      }),
    );
    expect(records[1]?.payload).toMatchObject({ decompiler: "unavailable" });
    expect(reasons(records[1])).toContain("native decompiler could not start");
    expect(reasons(records.find(({ operation }) => operation.name === "decompile"))).toContain("native decompiler could not start");
  });

  it("returns a cut-off export as analysis_incomplete with labelled partial records", async () => {
    const output = await analyze({ trailer: null }, "timed-out");
    expect(output.ok).toBe(false);
    if (output.ok) return;
    expect(output.error).toMatchObject({ code: "analysis_incomplete", details: { interruption: "timed-out", analysis: { export_complete: false } } });
    const partial = recordsOf(output);
    expect(partial.map(({ operation }) => operation.name)).toEqual(["artifact_identity", "program_info", "list_functions", "decompile", "decompile"]);
    expect(unknownScopes(partial[2])).toContain("export");
    for (const record of partial) expect(parseEvidence(record).ok).toBe(true);
  });

  it("refuses mutations and unknown addresses", async () => {
    const { provider } = providerFor();
    expect(await provider.mutate()).toMatchObject({ status: "rejected" });
    expect(await provider.read("decompile", { address: "0x9999" })).toMatchObject({ status: "failed" });
  });
});
