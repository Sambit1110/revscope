import { mkdir, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import {
  ARTIFACT_FORMAT,
  ARTIFACT_IDENTITY,
  BUILTIN_CAPABILITIES,
  EVIDENCE_COMPARISON,
  PRODUCT_VERSION,
} from "../../src/application/tools/builtinCapabilities.js";
import { TOOLS, executeTool } from "../../src/application/tools/registry.js";
import { toolOutputSchema, type ToolOutput } from "../../src/application/tools/types.js";
import { capabilityIssues } from "../../src/domain/capability.js";
import { parseEvidence } from "../../src/domain/evidence.js";
import { exploding, fixturePath, REPO_ROOT, tempDir, testContext } from "../support/context.js";

const success = (output: ToolOutput) => {
  if (!output.ok) throw new Error(JSON.stringify(output.error));
  return output;
};
const failure = (output: ToolOutput) => {
  if (output.ok) throw new Error("expected failure");
  return output.error;
};

describe("tool registry", () => {
  it("declares coherent semantics for every built-in capability", () => {
    for (const capability of BUILTIN_CAPABILITIES)
      expect(capabilityIssues(capability), capability.operation).toEqual([]);
    // Each built-in capability describes the subject its tool records.
    expect(capabilityIssues(ARTIFACT_IDENTITY, { subjectKind: "artifact" })).toEqual([]);
    expect(capabilityIssues(ARTIFACT_FORMAT, { subjectKind: "artifact" })).toEqual([]);
    expect(capabilityIssues(EVIDENCE_COMPARISON, { subjectKind: "evidence-set" })).toEqual([]);
  });

  it("keeps the product version in step with package.json", async () => {
    const { readFile } = await import("node:fs/promises");
    const manifest = JSON.parse(await readFile(join(REPO_ROOT, "package.json"), "utf8")) as { version: string };
    expect(PRODUCT_VERSION).toBe(manifest.version);
  });

  it("has unique snake_case tool names", () => {
    const names = TOOLS.map(({ name }) => name);
    expect(new Set(names).size).toBe(names.length);
    for (const name of names) expect(name).toMatch(/^[a-z][a-z0-9_]*$/u);
  });
});

describe("inspect_artifact", () => {
  it("returns separately labelled identity and format evidence", async () => {
    const { context } = testContext();
    const output = success(
      await executeTool(context, "inspect_artifact", { path: fixturePath("artifacts", "notes.txt") }),
    );
    expect(toolOutputSchema.safeParse(output).success).toBe(true);
    const [identity, format] = output.records;
    expect(identity?.operation.name).toBe("artifact_identity");
    expect(identity?.confidence).toBe("observed");
    expect(identity?.authority).toBe("original-artifact");
    expect(format?.operation.name).toBe("artifact_format");
    expect(format?.confidence).toBe("inferred");
    expect(format?.payload).toMatchObject({ label: "utf8-text" });
    for (const record of output.records) expect(parseEvidence(record).ok).toBe(true);
  });

  it("recognizes synthetic headers and records an unknown for unrecognized bytes", async () => {
    const { context } = testContext();
    const directory = await tempDir();
    const elf = join(directory, "header.elf");
    const noise = join(directory, "noise.bin");
    await writeFile(elf, Uint8Array.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]));
    await writeFile(noise, Uint8Array.from([0x00, 0x01, 0xfe, 0xff]));
    const elfOutput = success(await executeTool(context, "inspect_artifact", { path: elf }));
    expect(elfOutput.records[1]?.payload).toMatchObject({ label: "elf", matched_signature_hex: "7f454c46" });
    const noiseOutput = success(await executeTool(context, "inspect_artifact", { path: noise }));
    expect(noiseOutput.records[1]?.unknowns).toEqual([
      { scope: "format", reason: "No known signature matched the leading bytes." },
    ]);
  });

  it("classifies text by whether the sampled header is the whole file", async () => {
    const { context } = testContext();
    const directory = await tempDir();
    const cutText = join(directory, "long.txt");
    const invalidText = join(directory, "short.txt");
    // 63 ASCII bytes, then a two-byte character split by the 64-byte sample.
    await writeFile(cutText, `${"a".repeat(63)}é and more text`);
    await writeFile(invalidText, Buffer.concat([Buffer.from("hello"), Buffer.from([0xff])]));
    const cut = success(await executeTool(context, "inspect_artifact", { path: cutText }));
    expect(cut.records[1]?.payload).toMatchObject({ label: "utf8-text" });
    const invalid = success(await executeTool(context, "inspect_artifact", { path: invalidText }));
    expect(invalid.records[1]?.payload).toMatchObject({ label: "unknown" });
  });

  it("gives the same evidence identifiers for identical bytes under different paths and names", async () => {
    const { context } = testContext();
    const directory = await tempDir();
    await writeFile(join(directory, "a.txt"), "same");
    await mkdir(join(directory, "nested"));
    await writeFile(join(directory, "nested", "renamed.bin"), "same");
    const first = success(await executeTool(context, "inspect_artifact", { path: join(directory, "a.txt") }));
    const second = success(await executeTool(context, "inspect_artifact", { path: join(directory, "nested", "renamed.bin") }));
    expect(first.records.map(({ evidence_id }) => evidence_id)).toEqual(
      second.records.map(({ evidence_id }) => evidence_id),
    );
    // The name is still reported, beside the evidence rather than inside it.
    expect(first.data["display_name"]).toBe("a.txt");
    expect(second.data["display_name"]).toBe("renamed.bin");
    expect(JSON.stringify(second.records)).not.toContain("renamed.bin");
  });

  it.each([
    ["a missing file", async () => join(await tempDir(), "absent"), "target_not_found"],
    ["a directory", async () => tempDir(), "unsupported_target"],
    [
      "a symbolic link",
      async () => {
        const directory = await tempDir();
        await writeFile(join(directory, "real"), "x");
        await symlink(join(directory, "real"), join(directory, "link"));
        return join(directory, "link");
      },
      "unsupported_target",
    ],
  ])("refuses %s", async (_label, makePath, code) => {
    const { context } = testContext();
    expect(failure(await executeTool(context, "inspect_artifact", { path: await makePath() })).code).toBe(code);
  });

  it("requires an absolute path and rejects unknown fields", async () => {
    const { context } = testContext();
    const relative = failure(await executeTool(context, "inspect_artifact", { path: "notes.txt" }));
    expect(relative.code).toBe("invalid_input");
    expect(relative.details["issues"]).toEqual([{ path: "path", message: "Must be an absolute path" }]);
    const extra = failure(
      await executeTool(context, "inspect_artifact", { path: fixturePath("artifacts", "notes.txt"), mode: "deep" }),
    );
    expect(extra.code).toBe("invalid_input");
  });
});

const writeOutput = async (directory: string, name: string, artifact: string) => {
  const { context } = testContext();
  const output = success(await executeTool(context, "inspect_artifact", { path: fixturePath("artifacts", artifact) }));
  const path = join(directory, name);
  await writeFile(path, JSON.stringify(output));
  return { path, output };
};

describe("report_evidence and compare_evidence", () => {

  it("reports a tool output as a bundle", async () => {
    const directory = await tempDir();
    const { path } = await writeOutput(directory, "notes.json", "notes.txt");
    const { context } = testContext();
    const report = success(await executeTool(context, "report_evidence", { path }));
    expect(report.data["report"]).toMatchObject({
      total_records: 2,
      valid_records: 2,
      by_confidence: { inferred: 1, observed: 1 },
      by_authority: { "original-artifact": 2 },
      invalid_records: [],
    });
  });

  it("lists tampered records as invalid without hiding valid ones", async () => {
    const directory = await tempDir();
    const { output } = await writeOutput(directory, "notes.json", "notes.txt");
    const tampered = join(directory, "tampered.json");
    const [first, second] = output.records;
    await writeFile(tampered, JSON.stringify({ records: [first, { ...second, confidence: "observed" }] }));
    const { context } = testContext();
    const report = success(await executeTool(context, "report_evidence", { path: tampered }));
    expect(report.data["report"]).toMatchObject({ valid_records: 1, invalid_records: [{ index: 1 }] });
  });

  it("compares bundles and labels the comparison as a Revscope computation", async () => {
    const directory = await tempDir();
    const notes = await writeOutput(directory, "notes.json", "notes.txt");
    const config = await writeOutput(directory, "config.json", "config.json");
    const { context } = testContext();
    const same = success(await executeTool(context, "compare_evidence", { left_path: notes.path, right_path: notes.path }));
    expect(same.data["summary"]).toMatchObject({ unchanged: 2, changed: 0 });
    const different = success(await executeTool(context, "compare_evidence", { left_path: notes.path, right_path: config.path }));
    expect(different.data["summary"]).toMatchObject({ added: 2, removed: 2 });
    expect(different.records[0]?.confidence).toBe("derived");
    expect(different.records[0]?.authority).toBe("revscope-computation");
    expect(different.records[0]?.subject.kind).toBe("evidence-set");
  });

  it("refuses to compare bundles with invalid records", async () => {
    const directory = await tempDir();
    const notes = await writeOutput(directory, "notes.json", "notes.txt");
    const bad = join(directory, "bad.json");
    await writeFile(bad, JSON.stringify({ records: [{ evidence_id: "ev_x" }] }));
    const { context } = testContext();
    const error = failure(await executeTool(context, "compare_evidence", { left_path: notes.path, right_path: bad }));
    expect(error.code).toBe("evidence_integrity");
    expect(error.details).toMatchObject({ left_invalid_indexes: [], right_invalid_indexes: [0] });
  });

  it("rejects files that are not bundles or not JSON", async () => {
    const directory = await tempDir();
    const notJson = join(directory, "x.json");
    const notBundle = join(directory, "y.json");
    await writeFile(notJson, "{");
    await writeFile(notBundle, JSON.stringify({ items: [] }));
    const { context } = testContext();
    expect(failure(await executeTool(context, "report_evidence", { path: notJson })).code).toBe("invalid_input");
    const shape = failure(await executeTool(context, "report_evidence", { path: notBundle }));
    expect(shape.code).toBe("invalid_input");
    expect(shape.details["issues"]).toEqual([{ path: "path.records", message: expect.any(String) }]);
  });
});

const runStub = (fixture: string, steps: unknown, extra: Record<string, unknown> = {}) =>
  executeTool(testContext().context, "stub_analysis", {
    fixture_path: fixturePath("stub", fixture),
    steps,
    ...extra,
  });

describe("stub_analysis", () => {

  it("runs a successful session with distinct labels for state and decompiler output", async () => {
    const output = success(
      await runStub("database.json", [
        { action: "read", operation: "get_name", params: { address: "0x1000" } },
        { action: "read", operation: "decompile", params: { address: "0x1000" } },
        { action: "mutate", operation: "rename", params: { names: { "0x1000": "entry" } } },
        { action: "snapshot" },
      ]),
    );
    expect(output.records.map(({ confidence, authority }) => `${confidence}/${authority}`)).toEqual([
      "observed/analysis-state",
      "derived/analysis-engine",
      "reported/analysis-state",
    ]);
    expect(output.data["snapshots"]).toHaveLength(1);
  });

  it("surfaces an unsupported operation as the top-level error with earlier observations preserved", async () => {
    const error = failure(
      await runStub("database.json", [
        { action: "read", operation: "get_name", params: { address: "0x1000" } },
        { action: "read", operation: "trace_calls" },
      ]),
    );
    expect(error.code).toBe("unsupported_operation");
    expect(error.details["failed_step"]).toBe(1);
    expect(error.details["partial_records"]).toHaveLength(1);
  });

  it("reports a partial mutation failure and the subsequent snapshot refusal", async () => {
    const error = failure(
      await runStub(
        "database-partial-failure.json",
        [
          { action: "mutate", operation: "rename", params: { names: { "0x1000": "entry", "0x2000": "util" } } },
          { action: "snapshot" },
          { action: "reconcile" },
          { action: "snapshot" },
        ],
        { continue_on_error: true },
      ),
    );
    expect(error.code).toBe("partial_failure");
    expect(error.details).toMatchObject({ possibly_mutated: true, state_effect: "unknown", failed_step: 0 });
    const steps = error.details["steps"] as { outcome: string; error?: { code: string } }[];
    expect(steps.map((step) => step.error?.code ?? step.outcome)).toEqual([
      "partial_failure",
      "state_uncertain",
      "ok",
      "ok",
    ]);
    // open (1), uncertain mutation (2), reconcile (3)
    expect(error.details["final_state"]).toMatchObject({ consistency: "consistent", revision: 3 });
  });

  it("stops at the first failure unless asked to continue", async () => {
    const error = failure(
      await runStub("database-partial-failure.json", [
        { action: "mutate", operation: "rename", params: { names: { "0x1000": "a", "0x2000": "b" } } },
        { action: "snapshot" },
      ]),
    );
    expect((error.details["steps"] as unknown[]).length).toBe(1);
  });

  it("validates the fixture document and the steps", async () => {
    const directory = await tempDir();
    const badFixture = join(directory, "fixture.json");
    await writeFile(badFixture, JSON.stringify({ schema: "revscope.stub-database/1" }));
    const fixtureError = failure(
      await executeTool(testContext().context, "stub_analysis", {
        fixture_path: badFixture,
        steps: [{ action: "snapshot" }],
      }),
    );
    expect(fixtureError.code).toBe("invalid_input");
    expect(JSON.stringify(fixtureError.details)).toContain("fixture.artifact");
    const stepError = failure(await runStub("database.json", [{ action: "explode" }]));
    expect(stepError.code).toBe("invalid_input");
    expect(failure(await runStub("database.json", [])).code).toBe("invalid_input");
  });

  it("never modifies the fixture file", async () => {
    const { readFile } = await import("node:fs/promises");
    const before = await readFile(fixturePath("stub", "database.json"), "utf8");
    success(await runStub("database.json", [{ action: "mutate", operation: "rename", params: { names: { "0x1000": "x" } } }]));
    expect(await readFile(fixturePath("stub", "database.json"), "utf8")).toBe(before);
  });
});

describe("execution safety", () => {
  it("converts unexpected exceptions into an internal error without leaking details", async () => {
    const { context, logs } = exploding();
    const output = await executeTool(context, "inspect_artifact", { path: fixturePath("artifacts", "notes.txt") });
    const error = failure(output);
    expect(error).toMatchObject({ code: "internal_error", category: "internal", details: { correlation_id: "cor_test" } });
    const text = JSON.stringify(output);
    expect(text).not.toContain("EXPLODE_SECRET");
    expect(text).not.toContain("/Users/secret");
    expect(text).not.toMatch(/\bat .+:\d+:\d+/u);
    expect(logs.join("")).toContain("tool_internal_error");
    expect(logs.join("")).not.toContain("EXPLODE_SECRET");
  });

  it("returns unknown_tool for names outside the registry", async () => {
    const error = failure(await executeTool(testContext().context, "decompile_everything", {}));
    expect(error.code).toBe("unknown_tool");
  });
});
