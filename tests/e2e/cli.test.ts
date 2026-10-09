import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";

import { toolOutputSchema } from "../../src/application/tools/types.js";
import { BIN, REPO_ROOT, tempDir } from "../support/context.js";

/** Run the built executable from the repository root, exactly as documented. */
const revscope = (...args: string[]) => {
  const run = spawnSync(process.execPath, [BIN, ...args], {
    cwd: REPO_ROOT,
    encoding: "utf8",
    env: { PATH: "/usr/bin:/bin" },
    timeout: 30_000,
  });
  return { status: run.status, stdout: run.stdout, stderr: run.stderr };
};

const json = (stdout: string) => toolOutputSchema.parse(JSON.parse(stdout));

describe("documented CLI usage against fixtures", () => {
  beforeAll(() => {
    if (!existsSync(BIN)) throw new Error("Build first: npm run build");
  });

  it("prints help, version, and the tool list", async () => {
    const help = revscope("--help");
    expect(help.status).toBe(0);
    expect(help.stdout).toContain("revscope inspect-artifact <file>");
    const manifest = JSON.parse(await readFile(join(REPO_ROOT, "package.json"), "utf8")) as { version: string };
    expect(revscope("version").stdout.trim()).toBe(manifest.version);
    const tools = JSON.parse(revscope("tools").stdout) as { tools: { name: string; cli_command: string }[] };
    expect(tools.tools.map(({ cli_command }) => cli_command)).toEqual([
      "inspect-artifact",
      "report-evidence",
      "compare-evidence",
      "stub-analysis",
    ]);
  });

  it("inspects fixtures, reports, and compares the resulting evidence", async () => {
    const directory = await tempDir();
    const notes = revscope("inspect-artifact", "fixtures/artifacts/notes.txt");
    expect(notes.status).toBe(0);
    expect(notes.stderr).toBe("");
    const notesPath = join(directory, "notes.json");
    await writeFile(notesPath, notes.stdout);
    const config = revscope("inspect-artifact", "fixtures/artifacts/config.json");
    const configPath = join(directory, "config.json");
    await writeFile(configPath, config.stdout);

    const report = json(revscope("report-evidence", notesPath).stdout);
    expect(report.ok && report.data["report"]).toMatchObject({ valid_records: 2 });

    const compared = revscope("compare-evidence", notesPath, configPath);
    expect(compared.status).toBe(0);
    const comparison = json(compared.stdout);
    expect(comparison.ok && comparison.data["summary"]).toMatchObject({ added: 2, removed: 2 });
  });

  it("produces byte-identical output for repeated runs", () => {
    const first = revscope("inspect-artifact", "fixtures/artifacts/notes.txt").stdout;
    const second = revscope("inspect-artifact", "fixtures/artifacts/notes.txt").stdout;
    expect(second).toBe(first);
  });

  it("runs the stub success, unsupported-operation, and partial-failure scenarios", () => {
    const succeeded = revscope(
      "stub-analysis",
      "fixtures/stub/database.json",
      "--steps-file",
      "fixtures/stub/steps-success.json",
    );
    expect(succeeded.status).toBe(0);
    const success = json(succeeded.stdout);
    expect(success.ok && success.records.map(({ confidence }) => confidence)).toEqual([
      "observed",
      "derived",
      "observed",
      "reported",
      "observed",
    ]);

    const unsupported = revscope(
      "stub-analysis",
      "fixtures/stub/database.json",
      "--steps-file",
      "fixtures/stub/steps-unsupported.json",
    );
    expect(unsupported.status).toBe(4);
    const unsupportedOutput = json(unsupported.stdout);
    expect(!unsupportedOutput.ok && unsupportedOutput.error.code).toBe("unsupported_operation");

    const partial = revscope(
      "stub-analysis",
      "fixtures/stub/database-partial-failure.json",
      "--steps-file",
      "fixtures/stub/steps-partial-failure.json",
      "--continue-on-error",
    );
    expect(partial.status).toBe(9);
    const partialOutput = json(partial.stdout);
    expect(!partialOutput.ok && partialOutput.error.code).toBe("partial_failure");
    if (!partialOutput.ok) {
      const steps = partialOutput.error.details["steps"] as { error?: { code: string }; outcome: string }[];
      expect(steps.map((step) => step.error?.code ?? step.outcome)).toEqual([
        "ok",
        "partial_failure",
        "ok",
        "state_uncertain",
        "ok",
        "ok",
      ]);
    }
  });

  it("maps failure categories to documented exit codes and writes JSON to stdout", () => {
    expect(revscope("inspect-artifact", "fixtures/does-not-exist").status).toBe(3);
    expect(revscope("inspect-artifact", "fixtures").status).toBe(4);
    expect(revscope("inspect-artifact").status).toBe(2);
    const unknown = revscope("frobnicate");
    expect(unknown.status).toBe(4);
    expect(json(unknown.stdout).ok).toBe(false);
  });

  it("rejects invalid configuration with the shared envelope", () => {
    const run = spawnSync(process.execPath, [BIN, "tools"], {
      cwd: REPO_ROOT,
      encoding: "utf8",
      env: { PATH: "/usr/bin:/bin", REVSCOPE_LOG_LEVEL: "chatty" },
    });
    expect(run.status).toBe(2);
    expect(JSON.parse(run.stdout)).toMatchObject({ ok: false, error: { code: "invalid_input" } });
  });
});
