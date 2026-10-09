import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { runChild } from "../../src/infrastructure/childProcess.js";
import {
  DEFAULT_BASELINE,
  buildChildEnvironment,
} from "../../src/infrastructure/envPolicy.js";

const REPORTER = fileURLToPath(
  new URL("../fixtures/child/report-environment.mjs", import.meta.url),
);

/** A synthetic host environment: the real host environment is never used or printed. */
const syntheticHost = () => {
  const suffix = randomBytes(6).toString("hex").toUpperCase();
  const canaryName = `REVSCOPE_TEST_CANARY_${suffix}`;
  const canaryValue = `canary-${randomBytes(8).toString("hex")}`;
  const unrelatedName = `REVSCOPE_TEST_UNRELATED_${suffix}`;
  const unrelatedValue = `unrelated-${randomBytes(8).toString("hex")}`;
  const host = (extra: Record<string, string> = {}): Record<string, string> => ({
    PATH: "/usr/bin:/bin",
    LANG: "C",
    [canaryName]: canaryValue,
    [unrelatedName]: unrelatedValue,
    ...extra,
  });
  return { canaryName, canaryValue, unrelatedName, unrelatedValue, host };
};

const reportFromChild = async (
  host: Record<string, string>,
  policy: Parameters<typeof runChild>[0]["environment"],
  requested: string[],
) => {
  const outcome = await runChild(
    {
      executable: process.execPath,
      args: [REPORTER, ...requested],
      ...(policy === undefined ? {} : { environment: policy }),
      timeoutMs: 10_000,
      maxOutputBytes: 64 * 1024,
    },
    host,
  );
  if (!outcome.ok) throw new Error(JSON.stringify(outcome.error));
  return {
    report: JSON.parse(outcome.value.stdout) as {
      names: string[];
      values: Record<string, string | null>;
      echoed: string[];
    },
    manifest: outcome.value.environment,
  };
};

describe("environment policy construction", () => {
  it("passes only baseline variables by default and records names, never values", () => {
    const fixture = syntheticHost();
    const host = fixture.host();
    const built = buildChildEnvironment(host);
    expect(built.ok).toBe(true);
    if (!built.ok) return;
    expect(Object.keys(built.value.env).toSorted()).toEqual(["LANG", "PATH"]);
    expect(built.value.manifest).toEqual({
      approved_names: [...DEFAULT_BASELINE].toSorted(),
      inherited_names: ["LANG", "PATH"],
      absent_names: ["LC_ALL", "LC_CTYPE", "TZ"],
      set_names: [],
    });
    const manifestText = JSON.stringify(built.value.manifest);
    expect(manifestText).not.toContain(fixture.canaryValue);
    expect(manifestText).not.toContain("/usr/bin");
  });

  it("applies deliberate passthrough and explicit values by name", () => {
    const fixture = syntheticHost();
    const built = buildChildEnvironment(fixture.host(), {
      baseline: [],
      passthrough: [fixture.canaryName],
      set: { REVSCOPE_MODE: "test" },
    });
    expect(built.ok).toBe(true);
    if (!built.ok) return;
    expect(built.value.env).toEqual({
      [fixture.canaryName]: fixture.canaryValue,
      REVSCOPE_MODE: "test",
    });
    expect(JSON.stringify(built.value.manifest)).not.toContain("test\"");
    expect(built.value.manifest.set_names).toEqual(["REVSCOPE_MODE"]);
  });

  it.each([
    [{ passthrough: ["BAD-NAME"] }, "passthrough.0"],
    [{ baseline: ["1PATH"] }, "baseline.0"],
    [{ set: { OK: "a\0b" } }, "set.OK"],
    [{ passthrough: ["X"], set: { X: "1" } }, "set.X"],
  ])("rejects an invalid policy %#", (policy, path) => {
    const built = buildChildEnvironment({}, policy);
    expect(built.ok).toBe(false);
    if (!built.ok) {
      expect(built.error.code).toBe("invalid_input");
      expect(JSON.stringify(built.error.details)).toContain(path);
    }
  });
});

describe("child process environment", () => {
  it("does not let a host-only canary reach the child by default", async () => {
    const fixture = syntheticHost();
    const { report } = await reportFromChild(
      fixture.host(),
      undefined,
      [fixture.canaryName],
    );
    expect(report.values[fixture.canaryName]).toBeNull();
    expect(report.names).not.toContain(fixture.canaryName);
    expect(report.names).not.toContain(fixture.unrelatedName);
  });

  it("delivers the canary only when it is explicitly allowed", async () => {
    const fixture = syntheticHost();
    const { report, manifest } = await reportFromChild(
      fixture.host(),
      { passthrough: [fixture.canaryName] },
      [fixture.canaryName, fixture.unrelatedName],
    );
    expect(report.values[fixture.canaryName]).toBe(fixture.canaryValue);
    expect(report.values[fixture.unrelatedName]).toBeNull();
    expect(manifest.inherited_names).toContain(fixture.canaryName);
    expect(JSON.stringify(manifest)).not.toContain(fixture.canaryValue);
  });

  it("gives the child exactly the approved names that exist on the host", async () => {
    const fixture = syntheticHost();
    const { report, manifest } = await reportFromChild(
      fixture.host({ TZ: "UTC" }),
      { passthrough: [fixture.canaryName], set: { REVSCOPE_MODE: "test" } },
      [],
    );
    const expected = [...manifest.inherited_names, ...manifest.set_names].toSorted();
    // The runtime may add its own bookkeeping variables; nothing else may appear.
    const unexpected = report.names.filter(
      (name) => !expected.includes(name) && !name.startsWith("__CF_"),
    );
    expect(unexpected).toEqual([]);
    expect(expected.every((name) => report.names.includes(name))).toBe(true);
  });

  it("passes shell metacharacters as literal arguments", async () => {
    const fixture = syntheticHost();
    const hostile = ["$(echo injected)", "`id`", "a; rm -rf /", "*", "$HOME"];
    const { report } = await reportFromChild(
      fixture.host(),
      undefined,
      ["--", ...hostile],
    );
    expect(report.echoed).toEqual(hostile);
  });
});

describe("child command validation and limits", () => {
  it("refuses relative executables and NUL arguments without spawning", async () => {
    const outcome = await runChild(
      { executable: "node", args: ["a\0b"], timeoutMs: 1000, maxOutputBytes: 10 },
      {},
    );
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.error.code).toBe("invalid_input");
      expect(JSON.stringify(outcome.error.details)).toContain("executable");
      expect(JSON.stringify(outcome.error.details)).toContain("args.0");
    }
  });

  it("reports a missing executable as not found", async () => {
    const outcome = await runChild(
      { executable: "/nonexistent/revscope-test-binary", args: [], timeoutMs: 1000, maxOutputBytes: 10 },
      {},
    );
    expect(outcome.ok ? "ok" : outcome.error.code).toBe("target_not_found");
  });

  it("kills a child that exceeds its deadline", async () => {
    const outcome = await runChild(
      {
        executable: process.execPath,
        args: ["-e", "setTimeout(() => {}, 20000)"],
        timeoutMs: 200,
        maxOutputBytes: 1024,
      },
      {},
    );
    expect(outcome.ok && outcome.value.termination).toBe("timed-out");
  });

  it("bounds captured output", async () => {
    const outcome = await runChild(
      {
        executable: process.execPath,
        args: ["-e", "process.stdout.write('x'.repeat(5000))"],
        timeoutMs: 10_000,
        maxOutputBytes: 100,
      },
      {},
    );
    expect(outcome.ok).toBe(true);
    if (outcome.ok) {
      expect(outcome.value.stdout).toHaveLength(100);
      expect(outcome.value.outputTruncated).toBe(true);
    }
  });
});
