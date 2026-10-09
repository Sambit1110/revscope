import { describe, expect, it } from "vitest";

import { createToolContext } from "../../src/composition.js";
import { parseConfig } from "../../src/interfaces/config.js";

describe("runtime configuration", () => {
  it("leaves the engine unconfigured unless REVSCOPE_GHIDRA_DIR is set", () => {
    const config = parseConfig({ PATH: "/usr/bin", GHIDRA_INSTALL_DIR: "/opt/ghidra", JAVA_HOME: "/opt/java" });
    expect(config).toEqual({ ok: true, value: { logLevel: "warn", ghidra: null, ghidraDiagnostics: false } });
    expect(createToolContext({ logLevel: "silent", writeLog: () => undefined, ghidra: null }).binaryAnalysis).toBeNull();
  });

  it("reads only Revscope's own Ghidra variables and defers checking them to the analysis", () => {
    const config = parseConfig({ REVSCOPE_GHIDRA_DIR: "relative/is/checked/later", REVSCOPE_JAVA_HOME: "/opt/jdk" });
    expect(config).toEqual({
      ok: true,
      value: { logLevel: "warn", ghidra: { ghidraDir: "relative/is/checked/later", javaHome: "/opt/jdk" }, ghidraDiagnostics: false },
    });
    if (!config.ok) return;
    expect(createToolContext({ logLevel: "silent", writeLog: () => undefined, ghidra: config.value.ghidra }).binaryAnalysis).not.toBeNull();
  });

  it("rejects empty values without echoing them", () => {
    const config = parseConfig({ REVSCOPE_GHIDRA_DIR: "" });
    expect(config.ok ? "accepted" : config.error).toMatchObject({ code: "invalid_input", details: { issues: [{ path: "REVSCOPE_GHIDRA_DIR" }] } });
  });
});
