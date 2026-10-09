import { z } from "zod";

import { invalidInput, issuesFromZod, type ErrorEnvelope } from "../domain/errors.js";
import { err, ok, type Result } from "../domain/result.js";
import { LOG_LEVELS, type LogLevel } from "../infrastructure/logger.js";

export interface RuntimeConfig {
  readonly logLevel: LogLevel;
  /** Present when REVSCOPE_GHIDRA_DIR is set. Checked when an analysis runs, so other tools work regardless. */
  readonly ghidra: { readonly ghidraDir: string; readonly javaHome?: string } | null;
  /** REVSCOPE_GHIDRA_DIAGNOSTICS=1: keep failed Ghidra runs for local diagnosis. Off by default. */
  readonly ghidraDiagnostics: boolean;
}

/** Only Revscope's own variables are read; the rest of the environment is ignored. */
const configSchema = z.object({
  REVSCOPE_LOG_LEVEL: z.enum(LOG_LEVELS).optional(),
  REVSCOPE_GHIDRA_DIR: z.string().min(1).optional(),
  REVSCOPE_JAVA_HOME: z.string().min(1).optional(),
  REVSCOPE_GHIDRA_DIAGNOSTICS: z.enum(["0", "1"]).optional(),
});

export const parseConfig = (
  env: Readonly<Record<string, string | undefined>>,
): Result<RuntimeConfig, ErrorEnvelope> => {
  const parsed = configSchema.safeParse({
    REVSCOPE_LOG_LEVEL: env["REVSCOPE_LOG_LEVEL"],
    REVSCOPE_GHIDRA_DIR: env["REVSCOPE_GHIDRA_DIR"],
    REVSCOPE_JAVA_HOME: env["REVSCOPE_JAVA_HOME"],
    REVSCOPE_GHIDRA_DIAGNOSTICS: env["REVSCOPE_GHIDRA_DIAGNOSTICS"],
  });
  if (!parsed.success)
    return err(invalidInput("Revscope configuration is invalid", issuesFromZod(parsed.error)));
  const { REVSCOPE_GHIDRA_DIR: ghidraDir, REVSCOPE_JAVA_HOME: javaHome } = parsed.data;
  return ok({
    logLevel: parsed.data.REVSCOPE_LOG_LEVEL ?? "warn",
    ghidra: ghidraDir === undefined ? null : { ghidraDir, ...(javaHome === undefined ? {} : { javaHome }) },
    ghidraDiagnostics: parsed.data.REVSCOPE_GHIDRA_DIAGNOSTICS === "1",
  });
};
