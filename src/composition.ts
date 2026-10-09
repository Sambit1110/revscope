import { randomUUID } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { ToolContext } from "./application/tools/types.js";
import { invalidInput, issuesFromZod } from "./domain/errors.js";
import { err, ok } from "./domain/result.js";
import { FsArtifactReader } from "./infrastructure/fsArtifactReader.js";
import { GhidraEngine } from "./infrastructure/ghidra/engine.js";
import type { GhidraSettings } from "./infrastructure/ghidra/installation.js";
import { FsJsonFileReader } from "./infrastructure/jsonFileReader.js";
import { createLogger, type LogLevel } from "./infrastructure/logger.js";
import {
  StubAnalysisProvider,
  stubFixtureSchema,
} from "./infrastructure/stubProvider.js";

/** Where opt-in Ghidra diagnostics are kept: a predictable place under the system temp directory. */
export const DIAGNOSTICS_DIRECTORY = join(tmpdir(), "revscope-diagnostics");

/** Wire production infrastructure into the shared tool context. */
export const createToolContext = (options: {
  readonly logLevel: LogLevel;
  readonly writeLog: (line: string) => void;
  /** Ghidra settings from configuration; null leaves analyze_binary unconfigured. */
  readonly ghidra?: GhidraSettings | null;
  /**
   * Opt-in local diagnostics for failed Ghidra runs. The report sink must be
   * local developer output (the CLI's stderr), never a tool result.
   */
  readonly ghidraDiagnostics?: { readonly report: (line: string) => void } | null;
}): ToolContext => ({
  artifactReader: new FsArtifactReader(),
  jsonReader: new FsJsonFileReader(),
  createStubProvider: (fixture) => {
    const parsed = stubFixtureSchema.safeParse(fixture);
    return parsed.success
      ? ok(new StubAnalysisProvider(parsed.data))
      : err(invalidInput("The stub fixture is invalid", issuesFromZod(parsed.error, "fixture")));
  },
  binaryAnalysis:
    options.ghidra === undefined || options.ghidra === null
      ? null
      : new GhidraEngine({
          settings: options.ghidra,
          ...(options.ghidraDiagnostics === undefined || options.ghidraDiagnostics === null
            ? {}
            : { diagnostics: { directory: DIAGNOSTICS_DIRECTORY, report: options.ghidraDiagnostics.report } }),
        }),
  logger: createLogger(options.logLevel, options.writeLog),
  newCorrelationId: () => `cor_${randomUUID().replaceAll("-", "")}`,
});
