import { randomUUID } from "node:crypto";

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

/** Wire production infrastructure into the shared tool context. */
export const createToolContext = (options: {
  readonly logLevel: LogLevel;
  readonly writeLog: (line: string) => void;
  /** Ghidra settings from configuration; null leaves analyze_binary unconfigured. */
  readonly ghidra?: GhidraSettings | null;
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
    options.ghidra === undefined || options.ghidra === null ? null : new GhidraEngine({ settings: options.ghidra }),
  logger: createLogger(options.logLevel, options.writeLog),
  newCorrelationId: () => `cor_${randomUUID().replaceAll("-", "")}`,
});
