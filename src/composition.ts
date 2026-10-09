import { randomUUID } from "node:crypto";

import type { ToolContext } from "./application/tools/types.js";
import { invalidInput, issuesFromZod } from "./domain/errors.js";
import { err, ok } from "./domain/result.js";
import { FsArtifactReader } from "./infrastructure/fsArtifactReader.js";
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
}): ToolContext => ({
  artifactReader: new FsArtifactReader(),
  jsonReader: new FsJsonFileReader(),
  createStubProvider: (fixture) => {
    const parsed = stubFixtureSchema.safeParse(fixture);
    return parsed.success
      ? ok(new StubAnalysisProvider(parsed.data))
      : err(invalidInput("The stub fixture is invalid", issuesFromZod(parsed.error, "fixture")));
  },
  binaryAnalysis: null,
  logger: createLogger(options.logLevel, options.writeLog),
  newCorrelationId: () => `cor_${randomUUID().replaceAll("-", "")}`,
});
