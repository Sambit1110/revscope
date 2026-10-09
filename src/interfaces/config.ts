import { z } from "zod";

import { invalidInput, issuesFromZod, type ErrorEnvelope } from "../domain/errors.js";
import { err, ok, type Result } from "../domain/result.js";
import { LOG_LEVELS, type LogLevel } from "../infrastructure/logger.js";

export interface RuntimeConfig {
  readonly logLevel: LogLevel;
}

/** Only Revscope's own variables are read; the rest of the environment is ignored. */
const configSchema = z.object({
  REVSCOPE_LOG_LEVEL: z.enum(LOG_LEVELS).optional(),
});

export const parseConfig = (
  env: Readonly<Record<string, string | undefined>>,
): Result<RuntimeConfig, ErrorEnvelope> => {
  const parsed = configSchema.safeParse({ REVSCOPE_LOG_LEVEL: env["REVSCOPE_LOG_LEVEL"] });
  if (!parsed.success)
    return err(invalidInput("Revscope configuration is invalid", issuesFromZod(parsed.error)));
  return ok({ logLevel: parsed.data.REVSCOPE_LOG_LEVEL ?? "warn" });
};
