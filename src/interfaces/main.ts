import { randomUUID } from "node:crypto";

import { createToolContext } from "../composition.js";
import { makeError } from "../domain/errors.js";
import { runCli } from "./cli.js";
import { parseConfig } from "./config.js";
import { serveMcp } from "./mcp.js";
import { EXIT_CODES, renderJson } from "./output.js";

export interface ProcessIo {
  readonly argv: readonly string[];
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly cwd: string;
  readonly stdin: NodeJS.ReadableStream;
  readonly stdout: (text: string) => void;
  readonly stderr: (text: string) => void;
}

/** Entry point shared by the executable and in-process tests. */
export const main = async (io: ProcessIo): Promise<number> => {
  const config = parseConfig(io.env);
  if (!config.ok) {
    io.stdout(renderJson({ ok: false, error: config.error }));
    return EXIT_CODES.invalid_input;
  }
  const context = createToolContext({ logLevel: config.value.logLevel, writeLog: io.stderr });
  try {
    if (io.argv[0] === "mcp") {
      if (io.argv.length > 1) {
        io.stdout(renderJson({ ok: false, error: makeError("invalid_input", "mcp takes no arguments", { issues: [{ path: "$argv.1", message: "Unexpected argument" }] }) }));
        return EXIT_CODES.invalid_input;
      }
      await serveMcp(context, io.stdin, io.stdout);
      return 0;
    }
    return await runCli(io.argv, { stdout: io.stdout, cwd: io.cwd }, context);
  } catch (cause: unknown) {
    // Last resort: never print a stack trace or host details to the caller.
    const correlationId = `cor_${randomUUID().replaceAll("-", "")}`;
    context.logger.error({
      event: "unhandled_failure",
      error_class: cause instanceof Error ? cause.name : typeof cause,
      correlation_id: correlationId,
    });
    io.stdout(
      renderJson({
        ok: false,
        error: makeError("internal_error", "Revscope failed unexpectedly", { correlation_id: correlationId }),
      }),
    );
    return EXIT_CODES.internal;
  }
};
