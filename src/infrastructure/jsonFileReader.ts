import { lstat, readFile } from "node:fs/promises";

import type { JsonFileReader } from "../application/ports.js";
import { invalidInput, makeError, type ErrorEnvelope } from "../domain/errors.js";
import { err, ok, type Result } from "../domain/result.js";
import { filesystemError } from "./fsArtifactReader.js";

/** JSON inputs are parsed in memory, so their size is bounded. */
export const MAX_JSON_BYTES = 16 * 1024 * 1024;

export class FsJsonFileReader implements JsonFileReader {
  readonly #maxBytes: number;

  constructor(maxBytes = MAX_JSON_BYTES) {
    this.#maxBytes = maxBytes;
  }

  async read(path: string): Promise<Result<unknown, ErrorEnvelope>> {
    let text: string;
    try {
      const stats = await lstat(path);
      if (!stats.isFile())
        return err(makeError("unsupported_target", "The JSON input is not a regular file", { path }));
      if (stats.size > this.#maxBytes)
        return err(
          makeError("resource_limit", "The JSON input is larger than the supported limit", {
            path,
            limit_bytes: this.#maxBytes,
            size_bytes: stats.size,
          }),
        );
      text = await readFile(path, "utf8");
    } catch (cause: unknown) {
      return err(filesystemError(cause, path));
    }
    try {
      return ok(JSON.parse(text) as unknown);
    } catch {
      return err(invalidInput("The input file is not valid JSON", [{ path: "$", message: "Invalid JSON" }]));
    }
  }
}
