import type { JsonFileReader } from "../application/ports.js";
import { invalidInput, jsonShapeError, makeError, type ErrorEnvelope } from "../domain/errors.js";
import { jsonShapeIssue } from "../domain/json.js";
import { err, ok, type Result } from "../domain/result.js";
import { filesystemError, openRegularFile, readChunks } from "./safeFile.js";

/** JSON inputs are parsed in memory, so their size is bounded. */
export const MAX_JSON_BYTES = 16 * 1024 * 1024;

export class FsJsonFileReader implements JsonFileReader {
  readonly #maxBytes: number;

  constructor(maxBytes = MAX_JSON_BYTES) {
    this.#maxBytes = maxBytes;
  }

  async read(path: string): Promise<Result<unknown, ErrorEnvelope>> {
    const opened = await openRegularFile(path);
    if (!opened.ok) return opened;
    const tooLarge = (size: number) =>
      err(
        makeError("resource_limit", "The JSON input is larger than the supported limit", {
          path,
          limit_bytes: this.#maxBytes,
          size_bytes: size,
        }),
      );
    if (opened.value.size > this.#maxBytes) {
      await opened.value.handle.close();
      return tooLarge(opened.value.size);
    }
    // The limit also holds if the file grows after it was measured.
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
      for await (const chunk of readChunks(opened.value.handle)) {
        size += chunk.length;
        if (size > this.#maxBytes) break;
        chunks.push(chunk);
      }
    } catch (cause: unknown) {
      return err(filesystemError(cause, path));
    }
    if (size > this.#maxBytes) return tooLarge(size);
    let text: string;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks));
    } catch {
      return err(invalidInput("The input file is not valid UTF-8", [{ path: "$", message: "Invalid UTF-8" }]));
    }
    let value: unknown;
    try {
      value = JSON.parse(text) as unknown;
    } catch {
      return err(invalidInput("The input file is not valid JSON", [{ path: "$", message: "Invalid JSON" }]));
    }
    const shape = jsonShapeIssue(value);
    return shape === null ? ok(value) : err(jsonShapeError(shape));
  }
}
