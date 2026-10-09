import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { lstat } from "node:fs/promises";
import { basename } from "node:path";

import type { ArtifactFacts, ArtifactReader } from "../application/ports.js";
import { makeError, type ErrorEnvelope } from "../domain/errors.js";
import { err, ok, type Result } from "../domain/result.js";

const HEADER_BYTES = 64;

/** Map filesystem failures to stable codes without exposing host error text. */
export const filesystemError = (
  cause: unknown,
  path: string,
): ErrorEnvelope => {
  const code =
    typeof cause === "object" && cause !== null && "code" in cause
      ? String(cause.code)
      : "";
  if (code === "ENOENT" || code === "ENOTDIR")
    return makeError("target_not_found", "The target does not exist", { path });
  if (code === "EACCES" || code === "EPERM")
    return makeError("access_denied", "The target cannot be read by the current user", { path });
  if (code === "EISDIR")
    return makeError("unsupported_target", "The target is a directory", { path });
  return makeError("provider_failure", "The target could not be read", { path });
};

/** Hash and sample a regular file. The file is only read, never executed. */
export class FsArtifactReader implements ArtifactReader {
  async read(path: string): Promise<Result<ArtifactFacts, ErrorEnvelope>> {
    let stats;
    try {
      stats = await lstat(path);
    } catch (cause: unknown) {
      return err(filesystemError(cause, path));
    }
    if (!stats.isFile())
      return err(
        makeError(
          "unsupported_target",
          stats.isSymbolicLink()
            ? "The target is a symbolic link; select the file it points to"
            : "The target is not a regular file",
          { path },
        ),
      );
    const hash = createHash("sha256");
    const header: Buffer[] = [];
    let headerLength = 0;
    let size = 0;
    try {
      for await (const chunk of createReadStream(path)) {
        const bytes = chunk as Buffer;
        hash.update(bytes);
        size += bytes.length;
        if (headerLength < HEADER_BYTES) {
          const part = bytes.subarray(0, HEADER_BYTES - headerLength);
          header.push(part);
          headerLength += part.length;
        }
      }
    } catch (cause: unknown) {
      return err(filesystemError(cause, path));
    }
    return ok({
      displayName: basename(path),
      sizeBytes: size,
      sha256: hash.digest("hex"),
      header: new Uint8Array(Buffer.concat(header)),
    });
  }
}
