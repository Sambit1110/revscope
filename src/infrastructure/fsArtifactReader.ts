import { createHash } from "node:crypto";
import { basename } from "node:path";

import type { ArtifactFacts, ArtifactReader } from "../application/ports.js";
import type { ErrorEnvelope } from "../domain/errors.js";
import { err, ok, type Result } from "../domain/result.js";
import { filesystemError, openRegularFile, readChunks } from "./safeFile.js";

const HEADER_BYTES = 64;

/** Hash and sample a regular file. The file is only read, never executed. */
export class FsArtifactReader implements ArtifactReader {
  async read(path: string): Promise<Result<ArtifactFacts, ErrorEnvelope>> {
    const opened = await openRegularFile(path);
    if (!opened.ok) return opened;
    const hash = createHash("sha256");
    const header: Uint8Array[] = [];
    let headerLength = 0;
    let size = 0;
    try {
      for await (const bytes of readChunks(opened.value.handle)) {
        hash.update(bytes);
        size += bytes.length;
        if (headerLength < HEADER_BYTES) {
          const part = bytes.slice(0, HEADER_BYTES - headerLength);
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
