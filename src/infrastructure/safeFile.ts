import { constants } from "node:fs";
import { lstat, open, type FileHandle } from "node:fs/promises";
import { constants as osConstants } from "node:os";

import { makeError, type ErrorEnvelope } from "../domain/errors.js";
import { err, ok, type Result } from "../domain/result.js";

/** Errors that mean "this is not something that can be opened as a file". */
const NOT_A_FILE_ERRNOS = new Set(
  [osConstants.errno.ENXIO, osConstants.errno.EOPNOTSUPP, osConstants.errno.ENOTSUP].filter(
    (value): value is number => value !== undefined,
  ),
);

/** Map filesystem failures to stable codes without exposing host error text. */
export const filesystemError = (cause: unknown, path: string): ErrorEnvelope => {
  const code =
    typeof cause === "object" && cause !== null && "code" in cause ? String(cause.code) : "";
  // libuv does not name every errno (opening a socket on macOS gives an
  // unnamed EOPNOTSUPP), so the number is checked as well.
  const errno =
    typeof cause === "object" && cause !== null && "errno" in cause && typeof cause.errno === "number"
      ? Math.abs(cause.errno)
      : null;
  if (code === "ENOENT" || code === "ENOTDIR")
    return makeError("target_not_found", "The target does not exist", { path });
  if (code === "EACCES" || code === "EPERM")
    return makeError("access_denied", "The target cannot be read by the current user", { path });
  if (code === "EISDIR")
    return makeError("unsupported_target", "The target is a directory", { path });
  // O_NOFOLLOW refuses a symbolic link as the final component with ELOOP
  // (EMLINK on some BSDs); a socket cannot be opened as a file.
  if (code === "ELOOP" || code === "EMLINK")
    return makeError("unsupported_target", "The target is a symbolic link; select the file it points to", { path });
  if (code === "ENXIO" || code === "EOPNOTSUPP" || (errno !== null && NOT_A_FILE_ERRNOS.has(errno)))
    return makeError("unsupported_target", "The target is not a regular file", { path });
  return makeError("provider_failure", "The target could not be read", { path });
};

/**
 * Open flags: read-only; never follow a symbolic link as the final path
 * component; never block opening a FIFO or device. Flags the platform does
 * not define (O_NOFOLLOW and O_NONBLOCK on Windows) are left out.
 */
const OPEN_FLAGS = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0);
const NOFOLLOW_SUPPORTED = constants.O_NOFOLLOW !== undefined;

export interface OpenedFile {
  readonly handle: FileHandle;
  readonly size: number;
}

/**
 * Open a regular file for reading, deciding what it is from the opened
 * descriptor rather than from an earlier lookup of the path, so the file
 * cannot be swapped for a link, FIFO or device between check and use.
 *
 * Only the final path component is protected: symbolic links in parent
 * directories are followed. Where O_NOFOLLOW is unavailable (Windows), the
 * path is checked with lstat first and the opened file must be the same
 * file (device and inode); that fallback has not been run on Windows.
 */
export const openRegularFile = async (path: string): Promise<Result<OpenedFile, ErrorEnvelope>> => {
  let before;
  if (!NOFOLLOW_SUPPORTED) {
    try {
      before = await lstat(path);
    } catch (cause: unknown) {
      return err(filesystemError(cause, path));
    }
    if (before.isSymbolicLink()) return err(filesystemError({ code: "ELOOP" }, path));
  }
  let handle: FileHandle;
  try {
    handle = await open(path, OPEN_FLAGS);
  } catch (cause: unknown) {
    return err(filesystemError(cause, path));
  }
  const refuse = async (message: string): Promise<Result<OpenedFile, ErrorEnvelope>> => {
    await handle.close();
    return err(makeError("unsupported_target", message, { path }));
  };
  let stats;
  try {
    stats = await handle.stat();
  } catch (cause: unknown) {
    await handle.close();
    return err(filesystemError(cause, path));
  }
  if (stats.isDirectory()) return refuse("The target is a directory");
  if (!stats.isFile()) return refuse("The target is not a regular file");
  if (before !== undefined && (before.dev !== stats.dev || before.ino !== stats.ino))
    return refuse("The target changed while it was being opened");
  return ok({ handle, size: stats.size });
};

/** Read chunks from an opened file until its end, closing it afterwards. */
export async function* readChunks(handle: FileHandle, chunkBytes = 64 * 1024): AsyncGenerator<Uint8Array> {
  try {
    for (;;) {
      const buffer = new Uint8Array(chunkBytes);
      const { bytesRead } = await handle.read(buffer, 0, chunkBytes, null);
      if (bytesRead === 0) return;
      yield buffer.subarray(0, bytesRead);
    }
  } finally {
    await handle.close();
  }
}
