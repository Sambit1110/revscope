import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { chmod, lstat, mkdir, mkdtemp, open, readdir, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";

import type { ArtifactFacts } from "../../application/ports.js";
import { makeError, type ErrorEnvelope } from "../../domain/errors.js";
import { err, ok, type Result } from "../../domain/result.js";
import { readChunks, type OpenedFile } from "../safeFile.js";

export const WORKSPACE_PREFIX = "revscope-ghidra-";
/** Largest input Revscope copies into a workspace. */
export const MAX_INPUT_BYTES = 256 * 1024 * 1024;
const HEADER_BYTES = 64;

/**
 * Workspace paths are passed to the engine on its command line and in
 * JAVA_TOOL_OPTIONS, which splits on whitespace. Only plain characters are
 * accepted, so no quoting is ever needed.
 */
const PLAIN_PATH = /^[A-Za-z0-9._/-]+$/u;

/** One run's private directory tree; nothing outside it is written. */
export interface Workspace {
  readonly parent: string;
  readonly root: string;
  /** The copy of the input the engine analyzes, under a neutral name. */
  readonly input: string;
  readonly project: string;
  readonly exportPath: string;
  readonly home: string;
  readonly tmp: string;
  readonly logs: string;
}

const failure = (message: string, check?: string): ErrorEnvelope =>
  check === undefined
    ? makeError("provider_failure", message, {})
    : makeError("provider_not_configured", message, { engine: "ghidra", check });

/** Create a fresh workspace (directories mode 0700) under the system temporary directory. */
export const createWorkspace = async (parent?: string): Promise<Result<Workspace, ErrorEnvelope>> => {
  let base: string;
  let root: string;
  try {
    base = await realpath(parent ?? tmpdir());
    root = await mkdtemp(join(base, WORKSPACE_PREFIX));
  } catch {
    return err(failure("The analysis workspace could not be created"));
  }
  const workspace: Workspace = {
    parent: base,
    root,
    input: join(root, "input", "artifact"),
    project: join(root, "project"),
    exportPath: join(root, "out", "export.ndjson"),
    home: join(root, "home"),
    tmp: join(root, "tmp"),
    logs: join(root, "logs"),
  };
  if (!PLAIN_PATH.test(root)) {
    await removeWorkspace(workspace);
    return err(failure("The temporary directory's path is not usable by the engine", "temp_dir_unsuitable"));
  }
  try {
    await chmod(root, 0o700);
    for (const directory of ["input", "project", "out", "home", "tmp", "logs"])
      await mkdir(join(root, directory), { mode: 0o700 });
  } catch {
    await removeWorkspace(workspace);
    return err(failure("The analysis workspace could not be prepared"));
  }
  return ok(workspace);
};

const tooLarge = (path: string, size: number, limit: number): ErrorEnvelope =>
  makeError("resource_limit", "The input is larger than the supported limit", {
    path,
    limit_bytes: limit,
    size_bytes: size,
  });

/**
 * Copy an opened input into the workspace, hashing exactly the bytes written,
 * so the identity evidence describes what the engine analyzed. The copy is
 * made read-only. `path` is the caller's path, used only in errors.
 */
export const copyInput = async (
  source: OpenedFile,
  path: string,
  workspace: Workspace,
  maxBytes = MAX_INPUT_BYTES,
): Promise<Result<ArtifactFacts, ErrorEnvelope>> => {
  if (source.size > maxBytes) {
    await source.handle.close();
    return err(tooLarge(path, source.size, maxBytes));
  }
  const hash = createHash("sha256");
  const header: Uint8Array[] = [];
  let headerLength = 0;
  let size = 0;
  let target;
  try {
    target = await open(
      workspace.input,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0),
      0o600,
    );
  } catch {
    await source.handle.close();
    return err(failure("The input could not be copied into the workspace"));
  }
  try {
    for await (const chunk of readChunks(source.handle)) {
      size += chunk.length;
      // The limit also holds if the file grows after it was measured.
      if (size > maxBytes) return err(tooLarge(path, size, maxBytes));
      hash.update(chunk);
      if (headerLength < HEADER_BYTES) {
        const part = chunk.slice(0, HEADER_BYTES - headerLength);
        header.push(part);
        headerLength += part.length;
      }
      await target.write(chunk);
    }
  } catch {
    return err(failure("The input could not be copied into the workspace"));
  } finally {
    await target.close();
  }
  try {
    await chmod(workspace.input, 0o400);
  } catch {
    return err(failure("The input copy could not be made read-only"));
  }
  return ok({
    displayName: basename(path),
    sizeBytes: size,
    sha256: hash.digest("hex"),
    header: new Uint8Array(Buffer.concat(header)),
  });
};

/** Give the owner write access throughout, without following links, so removal cannot be blocked. */
const makeRemovable = async (directory: string): Promise<void> => {
  await chmod(directory, 0o700);
  for (const entry of await readdir(directory, { withFileTypes: true }))
    if (entry.isDirectory()) await makeRemovable(join(directory, entry.name));
};

/**
 * Remove a workspace, and only a workspace: the path must be a real
 * directory (not a link) directly inside the parent it was created in, with
 * the workspace prefix. Returns whether it is gone; never throws.
 */
export const removeWorkspace = async (workspace: Pick<Workspace, "parent" | "root">): Promise<"removed" | "failed"> => {
  const { parent, root } = workspace;
  if (dirname(root) !== parent || !basename(root).startsWith(WORKSPACE_PREFIX)) return "failed";
  const gone = async () => {
    try {
      await lstat(root);
      return false;
    } catch (cause: unknown) {
      return typeof cause === "object" && cause !== null && "code" in cause && cause.code === "ENOENT";
    }
  };
  try {
    const stats = await lstat(root);
    if (!stats.isDirectory() || stats.isSymbolicLink()) return "failed";
  } catch {
    return (await gone()) ? "removed" : "failed";
  }
  for (const attempt of [1, 2]) {
    try {
      if (attempt === 2) await makeRemovable(root);
      await rm(root, { recursive: true, force: true });
    } catch {
      // Retried once with permissions repaired.
    }
    if (await gone()) return "removed";
  }
  return "failed";
};
