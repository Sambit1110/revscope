import { constants } from "node:fs";
import { access, stat } from "node:fs/promises";
import { isAbsolute, join } from "node:path";

import { makeError, type ErrorEnvelope } from "../../domain/errors.js";
import { err, ok, type Result } from "../../domain/result.js";
import { openRegularFile, readChunks } from "../safeFile.js";

/** Where Revscope was told to find Ghidra and, optionally, a JDK. Values come from configuration. */
export interface GhidraSettings {
  readonly ghidraDir: string;
  readonly javaHome?: string;
}

export interface GhidraInstallation {
  readonly root: string;
  readonly analyzeHeadless: string;
  /** From Ghidra/application.properties, e.g. "11.4". */
  readonly version: string;
  readonly javaHome: string | null;
}

/** Fixed names for every check, reported in details.check; configured paths never appear. */
export type InstallationCheck =
  | "ghidra_dir_not_absolute"
  | "ghidra_dir_missing"
  | "analyze_headless_missing"
  | "analyze_headless_not_executable"
  | "version_unreadable"
  | "java_home_not_absolute"
  | "java_home_invalid";

const PROPERTIES_LIMIT_BYTES = 64 * 1024;
const VERSION = /^[0-9A-Za-z][0-9A-Za-z._-]{0,63}$/u;

export const notConfigured = (check: string, message: string): ErrorEnvelope =>
  makeError("provider_not_configured", message, { engine: "ghidra", check });

const isDirectory = (path: string) =>
  stat(path).then(
    (stats) => stats.isDirectory(),
    () => false,
  );
const isFile = (path: string) =>
  stat(path).then(
    (stats) => stats.isFile(),
    () => false,
  );
const isExecutable = (path: string) =>
  access(path, constants.X_OK).then(
    () => true,
    () => false,
  );

/** Read application.version from Ghidra's application.properties, bounded. */
const readVersion = async (root: string): Promise<string | null> => {
  const opened = await openRegularFile(join(root, "Ghidra", "application.properties"));
  if (!opened.ok) return null;
  if (opened.value.size > PROPERTIES_LIMIT_BYTES) {
    await opened.value.handle.close();
    return null;
  }
  const chunks: Uint8Array[] = [];
  for await (const chunk of readChunks(opened.value.handle)) chunks.push(chunk);
  const text = Buffer.concat(chunks).toString("utf8");
  for (const line of text.split(/\r?\n/u)) {
    const match = /^\s*application\.version\s*=\s*(\S+)\s*$/u.exec(line);
    if (match?.[1] !== undefined) return VERSION.test(match[1]) ? match[1] : null;
  }
  return null;
};

/**
 * Check a configured installation. The installation directory itself is
 * trusted configuration, so links within it are followed; the input binary
 * never is. Java itself is only found when Ghidra launches.
 */
export const locateGhidra = async (settings: GhidraSettings): Promise<Result<GhidraInstallation, ErrorEnvelope>> => {
  const root = settings.ghidraDir;
  if (!isAbsolute(root)) return err(notConfigured("ghidra_dir_not_absolute", "The Ghidra directory must be an absolute path"));
  if (!(await isDirectory(root))) return err(notConfigured("ghidra_dir_missing", "The Ghidra directory does not exist"));
  const analyzeHeadless = join(root, "support", "analyzeHeadless");
  if (!(await isFile(analyzeHeadless)))
    return err(notConfigured("analyze_headless_missing", "The Ghidra directory has no support/analyzeHeadless launcher"));
  if (!(await isExecutable(analyzeHeadless)))
    return err(notConfigured("analyze_headless_not_executable", "Ghidra's analyzeHeadless launcher is not executable"));
  const version = await readVersion(root);
  if (version === null) return err(notConfigured("version_unreadable", "Ghidra's version could not be read"));
  let javaHome: string | null = null;
  if (settings.javaHome !== undefined) {
    if (!isAbsolute(settings.javaHome))
      return err(notConfigured("java_home_not_absolute", "The Java home must be an absolute path"));
    const java = join(settings.javaHome, "bin", "java");
    if (!(await isFile(java)) || !(await isExecutable(java)))
      return err(notConfigured("java_home_invalid", "The Java home has no executable bin/java"));
    javaHome = settings.javaHome;
  }
  return ok({ root, analyzeHeadless, version, javaHome });
};
