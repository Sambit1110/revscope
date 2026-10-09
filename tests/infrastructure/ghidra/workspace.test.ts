import { createHash } from "node:crypto";
import { chmod, lstat, mkdir, readFile, stat, symlink, writeFile } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { describe, expect, it } from "vitest";

import { openRegularFile } from "../../../src/infrastructure/safeFile.js";
import {
  WORKSPACE_PREFIX,
  copyInput,
  createWorkspace,
  removeWorkspace,
  type Workspace,
} from "../../../src/infrastructure/ghidra/workspace.js";
import { tempDir } from "../../support/context.js";

const created = async (parent?: string): Promise<Workspace> => {
  const workspace = await createWorkspace(parent ?? (await tempDir()));
  if (!workspace.ok) throw new Error(JSON.stringify(workspace.error));
  return workspace.value;
};

const exists = async (path: string) =>
  lstat(path).then(
    () => true,
    () => false,
  );

const mode = async (path: string) => (await stat(path)).mode & 0o777;

const opened = async (path: string) => {
  const file = await openRegularFile(path);
  if (!file.ok) throw new Error(JSON.stringify(file.error));
  return file.value;
};

describe("analysis workspaces", () => {
  it("creates a private directory tree under the given parent", async () => {
    const parent = await tempDir();
    const workspace = await created(parent);
    expect(dirname(workspace.root)).toBe(workspace.parent);
    expect(basename(workspace.root).startsWith(WORKSPACE_PREFIX)).toBe(true);
    expect(await mode(workspace.root)).toBe(0o700);
    for (const directory of [workspace.project, workspace.home, workspace.tmp, workspace.cache, workspace.logs, dirname(workspace.input), dirname(workspace.exportPath)])
      expect(await mode(directory)).toBe(0o700);
    expect(basename(workspace.input)).toBe("artifact");
  });

  it("gives every run its own workspace", async () => {
    const parent = await tempDir();
    const [first, second] = await Promise.all([created(parent), created(parent)]);
    expect(first.root).not.toBe(second.root);
  });

  it("refuses a temporary directory whose path the engine cannot take unquoted, leaving nothing behind", async () => {
    const parent = join(await tempDir(), "has space");
    await mkdir(parent);
    const workspace = await createWorkspace(parent);
    expect(workspace.ok ? "created" : workspace.error).toMatchObject({ code: "provider_not_configured", details: { check: "temp_dir_unsuitable" } });
    expect(JSON.stringify(workspace)).not.toContain("has space");
  });
});

describe("copying the input", () => {
  it("copies under a neutral name, read-only, and hashes exactly the bytes copied", async () => {
    const source = join(await tempDir(), "Secret Customer Build.bin");
    const bytes = Buffer.from([0x7f, 0x45, 0x4c, 0x46, ...Array.from({ length: 200 }, (_, index) => index % 256)]);
    await writeFile(source, bytes);
    const workspace = await created();
    const facts = await copyInput(await opened(source), source, workspace);
    if (!facts.ok) throw new Error(JSON.stringify(facts.error));
    expect(facts.value).toMatchObject({
      displayName: "Secret Customer Build.bin",
      sizeBytes: bytes.length,
      sha256: createHash("sha256").update(bytes).digest("hex"),
    });
    expect([...facts.value.header]).toEqual([...bytes.subarray(0, 64)]);
    expect(await readFile(workspace.input)).toEqual(bytes);
    expect(await mode(workspace.input)).toBe(0o400);
    expect(await readFile(source)).toEqual(bytes);
  });

  it("refuses inputs over the limit, including ones that grow after being measured", async () => {
    const source = join(await tempDir(), "big.bin");
    await writeFile(source, Buffer.alloc(100));
    const workspace = await created();
    const declared = await copyInput(await opened(source), source, workspace, 50);
    expect(declared.ok ? "copied" : declared.error).toMatchObject({ code: "resource_limit", details: { limit_bytes: 50, size_bytes: 100 } });
    // Measured at 10 bytes, but 100 arrive while copying.
    const grown = await copyInput({ ...(await opened(source)), size: 10 }, source, await created(), 50);
    expect(grown.ok ? "copied" : grown.error.code).toBe("resource_limit");
  });
});

describe("removing a workspace", () => {
  it("removes everything, including read-only files and directories the engine left", async () => {
    const workspace = await created();
    await writeFile(join(workspace.home, "settings"), "x");
    await mkdir(join(workspace.project, "locked"));
    await writeFile(join(workspace.project, "locked", "db"), "x");
    await chmod(join(workspace.project, "locked", "db"), 0o400);
    await chmod(join(workspace.project, "locked"), 0o500);
    expect(await removeWorkspace(workspace)).toBe("removed");
    expect(await exists(workspace.root)).toBe(false);
  });

  it("removes links inside the workspace without following them", async () => {
    const outside = join(await tempDir(), "keep.txt");
    await writeFile(outside, "keep");
    const workspace = await created();
    await symlink(outside, join(workspace.tmp, "link"));
    await symlink(dirname(outside), join(workspace.tmp, "dir-link"));
    expect(await removeWorkspace(workspace)).toBe("removed");
    expect(await readFile(outside, "utf8")).toBe("keep");
  });

  it("refuses anything that is not a workspace it created", async () => {
    const parent = await tempDir();
    const elsewhere = join(parent, "important");
    await mkdir(elsewhere);
    const lookalike = join(parent, `${WORKSPACE_PREFIX}link`);
    await symlink(elsewhere, lookalike);
    const nested = join(parent, "sub", `${WORKSPACE_PREFIX}x`);
    await mkdir(nested, { recursive: true });
    expect(await removeWorkspace({ parent, root: elsewhere })).toBe("failed");
    expect(await removeWorkspace({ parent, root: lookalike })).toBe("failed");
    expect(await removeWorkspace({ parent, root: nested })).toBe("failed");
    expect(await removeWorkspace({ parent, root: join(parent, `${WORKSPACE_PREFIX}x`, "..", "important") })).toBe("failed");
    for (const path of [elsewhere, lookalike, nested]) expect(await exists(path)).toBe(true);
  });

  it("reports an already removed workspace as removed", async () => {
    const workspace = await created();
    expect(await removeWorkspace(workspace)).toBe("removed");
    expect(await removeWorkspace(workspace)).toBe("removed");
  });
});
