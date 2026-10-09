import { mkdir, symlink, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { FsJsonFileReader } from "../../src/infrastructure/jsonFileReader.js";
import { openRegularFile } from "../../src/infrastructure/safeFile.js";
import { tempDir } from "../support/context.js";

const posix = process.platform !== "win32";

const outcome = async (path: string) => {
  const opened = await openRegularFile(path);
  if (opened.ok) {
    await opened.value.handle.close();
    return { ok: true as const, size: opened.value.size };
  }
  return { ok: false as const, code: opened.error.code, message: opened.error.message };
};

describe("opening regular files", () => {
  it("opens a regular file and reports its size from the opened descriptor", async () => {
    const directory = await tempDir();
    await writeFile(join(directory, "file.bin"), "12345");
    expect(await outcome(join(directory, "file.bin"))).toEqual({ ok: true, size: 5 });
  });

  it("refuses a symbolic link as the final component, whatever it points to", async () => {
    const directory = await tempDir();
    await writeFile(join(directory, "real"), "x");
    await mkdir(join(directory, "folder"));
    await symlink(join(directory, "real"), join(directory, "to-file"));
    await symlink(join(directory, "folder"), join(directory, "to-folder"));
    for (const link of ["to-file", "to-folder"])
      expect(await outcome(join(directory, link))).toMatchObject({ ok: false, code: "unsupported_target", message: expect.stringContaining("symbolic link") });
  });

  it("follows symbolic links in parent directories (documented limitation)", async () => {
    const directory = await tempDir();
    await mkdir(join(directory, "real-parent"));
    await writeFile(join(directory, "real-parent", "file"), "abc");
    await symlink(join(directory, "real-parent"), join(directory, "linked-parent"));
    expect(await outcome(join(directory, "linked-parent", "file"))).toEqual({ ok: true, size: 3 });
  });

  it("refuses directories and missing files with stable codes", async () => {
    const directory = await tempDir();
    expect(await outcome(directory)).toMatchObject({ ok: false, code: "unsupported_target" });
    expect(await outcome(join(directory, "absent"))).toMatchObject({ ok: false, code: "target_not_found" });
  });

  it.skipIf(!posix)("refuses a socket without blocking", async () => {
    const directory = await tempDir();
    const socketPath = join(directory, "s.sock");
    const server = createServer();
    await new Promise<void>((resolve) => server.listen(socketPath, resolve));
    try {
      expect(await outcome(socketPath)).toMatchObject({ ok: false, code: "unsupported_target" });
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});

describe("JSON file reading", () => {
  it("refuses invalid UTF-8 instead of replacing it", async () => {
    const directory = await tempDir();
    const path = join(directory, "bad.json");
    await writeFile(path, Buffer.concat([Buffer.from('{"name": "a'), Buffer.from([0xff]), Buffer.from('b"}')]));
    const read = await new FsJsonFileReader().read(path);
    expect(read.ok ? "accepted" : read.error.code).toBe("invalid_input");
  });

  it("enforces the byte limit", async () => {
    const directory = await tempDir();
    const path = join(directory, "big.json");
    await writeFile(path, JSON.stringify({ padding: "x".repeat(100) }));
    const read = await new FsJsonFileReader(32).read(path);
    expect(read.ok ? "accepted" : read.error).toMatchObject({ code: "resource_limit", details: { limit_bytes: 32 } });
  });

  it("refuses a symbolic link to a JSON file", async () => {
    const directory = await tempDir();
    await writeFile(join(directory, "real.json"), "{}");
    await symlink(join(directory, "real.json"), join(directory, "link.json"));
    const read = await new FsJsonFileReader().read(join(directory, "link.json"));
    expect(read.ok ? "accepted" : read.error.code).toBe("unsupported_target");
  });
});
