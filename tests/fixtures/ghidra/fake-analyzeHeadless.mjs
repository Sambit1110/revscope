// Test stand-in for Ghidra's support/analyzeHeadless. It never analyzes
// anything: it records how it was invoked, then behaves as its control file
// (<install>/fake-control.json) says. Modes:
// - success:       write control.export to the export path and exit 0;
// - slow-success:  wait control.delayMs, then as success;
// - partial-hang:  write control.export (normally without a trailer), then hang;
// - partial-exit:  write control.export, then exit 1;
// - hang:          write nothing and hang; control.grandchild starts a
//                  grandchild that inherits stdout/stderr; control.ignoreTerm
//                  ignores SIGTERM;
// - say:           print control.stdout / control.stderr, exit control.exitCode;
// - huge:          write an export larger than Revscope accepts.
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

const root = dirname(dirname(process.argv[1]));
const control = JSON.parse(readFileSync(join(root, "fake-control.json"), "utf8"));
const args = process.argv.slice(2);
const after = (flag, count = 1) => {
  const index = args.indexOf(flag);
  return index === -1 ? [] : args.slice(index + 1, index + 1 + count);
};
const [input] = after("-import");
const [scriptName, exportPath, maxFunctions, decompile, decompileTimeout, deadlineEpochMs, maxPseudocode] = after("-postScript", 7);

let grandchild = null;
if (control.mode === "hang" && control.grandchild) {
  const child = spawn(process.execPath, ["-e", "setTimeout(() => {}, 60000)"], { stdio: "inherit" });
  child.unref();
  grandchild = child.pid;
}

writeFileSync(
  join(root, "last-run.json"),
  JSON.stringify({
    args,
    cwd: process.cwd(),
    pid: process.pid,
    grandchild,
    envNames: Object.keys(process.env).toSorted(),
    env: {
      HOME: process.env.HOME ?? null,
      TMPDIR: process.env.TMPDIR ?? null,
      JAVA_TOOL_OPTIONS: process.env.JAVA_TOOL_OPTIONS ?? null,
      JAVA_HOME: process.env.JAVA_HOME ?? null,
    },
    script: { name: scriptName, exportPath, maxFunctions, decompile, decompileTimeout, deadlineEpochMs: Number(deadlineEpochMs), maxPseudocode },
    inputSha256: createHash("sha256").update(readFileSync(input)).digest("hex"),
  }),
);

const hang = () => setInterval(() => {}, 1000);
const writeExport = () => writeFileSync(exportPath, control.export ?? "");

switch (control.mode) {
  case "success":
    writeExport();
    process.exit(0);
    break;
  case "slow-success":
    setTimeout(() => {
      writeExport();
      process.exit(0);
    }, control.delayMs);
    break;
  case "partial-hang":
    writeExport();
    hang();
    break;
  case "partial-exit":
    writeExport();
    process.exit(1);
    break;
  case "hang":
    if (control.ignoreTerm) process.on("SIGTERM", () => {});
    hang();
    break;
  case "say":
    if (control.stdout) process.stdout.write(control.stdout);
    if (control.stderr) process.stderr.write(control.stderr);
    process.exitCode = control.exitCode ?? 0;
    break;
  case "huge":
    writeFileSync(exportPath, Buffer.alloc(33 * 1024 * 1024, 0x20));
    process.exit(0);
    break;
  default:
    process.stderr.write(`unknown fake mode ${control.mode}\n`);
    process.exit(99);
}
