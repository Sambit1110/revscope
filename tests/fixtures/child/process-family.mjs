// Test child for process-lifecycle tests. Prints one JSON line with the pids it
// owns, then behaves according to its mode:
// - quick:       exit immediately with no descendants;
// - linger:      start a grandchild that inherits stdout/stderr, then wait;
// - exit-early:  start a grandchild that inherits stdout/stderr, then exit;
// - daemon:      start a grandchild with closed stdio, then exit;
// - ignore-term: ignore SIGTERM and wait (no grandchild).
import { spawn } from "node:child_process";

const mode = process.argv[2];
const sleeper = "setTimeout(() => {}, 60000)";
const report = (pids, then) => process.stdout.write(`${JSON.stringify(pids)}\n`, then);

if (mode === "quick") {
  report({ child: process.pid }, () => process.exit(0));
} else if (mode === "ignore-term") {
  process.on("SIGTERM", () => {});
  report({ child: process.pid });
  setTimeout(() => {}, 60000);
} else {
  const grandchild = spawn(process.execPath, ["-e", sleeper], {
    stdio: mode === "daemon" ? "ignore" : "inherit",
  });
  grandchild.unref();
  const pids = { child: process.pid, grandchild: grandchild.pid };
  if (mode === "linger") {
    report(pids);
    setTimeout(() => {}, 60000);
  } else {
    report(pids, () => process.exit(0));
  }
}
