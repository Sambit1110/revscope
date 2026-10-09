#!/usr/bin/env node
import { main } from "../interfaces/main.js";

// The first SIGINT or SIGTERM cancels running work, which then stops its
// child processes and reports `cancelled`; a second one exits at once.
const shutdown = new AbortController();
const onSignal = () => {
  if (shutdown.signal.aborted) process.exit(130);
  shutdown.abort();
};
process.on("SIGINT", onSignal);
process.on("SIGTERM", onSignal);

process.exitCode = await main({
  argv: process.argv.slice(2),
  env: process.env,
  cwd: process.cwd(),
  stdin: process.stdin,
  stdout: (text) => process.stdout.write(text),
  stderr: (text) => process.stderr.write(text),
  signal: shutdown.signal,
});
process.off("SIGINT", onSignal);
process.off("SIGTERM", onSignal);
