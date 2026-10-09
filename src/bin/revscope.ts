#!/usr/bin/env node
import { main } from "../interfaces/main.js";

process.exitCode = await main({
  argv: process.argv.slice(2),
  env: process.env,
  cwd: process.cwd(),
  stdin: process.stdin,
  stdout: (text) => process.stdout.write(text),
  stderr: (text) => process.stderr.write(text),
});
