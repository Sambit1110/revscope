import { defineConfig } from "vitest/config";

/** Real-engine tests: run with `npm run test:ghidra`; they need REVSCOPE_GHIDRA_DIR. */
export default defineConfig({
  test: {
    include: ["tests/ghidra/**/*.test.ts"],
    environment: "node",
    testTimeout: 300_000,
    hookTimeout: 60_000,
    // One JVM at a time: Ghidra is memory-hungry and timings matter.
    fileParallelism: false,
  },
});
