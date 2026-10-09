import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    // Real-engine tests need an installed Ghidra; they run only through `npm run test:ghidra`.
    exclude: ["tests/ghidra/**", "node_modules/**"],
    environment: "node",
    testTimeout: 30_000,
    hookTimeout: 30_000,
  },
});
