import { defineConfig } from "@playwright/test";

// Unit tests of the plain-English layer (src/humanize, ADR-0039). No browser, no server.
export default defineConfig({
  testDir: "src/humanize",
  testMatch: "**/*.test.ts",
  outputDir: "e2e/.results-unit",
  reporter: [["list"]],
  workers: 1,
});
