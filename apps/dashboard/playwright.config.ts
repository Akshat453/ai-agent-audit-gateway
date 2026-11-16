import { defineConfig, devices } from "@playwright/test";

// Phase 9 dashboard e2e. The stack is started by e2e/run.sh (gateway + seeded tenant +
// production dashboard build); this config only drives the browser.
export default defineConfig({
  testDir: "e2e",
  outputDir: "e2e/.results",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL: process.env.AGW_E2E_BASE_URL ?? "http://127.0.0.1:13000",
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
