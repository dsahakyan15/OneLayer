import { defineConfig, devices } from "@playwright/test";

// Guarded live-devnet smoke (OL-C-34) against the native MVP. It is never part
// of the default CI run.
export default defineConfig({
  testDir: "./specs-live",
  workers: 1,
  retries: 0,
  timeout: 180_000,
  reporter: [["list"]],
  use: {
    baseURL: process.env.ONELAYER_LIVE_WEB_URL ?? "http://127.0.0.1:8091",
    trace: "on",
    screenshot: "on",
  },
  outputDir: "../../deploy/devnet-demo/artifacts/live-smoke",
  projects: [{ name: "live", use: { ...devices["Desktop Chrome"] } }],
});
