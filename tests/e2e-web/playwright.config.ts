import { defineConfig, devices } from "@playwright/test";

const webPort = Number(process.env.ONELAYER_E2E_WEB_PORT ?? "8198");
const gateCEvidence = process.env.ONELAYER_GATE_C_EVIDENCE === "yes";
const reportDirectory = process.env.ONELAYER_E2E_REPORT_DIR ?? "playwright-report";
const outputDirectory = process.env.ONELAYER_E2E_OUTPUT_DIR ?? "test-results";

export default defineConfig({
  testDir: "./specs",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 60_000,
  reporter: [["list"], ["html", { open: "never", outputFolder: reportDirectory }]],
  outputDir: outputDirectory,
  use: {
    baseURL: `http://127.0.0.1:${webPort}`,
    trace: gateCEvidence ? "on" : "retain-on-failure",
    screenshot: gateCEvidence ? "on" : "only-on-failure",
    video: "off",
  },
  projects: [
    { name: "desktop", use: { ...devices["Desktop Chrome"] } },
    { name: "mobile", use: { ...devices["Pixel 7"] } },
  ],
  webServer: {
    command: "node --experimental-transform-types start-stack.ts",
    url: `http://127.0.0.1:${webPort}/verify`,
    reuseExistingServer: false,
    timeout: 120_000,
    stdout: "pipe",
    stderr: "pipe",
  },
});
