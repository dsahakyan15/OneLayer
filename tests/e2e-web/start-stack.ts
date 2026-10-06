// Boots deterministic E2E: the fixture backend plus a production build of
// apps/mvp-web pointed at it. No validator and no SOL are required.
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { createFixtureBackend } from "./fixture-backend.ts";

const here = dirname(fileURLToPath(import.meta.url));
const webRoot = resolve(here, "../../apps/mvp-web");
const webPort = Number(process.env.ONELAYER_E2E_WEB_PORT ?? "8198");
const fixturePort = Number(process.env.ONELAYER_E2E_FIXTURE_PORT ?? "8199");
const webBaseUrl = `http://127.0.0.1:${webPort}`;

const { server } = createFixtureBackend(webBaseUrl);
server.listen(fixturePort, "127.0.0.1", () => {
  process.stdout.write(`fixture backend on 127.0.0.1:${fixturePort}\n`);
});

const next = spawn("npx", ["next", "start", "-H", "127.0.0.1", "-p", String(webPort)], {
  cwd: webRoot,
  stdio: "inherit",
  env: {
    ...process.env,
    NODE_ENV: "production",
    NEXT_TELEMETRY_DISABLED: "1",
    ONELAYER_ADMIN_API_URL: `http://127.0.0.1:${fixturePort}`,
    ONELAYER_VERIFIER_URL: `http://127.0.0.1:${fixturePort}`,
  },
});

function shutdown(): void {
  next.kill("SIGTERM");
  server.close();
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
next.on("exit", (code) => {
  server.close();
  process.exit(code ?? 0);
});
