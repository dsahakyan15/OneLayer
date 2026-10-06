import assert from "node:assert/strict";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { once } from "node:events";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { createServer as createSocketServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test, { type TestContext } from "node:test";
import { fileURLToPath } from "node:url";
import { HttpIncidentIndex, HttpLifecycleIndex, HttpPublicLookup } from "../src/http-adapters.ts";
import { readServiceToken } from "../src/service-auth.ts";

/** Shape-valid synthetic credential (never a real secret). */
const SERVICE_TOKEN = `olsp_${"A".repeat(22)}.${"B".repeat(43)}`;
const REGISTRY = "gov.registry.land";
const CERTIFICATE = "ab".repeat(16);

interface Recorded {
  method: string | undefined;
  url: string;
  authorization: string | undefined;
}

/** Real loopback HTTP upstream that records what the adapter sent. */
async function upstream(
  context: TestContext,
  handler: (request: IncomingMessage, response: ServerResponse) => void = (request, response) => {
    response.writeHead(404, { "content-type": "application/json" });
    response.end("{\"code\":\"NOT_FOUND\"}");
  },
): Promise<{ baseUrl: string; requests: Recorded[] }> {
  const requests: Recorded[] = [];
  const server: Server = createServer((request, response) => {
    requests.push({ method: request.method, url: request.url ?? "", authorization: request.headers.authorization });
    handler(request, response);
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  context.after(() => new Promise<void>(resolve => server.close(() => resolve())));
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  return { baseUrl: `http://127.0.0.1:${address.port}`, requests };
}

function jsonBody(value: unknown): string {
  return JSON.stringify(value);
}

test("all four adapter reads send the scoped service bearer to the exact existing API paths", async context => {
  const bodies = new Map<string, string>([
    ["/v1/incidents", jsonBody({ registryId: REGISTRY, indexedThroughSlot: "42", incidents: [] })],
    [`/v1/certificates/${CERTIFICATE}/lifecycle`, jsonBody({ registryId: REGISTRY, certificateId: CERTIFICATE, currentRecordVersion: "2", certificateStatus: "ACTIVE" })],
    ["/v1/anchors/7", jsonBody({ batchSequence: "7" })],
    [`/v1/certificates/${CERTIFICATE}/status`, jsonBody({ certificateId: CERTIFICATE, status: "ACTIVE" })],
  ]);
  const { baseUrl, requests } = await upstream(context, (request, response) => {
    const path = (request.url ?? "").split("?")[0]!;
    const body = bodies.get(path);
    response.writeHead(body === undefined ? 404 : 200, { "content-type": "application/json" });
    response.end(body ?? jsonBody({ code: "NOT_FOUND" }));
  });

  const options = { serviceToken: SERVICE_TOKEN };
  const incidents = await new HttpIncidentIndex(baseUrl, options).query(REGISTRY, 3n);
  const lifecycle = await new HttpLifecycleIndex(baseUrl, options).query(REGISTRY, CERTIFICATE);
  const anchor = await new HttpPublicLookup(baseUrl, options).getAnchor(7n);
  const status = await new HttpPublicLookup(baseUrl, options).getCertificateStatus(CERTIFICATE);

  assert.equal(incidents?.registryId, REGISTRY);
  assert.equal(lifecycle?.certificateStatus, "ACTIVE");
  assert.deepEqual(anchor, { batchSequence: "7" });
  assert.deepEqual(status, { certificateId: CERTIFICATE, status: "ACTIVE" });
  assert.deepEqual(requests.map(entry => entry.url), [
    `/v1/incidents?registryId=${REGISTRY}&batchSequence=3`,
    `/v1/certificates/${CERTIFICATE}/lifecycle?registryId=${REGISTRY}`,
    "/v1/anchors/7",
    `/v1/certificates/${CERTIFICATE}/status`,
  ]);
  for (const entry of requests) {
    assert.equal(entry.authorization, `Bearer ${SERVICE_TOKEN}`);
    assert.equal(entry.method, "GET");
  }
});

test("without a configured token the adapters stay anonymous", async context => {
  const { baseUrl, requests } = await upstream(context, (request, response) => {
    response.writeHead(200, { "content-type": "application/json" });
    const url = request.url ?? "";
    response.end(jsonBody(url.startsWith("/v1/incidents")
      ? { registryId: REGISTRY, indexedThroughSlot: "1", incidents: [] }
      : url.includes("/lifecycle")
        ? { registryId: REGISTRY, certificateId: CERTIFICATE, currentRecordVersion: "1", certificateStatus: "ACTIVE" }
        : url.endsWith("/status")
          ? { certificateId: CERTIFICATE, status: "ACTIVE" }
          : { batchSequence: "1" }));
  });
  await new HttpPublicLookup(baseUrl).getAnchor(1n);
  await new HttpIncidentIndex(baseUrl).query(REGISTRY, 1n);
  await new HttpLifecycleIndex(baseUrl).query(REGISTRY, CERTIFICATE);
  await new HttpPublicLookup(baseUrl).getCertificateStatus(CERTIFICATE);
  assert.equal(requests.length, 4);
  for (const entry of requests) assert.equal(entry.authorization, undefined);
});

test("401 and 403 fail closed instead of reading as an absent resource", async context => {
  let status = 401;
  const { baseUrl } = await upstream(context, (_request, response) => {
    response.writeHead(status, { "content-type": "application/json" });
    response.end(jsonBody({ code: "SERVICE_CREDENTIAL_REQUIRED" }));
  });
  const lookup = new HttpPublicLookup(baseUrl, { serviceToken: SERVICE_TOKEN });
  const incidents = new HttpIncidentIndex(baseUrl, { serviceToken: SERVICE_TOKEN });
  const lifecycle = new HttpLifecycleIndex(baseUrl, { serviceToken: SERVICE_TOKEN });
  for (const call of [
    () => lookup.getAnchor(1n),
    () => lookup.getCertificateStatus(CERTIFICATE),
    () => incidents.query(REGISTRY, 1n),
    () => lifecycle.query(REGISTRY, CERTIFICATE),
  ]) {
    await assert.rejects(call(), /upstream HTTP 401/);
    status = 403;
    await assert.rejects(call(), /upstream HTTP 403/);
    status = 401;
  }
});

test("404 stays a null lookup, and 5xx or malformed JSON fail closed", async context => {
  let mode: "404" | "500" | "garbage" = "404";
  const { baseUrl } = await upstream(context, (_request, response) => {
    if (mode === "garbage") {
      response.writeHead(200, { "content-type": "application/json" });
      response.end("{not json");
      return;
    }
    response.writeHead(mode === "404" ? 404 : 500, { "content-type": "application/json" });
    response.end(jsonBody({ code: "NOT_FOUND" }));
  });
  const lookup = new HttpPublicLookup(baseUrl, { serviceToken: SERVICE_TOKEN });
  assert.equal(await lookup.getAnchor(1n), null);
  assert.equal(await lookup.getCertificateStatus(CERTIFICATE), null);
  mode = "500";
  await assert.rejects(lookup.getAnchor(1n), /upstream HTTP 500/);
  mode = "garbage";
  await assert.rejects(lookup.getAnchor(1n), SyntaxError);
});

test("a lifecycle response for another registry or certificate is refused", async context => {
  let registryId = REGISTRY;
  let certificateId = CERTIFICATE;
  const { baseUrl } = await upstream(context, (_request, response) => {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(jsonBody({ registryId, certificateId, currentRecordVersion: "1", certificateStatus: "ACTIVE" }));
  });
  const lifecycle = new HttpLifecycleIndex(baseUrl, { serviceToken: SERVICE_TOKEN });
  assert.equal((await lifecycle.query(REGISTRY, CERTIFICATE))?.certificateId, CERTIFICATE);

  // The thrown error is a fixed message: neither the mismatched identifier nor
  // any other response body content is echoed back to the caller or to logs.
  registryId = "other.registry";
  const foreignRegistry = await lifecycle.query(REGISTRY, CERTIFICATE).then(() => null, (error: Error) => error);
  assert.equal(foreignRegistry?.message, "lifecycle response does not match the requested certificate");
  assert.ok(!foreignRegistry!.message.includes(registryId));
  registryId = REGISTRY;
  certificateId = "cd".repeat(16);
  const foreignCertificate = await lifecycle.query(REGISTRY, CERTIFICATE).then(() => null, (error: Error) => error);
  assert.equal(foreignCertificate?.message, "lifecycle response does not match the requested certificate");
  assert.ok(!foreignCertificate!.message.includes(certificateId));
});

test("a redirect is not followed and the target never sees the token", async context => {
  const target = await upstream(context, (_request, response) => {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(jsonBody({ batchSequence: "1" }));
  });
  const redirector = await upstream(context, (_request, response) => {
    response.writeHead(302, { location: `${target.baseUrl}/v1/anchors/1` });
    response.end();
  });
  const lookup = new HttpPublicLookup(redirector.baseUrl, { serviceToken: SERVICE_TOKEN });
  await assert.rejects(lookup.getAnchor(1n));
  assert.equal(redirector.requests.length, 1);
  assert.equal(redirector.requests[0]!.authorization, `Bearer ${SERVICE_TOKEN}`);
  assert.equal(target.requests.length, 0, "redirect target must receive no request and no token");
});

test("token-authenticated origins are restricted to HTTPS or explicit loopback HTTP", () => {
  const token = { serviceToken: SERVICE_TOKEN };
  for (const baseUrl of ["http://lookup.example", "http://10.0.0.5:8090", "http://0.0.0.0:8090", "ftp://lookup.example"]) {
    assert.throws(() => new HttpPublicLookup(baseUrl, token), TypeError, baseUrl);
    assert.throws(() => new HttpIncidentIndex(baseUrl, token), TypeError, baseUrl);
    assert.throws(() => new HttpLifecycleIndex(baseUrl, token), TypeError, baseUrl);
  }
  assert.doesNotThrow(() => new HttpPublicLookup("https://lookup.example", token));
  assert.doesNotThrow(() => new HttpPublicLookup("http://127.0.0.1:8090", token));
  assert.doesNotThrow(() => new HttpPublicLookup("http://127.9.9.9:8090", token));
  assert.doesNotThrow(() => new HttpPublicLookup("http://localhost:8090", token));
  assert.doesNotThrow(() => new HttpPublicLookup("http://[::1]:8090", token));
});

test("base URLs with userinfo, a path, a query or a fragment are refused in every mode", () => {
  const ambiguous = [
    "http://user:pass@lookup.example",
    "http://lookup.example/api",
    "http://lookup.example/?tenant=1",
    "http://lookup.example/#fragment",
    "ftp://lookup.example",
    "file:///etc/passwd",
    "not a url",
  ];
  for (const baseUrl of ambiguous) {
    assert.throws(() => new HttpPublicLookup(baseUrl), TypeError, baseUrl);
    assert.throws(() => new HttpIncidentIndex(baseUrl, { serviceToken: SERVICE_TOKEN }), TypeError, baseUrl);
    assert.throws(() => new HttpLifecycleIndex(baseUrl, { serviceToken: SERVICE_TOKEN }), TypeError, baseUrl);
  }
  // Anonymous demo mode keeps accepting plain HTTP outside loopback.
  assert.doesNotThrow(() => new HttpPublicLookup("http://lookup.example"));
});

test("token files are bounded and refused before anything is sent", async context => {
  const dir = await mkdtemp(join(tmpdir(), "onelayer-token-size-"));
  context.after(() => rm(dir, { recursive: true, force: true }));
  const oversized = join(dir, "oversized.token");
  await writeFile(oversized, `${SERVICE_TOKEN}\n${"#".repeat(5000)}\n`);
  assert.throws(() => readServiceToken({ ONELAYER_LOOKUP_SERVICE_TOKEN_FILE: oversized }, "ONELAYER_LOOKUP_SERVICE_TOKEN_FILE"), /larger than 4096 bytes/);
  const directory = join(dir, "subdir");
  await mkdir(directory);
  assert.throws(() => readServiceToken({ ONELAYER_LOOKUP_SERVICE_TOKEN_FILE: directory }, "ONELAYER_LOOKUP_SERVICE_TOKEN_FILE"), /not a regular file/);
  assert.throws(() => readServiceToken({ ONELAYER_LOOKUP_SERVICE_TOKEN_FILE: "" }, "ONELAYER_LOOKUP_SERVICE_TOKEN_FILE"), /is empty/);
  assert.throws(() => new HttpPublicLookup("http://127.0.0.1:1", { serviceToken: SERVICE_TOKEN.repeat(2) }), TypeError);
});

test("resource IDs and a malformed token are rejected before any request is made", async context => {
  const original = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (async () => { calls += 1; throw new Error("fetch must not run"); }) as typeof fetch;
  context.after(() => { globalThis.fetch = original; });

  const absent = join(tmpdir(), "onelayer-absent-token-file");
  assert.throws(() => readServiceToken({ ONELAYER_LOOKUP_SERVICE_TOKEN_FILE: absent }, "ONELAYER_LOOKUP_SERVICE_TOKEN_FILE"), /cannot be read/);
  assert.throws(() => new HttpPublicLookup("http://127.0.0.1:1", { serviceToken: "olsp_short" }), TypeError);
  assert.throws(() => new HttpIncidentIndex("http://127.0.0.1:1", { serviceToken: `${SERVICE_TOKEN} ` }), TypeError);

  const lookup = new HttpPublicLookup("http://127.0.0.1:1", { serviceToken: SERVICE_TOKEN });
  const incidents = new HttpIncidentIndex("http://127.0.0.1:1", { serviceToken: SERVICE_TOKEN });
  const lifecycle = new HttpLifecycleIndex("http://127.0.0.1:1", { serviceToken: SERVICE_TOKEN });
  await assert.rejects(lookup.getAnchor(-1n), TypeError);
  await assert.rejects(lookup.getCertificateStatus("../../v1/incidents"), TypeError);
  await assert.rejects(lookup.getCertificateStatus("AB".repeat(16)), TypeError);
  // Token-authenticated reads apply the stricter registry character set.
  await assert.rejects(incidents.query("../registry", 1n), TypeError);
  await assert.rejects(incidents.query("gov/registry", 1n), TypeError);
  await assert.rejects(incidents.query("gov registry", 1n), TypeError);
  await assert.rejects(incidents.query("registry?x=1", 1n), TypeError);
  await assert.rejects(incidents.query(REGISTRY, 0x1_0000_0000_0000_0000n), TypeError);
  await assert.rejects(lifecycle.query(REGISTRY, "../../v1/incidents"), TypeError);
  assert.equal(calls, 0, "no request may be attempted with an invalid resource ID or token");

  // The anonymous adapters keep the pre-existing permissive semantics: the
  // registry ID travels in a query parameter and is URL-encoded there.
  const anonymous = new HttpIncidentIndex("http://127.0.0.1:1");
  await assert.rejects(anonymous.query("r", 1n), /fetch must not run/);
  await assert.rejects(anonymous.query("gov registry", 1n), /fetch must not run/);
  assert.equal(calls, 2, "anonymous adapters reach the request for the prior fixture IDs");
});

/**
 * Runs the checked-in verifier entry point to a decision: it either refuses at
 * startup (process exits non-zero) or reaches "verifier listening", after which
 * the test terminates the process it owns.
 */
async function startVerifier(context: TestContext, env: NodeJS.ProcessEnv): Promise<{ refused: boolean; output: string }> {
  const child: ChildProcess = spawn(process.execPath, ["--experimental-transform-types", fileURLToPath(new URL("../src/main.ts", import.meta.url))], {
    env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  context.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL"); });
  let output = "";
  child.stdout!.on("data", data => { output += String(data); });
  child.stderr!.on("data", data => { output += String(data); });
  const exited = new Promise<void>(resolve => child.once("exit", () => resolve()));
  const listening = new Promise<void>(resolve => {
    const check = () => { if (output.includes("verifier listening")) resolve(); };
    child.stdout!.on("data", check);
    child.once("exit", check);
  });
  let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; child.kill("SIGKILL"); }, 20_000);
  await Promise.race([exited, listening]);
  clearTimeout(timer);
  if (timedOut) {
    assert.fail(`verifier startup timed out: ${output}`);
  }
  if (child.exitCode === null && output.includes("verifier listening")) {
    const closed = once(child, "close");
    child.kill("SIGKILL");
    await closed;
    return { refused: false, output };
  }
  assert.notEqual(child.exitCode, 0, `verifier exited ${child.exitCode} without a startup decision: ${output}`);
  return { refused: true, output };
}

/** Reserves an ephemeral loopback port; the listener is closed before use. */
async function unusedPort(): Promise<number> {
  const listener = createSocketServer().listen(0, "127.0.0.1");
  await once(listener, "listening");
  const address = listener.address();
  assert.ok(address && typeof address !== "string");
  await new Promise<void>(resolve => listener.close(() => resolve()));
  return address.port;
}

test("startup refuses a configured token file that is missing, unreadable, empty or malformed", { timeout: 90_000 }, async context => {
  const dir = await mkdtemp(join(tmpdir(), "onelayer-verifier-token-"));
  context.after(() => rm(dir, { recursive: true, force: true }));
  // The trust watermark must live in a directory disjoint from the policy directory.
  const stateDir = await mkdtemp(join(tmpdir(), "onelayer-verifier-state-"));
  context.after(() => rm(stateDir, { recursive: true, force: true }));
  const policyFile = join(dir, "policy.json");
  const policyDocument = JSON.stringify({
    version: 1, revision: 1, validUntil: "2099-01-01T00:00:00Z", genesisHash: "synthetic-genesis",
    registryId: REGISTRY, programIdHex: "01".repeat(32), configPdaHex: "02".repeat(32),
    schemaVersions: [1], registryVersions: ["1"],
    issuers: [{
      keyId: "synthetic", publicKeyHex: "03".repeat(32), algorithm: "Ed25519",
      validFrom: "2020-01-01T00:00:00Z", validUntil: "2099-01-01T00:00:00Z", revoked: false,
    }],
  });
  await writeFile(policyFile, policyDocument);
  const baseEnv: NodeJS.ProcessEnv = {
    ...process.env,
    ONELAYER_TRUST_POLICY_FILE: policyFile,
    ONELAYER_TRUST_STATE_FILE: join(stateDir, "accepted.json"),
    ONELAYER_TRUST_POLICY_MIN_REVISION: "1",
    ONELAYER_TRUST_POLICY_UNSIGNED: "1",
    ONELAYER_TRUST_STATE_BOOTSTRAP: createHash("sha256").update(policyDocument).digest("hex"),
    ONELAYER_RPC_URL: "http://127.0.0.1:1",
    ONELAYER_INCIDENT_INDEX_URL: "http://127.0.0.1:1",
    ONELAYER_LOOKUP_URL: "http://127.0.0.1:1",
  };

  const malformed = join(dir, "malformed.token");
  await writeFile(malformed, "not-a-service-token\n");
  const empty = join(dir, "empty.token");
  await writeFile(empty, "\n");
  const missing = join(dir, "missing.token");

  const refused = await startVerifier(context, { ...baseEnv, ONELAYER_LOOKUP_SERVICE_TOKEN_FILE: malformed });
  assert.equal(refused.refused, true);
  assert.match(refused.output, /ONELAYER_LOOKUP_SERVICE_TOKEN_FILE does not contain a valid service token/);
  assert.ok(!refused.output.includes("not-a-service-token"), "the rejected content must not be logged");

  const unreadable = await startVerifier(context, { ...baseEnv, ONELAYER_INCIDENT_SERVICE_TOKEN_FILE: missing });
  assert.equal(unreadable.refused, true);
  assert.match(unreadable.output, /ONELAYER_INCIDENT_SERVICE_TOKEN_FILE cannot be read/);

  const blank = await startVerifier(context, { ...baseEnv, ONELAYER_INCIDENT_SERVICE_TOKEN_FILE: empty });
  assert.equal(blank.refused, true);
  assert.match(blank.output, /ONELAYER_INCIDENT_SERVICE_TOKEN_FILE does not contain a valid service token/);

  const directory = await startVerifier(context, { ...baseEnv, ONELAYER_LOOKUP_SERVICE_TOKEN_FILE: dir });
  assert.equal(directory.refused, true);
  assert.match(directory.output, /ONELAYER_LOOKUP_SERVICE_TOKEN_FILE is not a regular file/);

  const tokenFile = join(dir, "lookup.token");
  await writeFile(tokenFile, `${SERVICE_TOKEN}\n`);
  const started = await startVerifier(context, { ...baseEnv, PORT: String(await unusedPort()), ONELAYER_LOOKUP_SERVICE_TOKEN_FILE: tokenFile });
  assert.equal(started.refused, false, started.output);
  assert.match(started.output, /verifier listening/);
});

test("a configured FIFO token file is refused without blocking startup", { timeout: 60_000 }, async context => {
  const dir = await mkdtemp(join(tmpdir(), "onelayer-verifier-fifo-"));
  context.after(() => rm(dir, { recursive: true, force: true }));
  const stateDir = await mkdtemp(join(tmpdir(), "onelayer-verifier-fifo-state-"));
  context.after(() => rm(stateDir, { recursive: true, force: true }));
  const fifo = join(dir, "lookup.token");
  const made = spawnSync("mkfifo", [fifo], { encoding: "utf8" });
  assert.equal(made.status, 0, `mkfifo failed: ${made.stderr}`);
  const policyDocument = JSON.stringify({
    version: 1, revision: 1, validUntil: "2099-01-01T00:00:00Z", genesisHash: "synthetic-genesis",
    registryId: REGISTRY, programIdHex: "01".repeat(32), configPdaHex: "02".repeat(32),
    schemaVersions: [1], registryVersions: ["1"],
    issuers: [{
      keyId: "synthetic", publicKeyHex: "03".repeat(32), algorithm: "Ed25519",
      validFrom: "2020-01-01T00:00:00Z", validUntil: "2099-01-01T00:00:00Z", revoked: false,
    }],
  });
  const policyFile = join(dir, "policy.json");
  await writeFile(policyFile, policyDocument);

  // No writer is ever attached to the FIFO. With a blocking open this would
  // hang until the helper's 20 s deadline; the fix must refuse it immediately.
  const started = await startVerifier(context, {
    ...process.env,
    ONELAYER_TRUST_POLICY_FILE: policyFile,
    ONELAYER_TRUST_STATE_FILE: join(stateDir, "accepted.json"),
    ONELAYER_TRUST_POLICY_MIN_REVISION: "1",
    ONELAYER_TRUST_POLICY_UNSIGNED: "1",
    ONELAYER_TRUST_STATE_BOOTSTRAP: createHash("sha256").update(policyDocument).digest("hex"),
    ONELAYER_RPC_URL: "http://127.0.0.1:1",
    ONELAYER_INCIDENT_INDEX_URL: "http://127.0.0.1:1",
    ONELAYER_LOOKUP_URL: "http://127.0.0.1:1",
    ONELAYER_LOOKUP_SERVICE_TOKEN_FILE: fifo,
    PORT: "8080",
  });
  assert.equal(started.refused, true, started.output);
  assert.match(started.output, /ONELAYER_LOOKUP_SERVICE_TOKEN_FILE is not a regular file/);
});
