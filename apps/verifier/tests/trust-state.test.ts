import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createPrivateKey, sign } from "node:crypto";
import { chmod, mkdir, mkdtemp, readdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { hostname } from "node:os";
import { fileURLToPath } from "node:url";
import test, { type TestContext } from "node:test";
import { floorStateFile, loadTrustPolicy, policyDigest, startTrustRefresh, POLICY_SIGNATURE_DOMAIN, SIGNED_POLICY_FORMAT, trustOptionsFromEnv, type LoadTrustPolicyOptions, type RootSet, type TrustMode, type TrustRootKey } from "../src/trust-state.ts";
import { addEnvelopeSignature, createEnvelope, publicKeyHexFromSeed, ROOT_SET_FORMAT } from "../src/trust-envelope.ts";
import { FileTrustFloorSource, FLOOR_FORMAT, LabChallengeFloorSource } from "../src/trust-floor.ts";
import { authorizeCertificate, parseTrustPolicy, type TrustPolicy } from "../src/trust-policy.ts";
import type { CertificateBody } from "../../../packages/canonical-ts/src/index.ts";

const synthetic = {
  version: 1, revision: 2, validUntil: "2099-01-01T00:00:00Z", genesisHash: "synthetic-genesis",
  registryId: "synthetic", programIdHex: "01".repeat(32), configPdaHex: "02".repeat(32), schemaVersions: [1], registryVersions: ["1"],
  issuers: [{ keyId: "synthetic", publicKeyHex: "03".repeat(32), algorithm: "Ed25519", validFrom: "2020-01-01T00:00:00Z", validUntil: "2099-01-01T00:00:00Z", revoked: false }],
};

async function unusedPort(): Promise<number> {
  const server = createServer().listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  await new Promise<void>(resolve => server.close(() => resolve()));
  return address.port;
}

/** Runs the checked-in verifier entry point; resolves "listening" or the exit output. */
async function startVerifier(context: TestContext, env: Record<string, string>): Promise<{ ok: boolean; output: string }> {
  const child = spawn(process.execPath, ["--experimental-transform-types", fileURLToPath(new URL("../src/main.ts", import.meta.url))], {
    env: { ...process.env, PORT: String(await unusedPort()), ONELAYER_TRUST_POLICY_MIN_REVISION: "1",
      ONELAYER_RPC_URL: "http://127.0.0.1:1", ONELAYER_INCIDENT_INDEX_URL: "http://127.0.0.1:1", ONELAYER_LOOKUP_URL: "http://127.0.0.1:1", ...env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  context.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL"); });
  let output = "";
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`verifier startup timed out: ${output}`)), 10_000);
    child.stderr.on("data", data => { output += String(data); });
    child.stdout.on("data", data => {
      output += String(data);
      if (output.includes("verifier listening")) { clearTimeout(timer); child.kill("SIGKILL"); resolve({ ok: true, output }); }
    });
    child.once("exit", () => { clearTimeout(timer); resolve({ ok: output.includes("verifier listening"), output }); });
  });
}

const UNSIGNED: TrustMode = { kind: "unsigned" };
const PIN = { genesisHash: synthetic.genesisHash, registryId: synthetic.registryId, programIdHex: synthetic.programIdHex };
const BASE58_GENESIS = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
const digestOf = (text: string) => policyDigest(Buffer.from(text));

async function workspace(context: TestContext) {
  const dir = await mkdtemp(join(tmpdir(), "onelayer-trust-state-"));
  context.after(() => rm(dir, { recursive: true, force: true }));
  await mkdir(join(dir, "policy"), { mode: 0o700 });
  await mkdir(join(dir, "state"), { mode: 0o700 });
  const policyFile = join(dir, "policy", "policy.json");
  const stateFile = join(dir, "state", "accepted.json");
  const load = (extra: Partial<LoadTrustPolicyOptions> = {}) => loadTrustPolicy({ policyFile, stateFile, minimumRevision: 1, mode: UNSIGNED, ...extra });
  const put = async (text: string) => { await writeFile(policyFile, text); return digestOf(text); };
  return { dir, policyFile, stateFile, load, put };
}

test("regression: verifier restart refuses a policy rolled back below the accepted revision", { timeout: 30_000 }, async context => {
  const { policyFile, stateFile, put } = await workspace(context);
  const env = { ONELAYER_TRUST_POLICY_FILE: policyFile, ONELAYER_TRUST_STATE_FILE: stateFile, ONELAYER_TRUST_POLICY_UNSIGNED: "1" };
  const digest = await put(JSON.stringify(synthetic));
  assert.equal((await startVerifier(context, { ...env, ONELAYER_TRUST_STATE_BOOTSTRAP: digest })).ok, true);
  // The deployment floor alone (MIN_REVISION=1) would accept revision 1 again.
  await put(JSON.stringify({ ...synthetic, revision: 1 }));
  const rolledBack = await startVerifier(context, env);
  assert.equal(rolledBack.ok, false);
  assert.match(rolledBack.output, /TRUST_POLICY_ROLLBACK/);
});

test("environment contract: explicit mode, strict revision floor, digest-pinned bootstrap, deployment pin for signed", () => {
  const base = { ONELAYER_TRUST_POLICY_FILE: "/p/policy.json", ONELAYER_TRUST_STATE_FILE: "/s/state.json", ONELAYER_TRUST_POLICY_MIN_REVISION: "1" };
  const root = `root-1:${"0a".repeat(32)}`;
  const deployment = `${BASE58_GENESIS}/${PIN.registryId}/${PIN.programIdHex}`;
  for (const env of [
    base, // neither signed nor explicit unsigned
    { ...base, ONELAYER_TRUST_POLICY_UNSIGNED: "true" },
    { ...base, ONELAYER_TRUST_POLICY_UNSIGNED: "1", ONELAYER_TRUST_ROOT_KEYS: root, ONELAYER_TRUST_DEPLOYMENT: deployment },
    { ...base, ONELAYER_TRUST_ROOT_KEYS: root }, // signed without deployment pin
    { ...base, ONELAYER_TRUST_ROOT_KEYS: "", ONELAYER_TRUST_DEPLOYMENT: deployment },
    { ...base, ONELAYER_TRUST_POLICY_UNSIGNED: "1", ONELAYER_TRUST_POLICY_MIN_REVISION: "01" },
    { ...base, ONELAYER_TRUST_POLICY_UNSIGNED: "1", ONELAYER_TRUST_POLICY_MIN_REVISION: "1e3" },
    { ...base, ONELAYER_TRUST_POLICY_UNSIGNED: "1", ONELAYER_TRUST_POLICY_MIN_REVISION: "0" },
    { ...base, ONELAYER_TRUST_POLICY_UNSIGNED: "1", ONELAYER_TRUST_STATE_BOOTSTRAP: "1" },
    { ...base, ONELAYER_TRUST_POLICY_UNSIGNED: "1", ONELAYER_TRUST_STATE_FILE: "" },
    { ...base, ONELAYER_TRUST_ROOT_KEYS: root, ONELAYER_TRUST_DEPLOYMENT: `${BASE58_GENESIS}/${PIN.programIdHex}` },
    // Non-canonical deployment pins.
    ...[` ${deployment}`, `${deployment} `, `${BASE58_GENESIS}/ ${PIN.registryId}/${PIN.programIdHex}`, `${BASE58_GENESIS}/a/b/${PIN.programIdHex}`,
      `${BASE58_GENESIS}//${PIN.programIdHex}`, `${BASE58_GENESIS}/../${PIN.programIdHex}`, `${BASE58_GENESIS}/${PIN.registryId}/${PIN.programIdHex.slice(0, -2)}AB`,
      `synthetic-genesis/${PIN.registryId}/${PIN.programIdHex}`, `${BASE58_GENESIS}/${PIN.registryId}/${PIN.programIdHex}/`]
      .map(value => ({ ...base, ONELAYER_TRUST_ROOT_KEYS: root, ONELAYER_TRUST_DEPLOYMENT: value })),
  ]) assert.throws(() => trustOptionsFromEnv(env), /TRUST_CONFIG_INVALID|TRUST_ROOT_INVALID|TRUST_DEPLOYMENT_INVALID/, JSON.stringify(env));
  // The positive signed-mode contract (threshold, floor, rotations) is covered by "environment contract (signed)".
  assert.equal(trustOptionsFromEnv({ ...base, ONELAYER_TRUST_POLICY_UNSIGNED: "1" }).mode.kind, "unsigned");
});

test("watermark: digest-pinned bootstrap, atomic advance, rollback/substitution/jump fail closed", async context => {
  const { dir, stateFile, load, put } = await workspace(context);
  const digest = await put(JSON.stringify(synthetic));
  await assert.rejects(load(), /TRUST_STATE_MISSING/);
  await assert.rejects(load({ bootstrapDigest: "00".repeat(32) }), (error: Error) =>
    /TRUST_STATE_BOOTSTRAP_MISMATCH/.test(error.message) && !error.message.includes(digest), "mismatch does not disclose the actual digest");
  assert.equal((await load({ bootstrapDigest: digest })).policy.revision, 2);
  assert.equal((await load()).policy.revision, 2, "same accepted document is idempotent");
  // Same revision, different content (e.g. an issuer quietly re-added) is not a legal rotation.
  await put(JSON.stringify({ ...synthetic, issuers: [{ ...synthetic.issuers[0], revoked: true }] }));
  await assert.rejects(load(), /TRUST_POLICY_CONFLICT/);
  await put(JSON.stringify({ ...synthetic, revision: 3 }));
  assert.equal((await load()).policy.revision, 3);
  assert.equal(JSON.parse(await readFile(stateFile, "utf8")).revision, 3);
  assert.deepEqual(await readdir(join(dir, "state")), ["accepted.json"], "no temp or lock file left behind");
  const stale = await put(JSON.stringify(synthetic));
  await assert.rejects(load(), /TRUST_POLICY_ROLLBACK/);
  await assert.rejects(load({ bootstrapDigest: stale }), /TRUST_POLICY_ROLLBACK/, "bootstrap never resets an existing watermark");
  for (const revision of [3 + 1_001, Number.MAX_SAFE_INTEGER]) {
    await put(JSON.stringify({ ...synthetic, revision }));
    await assert.rejects(load(), /TRUST_POLICY_REVISION_JUMP/, "revision space cannot be exhausted in one step");
  }
  await put(JSON.stringify({ ...synthetic, revision: 3 + 1_000 }));
  assert.equal((await load()).policy.revision, 1_003);
});

test("first bootstrap is bounded by the revision floor", async context => {
  const { load, put } = await workspace(context);
  const tooHigh = await put(JSON.stringify({ ...synthetic, revision: 1 + 1_001 }));
  await assert.rejects(load({ bootstrapDigest: tooHigh }), /TRUST_POLICY_REVISION_JUMP/);
  const highest = await put(JSON.stringify({ ...synthetic, revision: 1 + 1_000 }));
  assert.equal((await load({ bootstrapDigest: highest })).policy.revision, 1_001);
});

test("stale lock after a crash fails closed with a diagnostic; documented removal recovers", async context => {
  const { stateFile, load, put } = await workspace(context);
  const digest = await put(JSON.stringify(synthetic));
  await load({ bootstrapDigest: digest });
  await writeFile(`${stateFile}.lock`, `${2 ** 22 + 12_345} ${hostname()}\n`, { mode: 0o600 });
  await assert.rejects(load({ lockTimeoutMs: 100 }), /TRUST_STATE_LOCKED.*NOT running/);
  assert.equal(JSON.parse(await readFile(stateFile, "utf8")).revision, 2, "watermark untouched");
  await rm(`${stateFile}.lock`); // documented operator step after confirming nothing uses the state
  assert.equal((await load()).policy.revision, 2);
});

test("watermark: corrupt, unreadable or unwritable state and expired policy fail closed without reset", async context => {
  const { dir, policyFile, stateFile, load, put } = await workspace(context);
  const digest = await put(JSON.stringify(synthetic));
  for (const corrupt of ["", "{", "null", JSON.stringify({ format: "onelayer.trust-state.v1", revision: 0, policyDigest: "00".repeat(32), authenticated: false }),
    JSON.stringify({ format: "onelayer.trust-state.v1", revision: 2, policyDigest: "00".repeat(32) }),
    JSON.stringify({ format: "onelayer.trust-state.v1", revision: 2, policyDigest: "00".repeat(32), authenticated: false, extra: 1 })]) {
    await writeFile(stateFile, corrupt, { mode: 0o600 });
    await assert.rejects(load({ bootstrapDigest: digest }), /TRUST_STATE_CORRUPT/);
    assert.equal(await readFile(stateFile, "utf8"), corrupt, "corrupt state is preserved for investigation");
  }
  await rm(stateFile);
  await mkdir(stateFile, { mode: 0o700 });
  await assert.rejects(load({ bootstrapDigest: digest }), /TRUST_STATE_(UNAVAILABLE|LOCATION_UNSAFE)/);
  await assert.rejects(load({ stateFile: join(dir, "missing-dir", "state.json"), bootstrapDigest: digest }), /TRUST_STATE_UNAVAILABLE/);
  await assert.rejects(load({ policyFile: join(dir, "policy", "absent.json"), bootstrapDigest: digest }), /TRUST_POLICY_UNAVAILABLE/);
  const expiredState = join(dir, "state", "expired.json");
  const expired = await put(JSON.stringify({ ...synthetic, revision: 9, validUntil: "2020-01-01T00:00:00Z" }));
  await assert.rejects(load({ stateFile: expiredState, bootstrapDigest: expired }), /TRUST_POLICY_EXPIRED/);
  await assert.rejects(readFile(expiredState), { code: "ENOENT" }, "an expired policy never advances the watermark");
  assert.ok(policyFile);
});

test("state location: disjoint private directory, private ancestors, no symlinks", async context => {
  const { dir, policyFile, stateFile, load, put } = await workspace(context);
  const digest = await put(JSON.stringify(synthetic));
  const at = async (path: string) => { await mkdir(dirname(path), { recursive: true, mode: 0o700 }); return load({ stateFile: path, bootstrapDigest: digest }); };
  await assert.rejects(load({ stateFile: join(dir, "policy", "accepted.json"), bootstrapDigest: digest }), /TRUST_STATE_LOCATION_UNSAFE.*policy directory/);
  // Probe 1: state directory inside the policy directory, and policy directory inside the state directory.
  await assert.rejects(at(join(dir, "policy", "nested", "accepted.json")), /TRUST_STATE_LOCATION_UNSAFE.*disjoint/);
  await mkdir(join(dir, "outer", "policy"), { recursive: true, mode: 0o700 });
  await writeFile(join(dir, "outer", "policy", "p.json"), JSON.stringify(synthetic));
  await assert.rejects(load({ policyFile: join(dir, "outer", "policy", "p.json"), stateFile: join(dir, "outer", "accepted.json"), bootstrapDigest: digest }),
    /TRUST_STATE_LOCATION_UNSAFE.*disjoint/);
  // Probe 2: an ancestor writable by others without the sticky bit; with the sticky bit it is accepted.
  await mkdir(join(dir, "shared"), { mode: 0o700 });
  await chmod(join(dir, "shared"), 0o777);
  await assert.rejects(at(join(dir, "shared", "state", "accepted.json")), /TRUST_STATE_LOCATION_UNSAFE.*without the sticky bit/);
  await chmod(join(dir, "shared"), 0o1777);
  assert.equal((await at(join(dir, "shared", "state", "accepted.json"))).policy.revision, 2);
  // Probe 3: a symlink anywhere in the configured state path.
  await symlink(join(dir, "shared"), join(dir, "shared-alias"));
  await assert.rejects(load({ stateFile: join(dir, "shared-alias", "state", "accepted.json") }), /TRUST_STATE_LOCATION_UNSAFE.*symlinks/);
  // Probe 4: the policy file is a symlink whose target lives in the state directory.
  await writeFile(join(dir, "state", "planted.json"), JSON.stringify(synthetic), { mode: 0o600 });
  await symlink(join(dir, "state", "planted.json"), join(dir, "policy", "via-link.json"));
  await assert.rejects(load({ policyFile: join(dir, "policy", "via-link.json"), bootstrapDigest: digest }), /TRUST_STATE_LOCATION_UNSAFE.*disjoint/);
  await rm(join(dir, "state", "planted.json"));
  // State file and directory themselves.
  await load({ bootstrapDigest: digest });
  await chmod(stateFile, 0o666);
  await assert.rejects(load(), /TRUST_STATE_LOCATION_UNSAFE.*state file/);
  await chmod(stateFile, 0o600);
  await chmod(join(dir, "state"), 0o777);
  await assert.rejects(load(), /TRUST_STATE_LOCATION_UNSAFE.*state directory/);
  await chmod(join(dir, "state"), 0o700);
  await rm(stateFile);
  await writeFile(join(dir, "elsewhere.json"), "{}", { mode: 0o600 });
  await symlink(join(dir, "elsewhere.json"), stateFile);
  await assert.rejects(load({ bootstrapDigest: digest }), /TRUST_STATE_LOCATION_UNSAFE.*symlink/, "state file opened with O_NOFOLLOW");
  assert.ok(policyFile);
});

test("concurrency: racing acceptances never lower the watermark", async context => {
  const { dir, stateFile, load, put } = await workspace(context);
  const second = join(dir, "policy", "second.json");
  for (let round = 0; round < 30; round++) {
    await rm(stateFile, { force: true });
    const digest = await put(JSON.stringify({ ...synthetic, revision: 1 }));
    await load({ bootstrapDigest: digest });
    await put(JSON.stringify({ ...synthetic, revision: 3 }));
    await writeFile(second, JSON.stringify({ ...synthetic, revision: 2 }));
    const results = await Promise.allSettled([load(), load({ policyFile: second })]);
    assert.equal(results[0].status, "fulfilled");
    if (results[1].status === "rejected") assert.match(String(results[1].reason), /TRUST_POLICY_ROLLBACK/);
    assert.equal(JSON.parse(await readFile(stateFile, "utf8")).revision, 3, `round ${round}`);
  }
});

// ---------------------------------------------------------------------------
// Signed mode: pinned anchor root set (k-of-n), signed root rotations, external floor.
// ---------------------------------------------------------------------------

const DEPLOYMENT_ID = `${PIN.genesisHash}/${PIN.registryId}/${PIN.programIdHex}`;
const iso = (ms: number) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");

function syntheticRoot(fill: number, keyId = `synthetic-root-${fill}`) {
  const seed = new Uint8Array(32).fill(fill);
  const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" });
  const pin: TrustRootKey = { keyId, publicKeyHex: publicKeyHexFromSeed(seed) };
  const signature = (payload: Buffer, signerKeyId = keyId) => ({ rootKeyId: signerKeyId, signatureHex: sign(null, Buffer.concat([POLICY_SIGNATURE_DOMAIN, payload]), privateKey).toString("hex") });
  /** Policy envelope signed by this key only. */
  const envelope = (policy: unknown, signerKeyId = keyId, extraEntries: unknown[] = []) => {
    const payload = Buffer.from(JSON.stringify(policy));
    return { text: JSON.stringify({ format: SIGNED_POLICY_FORMAT, payloadBase64: payload.toString("base64"), signatures: [...extraEntries, signature(payload, signerKeyId)] }), digest: policyDigest(payload) };
  };
  return { pin, seed, keyId, envelope };
}
type Root = ReturnType<typeof syntheticRoot>;

/** Envelope of any kind signed by every given root (threshold signing). */
function signedBy(kind: "policy" | "rootSet" | "floor", payload: unknown, signers: Root[]): { format: string; payloadBase64: string; signatures: unknown[] } {
  let envelope: unknown = createEnvelope(kind, Buffer.from(JSON.stringify(payload)));
  for (const signer of signers) envelope = addEnvelopeSignature(envelope, kind, signer.keyId, signer.seed);
  return envelope as { format: string; payloadBase64: string; signatures: unknown[] };
}
const rootSet = (epoch: number, threshold: number, roots: Root[]): RootSet => ({ epoch, threshold, keys: roots.map(root => root.pin) });
function rotation(next: RootSet, signers: Root[], deploymentId = DEPLOYMENT_ID) {
  return signedBy("rootSet", { format: ROOT_SET_FORMAT, deploymentId, epoch: next.epoch, threshold: next.threshold, keys: next.keys }, signers);
}
type FloorFields = Partial<{ deploymentId: string; floorSequence: number; rootEpoch: number; minimumPolicyRevision: number; minimumRootEpoch: number; issuedAt: string; expiresAt: string; nonce: string | null }>;
function floorStatement(signers: Root[], fields: FloorFields = {}) {
  const now = Date.now();
  return JSON.stringify(signedBy("floor", {
    format: FLOOR_FORMAT, deploymentId: DEPLOYMENT_ID, floorSequence: 1, rootEpoch: 1, minimumPolicyRevision: 1, minimumRootEpoch: 1,
    issuedAt: iso(now - 60_000), expiresAt: iso(now + 60 * 60_000), nonce: null, ...fields,
  }, signers));
}

async function signedWorkspace(context: TestContext) {
  const ws = await workspace(context);
  await mkdir(join(ws.dir, "trust"), { mode: 0o700 });
  const floorFile = join(ws.dir, "trust", "floor.json");
  const rotationsFile = join(ws.dir, "trust", "rotations.json");
  const putFloor = (signers: Root[], fields: FloorFields = {}) => writeFile(floorFile, floorStatement(signers, fields));
  const putRotations = (chain: unknown[]) => writeFile(rotationsFile, JSON.stringify(chain));
  const mode = (anchor: RootSet, extra: Partial<Extract<TrustMode, { kind: "signed" }>> = {}): TrustMode =>
    ({ kind: "signed", anchor, rotationsFile, deployment: PIN, floor: new FileTrustFloorSource(floorFile), ...extra });
  const putSigned = async (policy: unknown, signers: Root[]) => {
    await writeFile(ws.policyFile, JSON.stringify(signedBy("policy", policy, signers)));
    return policyDigest(Buffer.from(JSON.stringify(policy)));
  };
  const state = async () => JSON.parse(await readFile(ws.stateFile, "utf8"));
  await putRotations([]);
  return { ...ws, floorFile, rotationsFile, putFloor, putRotations, mode, putSigned, state };
}

test("environment contract (signed): threshold, anchor epoch, floor and rotation settings are explicit and strict", () => {
  const base = { ONELAYER_TRUST_POLICY_FILE: "/p/policy.json", ONELAYER_TRUST_STATE_FILE: "/s/state.json", ONELAYER_TRUST_POLICY_MIN_REVISION: "1" };
  const deployment = `${BASE58_GENESIS}/${PIN.registryId}/${PIN.programIdHex}`;
  const keys = `root-1:${"0a".repeat(32)},root-2:${"0b".repeat(32)}`;
  const signedBase = { ...base, ONELAYER_TRUST_ROOT_KEYS: keys, ONELAYER_TRUST_DEPLOYMENT: deployment, ONELAYER_TRUST_ROOT_THRESHOLD: "2", ONELAYER_TRUST_ROOT_EPOCH: "1", ONELAYER_TRUST_FLOOR_FILE: "/t/floor.json" };
  for (const env of [
    { ...signedBase, ONELAYER_TRUST_ROOT_THRESHOLD: undefined }, // threshold is never implied
    { ...signedBase, ONELAYER_TRUST_ROOT_THRESHOLD: "3" }, // more than n
    { ...signedBase, ONELAYER_TRUST_ROOT_THRESHOLD: "0" },
    { ...signedBase, ONELAYER_TRUST_ROOT_THRESHOLD: "02" },
    { ...signedBase, ONELAYER_TRUST_FLOOR_FILE: undefined }, // signed mode has no floor-less variant
    { ...signedBase, ONELAYER_TRUST_FLOOR_FILE: "" },
    { ...signedBase, ONELAYER_TRUST_FLOOR_MAX_AGE_SECONDS: "0" },
    { ...signedBase, ONELAYER_TRUST_FLOOR_MAX_AGE_SECONDS: String(30 * 24 * 3600 + 1) },
    { ...signedBase, ONELAYER_TRUST_ROOT_ROTATIONS_FILE: "" },
    { ...signedBase, ONELAYER_TRUST_ROOT_EPOCH: undefined }, // the anchor epoch is never implied
    { ...signedBase, ONELAYER_TRUST_ROOT_EPOCH: "0" },
    { ...signedBase, ONELAYER_TRUST_ROOT_EPOCH: "1.5" },
    { ...signedBase, ONELAYER_TRUST_ROOT_KEYS: `root-1:${"0a".repeat(32)},root-1:${"0b".repeat(32)}` }, // duplicate keyId
    { ...signedBase, ONELAYER_TRUST_ROOT_KEYS: `root-1:${"0a".repeat(32)},root-2:${"0a".repeat(32)}` }, // duplicate public key
    // Signed-only settings are refused in unsigned mode instead of being silently ignored.
    ...["ONELAYER_TRUST_ROOT_THRESHOLD", "ONELAYER_TRUST_ROOT_EPOCH", "ONELAYER_TRUST_ROOT_ROTATIONS_FILE", "ONELAYER_TRUST_FLOOR_FILE", "ONELAYER_TRUST_FLOOR_MAX_AGE_SECONDS"]
      .map(name => ({ ...base, ONELAYER_TRUST_POLICY_UNSIGNED: "1", [name]: "1" })),
  ]) {
    const clean = Object.fromEntries(Object.entries(env).filter(([, value]) => value !== undefined)) as NodeJS.ProcessEnv;
    assert.throws(() => trustOptionsFromEnv(clean), /TRUST_CONFIG_INVALID|TRUST_ROOT_INVALID/, JSON.stringify(env));
  }
  const options = trustOptionsFromEnv({ ...signedBase, ONELAYER_TRUST_ROOT_ROTATIONS_FILE: "/t/rotations.json", ONELAYER_TRUST_FLOOR_MAX_AGE_SECONDS: "3600" });
  assert.ok(options.mode.kind === "signed");
  assert.deepEqual(options.mode.anchor, { epoch: 1, threshold: 2, keys: [{ keyId: "root-1", publicKeyHex: "0a".repeat(32) }, { keyId: "root-2", publicKeyHex: "0b".repeat(32) }] });
  assert.equal(options.mode.rotationsFile, "/t/rotations.json");
  assert.equal(options.mode.floorMaxAgeMs, 3_600_000);
  assert.ok(options.mode.floor instanceof FileTrustFloorSource);
  assert.deepEqual(options.mode.deployment, { ...PIN, genesisHash: BASE58_GENESIS });
  const repinned = trustOptionsFromEnv({ ...signedBase, ONELAYER_TRUST_ROOT_EPOCH: "3" });
  assert.ok(repinned.mode.kind === "signed" && repinned.mode.anchor.epoch === 3 && repinned.mode.rotationsFile === undefined);
});

test("authenticated distribution: pinned roots, pinned deployment, signed rollback and signed→unsigned downgrade refused", async context => {
  const { load, put, putFloor, mode } = await signedWorkspace(context);
  const root = syntheticRoot(0x21);
  const attacker = syntheticRoot(0x22);
  const signed = mode(rootSet(1, 1, [root]));
  await putFloor([root]);
  const v5 = root.envelope({ ...synthetic, revision: 5 });
  await put(JSON.stringify({ ...synthetic, revision: 5 }));
  await assert.rejects(load({ mode: signed, bootstrapDigest: v5.digest }), /TRUST_POLICY_UNSIGNED/, "a plain policy file is not accepted in signed mode");
  await put(attacker.envelope({ ...synthetic, revision: 5 }).text);
  await assert.rejects(load({ mode: signed, bootstrapDigest: v5.digest }), /TRUST_POLICY_SIGNATURE_INVALID/, "foreign root");
  await put(attacker.envelope({ ...synthetic, revision: 5 }, root.pin.keyId).text);
  await assert.rejects(load({ mode: signed, bootstrapDigest: v5.digest }), /TRUST_POLICY_SIGNATURE_INVALID/, "claiming the pinned keyId does not help");
  const tampered = JSON.parse(v5.text);
  tampered.payloadBase64 = Buffer.from(JSON.stringify({ ...synthetic, revision: 5, registryId: "other" })).toString("base64");
  await put(JSON.stringify(tampered));
  await assert.rejects(load({ mode: signed, bootstrapDigest: v5.digest }), /TRUST_POLICY_SIGNATURE_INVALID/);
  await assert.rejects(load({ mode: mode({ epoch: 1, threshold: 1, keys: [] }), bootstrapDigest: v5.digest }), /TRUST_ROOT_INVALID/, "empty anchor");
  // One malformed or foreign entry must not veto a valid signature.
  await put(root.envelope({ ...synthetic, revision: 5 }, root.pin.keyId, [{ rootKeyId: root.pin.keyId, signatureHex: "zz" }, "garbage", { rootKeyId: "unknown", signatureHex: "00".repeat(64) }]).text);
  assert.equal((await load({ mode: signed, bootstrapDigest: v5.digest })).policy.revision, 5);
  await put(root.envelope({ ...synthetic, revision: 4 }).text);
  await assert.rejects(load({ mode: signed }), /TRUST_POLICY_ROLLBACK/, "replaying an older, validly signed policy is a rollback");
  await put(root.envelope({ ...synthetic, revision: 5, validUntil: "2098-01-01T00:00:00Z" }).text);
  await assert.rejects(load({ mode: signed }), /TRUST_POLICY_CONFLICT/, "a second signed document for an accepted revision is refused");
  // A validly signed policy of another deployment (e.g. devnet) under the same root, with a higher revision.
  for (const foreign of [{ genesisHash: "devnet-genesis" }, { registryId: "devnet.registry" }, { programIdHex: "0f".repeat(32) }]) {
    await put(root.envelope({ ...synthetic, ...foreign, revision: 6 }).text);
    await assert.rejects(load({ mode: signed }), /TRUST_POLICY_DEPLOYMENT_MISMATCH/, JSON.stringify(foreign));
  }
  // Silent signed→unsigned downgrade: the exact payload bytes presented as a plain file.
  await put(JSON.stringify({ ...synthetic, revision: 6 }));
  await assert.rejects(load(), /TRUST_POLICY_DOWNGRADE/);
  await put(root.envelope({ ...synthetic, revision: 6 }).text);
  assert.equal((await load({ mode: signed })).policy.revision, 6);
});

test("threshold: k distinct pinned roots are required; duplicated and foreign signatures do not count", async context => {
  const { policyFile, load, putFloor, mode, putSigned, state } = await signedWorkspace(context);
  const [a, b, c] = [syntheticRoot(0x41), syntheticRoot(0x42), syntheticRoot(0x43)];
  const attacker = syntheticRoot(0x44);
  const signed = mode(rootSet(1, 2, [a, b, c]));
  await putFloor([a]);
  await assert.rejects(load({ mode: signed }), /TRUST_FLOOR_SIGNATURE_INVALID.*1 of required 2/, "the floor needs the threshold too");
  await putFloor([a, attacker]);
  await assert.rejects(load({ mode: signed }), /TRUST_FLOOR_SIGNATURE_INVALID/);
  await putFloor([a, c]);
  const digest = await putSigned(synthetic, [b]);
  await assert.rejects(load({ mode: signed, bootstrapDigest: digest }), /TRUST_POLICY_SIGNATURE_INVALID.*1 of required 2/);
  const duplicated = signedBy("policy", synthetic, [b]);
  duplicated.signatures.push(duplicated.signatures[0]);
  await writeFile(policyFile, JSON.stringify(duplicated));
  await assert.rejects(load({ mode: signed, bootstrapDigest: digest }), /TRUST_POLICY_SIGNATURE_INVALID.*1 of required 2/, "the same key twice is one signer");
  await putSigned(synthetic, [b, attacker]);
  await assert.rejects(load({ mode: signed, bootstrapDigest: digest }), /TRUST_POLICY_SIGNATURE_INVALID/);
  await putSigned(synthetic, [c, b]);
  assert.equal((await load({ mode: signed, bootstrapDigest: digest })).policy.revision, 2);
  assert.equal((await state()).rootEpoch, 1);
});

test("root rotation: legal chain moves trust to the new set; foreign, forked, skipped and rolled-back chains fail closed", async context => {
  const { load, putFloor, putRotations, mode, putSigned, state, stateFile } = await signedWorkspace(context);
  const [old1, old2] = [syntheticRoot(0x51), syntheticRoot(0x52)];
  const [new1, new2] = [syntheticRoot(0x61), syntheticRoot(0x62)];
  const attacker = syntheticRoot(0x6f);
  const anchor = rootSet(1, 2, [old1, old2]);
  const epoch2 = rootSet(2, 2, [new1, new2]);
  const signed = mode(anchor);
  const toEpoch2 = rotation(epoch2, [old1, old2]);

  // Bootstrap on the anchor set.
  await putFloor([old1, old2]);
  await load({ mode: signed, bootstrapDigest: await putSigned(synthetic, [old1, old2]) });

  // Invalid rotation links fail closed; they never truncate the chain to the anchor.
  for (const [label, chain] of [
    ["foreign root signs the rotation", [rotation(epoch2, [attacker, old1])]],
    ["below threshold", [rotation(epoch2, [old1])]],
    ["another deployment", [rotation(epoch2, [old1, old2], `${PIN.genesisHash}/devnet.registry/${PIN.programIdHex}`)]],
    ["epoch skipped", [rotation(rootSet(3, 2, [new1, new2]), [old1, old2])]],
    ["epoch replayed", [rotation(rootSet(1, 2, [new1, new2]), [old1, old2])]],
    ["threshold above n", [rotation({ epoch: 2, threshold: 3, keys: epoch2.keys }, [old1, old2])]],
    ["not an array element envelope", ["garbage"]],
  ] as const) {
    await putRotations([...chain]);
    await assert.rejects(load({ mode: signed }), /TRUST_ROOT_ROTATION_INVALID/, label);
  }
  await putRotations([]);
  await assert.rejects(load({ mode: mode(anchor, { rotationsFile: join(dirname(stateFile), "..", "trust", "absent.json") }) }), /TRUST_ROOT_UNAVAILABLE/, "configured chain missing");

  // Legal rotation: after it, only the new set may sign policies and floors.
  await putRotations([toEpoch2]);
  await assert.rejects(load({ mode: signed }), /TRUST_FLOOR_SIGNATURE_INVALID/, "a floor of the retired set is not accepted after rotation");
  await putFloor([new1, new2], { floorSequence: 2, rootEpoch: 2, minimumRootEpoch: 2, minimumPolicyRevision: 2 });
  await putSigned({ ...synthetic, revision: 3 }, [old1, old2]);
  await assert.rejects(load({ mode: signed }), /TRUST_POLICY_SIGNATURE_INVALID.*root epoch 2/, "the retired set cannot sign policies");
  await putSigned({ ...synthetic, revision: 3 }, [new1, new2]);
  assert.equal((await load({ mode: signed })).policy.revision, 3);
  assert.deepEqual([(await state()).rootEpoch, (await state()).format], [2, "onelayer.trust-state.v2"]);

  // Rotation rollback: truncating the chain back to the anchor.
  await putRotations([]);
  await putFloor([old1, old2]);
  await putSigned({ ...synthetic, revision: 4 }, [old1, old2]);
  await assert.rejects(load({ mode: signed }), /TRUST_ROOT_ROLLBACK/, "local watermark refuses a lower root epoch");
  // Fork: a different, validly signed epoch-2 set (e.g. produced with compromised old keys).
  const fork = rootSet(2, 1, [attacker]);
  await putRotations([rotation(fork, [old1, old2])]);
  await putFloor([attacker], { floorSequence: 3, rootEpoch: 2, minimumRootEpoch: 2, minimumPolicyRevision: 3 });
  await putSigned({ ...synthetic, revision: 4 }, [attacker]);
  await assert.rejects(load({ mode: signed }), /TRUST_ROOT_CONFLICT/);
  // Rollback with the watermark deleted: the floor must be signed by the current set,
  // so a truncated chain cannot present the fresh epoch-2 floor.
  await rm(stateFile);
  await putRotations([]);
  await putFloor([new1, new2], { floorSequence: 3, rootEpoch: 2, minimumRootEpoch: 2, minimumPolicyRevision: 3 });
  const oldDigest = await putSigned({ ...synthetic, revision: 4 }, [old1, old2]);
  await assert.rejects(load({ mode: signed, bootstrapDigest: oldDigest }), /TRUST_FLOOR_SIGNATURE_INVALID/);
  // Truncated chain with a floor still signed by the old set but naming epoch 2.
  await putFloor([old1, old2], { minimumRootEpoch: 2, minimumPolicyRevision: 3 });
  await assert.rejects(load({ mode: signed, bootstrapDigest: oldDigest }), /TRUST_ROOT_ROLLBACK.*external floor/);
  // Replay of the genuine, still unexpired epoch-1 floor (sequence 1): the local floor high-water mark refuses it.
  await putFloor([old1, old2]);
  await assert.rejects(load({ mode: signed, bootstrapDigest: oldDigest }), /TRUST_FLOOR_ROLLBACK/);
  await assert.rejects(readFile(stateFile), { code: "ENOENT" }, "no watermark created by a refused bootstrap");
});

test("re-pinned anchor after a root compromise: nothing signed by older sets resolves", async context => {
  const { load, putFloor, putRotations, mode, putSigned } = await signedWorkspace(context);
  const [old1, new1] = [syntheticRoot(0x71), syntheticRoot(0x72)];
  const repinned = mode(rootSet(2, 1, [new1]));
  const epoch2 = { rootEpoch: 2, minimumRootEpoch: 2 };
  // The compromised epoch-1 key holder forges its own "epoch 2" and signs floor and policy with it.
  await putRotations([rotation(rootSet(2, 1, [old1]), [old1])]);
  await putFloor([old1], epoch2);
  const forgedDigest = await putSigned({ ...synthetic, revision: 9 }, [old1]);
  await assert.rejects(load({ mode: repinned, bootstrapDigest: forgedDigest }), /TRUST_ROOT_ROTATION_INVALID: rotation 1: .*0 of required 1/, "old-set signatures do not verify under the re-pinned set");
  // Even an entry signed by the re-pinned set itself is refused when its epoch is not above the anchor: not skipped.
  await putRotations([rotation(rootSet(2, 1, [new1]), [new1])]);
  await assert.rejects(load({ mode: repinned, bootstrapDigest: forgedDigest }), /TRUST_ROOT_ROTATION_INVALID: rotation 1: epoch must be 3/);
  await putRotations([]);
  await assert.rejects(load({ mode: repinned, bootstrapDigest: forgedDigest }), /TRUST_FLOOR_SIGNATURE_INVALID/);
  await putFloor([new1], epoch2);
  await assert.rejects(load({ mode: repinned, bootstrapDigest: forgedDigest }), /TRUST_POLICY_SIGNATURE_INVALID/);
  const legit = await putSigned({ ...synthetic, revision: 9 }, [new1]);
  assert.equal((await load({ mode: repinned, bootstrapDigest: legit })).roots?.epoch, 2);
});

test("re-pin at the already accepted epoch: same set in any key field order is not a conflict", async context => {
  const { load, putFloor, putRotations, mode, putSigned, state } = await signedWorkspace(context);
  const [old1, new1, new2] = [syntheticRoot(0x73), syntheticRoot(0x74), syntheticRoot(0x75)];
  // The rotation payload lists key fields in the opposite order to the env/anchor representation.
  const reordered = signedBy("rootSet", { format: ROOT_SET_FORMAT, deploymentId: DEPLOYMENT_ID, epoch: 2, threshold: 1,
    keys: [new2, new1].map(root => ({ publicKeyHex: root.pin.publicKeyHex, keyId: root.keyId })) }, [old1]);
  await putRotations([reordered]);
  await putFloor([new1], { rootEpoch: 2, minimumRootEpoch: 2 });
  await load({ mode: mode(rootSet(1, 1, [old1])), bootstrapDigest: await putSigned(synthetic, [new1]) });
  const viaRotation = await state();
  await putRotations([]);
  assert.equal((await load({ mode: mode(rootSet(2, 1, [new1, new2])) })).roots?.epoch, 2);
  assert.deepEqual(await state(), viaRotation, "identical root set digest, watermark unchanged");
  await assert.rejects(load({ mode: mode(rootSet(2, 1, [new1])) }), /TRUST_ROOT_CONFLICT/, "a different set at the same epoch is still a conflict");
});

test("floor replay after a watermark reset: the separate floor high-water mark refuses older and conflicting floors", async context => {
  const { load, putFloor, mode, putSigned, stateFile } = await signedWorkspace(context);
  const root = syntheticRoot(0x76);
  const signed = mode(rootSet(1, 1, [root]));
  const rev3 = { ...synthetic, revision: 3 };
  await putFloor([root], { floorSequence: 4, minimumPolicyRevision: 1 });
  const olderFloor = floorStatement([root], { floorSequence: 4, minimumPolicyRevision: 1 });
  await load({ mode: signed, bootstrapDigest: await putSigned(synthetic, [root]) });
  await putFloor([root], { floorSequence: 5, minimumPolicyRevision: 3 });
  await load({ mode: signed, bootstrapDigest: undefined, ...{} }).catch(() => undefined); // revision 2 is now below the floor
  const rev3Digest = await putSigned(rev3, [root]);
  assert.equal((await load({ mode: signed })).policy.revision, 3);
  assert.equal(JSON.parse(await readFile(floorStateFile(stateFile), "utf8")).floorSequence, 5);
  // Attacker deletes the watermark and replays the older, still unexpired floor with the older policy.
  await rm(stateFile);
  await writeFile(join(dirname(stateFile), "..", "trust", "floor.json"), olderFloor);
  const rev2Digest = await putSigned(synthetic, [root]);
  await assert.rejects(load({ mode: signed, bootstrapDigest: rev2Digest }), /TRUST_FLOOR_ROLLBACK.*sequence 4 is below the accepted 5/);
  // Same sequence, different content.
  await putFloor([root], { floorSequence: 5, minimumPolicyRevision: 2 });
  await assert.rejects(load({ mode: signed, bootstrapDigest: rev2Digest }), /TRUST_FLOOR_CONFLICT/);
  // Newer sequence that lowers the floor.
  await putFloor([root], { floorSequence: 6, minimumPolicyRevision: 2 });
  await assert.rejects(load({ mode: signed, bootstrapDigest: rev2Digest }), /TRUST_FLOOR_ROLLBACK.*may not lower/);
  // Recovery: bootstrap on the current policy with a current floor.
  await putFloor([root], { floorSequence: 6, minimumPolicyRevision: 3 });
  await putSigned(rev3, [root]);
  assert.equal((await load({ mode: signed, bootstrapDigest: rev3Digest })).policy.revision, 3);
  // Watermark present but the floor high-water mark removed: fail closed, never re-created silently.
  await rm(floorStateFile(stateFile));
  await assert.rejects(load({ mode: signed }), /TRUST_FLOOR_STATE_MISSING/);
  await writeFile(floorStateFile(stateFile), "{", { mode: 0o600 });
  await assert.rejects(load({ mode: signed }), /TRUST_FLOOR_STATE_CORRUPT/);
});

test("external floor: unavailable, stale, overlong, future, foreign, replayed or corrupt floors fail closed", async context => {
  const { load, floorFile, putFloor, mode, putSigned, stateFile } = await signedWorkspace(context);
  const root = syntheticRoot(0x81);
  const other = syntheticRoot(0x82);
  const signed = mode(rootSet(1, 1, [root]));
  const digest = await putSigned(synthetic, [root]);
  const now = Date.now();
  const cases: Array<[string, () => Promise<unknown>, RegExp]> = [
    ["missing floor file", () => rm(floorFile, { force: true }), /TRUST_FLOOR_UNAVAILABLE/],
    ["unparseable", () => writeFile(floorFile, "{"), /TRUST_FLOOR_INVALID/],
    ["plain statement without envelope", () => writeFile(floorFile, JSON.stringify({ format: FLOOR_FORMAT })), /TRUST_FLOOR_INVALID/],
    ["foreign signer", () => putFloor([other]), /TRUST_FLOOR_SIGNATURE_INVALID/],
    ["expired", () => putFloor([root], { issuedAt: iso(now - 3 * 3600_000), expiresAt: iso(now - 3600_000) }), /TRUST_FLOOR_STALE/],
    ["validity longer than the pinned maximum age", () => putFloor([root], { issuedAt: iso(now - 60_000), expiresAt: iso(now + 48 * 3600_000) }), /TRUST_FLOOR_STALE.*maximum age/],
    ["issued in the future", () => putFloor([root], { issuedAt: iso(now + 3600_000), expiresAt: iso(now + 2 * 3600_000) }), /TRUST_FLOOR_NOT_YET_VALID/],
    ["another deployment", () => putFloor([root], { deploymentId: `${PIN.genesisHash}/devnet.registry/${PIN.programIdHex}` }), /TRUST_FLOOR_DEPLOYMENT_MISMATCH/],
    ["epoch 0", () => putFloor([root], { minimumRootEpoch: 0 }), /TRUST_FLOOR_INVALID/],
    ["sequence 0", () => putFloor([root], { floorSequence: 0 }), /TRUST_FLOOR_INVALID/],
    ["signed for another root epoch", () => putFloor([root], { rootEpoch: 2 }), /TRUST_FLOOR_EPOCH_MISMATCH/],
    ["time-bounded file floor carrying a nonce", () => putFloor([root], { nonce: "ab".repeat(32) }), /TRUST_FLOOR_REPLAYED.*nonce null/],
    ["issuedAt after expiresAt", () => putFloor([root], { issuedAt: iso(now), expiresAt: iso(now - 1000) }), /TRUST_FLOOR_INVALID/],
    ["policy below the floor", () => putFloor([root], { minimumPolicyRevision: 3 }), /TRUST_POLICY_ROLLBACK.*external floor/],
    ["root epoch below the floor", () => putFloor([root], { minimumRootEpoch: 2 }), /TRUST_ROOT_ROLLBACK.*external floor/],
  ];
  for (const [label, arrange, expected] of cases) {
    await arrange();
    await assert.rejects(load({ mode: signed, bootstrapDigest: digest }), expected, label);
    await assert.rejects(readFile(stateFile), { code: "ENOENT" }, `${label}: no watermark written`);
    await assert.rejects(readFile(floorStateFile(stateFile)), { code: "ENOENT" }, `${label}: no floor high-water mark written`);
  }
  // Challenge-bound source (floor service stand-in): an answer to another challenge is a replay.
  const replaying = mode(rootSet(1, 1, [root]), { floor: new LabChallengeFloorSource([{ keyId: root.keyId, seed: root.seed }], { deploymentId: DEPLOYMENT_ID, floorSequence: 1, rootEpoch: 1, minimumPolicyRevision: 1, minimumRootEpoch: 1 }, 60_000, "ab".repeat(32)) });
  await assert.rejects(load({ mode: replaying, bootstrapDigest: digest }), /TRUST_FLOOR_REPLAYED/);
  const failing = mode(rootSet(1, 1, [root]), { floor: { challengeBound: true, fetch: async () => { throw Object.assign(new Error("connect"), { code: "ECONNREFUSED" }); } } });
  await assert.rejects(load({ mode: failing, bootstrapDigest: digest }), /TRUST_FLOOR_UNAVAILABLE.*ECONNREFUSED/);
  const live = mode(rootSet(1, 1, [root]), { floor: new LabChallengeFloorSource([{ keyId: root.keyId, seed: root.seed }], { deploymentId: DEPLOYMENT_ID, floorSequence: 1, rootEpoch: 1, minimumPolicyRevision: 2, minimumRootEpoch: 1 }) });
  assert.equal((await load({ mode: live, bootstrapDigest: digest })).floor?.minimumPolicyRevision, 2);
  // A shorter pinned maximum age turns an otherwise valid 1-hour floor into a stale one.
  await putFloor([root]);
  await assert.rejects(load({ mode: mode(rootSet(1, 1, [root]), { floorMaxAgeMs: 30 * 60_000 }) }), /TRUST_FLOOR_STALE/);
});

test("state rollback with a floor: deleting the watermark cannot bring back a key revoked after compromise (backdated issuedAt)", async context => {
  const { load, putFloor, mode, putSigned, state, stateFile } = await signedWorkspace(context);
  const root = syntheticRoot(0x91);
  const signed = mode(rootSet(1, 1, [root]));
  const issuerKey = synthetic.issuers[0];
  const rev1 = { ...synthetic, revision: 1 };
  const rev2 = { ...synthetic, revision: 2, issuers: [{ ...issuerKey, revoked: true }] };
  await putFloor([root]);
  await load({ mode: signed, bootstrapDigest: await putSigned(rev1, [root]) });
  // Compromise detected: revision 2 revokes the issuer, the floor service raises the floor.
  await putSigned(rev2, [root]);
  const accepted = await load({ mode: signed });
  await putFloor([root], { floorSequence: 2, minimumPolicyRevision: 2 });
  // A certificate signed with the compromised key and a backdated issuedAt inside the
  // key's former validity interval is refused: revocation covers purported history.
  const body = {
    registryId: synthetic.registryId, schemaVersion: 1, issuerKeyId: issuerKey.keyId, issuerPublicKey: Buffer.from(issuerKey.publicKeyHex, "hex"),
    issuedAt: "2021-06-01T00:00:00Z", anchor: { solanaProgramId: Buffer.from(synthetic.programIdHex, "hex"), registryVersion: 1n },
  } as unknown as CertificateBody;
  assert.equal(authorizeCertificate(body, accepted.policy), "ISSUER_REVOKED");
  assert.equal(authorizeCertificate(body, parseTrustPolicy(rev1, 1)), null, "the pre-revocation policy would accept it — that is what must not come back");
  // Attacker with write access to the verifier state deletes the watermark and replays revision 1.
  await rm(stateFile);
  const rev1Digest = await putSigned(rev1, [root]);
  await assert.rejects(load({ mode: signed, bootstrapDigest: rev1Digest }), /TRUST_POLICY_ROLLBACK.*external floor 2/);
  await assert.rejects(load({ mode: signed }), /TRUST_POLICY_ROLLBACK.*external floor 2/);
  // Legitimate recovery: bootstrap on the current revoking revision.
  const rev2Digest = await putSigned(rev2, [root]);
  assert.equal((await load({ mode: signed, bootstrapDigest: rev2Digest })).policy.issuers[0].revoked, true);
  assert.equal((await state()).revision, 2);
});

test("first bootstrap bound follows the authenticated floor, not only the env revision floor", async context => {
  const { load, putFloor, mode, putSigned } = await signedWorkspace(context);
  const root = syntheticRoot(0xa1);
  const signed = mode(rootSet(1, 1, [root]));
  await putFloor([root], { minimumPolicyRevision: 5_000 });
  const tooHigh = await putSigned({ ...synthetic, revision: 6_001 }, [root]);
  await assert.rejects(load({ mode: signed, bootstrapDigest: tooHigh }), /TRUST_POLICY_REVISION_JUMP/);
  const ok = await putSigned({ ...synthetic, revision: 5_001 }, [root]);
  assert.equal((await load({ mode: signed, bootstrapDigest: ok })).policy.revision, 5_001);
});

test("authenticated distribution: unsigned→signed upgrade of the same document is recorded", async context => {
  const { load, put, putFloor, mode, state } = await signedWorkspace(context);
  const root = syntheticRoot(0x21);
  const policy = { ...synthetic, revision: 7 };
  const digest = await put(JSON.stringify(policy));
  await load({ bootstrapDigest: digest });
  assert.equal((await state()).authenticated, false);
  await putFloor([root]);
  await put(root.envelope(policy).text);
  await load({ mode: mode(rootSet(1, 1, [root])) });
  assert.deepEqual({ ...(await state()), rootSetDigest: undefined }, { format: "onelayer.trust-state.v2", revision: 7, policyDigest: digest, authenticated: true, rootEpoch: 1, rootSetDigest: undefined });
  await put(JSON.stringify(policy));
  await assert.rejects(load(), /TRUST_POLICY_DOWNGRADE/);
});

test("unsigned→signed transition with a new revision carries the unsigned floor over", async context => {
  const { load, put, putFloor, mode, state } = await signedWorkspace(context);
  const root = syntheticRoot(0x21);
  const signed = mode(rootSet(1, 1, [root]));
  await putFloor([root]);
  const digest = await put(JSON.stringify({ ...synthetic, revision: 7 }));
  await load({ bootstrapDigest: digest });
  await put(root.envelope({ ...synthetic, revision: 7, validUntil: "2098-01-01T00:00:00Z" }).text);
  await assert.rejects(load({ mode: signed }), /TRUST_POLICY_CONFLICT/, "same revision needs byte-identical payload");
  await put(root.envelope({ ...synthetic, revision: 6 }).text);
  await assert.rejects(load({ mode: signed }), /TRUST_POLICY_ROLLBACK/, "unsigned floor carries over");
  await put(root.envelope({ ...synthetic, revision: 8 }).text);
  assert.equal((await load({ mode: signed })).policy.revision, 8);
  const accepted = await state();
  assert.equal(accepted.format, "onelayer.trust-state.v2");
  assert.equal(accepted.policyDigest, policyDigest(Buffer.from(JSON.stringify({ ...synthetic, revision: 8 }))));
  assert.equal(accepted.authenticated, true);
  assert.equal(accepted.rootEpoch, 1);
  assert.match(accepted.rootSetDigest, /^[0-9a-f]{64}$/);
});

test("watermark v1 (pre-rotation) migrates forward; inconsistent v2 state is corrupt", async context => {
  const { stateFile, load, put, putFloor, mode, state } = await signedWorkspace(context);
  const root = syntheticRoot(0x21);
  const digest = await put(JSON.stringify(synthetic));
  await writeFile(stateFile, JSON.stringify({ format: "onelayer.trust-state.v1", revision: 2, policyDigest: digest, authenticated: false }), { mode: 0o600 });
  assert.equal((await load()).policy.revision, 2, "an identical v1 acceptance stays valid");
  await putFloor([root]);
  await put(root.envelope({ ...synthetic, revision: 3 }).text);
  await load({ mode: mode(rootSet(1, 1, [root])) });
  assert.equal((await state()).format, "onelayer.trust-state.v2");
  // A v1 watermark written by the single-root signed mode (authenticated, no epoch, no floor mark).
  await rm(floorStateFile(stateFile));
  await writeFile(stateFile, JSON.stringify({ format: "onelayer.trust-state.v1", revision: 3, policyDigest: policyDigest(Buffer.from(JSON.stringify({ ...synthetic, revision: 3 }))), authenticated: true }), { mode: 0o600 });
  await put(JSON.stringify({ ...synthetic, revision: 3 }));
  await assert.rejects(load(), /TRUST_POLICY_DOWNGRADE/, "authenticated v1 still forbids unsigned");
  await put(root.envelope({ ...synthetic, revision: 3 }).text);
  await load({ mode: mode(rootSet(1, 1, [root])) });
  assert.deepEqual([(await state()).format, (await state()).rootEpoch, (await state()).authenticated], ["onelayer.trust-state.v2", 1, true]);
  assert.equal(JSON.parse(await readFile(floorStateFile(stateFile), "utf8")).floorSequence, 1, "floor mark created on migration");
  for (const corrupt of [
    { format: "onelayer.trust-state.v2", revision: 3, policyDigest: digest, authenticated: false, rootEpoch: 1, rootSetDigest: "00".repeat(32) },
    { format: "onelayer.trust-state.v2", revision: 3, policyDigest: digest, authenticated: true, rootEpoch: 0, rootSetDigest: null },
    { format: "onelayer.trust-state.v2", revision: 3, policyDigest: digest, authenticated: true, rootEpoch: 1, rootSetDigest: null },
    { format: "onelayer.trust-state.v2", revision: 3, policyDigest: digest, authenticated: false, rootEpoch: 0, rootSetDigest: "00".repeat(32) },
    { format: "onelayer.trust-state.v1", revision: 3, policyDigest: digest, authenticated: true, rootEpoch: 1, rootSetDigest: "00".repeat(32) },
  ]) {
    await writeFile(stateFile, JSON.stringify(corrupt), { mode: 0o600 });
    await assert.rejects(load({ mode: mode(rootSet(1, 1, [root])) }), /TRUST_STATE_CORRUPT/, JSON.stringify(corrupt));
  }
});

test("verifier process in signed mode: starts with a fresh floor, refuses a stale floor and a truncated rotation chain", { timeout: 60_000 }, async context => {
  const { policyFile, stateFile, floorFile, rotationsFile, putFloor, putRotations, putSigned } = await signedWorkspace(context);
  const [old1, new1] = [syntheticRoot(0xb1), syntheticRoot(0xb2)];
  // The env deployment pin is canonical (base58 genesis), so the policy and the signed statements use it too.
  const deploymentId = `${BASE58_GENESIS}/${PIN.registryId}/${PIN.programIdHex}`;
  const env = {
    ONELAYER_TRUST_POLICY_FILE: policyFile, ONELAYER_TRUST_STATE_FILE: stateFile, ONELAYER_TRUST_DEPLOYMENT: deploymentId,
    ONELAYER_TRUST_ROOT_KEYS: `${old1.keyId}:${old1.pin.publicKeyHex}`, ONELAYER_TRUST_ROOT_THRESHOLD: "1", ONELAYER_TRUST_ROOT_EPOCH: "1",
    ONELAYER_TRUST_ROOT_ROTATIONS_FILE: rotationsFile, ONELAYER_TRUST_FLOOR_FILE: floorFile,
  };
  const pinnedFloor = (fields: FloorFields = {}) => putFloor([new1], { rootEpoch: 2, minimumRootEpoch: 2, deploymentId, ...fields });
  await pinnedFloor();
  await putRotations([rotation(rootSet(2, 1, [new1]), [old1], deploymentId)]);
  const digest = await putSigned({ ...synthetic, genesisHash: BASE58_GENESIS }, [new1]);
  const started = await startVerifier(context, { ...env, ONELAYER_TRUST_STATE_BOOTSTRAP: digest });
  assert.equal(started.ok, true, started.output);
  const now = Date.now();
  await pinnedFloor({ issuedAt: iso(now - 3 * 3600_000), expiresAt: iso(now - 3600_000) });
  const stale = await startVerifier(context, env);
  assert.equal(stale.ok, false);
  assert.match(stale.output, /TRUST_FLOOR_STALE/);
  await pinnedFloor();
  await putRotations([]);
  const truncated = await startVerifier(context, env);
  assert.equal(truncated.ok, false);
  assert.match(truncated.output, /TRUST_FLOOR_SIGNATURE_INVALID/);
  await rm(floorFile);
  const unavailable = await startVerifier(context, env);
  assert.equal(unavailable.ok, false);
  assert.match(unavailable.output, /TRUST_FLOOR_UNAVAILABLE/);
});

test("running verifier: periodic re-validation withdraws the policy when the floor lapses and restores it on renewal", async context => {
  const { policyFile, stateFile, putFloor, mode, putSigned } = await signedWorkspace(context);
  const root = syntheticRoot(0xc1);
  const options: LoadTrustPolicyOptions = { policyFile, stateFile, minimumRevision: 1, mode: mode(rootSet(1, 1, [root])) };
  await putFloor([root]);
  const initial = await loadTrustPolicy({ ...options, bootstrapDigest: await putSigned(synthetic, [root]) });
  const target: { trustPolicy?: TrustPolicy } = { trustPolicy: initial.policy };
  const failures: string[] = [];
  const refresher = startTrustRefresh({ ...options, bootstrapDigest: "ff".repeat(32) }, target, { intervalMs: 3_600_000, onFailure: error => failures.push(error.message) });
  context.after(() => refresher.stop());
  await refresher.tick();
  assert.equal(target.trustPolicy?.revision, 2);
  const now = Date.now();
  await putFloor([root], { floorSequence: 2, issuedAt: iso(now - 3 * 3600_000), expiresAt: iso(now - 3600_000) });
  await refresher.tick();
  assert.equal(target.trustPolicy, undefined, "a lapsed floor withdraws trust");
  assert.match(failures.at(-1) ?? "", /TRUST_FLOOR_STALE/);
  await putFloor([root], { floorSequence: 2 });
  await refresher.tick();
  assert.equal((target as { trustPolicy?: TrustPolicy }).trustPolicy?.revision, 2, "a renewed floor restores trust");
});
