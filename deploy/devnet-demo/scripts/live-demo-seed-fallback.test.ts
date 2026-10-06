// Hermetic tests for the seed's standalone fallback certificate (B4): the
// explicit approval gate, the accepted A1 signer over real publish-anchor
// fixtures, reuse only after re-verification, and fresh private artifacts that
// never overwrite. No live RPC, no demo-api process, no GTK, no chain writes —
// every "server" here is an in-process fake and every transaction is a real
// unsigned publish-anchor message built with the generated instruction.
import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { after, before, test } from "node:test";
import {
  FALLBACK_DISCLOSED_PATHS,
  runFallbackCertificate,
  signApprovedFallback,
  signRequestForIntent,
  writeFreshFile,
  type FallbackOptions,
  type ParsedIntent,
} from "./live-demo-seed-fallback.ts";
import { intentHash } from "../../../apps/demo-api/src/transaction-state.ts";
import {
  prepareAnchorTransaction,
  validateSignedTransaction,
  type AnchorTransactionInput,
  type PreparedTransaction,
} from "../../../apps/demo-api/src/admin-transaction.ts";
import { ensureKeyPair } from "../../../apps/demo-api/scripts/live-demo-key-store.ts";
import {
  findLedgerSegmentPda,
  findRegistryConfigPda,
  findRolePda,
  getPublishAnchorInstruction,
  ONELAYER_REGISTRY_PROGRAM_ADDRESS,
  PUBLISH_ANCHOR_DISCRIMINATOR,
} from "../../../packages/onchain-client/src/index.ts";
import { registryIdHash } from "../../../packages/canonical-ts/src/index.ts";
import { kit, loadSeedSigner, SeedRefusal, toAddress, type SeedSigner } from "./live-demo-seed-kit.ts";

const DEMO = "http://127.0.0.1:8090";
const VERIFIER = "http://127.0.0.1:8080";
const CERTIFICATE_ID = "0123456789abcdef0123456789abcdef";
const REGISTRY_ID = "gov.registry.land";
// The real ledger day (`utc_day` / `ledgerDay`): a UTC calendar day as YYYYMMDD.
const DAY = 20261006;
const LOST_GOVERNANCE_KEY = "4Y4pGizJm5CL789jRKYx5jeQLJ58eBBmf5UzGRFChikn";
const BLOCKHASH = "11111111111111111111111111111111";

let home = "";
let credentialPath = "";
let keyFile = "";
let signer: SeedSigner;
let artifactRuns = 0;

before(async () => {
  home = await mkdtemp(path.join(tmpdir(), "onelayer-seed-fallback-"));
  const credentialDir = path.join(home, "creds");
  await mkdir(credentialDir, { recursive: true, mode: 0o700 });
  credentialPath = path.join(credentialDir, "admin-credentials.json");
  await writeFile(credentialPath, JSON.stringify({ operator: "test-operator-password-0123456789abcdef" }), { mode: 0o600 });
  await chmod(credentialPath, 0o600);
  // A real development key in the accepted A1 persistent store layout.
  const ensured = await ensureKeyPair({ home });
  keyFile = ensured.path;
  signer = await loadSeedSigner(keyFile, { home });
});

function freshArtifacts(): string {
  artifactRuns += 1;
  return path.join(home, `seed-${artifactRuns}`);
}

after(async () => {
  await rm(home, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// real publish-anchor fixtures (never a zero-instruction stand-in)
// ---------------------------------------------------------------------------

interface PublishFixture {
  plan: Record<string, unknown>;
  intent: ParsedIntent;
  prepared: PreparedTransaction;
  configPda: string;
  rolePda: string;
  segmentPda: string;
}

async function publishFixture(
  options: {
    dayUtc?: number;
    blockhash?: string;
    programId?: string;
    feePayer?: string;
    prepared?: PreparedTransaction;
    intentHash?: string;
    messageBase64ForHash?: string;
    planOverrides?: Record<string, unknown>;
  } = {},
): Promise<PublishFixture> {
  const feePayer = options.feePayer ?? signer.address;
  const blockhash = options.blockhash ?? BLOCKHASH;
  const operator = toAddress(feePayer);
  const programId = toAddress(options.programId ?? ONELAYER_REGISTRY_PROGRAM_ADDRESS);
  const [configPda] = await findRegistryConfigPda(registryIdHash(REGISTRY_ID), { programAddress: programId });
  const [rolePda] = await findRolePda({ config: configPda, operator }, { programAddress: programId });
  const day = options.dayUtc ?? DAY;
  const [segmentPda] = await findLedgerSegmentPda(
    { config: configPda, dayUtc: day, segmentIndex: 0 },
    { programAddress: programId },
  );
  const input: AnchorTransactionInput = {
    programId,
    configPda,
    rolePda,
    segmentPda,
    operator,
    blockhash,
    lastValidBlockHeight: 1_000n,
    batchSequence: 1n,
    registryVersion: 1n,
    cursorStart: 0n,
    cursorEnd: 2n,
    merkleRoot: new Uint8Array(32).fill(0xcd),
    manifestHash: new Uint8Array(32).fill(0xef),
    previousAnchorHash: new Uint8Array(32).fill(0x12),
    leafCount: 2,
    schemaVersion: 1,
    hashAlgorithm: 1,
    treeAlgorithm: 1,
  };
  const prepared = options.prepared ?? prepareAnchorTransaction(input);
  const plan: Record<string, unknown> = {
    registryId: REGISTRY_ID,
    batchSequence: "1",
    registryVersion: "1",
    cursorStart: "0",
    cursorEnd: "2",
    leafCount: 2,
    merkleRoot: "cd".repeat(32),
    manifestHash: "ef".repeat(32),
    previousAnchorHash: "12".repeat(32),
    cluster: "solana:devnet",
    programId: String(programId),
    configPda: String(configPda),
    rolePda: String(rolePda),
    segmentPda: String(segmentPda),
    segmentIndex: 0,
    dayUtc: day,
    feePayer,
    instructionData: prepared.instructionDataBase64,
    transactionBase64: prepared.transactionBase64,
    simulation: { ok: true, error: null, unitsConsumed: 1234 },
    ...(options.planOverrides ?? {}),
  };
  const hash =
    options.intentHash ??
    Buffer.from(
      intentHash({
        registryId: String(plan.registryId),
        batchSequence: BigInt(String(plan.batchSequence)),
        registryVersion: BigInt(String(plan.registryVersion)),
        cursorStart: BigInt(String(plan.cursorStart)),
        cursorEnd: BigInt(String(plan.cursorEnd)),
        leafCount: Number(plan.leafCount),
        merkleRootHex: String(plan.merkleRoot),
        manifestHashHex: String(plan.manifestHash),
        previousAnchorHashHex: String(plan.previousAnchorHash),
        programId: String(plan.programId),
        configPda: String(plan.configPda),
        rolePda: String(plan.rolePda),
        segmentPda: String(plan.segmentPda),
        segmentIndex: Number(plan.segmentIndex),
        dayUtc: Number(plan.dayUtc),
        feePayer: String(plan.feePayer),
        recentBlockhash: blockhash,
        lastValidBlockHeight: 1_000n,
        messageBase64: options.messageBase64ForHash ?? prepared.messageBase64,
      }),
    ).toString("hex");
  const intent: ParsedIntent = {
    intentId: "11111111-2222-3333-4444-555555555555",
    intentHash: hash,
    state: "SIMULATED",
    replayed: false,
    plan,
    recentBlockhash: blockhash,
    lastValidBlockHeight: "1000",
  };
  return { plan, intent, prepared, configPda: String(configPda), rolePda: String(rolePda), segmentPda: String(segmentPda) };
}

/** The permissive path the review refused: a message with no instruction. */
function zeroInstructionTransaction(feePayer: string): PreparedTransaction {
  const feePayerSigner = kit.createNoopSigner(toAddress(feePayer));
  const message = kit.pipe(
    kit.createTransactionMessage({ version: 0 }),
    (draft) => kit.setTransactionMessageFeePayerSigner(feePayerSigner, draft),
    (draft) =>
      kit.setTransactionMessageLifetimeUsingBlockhash(
        { blockhash: BLOCKHASH as never, lastValidBlockHeight: 1000n },
        draft,
      ),
  );
  const transaction = kit.compileTransaction(message);
  return {
    transactionBase64: Buffer.from(
      kit.getTransactionEncoder().encode({
        messageBytes: transaction.messageBytes,
        signatures: { [toAddress(feePayer)]: null },
      }),
    ).toString("base64"),
    messageBase64: Buffer.from(transaction.messageBytes).toString("base64"),
    instructionDataBase64: Buffer.alloc(178).toString("base64"),
    accounts: [],
  };
}

/** A message whose instruction accounts do not match the approved plan. */
function wrongMetaTransaction(feePayer: string, configPda: string, rolePda: string, segmentPda: string): PreparedTransaction {
  const operator = toAddress(feePayer);
  const instruction = getPublishAnchorInstruction(
    {
      config: toAddress(configPda),
      role: toAddress(rolePda),
      operator: kit.createNoopSigner(operator),
      segment: toAddress(segmentPda),
      batchSequence: 1n,
      registryVersion: 1n,
      sourceCursorStart: 0n,
      sourceCursorEnd: 2n,
      merkleRoot: new Uint8Array(32).fill(0xcd),
      manifestHash: new Uint8Array(32).fill(0xef),
      snapshotHash: new Uint8Array(32),
      previousAnchorHash: new Uint8Array(32).fill(0x12),
      leafCount: 2,
      schemaVersion: 1,
      flags: 0,
      hashAlgorithm: 1,
      treeAlgorithm: 1,
    },
    { programAddress: ONELAYER_REGISTRY_PROGRAM_ADDRESS },
  );
  const message = kit.pipe(
    kit.createTransactionMessage({ version: 0 }),
    (draft) => kit.setTransactionMessageFeePayerSigner(kit.createNoopSigner(operator), draft),
    (draft) =>
      kit.setTransactionMessageLifetimeUsingBlockhash(
        { blockhash: BLOCKHASH as never, lastValidBlockHeight: 1000n },
        draft,
      ),
    (draft) => kit.appendTransactionMessageInstruction(instruction, draft),
  );
  const transaction = kit.compileTransaction(message);
  return {
    transactionBase64: Buffer.from(
      kit.getTransactionEncoder().encode({
        messageBytes: transaction.messageBytes,
        signatures: { [operator]: null },
      }),
    ).toString("base64"),
    messageBase64: Buffer.from(transaction.messageBytes).toString("base64"),
    instructionDataBase64: Buffer.from(instruction.data).toString("base64"),
    accounts: [],
  };
}

function presignedTransaction(fixture: PreparedTransaction, feePayer: string): PreparedTransaction {
  const transaction = kit.getTransactionDecoder().decode(Buffer.from(fixture.transactionBase64, "base64"));
  return {
    ...fixture,
    transactionBase64: Buffer.from(
      kit.getTransactionEncoder().encode({
        messageBytes: transaction.messageBytes,
        signatures: {
          ...transaction.signatures,
          [toAddress(feePayer)]: kit.signatureBytes(new Uint8Array(64).fill(9)),
        },
      }),
    ).toString("base64"),
  };
}

// ---------------------------------------------------------------------------
// in-process fake services
// ---------------------------------------------------------------------------

interface FakeStack {
  request: typeof fetch;
  calls: string[];
  signedPosted: number;
  signedAccepted: number;
  setVerify(status: string, code?: string): void;
  setCertificateStatus(status: string): void;
}

function fakeStack(fixture: PublishFixture, options: { recordId?: string } = {}): FakeStack {
  const calls: string[] = [];
  let verifyStatus = "VERIFIED";
  let verifyCode: string | undefined;
  let certificateStatus = "ACTIVE";
  let signedPosted = 0;
  let signedAccepted = 0;
  const recordId = options.recordId ?? "SYNTHETIC-1";
  const intentPayload = (state: string) => ({
    intentId: fixture.intent.intentId,
    state,
    batchSequence: "1",
    intentHash: fixture.intent.intentHash,
    recentBlockhash: fixture.intent.recentBlockhash,
    lastValidBlockHeight: fixture.intent.lastValidBlockHeight,
    review: fixture.plan,
    transactionSignature: state === "FINALIZED" ? "sig" : null,
    anchorSlot: state === "FINALIZED" ? "42" : null,
    certificateId: null,
    failureCode: null,
    replayed: false,
  });
  const json = (status: number, payload: unknown, headers: Record<string, string> = {}) =>
    new Response(JSON.stringify(payload), {
      status,
      headers: { "content-type": "application/json", ...headers },
    });
  const request = (async (input: unknown, init?: unknown) => {
    const url = new URL(String(input));
    const method = ((init as { method?: string } | undefined)?.method ?? "GET").toUpperCase();
    calls.push(`${method} ${url.pathname}`);
    if (url.origin === DEMO) {
      if (url.pathname === "/v1/admin/session" && method === "POST") {
        return json(
          201,
          { csrfToken: "csrf-token-value-0123456789", username: "operator" },
          { "set-cookie": "onelayer_admin_session=session-cookie-value; Path=/; HttpOnly" },
        );
      }
      if (url.pathname === "/v1/admin/records" && method === "GET") return json(200, { records: [] });
      if (url.pathname === "/v1/admin/records" && method === "POST") {
        return json(201, { internalRecordId: recordId, recordVersion: "1", status: "ACTIVE", origin: "demo" });
      }
      if (url.pathname === "/v1/admin/publish-intents" && method === "POST") return json(201, intentPayload("SIMULATED"));
      if (/^\/v1\/admin\/publish-intents\/[^/]+\/signature$/.test(url.pathname)) {
        signedPosted += 1;
        // The demo-api's own gate: message identity plus a valid signature.
        const body = JSON.parse(String((init as { body?: string } | undefined)?.body ?? "{}")) as {
          signedTransactionBase64?: unknown;
        };
        const signed = typeof body.signedTransactionBase64 === "string" ? body.signedTransactionBase64 : "";
        try {
          validateSignedTransaction(signed, fixture.prepared.messageBase64, toAddress(String(fixture.plan.feePayer)));
          signedAccepted += 1;
        } catch {
          return json(422, { code: "SIGNED_TRANSACTION_SIGNATURE_INVALID" });
        }
        return json(200, intentPayload("SUBMITTED"));
      }
      if (/^\/v1\/admin\/publish-intents\/[^/]+\/reconciliation$/.test(url.pathname)) {
        return json(200, intentPayload("FINALIZED"));
      }
      if (/^\/v1\/admin\/publish-intents\/[^/]+\/certificate$/.test(url.pathname)) {
        return json(200, {
          intentId: fixture.intent.intentId,
          certificateId: CERTIFICATE_ID,
          certificateHash: "ab".repeat(32),
          qrUrl: "http://127.0.0.1:8091/verify?h=abcd",
          transactionSignature: "sig",
          anchorSlot: "42",
          explorerUrl: "https://explorer.solana.com/tx/sig?cluster=devnet",
          disclosureMode: "SELECTIVE_FIELDS",
          disclosedPaths: [...FALLBACK_DISCLOSED_PATHS],
          fieldCount: 2,
        });
      }
      if (url.pathname === `/v1/certificates/${CERTIFICATE_ID}/package` && method === "GET") {
        return json(200, {
          package_base64url: "AAAA",
          certificateHash: "ab".repeat(32),
          qrUrl: "http://127.0.0.1:8091/verify?h=abcd",
        });
      }
      if (url.pathname === `/v1/certificates/${CERTIFICATE_ID}/status` && method === "GET") {
        return json(200, { certificateId: CERTIFICATE_ID, status: certificateStatus, batchSequence: "1" });
      }
      if (url.pathname === `/v1/qr/${CERTIFICATE_ID}.png` && method === "GET") {
        return new Response(
          Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(32)]),
          { status: 200 },
        );
      }
      if (url.pathname === "/v1/admin/session" && method === "DELETE") return json(200, {});
      return json(404, { code: "NOT_FOUND" });
    }
    if (url.origin === VERIFIER && url.pathname === "/v1/verify") {
      return json(200, {
        status: verifyStatus,
        code: verifyCode ?? null,
        certificateId: CERTIFICATE_ID,
        disclosureMode: "SELECTIVE_FIELDS",
        disclosedFields: { status: "ACTIVE", areaSquareMeters: "1250.50" },
      });
    }
    return json(404, { code: "NOT_FOUND" });
  }) as typeof fetch;
  return {
    request,
    calls,
    get signedPosted() {
      return signedPosted;
    },
    get signedAccepted() {
      return signedAccepted;
    },
    setVerify: (status: string, code?: string) => {
      verifyStatus = status;
      verifyCode = code;
    },
    setCertificateStatus: (status: string) => {
      certificateStatus = status;
    },
  };
}

function optionsFor(stack: FakeStack, extra: Partial<FallbackOptions> = {}): FallbackOptions {
  return {
    demoApiUrl: DEMO,
    verifierUrl: VERIFIER,
    signer,
    approveFallback: true,
    keyFile,
    keyStore: { home },
    artifactsDir: freshArtifacts(),
    credentialPath,
    privateRoot: home,
    request: stack.request,
    reconcileAttempts: 2,
    reconcileDelayMs: 1,
    now: new Date("2026-10-06T12:00:00Z"),
    ...extra,
  };
}

// ---------------------------------------------------------------------------
// tests
// ---------------------------------------------------------------------------

test("fallback: the explicit approval flag is required before anything is sent", async () => {
  const fixture = await publishFixture();
  const stack = fakeStack(fixture);
  await assert.rejects(
    () => runFallbackCertificate(optionsFor(stack, { approveFallback: false })),
    (error: unknown) => {
      assert.ok(error instanceof SeedRefusal);
      assert.equal(error.code, "APPROVAL_REQUIRED");
      return true;
    },
  );
  assert.deepEqual(stack.calls, [], "nothing is contacted without --approve-fallback");
});

test("fallback: a fresh finalized certificate is issued through the accepted signer and stored privately", async () => {
  const fixture = await publishFixture();
  const stack = fakeStack(fixture);
  const report = await runFallbackCertificate(optionsFor(stack));
  assert.equal(report.mode, "created");
  assert.equal(report.ok, true);
  assert.equal(report.certificateId, CERTIFICATE_ID);
  assert.deepEqual(report.disclosedPaths, [...FALLBACK_DISCLOSED_PATHS]);
  assert.equal(report.verified?.status, "VERIFIED");
  assert.equal(stack.signedPosted, 1);
  assert.equal(stack.signedAccepted, 1, "the posted signature passes the server's own validation");
  assert.ok(report.artifacts !== null);
  const manifest = JSON.parse(await readFile(report.artifacts!.manifest, "utf8"));
  assert.equal(manifest.certificateId, CERTIFICATE_ID);
  assert.deepEqual(manifest.disclosedPaths, ["areaSquareMeters", "status"]);
  assert.equal(manifest.packageFile, "fallback-package.json");
  assert.equal((await stat(report.artifacts!.manifest)).mode & 0o777, 0o600, "artifacts are private");
  assert.equal((await stat(report.artifacts!.dir)).mode & 0o777, 0o700, "the run directory is private");
  const packaged = JSON.parse(await readFile(report.artifacts!.packageFile, "utf8"));
  assert.equal(packaged.package_base64url, "AAAA");
  const everything =
    (await readFile(report.artifacts!.manifest, "utf8")) + (await readFile(report.artifacts!.packageFile, "utf8"));
  assert.ok(!everything.includes("password"));
  assert.ok(!/PRIVATE|BEGIN .*KEY|keypair|seed/.test(everything));
});

test("fallback: a still-finalized earlier certificate is reused only after re-verification", async () => {
  const first = fakeStack(await publishFixture());
  const created = await runFallbackCertificate(optionsFor(first));
  assert.equal(created.mode, "created");
  const root = path.dirname(created.artifacts!.dir);

  const reuse = fakeStack(await publishFixture());
  const report = await runFallbackCertificate(optionsFor(reuse, { artifactsDir: root }));
  assert.equal(report.mode, "reused");
  assert.equal(report.ok, true);
  assert.equal(report.certificateId, CERTIFICATE_ID);
  assert.ok(reuse.calls.includes("POST /v1/verify"), "reuse re-verifies first");
  assert.ok(!reuse.calls.includes("POST /v1/admin/publish-intents"), "reuse publishes nothing");
  assert.ok(!reuse.calls.includes("POST /v1/admin/session"), "reuse signs in to nothing");
});

test("fallback: reuse matches the requested record id only", async () => {
  const first = fakeStack(await publishFixture(), { recordId: "SYNTHETIC-1" });
  const created = await runFallbackCertificate(optionsFor(first));
  assert.equal(created.recordId, "SYNTHETIC-1");
  const root = path.dirname(created.artifacts!.dir);

  // The same tree holds SYNTHETIC-1's artifact; asking for SYNTHETIC-2 must
  // not silently hand back another record's certificate.
  const other = fakeStack(await publishFixture(), { recordId: "SYNTHETIC-2" });
  const report = await runFallbackCertificate(optionsFor(other, { artifactsDir: root, recordId: "SYNTHETIC-2" }));
  assert.equal(report.mode, "created", "a different record id is never reused");
  assert.equal(report.recordId, "SYNTHETIC-2");
  assert.ok(other.calls.includes("POST /v1/admin/publish-intents"));
});

test("fallback: a certificate that no longer verifies is never reused and old evidence is kept", async () => {
  const first = fakeStack(await publishFixture());
  const created = await runFallbackCertificate(optionsFor(first));
  assert.equal(created.mode, "created");
  const root = path.dirname(created.artifacts!.dir);
  const originalManifest = await readFile(created.artifacts!.manifest, "utf8");

  const stale = fakeStack(await publishFixture());
  stale.setVerify("INVALID", "QR_HASH_MISMATCH");
  const report = await runFallbackCertificate(optionsFor(stale, { artifactsDir: root }));
  assert.equal(report.mode, "created", "a stale fallback is replaced by a fresh one");
  assert.notEqual(report.artifacts!.dir, created.artifacts!.dir, "a new run directory is used");
  assert.equal(await readFile(created.artifacts!.manifest, "utf8"), originalManifest, "old evidence is untouched");
});

test("fallback: a superseded certificate is not reused", async () => {
  const first = fakeStack(await publishFixture());
  const created = await runFallbackCertificate(optionsFor(first));
  const root = path.dirname(created.artifacts!.dir);
  const superseded = fakeStack(await publishFixture());
  superseded.setCertificateStatus("SUPERSEDED");
  const report = await runFallbackCertificate(optionsFor(superseded, { artifactsDir: root }));
  assert.equal(report.mode, "created");
});

test("fallback: fresh artifact writes never overwrite an existing file", async () => {
  const target = path.join(home, "fresh.bin");
  await writeFreshFile(target, Buffer.from("first"));
  await assert.rejects(
    () => writeFreshFile(target, Buffer.from("second")),
    (error: unknown) => {
      assert.ok(error instanceof SeedRefusal);
      assert.equal(error.code, "OUTPUT_REFUSED");
      return true;
    },
  );
  assert.equal(await readFile(target, "utf8"), "first", "the existing file is kept");
});

test("fallback: the run refuses a non-loopback service origin", async () => {
  const fixture = await publishFixture();
  const stack = fakeStack(fixture);
  await assert.rejects(
    () => runFallbackCertificate(optionsFor(stack, { verifierUrl: "https://example.invalid" })),
    (error: unknown) => {
      assert.ok(error instanceof SeedRefusal);
      assert.equal(error.code, "LINK_REFUSED");
      return true;
    },
  );
});

test("fallback: the sign request is exactly the accepted A1 contract field set", async () => {
  const fixture = await publishFixture();
  const request = signRequestForIntent(fixture.intent);
  assert.deepEqual(
    Object.keys(request).sort(),
    ["approved", "cluster", "instructionData", "intent", "intentHash", "intentId", "transactionBase64"],
  );
  assert.deepEqual(
    Object.keys(request.intent as Record<string, unknown>).sort(),
    [
      "batchSequence",
      "configPda",
      "cursorEnd",
      "cursorStart",
      "dayUtc",
      "feePayer",
      "lastValidBlockHeight",
      "leafCount",
      "manifestHashHex",
      "merkleRootHex",
      "previousAnchorHashHex",
      "programId",
      "recentBlockhash",
      "registryId",
      "registryVersion",
      "rolePda",
      "segmentIndex",
      "segmentPda",
    ],
  );
  const intent = request.intent as Record<string, unknown>;
  assert.equal(intent.merkleRootHex, fixture.plan.merkleRoot);
  assert.equal(intent.manifestHashHex, fixture.plan.manifestHash);
  assert.equal(intent.previousAnchorHashHex, fixture.plan.previousAnchorHash);
  assert.equal(intent.dayUtc, DAY);
});

test("fallback: the accepted A1 signer signs exactly the server-prepared bytes under the intent hash", async () => {
  const fixture = await publishFixture();
  const signedBase64 = await signApprovedFallback(fixture.intent, keyFile, { home });
  const signed = kit.getTransactionDecoder().decode(Buffer.from(signedBase64, "base64"));
  assert.equal(Buffer.from(signed.messageBytes).toString("base64"), fixture.prepared.messageBase64);
  validateSignedTransaction(signedBase64, fixture.prepared.messageBase64, toAddress(signer.address));

  const tampered = { ...fixture.intent, intentHash: "0".repeat(64) };
  await assert.rejects(
    () => signApprovedFallback(tampered, keyFile, { home }),
    (error: unknown) => {
      assert.ok(error instanceof SeedRefusal);
      assert.equal(error.code, "INTENT_HASH_MISMATCH");
      return true;
    },
  );
});

test("fallback: the strict signer refuses the retired permissive bypass", async () => {
  // DeepSeek's bypass probe: a zero-instruction message with a non-registry
  // program id used to be accepted by the fallback's own signing helper. The
  // accepted A1 signer must refuse it, and the run must post nothing.
  const zero = zeroInstructionTransaction(signer.address);
  const bogus = await publishFixture({
    programId: LOST_GOVERNANCE_KEY,
    prepared: zero,
    planOverrides: { instructionData: zero.instructionDataBase64 },
  });
  await assert.rejects(
    () => signApprovedFallback(bogus.intent, keyFile, { home }),
    (error: unknown) => {
      assert.ok(error instanceof SeedRefusal);
      assert.equal(error.code, "PROGRAM_UNSUPPORTED");
      return true;
    },
  );
  const stack = fakeStack(bogus);
  await assert.rejects(
    () => runFallbackCertificate(optionsFor(stack)),
    (error: unknown) => {
      assert.ok(error instanceof SeedRefusal);
      assert.equal(error.code, "PROGRAM_UNSUPPORTED");
      return true;
    },
  );
  assert.equal(stack.signedPosted, 0, "nothing is signed or posted for a refused message");

  // The same shape under the real program id is refused on structure.
  const zeroReal = await publishFixture({ prepared: zero, planOverrides: { instructionData: zero.instructionDataBase64 } });
  await assert.rejects(
    () => signApprovedFallback(zeroReal.intent, keyFile, { home }),
    (error: unknown) => {
      assert.ok(error instanceof SeedRefusal);
      assert.equal(error.code, "TRANSACTION_MESSAGE_UNEXPECTED");
      return true;
    },
  );
});

test("fallback: wrong accounts, a presigned message and a contradicting plan are all refused", async () => {
  const base = await publishFixture();
  // Account metas that do not match the approved plan.
  const wrong = await publishFixture({
    prepared: wrongMetaTransaction(signer.address, base.configPda, base.rolePda, base.segmentPda),
    planOverrides: {
      configPda: base.rolePda,
      rolePda: base.configPda,
      segmentPda: base.configPda,
    },
  });
  await assert.rejects(
    () => signApprovedFallback(wrong.intent, keyFile, { home }),
    (error: unknown) => {
      assert.ok(error instanceof SeedRefusal);
      assert.equal(error.code, "TRANSACTION_MESSAGE_UNEXPECTED");
      return true;
    },
  );

  // A message that already carries a signature is never re-signed.
  const presigned = await publishFixture({ prepared: presignedTransaction(base.prepared, signer.address) });
  await assert.rejects(
    () => signApprovedFallback(presigned.intent, keyFile, { home }),
    (error: unknown) => {
      assert.ok(error instanceof SeedRefusal);
      assert.equal(error.code, "TRANSACTION_MESSAGE_UNEXPECTED");
      return true;
    },
  );

  // Plan arguments that contradict the reviewed instruction data.
  const contradicting = await publishFixture({ planOverrides: { leafCount: 3 } });
  await assert.rejects(
    () => signApprovedFallback(contradicting.intent, keyFile, { home }),
    (error: unknown) => {
      assert.ok(error instanceof SeedRefusal);
      assert.equal(error.code, "TRANSACTION_MESSAGE_UNEXPECTED");
      return true;
    },
  );

  // The hash binds the exact signed message: another transaction's bytes are
  // a message mismatch, never a signature over the wrong message.
  const other = await publishFixture({ blockhash: "33333333333333333333333333333333" });
  assert.notEqual(other.prepared.messageBase64, base.prepared.messageBase64);
  const mismatched = await publishFixture({ messageBase64ForHash: other.prepared.messageBase64 });
  await assert.rejects(
    () => signApprovedFallback(mismatched.intent, keyFile, { home }),
    (error: unknown) => {
      assert.ok(error instanceof SeedRefusal);
      assert.equal(error.code, "INTENT_HASH_MISMATCH");
      return true;
    },
  );

  // An instruction data string that is not the reviewed bytes is refused.
  const dataTampered = await publishFixture({
    planOverrides: { instructionData: Buffer.alloc(178, 1).toString("base64") },
  });
  await assert.rejects(
    () => signApprovedFallback(dataTampered.intent, keyFile, { home }),
    (error: unknown) => {
      assert.ok(error instanceof SeedRefusal);
      assert.equal(error.code, "TRANSACTION_MESSAGE_UNEXPECTED");
      return true;
    },
  );
});

test("fallback: a real signed run posts a signature the server re-validation accepts", async () => {
  const fixture = await publishFixture();
  const stack = fakeStack(fixture);
  const report = await runFallbackCertificate(optionsFor(stack, { signer }));
  assert.equal(report.mode, "created");
  assert.equal(report.ok, true);
  assert.equal(stack.signedPosted, 1);
  assert.equal(stack.signedAccepted, 1);
  assert.ok(stack.calls.includes("POST /v1/admin/publish-intents/11111111-2222-3333-4444-555555555555/signature"));
  assert.ok(stack.calls.includes("POST /v1/admin/publish-intents/11111111-2222-3333-4444-555555555555/reconciliation"));
  assert.ok(stack.calls.includes("POST /v1/admin/publish-intents/11111111-2222-3333-4444-555555555555/certificate"));
  // The published discriminator is the real one in the reviewed bytes.
  const data = Buffer.from(String(fixture.plan.instructionData), "base64");
  assert.deepEqual([...data.subarray(0, 8)], [...PUBLISH_ANCHOR_DISCRIMINATOR]);
});

test("fallback: a legacy ordinal ledger day in a review is refused", async () => {
  const fixture = await publishFixture({ planOverrides: { dayUtc: 20231 } });
  // The A1 signer request contract refuses it outright …
  await assert.rejects(
    () => signApprovedFallback(fixture.intent, keyFile, { home }),
    (error: unknown) => {
      assert.ok(error instanceof SeedRefusal);
      assert.equal(error.code, "REQUEST_INVALID");
      return true;
    },
  );
  // … and the fallback's own review parser refuses it before anything is sent.
  const stack = fakeStack(fixture);
  await assert.rejects(
    () => runFallbackCertificate(optionsFor(stack)),
    (error: unknown) => {
      assert.ok(error instanceof SeedRefusal);
      assert.equal(error.code, "RESPONSE_INVALID");
      return true;
    },
  );
  assert.equal(stack.signedPosted, 0);
});
