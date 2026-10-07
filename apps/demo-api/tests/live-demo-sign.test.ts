import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createPrivateKey, createPublicKey, sign as ed25519Sign } from "node:crypto";
import { chmod, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { after, before, test } from "node:test";
import {
  appendTransactionMessageInstruction,
  compileTransaction,
  createNoopSigner,
  createTransactionMessage,
  getAddressDecoder,
  getTransactionDecoder,
  getTransactionEncoder,
  pipe,  setTransactionMessageFeePayerSigner,
  setTransactionMessageLifetimeUsingBlockhash,
  type Address,
  type Blockhash,
  type Instruction,
} from "@solana/kit";
import {
  prepareAnchorTransaction,
  validateSignedTransaction,
  type AnchorTransactionInput,
  type PreparedTransaction,
} from "../src/admin-transaction.ts";
import { intentHash, type PublishIntent } from "../src/transaction-state.ts";
import {
  findLedgerSegmentPda,
  findRegistryConfigPda,
  findRolePda,
  getPublishAnchorInstruction,
} from "../../../packages/onchain-client/src/index.ts";
import { registryIdHash } from "../../../packages/canonical-ts/src/index.ts";
import { assertKeyFilePolicy, defaultKeyFile } from "../scripts/live-demo-key-store.ts";
import {
  DEFAULT_KEY_FILE,
  dayUtcOf,
  parseSignRequest,
  signApprovedTransaction,
  SignerRefusal,
} from "../scripts/live-demo-sign.ts";

const SCRIPT = fileURLToPath(new URL("../scripts/live-demo-sign.ts", import.meta.url));
const PROGRAM_ID = "6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo" as Address;
const SYSTEM_PROGRAM = "11111111111111111111111111111111" as Address;
// The ledger day is the UTC calendar day as YYYYMMDD (`utc_day` / `ledgerDay`):
// the real numeric contract the registry program checks. Earlier fixtures used
// ordinal day numbers (20_665) that only the old 0..100_000 parser bound
// accepted; the on-chain check would have refused them with `WrongLedgerDay`.
const DAY_UTX = 20261006;
const operatorSecret = new Uint8Array(32).fill(3);
const foreignSecret = new Uint8Array(32).fill(5);

let keyDir = "";
let keyFile = "";
let otherDir = "";
let homeDir = "";
let storeDir = "";

function keysFor(secret: Uint8Array): {
  address: Address;
  privateKey: ReturnType<typeof createPrivateKey>;
  publicKeyBytes: Uint8Array;
} {
  const privateKey = createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(secret)]),
    format: "der",
    type: "pkcs8",
  });
  const publicDer = createPublicKey(privateKey).export({ format: "der", type: "spki" });
  const publicKeyBytes = new Uint8Array(publicDer).slice(-32);
  return {
    address: getAddressDecoder().decode(publicKeyBytes),
    privateKey,
    publicKeyBytes,
  };
}

function keypairJson(secret: Uint8Array, publicKeyBytes: Uint8Array): number[] {
  return [...secret, ...publicKeyBytes];
}

function hex(value: Uint8Array): string {
  return Buffer.from(value).toString("hex");
}

async function inputFor(operator: Address, batchSequence = 1n): Promise<AnchorTransactionInput> {
  const [configPda] = await findRegistryConfigPda(registryIdHash("gov.registry.land"), { programAddress: PROGRAM_ID });
  const [rolePda] = await findRolePda({ config: configPda, operator }, { programAddress: PROGRAM_ID });
  const [segmentPda] = await findLedgerSegmentPda(
    { config: configPda, dayUtc: DAY_UTX, segmentIndex: 0 },
    { programAddress: PROGRAM_ID },
  );
  return {
    programId: PROGRAM_ID,
    configPda,
    rolePda,
    segmentPda,
    operator,
    blockhash: "11111111111111111111111111111111",
    lastValidBlockHeight: 1_000n,
    batchSequence,
    registryVersion: 1n,
    cursorStart: 1n,
    cursorEnd: 2n,
    merkleRoot: new Uint8Array(32).fill(0xaa),
    manifestHash: new Uint8Array(32).fill(0xbb),
    previousAnchorHash: new Uint8Array(32).fill(0xcc),
    leafCount: 2,
    schemaVersion: 1,
    hashAlgorithm: 1,
    treeAlgorithm: 1,
  };
}

function derivedMessageBase64(transactionBase64: string): string {
  const transaction = getTransactionDecoder().decode(Buffer.from(transactionBase64, "base64"));
  return Buffer.from(transaction.messageBytes).toString("base64");
}

function hashIntent(intent: Record<string, unknown>, messageBase64: string): string {
  return hex(
    intentHash({
      registryId: intent.registryId as string,
      batchSequence: BigInt(intent.batchSequence as string),
      registryVersion: BigInt(intent.registryVersion as string),
      cursorStart: BigInt(intent.cursorStart as string),
      cursorEnd: BigInt(intent.cursorEnd as string),
      leafCount: intent.leafCount as number,
      merkleRootHex: intent.merkleRootHex as string,
      manifestHashHex: intent.manifestHashHex as string,
      previousAnchorHashHex: intent.previousAnchorHashHex as string,
      programId: intent.programId as Address,
      configPda: intent.configPda as Address,
      rolePda: intent.rolePda as Address,
      segmentPda: intent.segmentPda as Address,
      segmentIndex: intent.segmentIndex as number,
      dayUtc: intent.dayUtc as number,
      feePayer: intent.feePayer as Address,
      recentBlockhash: intent.recentBlockhash as string,
      lastValidBlockHeight: BigInt(intent.lastValidBlockHeight as string),
      messageBase64,
    } as PublishIntent),
  );
}

function buildRequest(input: AnchorTransactionInput): { request: Record<string, any>; prepared: PreparedTransaction } {
  const prepared = prepareAnchorTransaction(input);
  const intent = {
    registryId: "gov.registry.land",
    batchSequence: input.batchSequence.toString(),
    registryVersion: input.registryVersion.toString(),
    cursorStart: input.cursorStart.toString(),
    cursorEnd: input.cursorEnd.toString(),
    leafCount: input.leafCount,
    merkleRootHex: hex(input.merkleRoot),
    manifestHashHex: hex(input.manifestHash),
    previousAnchorHashHex: hex(input.previousAnchorHash),
    programId: input.programId,
    configPda: input.configPda,
    rolePda: input.rolePda,
    segmentPda: input.segmentPda,
    segmentIndex: 0,
    dayUtc: DAY_UTX,
    feePayer: input.operator,
    recentBlockhash: input.blockhash,
    lastValidBlockHeight: input.lastValidBlockHeight.toString(),
  };
  return {
    request: {
      approved: true,
      intentId: "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
      cluster: "solana:devnet",
      intentHash: hashIntent(intent, prepared.messageBase64),
      transactionBase64: prepared.transactionBase64,
      instructionData: prepared.instructionDataBase64,
      messageBase64: prepared.messageBase64,
      intent,
    },
    prepared,
  };
}

function rehash(request: Record<string, any>): void {
  request.intentHash = hashIntent(request.intent, derivedMessageBase64(request.transactionBase64));
}

// Real `GET /v1/admin/publish-intents/{id}` shape (admin.ts intentResponse plus
// admin-batch.ts batchReview): the review exposes `merkleRoot`, `manifestHash`
// and `previousAnchorHash` — NOT the signer's *Hex field names — and the
// response carries `intentHash`, `intentId`, `recentBlockhash` and
// `lastValidBlockHeight` at the top level. `messageBase64` is never included.
function apiIntentResponse(input: AnchorTransactionInput, prepared: PreparedTransaction): Record<string, any> {
  return {
    intentId: "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
    state: "SIMULATED",
    batchSequence: input.batchSequence.toString(),
    intentHash: "0".repeat(64),
    review: {
      registryId: "gov.registry.land",
      batchSequence: input.batchSequence.toString(),
      registryVersion: input.registryVersion.toString(),
      cursorStart: input.cursorStart.toString(),
      cursorEnd: input.cursorEnd.toString(),
      leafCount: input.leafCount,
      merkleRoot: hex(input.merkleRoot),
      manifestHash: hex(input.manifestHash),
      previousAnchorHash: hex(input.previousAnchorHash),
      records: [],
      createdAt: "2026-10-06T00:00:00Z",
      cluster: "solana:devnet",
      programId: input.programId,
      configPda: input.configPda,
      rolePda: input.rolePda,
      segmentPda: input.segmentPda,
      segmentIndex: 0,
      dayUtc: DAY_UTX,
      feePayer: input.operator,
      accounts: prepared.accounts,
      instructionData: prepared.instructionDataBase64,
      transactionBase64: prepared.transactionBase64,
      simulation: { ok: true, error: null, unitsConsumed: 5_000 },
    },
    recentBlockhash: input.blockhash,
    lastValidBlockHeight: input.lastValidBlockHeight.toString(),
    expiresAt: "2026-10-06T00:01:30Z",
    transactionSignature: null,
    anchorSlot: null,
    certificateId: null,
    failureCode: null,
    simulationLogs: [],
  };
}

// The launcher's (Python adapter) mapping from the API response to the signer
// stdin contract. The three review hash fields must be renamed to the signer's
// *Hex names; everything else keeps its name; `messageBase64` is omitted
// because the API response does not contain it.
function signerRequestFromApiIntent(response: Record<string, any>): Record<string, any> {
  const review = response.review;
  return {
    approved: true,
    intentId: response.intentId,
    cluster: review.cluster,
    intentHash: response.intentHash,
    transactionBase64: review.transactionBase64,
    instructionData: review.instructionData,
    intent: {
      registryId: review.registryId,
      batchSequence: review.batchSequence,
      registryVersion: review.registryVersion,
      cursorStart: review.cursorStart,
      cursorEnd: review.cursorEnd,
      leafCount: review.leafCount,
      merkleRootHex: review.merkleRoot,
      manifestHashHex: review.manifestHash,
      previousAnchorHashHex: review.previousAnchorHash,
      programId: review.programId,
      configPda: review.configPda,
      rolePda: review.rolePda,
      segmentPda: review.segmentPda,
      segmentIndex: review.segmentIndex,
      dayUtc: review.dayUtc,
      feePayer: review.feePayer,
      recentBlockhash: response.recentBlockhash,
      lastValidBlockHeight: response.lastValidBlockHeight,
    },
  };
}

function apiRequestFor(
  input: AnchorTransactionInput,
): { request: Record<string, any>; prepared: PreparedTransaction; response: Record<string, any> } {
  const prepared = prepareAnchorTransaction(input);
  const response = apiIntentResponse(input, prepared);
  const request = signerRequestFromApiIntent(response);
  request.intentHash = hashIntent(request.intent, prepared.messageBase64);
  response.intentHash = request.intentHash;
  return { request, prepared, response };
}

type CliResult = { status: number | null; stdout: string; stderr: string };

function runCli(body: string, keyFilePath: string): CliResult {
  return spawnSync(
    process.execPath,
    ["--experimental-transform-types", "--disable-warning=ExperimentalWarning", SCRIPT, "--key-file", keyFilePath],
    {
      input: body,
      encoding: "utf8",
      cwd: path.dirname(path.dirname(SCRIPT)),
      timeout: 60_000,
      maxBuffer: 4 * 1024 * 1024,
    },
  );
}

function assertRefusal(result: CliResult, code: string, status: number): void {
  assert.equal(result.status, status, result.stderr);
  assert.equal(result.stdout, "");
  assert.deepEqual(JSON.parse(result.stderr.trim()), { error: { code } });
}

async function expectRefusal(code: string, run: () => Promise<unknown>): Promise<void> {
  await assert.rejects(run, (error: unknown) => {
    assert.ok(error instanceof SignerRefusal, `expected SignerRefusal, got ${String(error)}`);
    assert.equal((error as SignerRefusal).code, code);
    return true;
  });
}

function walletSign(transactionBase64: string, keys: ReturnType<typeof keysFor>): string {
  const transaction = getTransactionDecoder().decode(Buffer.from(transactionBase64, "base64"));
  const signature = ed25519Sign(null, Buffer.from(transaction.messageBytes), keys.privateKey);
  const signed = {
    ...transaction,
    signatures: { ...transaction.signatures, [keys.address]: new Uint8Array(signature) },
  };
  return Buffer.from(getTransactionEncoder().encode(signed)).toString("base64");
}

before(async () => {
  keyDir = `/dev/shm/onelayer-live-demo-sign-test-${process.pid}-a`;
  otherDir = `/dev/shm/onelayer-live-demo-sign-test-${process.pid}-b`;
  await mkdir(keyDir, { mode: 0o700, recursive: true });
  await mkdir(otherDir, { mode: 0o700, recursive: true });
  keyFile = path.join(keyDir, "demo-operator.json");
  // Controlled temporary "home" for the persistent key store fixtures; nothing
  // is ever written under the real ~/.local/state/... during tests.
  homeDir = path.join(tmpdir(), `onelayer-live-demo-sign-home-${process.pid}`);
  await mkdir(homeDir, { mode: 0o700, recursive: true });
  storeDir = path.join(homeDir, ".local", "state", "onelayer-devnet-demo", "keys");
  await mkdir(storeDir, { mode: 0o700, recursive: true });
});

after(async () => {
  await rm(keyDir, { recursive: true, force: true });
  await rm(otherDir, { recursive: true, force: true });
  await rm(homeDir, { recursive: true, force: true });
});

test("the default key file is the persistent devnet key store location", () => {
  assert.equal(DEFAULT_KEY_FILE, defaultKeyFile());
  assert.equal(
    DEFAULT_KEY_FILE,
    path.join(homedir(), ".local", "state", "onelayer-devnet-demo", "keys", "demo-operator.json"),
  );
  assert.ok(path.isAbsolute(DEFAULT_KEY_FILE));
  // The legacy /dev/shm runtime location stays inside the allow-list.
  assert.equal(assertKeyFilePolicy("/dev/shm/onelayer-devnet-demo/demo-operator.json").kind, "shm");
  assert.equal(assertKeyFilePolicy(DEFAULT_KEY_FILE).kind, "persistent");
});

test("a signature over the approved intent passes the server validation", async () => {
  const operator = keysFor(operatorSecret);
  await writeFile(keyFile, JSON.stringify(keypairJson(operatorSecret, operator.publicKeyBytes)), { mode: 0o600 });
  const { request, prepared } = buildRequest(await inputFor(operator.address));
  const signed = await signApprovedTransaction(request, keyFile);
  const signature = validateSignedTransaction(signed, prepared.messageBase64, operator.address);
  assert.match(signature, /^[1-9A-HJ-NP-Za-km-z]{80,90}$/);
  const decoded = getTransactionDecoder().decode(Buffer.from(signed, "base64"));
  assert.deepEqual(Buffer.from(decoded.messageBytes).toString("base64"), prepared.messageBase64);
});

test("the CLI contract emits exactly the signed wire transaction and nothing else", async () => {
  const operator = keysFor(operatorSecret);
  await writeFile(keyFile, JSON.stringify(keypairJson(operatorSecret, operator.publicKeyBytes)), { mode: 0o600 });
  const { request, prepared } = buildRequest(await inputFor(operator.address));
  const result = runCli(JSON.stringify(request), keyFile);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, "");
  assert.deepEqual(Object.keys(JSON.parse(result.stdout)), ["signedTransactionBase64"]);
  const { signedTransactionBase64 } = JSON.parse(result.stdout) as { signedTransactionBase64: string };
  const signature = validateSignedTransaction(signedTransactionBase64, prepared.messageBase64, operator.address);
  assert.match(signature, /^[1-9A-HJ-NP-Za-km-z]{80,90}$/);
});

test("explicit approval is required by the request contract", async () => {
  const operator = keysFor(operatorSecret);
  await writeFile(keyFile, JSON.stringify(keypairJson(operatorSecret, operator.publicKeyBytes)), { mode: 0o600 });
  const { request } = buildRequest(await inputFor(operator.address));
  request.approved = false;
  await expectRefusal("APPROVAL_REQUIRED", () => signApprovedTransaction(request, keyFile));
  delete request.approved;
  await expectRefusal("APPROVAL_REQUIRED", () => signApprovedTransaction(request, keyFile));
  const result = runCli(JSON.stringify(request), keyFile);
  assertRefusal(result, "APPROVAL_REQUIRED", 2);
});

test("a cluster other than the local devnet profile is refused", async () => {
  const operator = keysFor(operatorSecret);
  await writeFile(keyFile, JSON.stringify(keypairJson(operatorSecret, operator.publicKeyBytes)), { mode: 0o600 });
  const { request } = buildRequest(await inputFor(operator.address));
  request.cluster = "solana:mainnet";
  await expectRefusal("CLUSTER_UNSUPPORTED", () => signApprovedTransaction(request, keyFile));
});

test("a program other than the devnet registry program is refused", async () => {
  const operator = keysFor(operatorSecret);
  await writeFile(keyFile, JSON.stringify(keypairJson(operatorSecret, operator.publicKeyBytes)), { mode: 0o600 });
  const { request } = buildRequest(await inputFor(operator.address));
  request.intent.programId = SYSTEM_PROGRAM;
  rehash(request);
  await expectRefusal("PROGRAM_UNSUPPORTED", () => signApprovedTransaction(request, keyFile));
});

test("tampered transaction bytes are refused against the approved intent hash", async () => {
  const operator = keysFor(operatorSecret);
  await writeFile(keyFile, JSON.stringify(keypairJson(operatorSecret, operator.publicKeyBytes)), { mode: 0o600 });
  const { request } = buildRequest(await inputFor(operator.address, 1n));
  const tampered = buildRequest(await inputFor(operator.address, 2n));
  request.transactionBase64 = tampered.request.transactionBase64;
  request.instructionData = tampered.request.instructionData;
  request.messageBase64 = derivedMessageBase64(request.transactionBase64);
  await expectRefusal("INTENT_HASH_MISMATCH", () => signApprovedTransaction(request, keyFile));
});

test("intent fields that contradict the approved transaction are refused", async () => {
  const operator = keysFor(operatorSecret);
  await writeFile(keyFile, JSON.stringify(keypairJson(operatorSecret, operator.publicKeyBytes)), { mode: 0o600 });
  const { request } = buildRequest(await inputFor(operator.address));
  request.intent.merkleRootHex = "dd".repeat(32);
  rehash(request);
  await expectRefusal("TRANSACTION_MESSAGE_UNEXPECTED", () => signApprovedTransaction(request, keyFile));
});

test("instruction data that differs from the reviewed bytes is refused", async () => {
  const operator = keysFor(operatorSecret);
  await writeFile(keyFile, JSON.stringify(keypairJson(operatorSecret, operator.publicKeyBytes)), { mode: 0o600 });
  const { request } = buildRequest(await inputFor(operator.address));
  const data = Buffer.from(request.instructionData, "base64");
  data[data.length - 1] ^= 0x01;
  request.instructionData = data.toString("base64");
  await expectRefusal("TRANSACTION_MESSAGE_UNEXPECTED", () => signApprovedTransaction(request, keyFile));
});

test("a messageBase64 that is not the transaction message is refused", async () => {
  const operator = keysFor(operatorSecret);
  await writeFile(keyFile, JSON.stringify(keypairJson(operatorSecret, operator.publicKeyBytes)), { mode: 0o600 });
  const { request } = buildRequest(await inputFor(operator.address));
  request.messageBase64 = buildRequest(await inputFor(operator.address, 2n)).prepared.messageBase64;
  await expectRefusal("MESSAGE_IDENTITY_MISMATCH", () => signApprovedTransaction(request, keyFile));
});

test("a transaction for a different fee payer is refused", async () => {
  const operator = keysFor(operatorSecret);
  await writeFile(keyFile, JSON.stringify(keypairJson(operatorSecret, operator.publicKeyBytes)), { mode: 0o600 });
  const foreign = keysFor(foreignSecret);
  const { request } = buildRequest(await inputFor(foreign.address));
  await expectRefusal("OPERATOR_MISMATCH", () => signApprovedTransaction(request, keyFile));
});

test("an already signed transaction is refused", async () => {
  const operator = keysFor(operatorSecret);
  await writeFile(keyFile, JSON.stringify(keypairJson(operatorSecret, operator.publicKeyBytes)), { mode: 0o600 });
  const { request } = buildRequest(await inputFor(operator.address));
  request.transactionBase64 = walletSign(request.transactionBase64, operator);
  await expectRefusal("TRANSACTION_MESSAGE_UNEXPECTED", () => signApprovedTransaction(request, keyFile));
});

test("a message with an extra instruction is refused", async () => {
  const operator = keysFor(operatorSecret);
  await writeFile(keyFile, JSON.stringify(keypairJson(operatorSecret, operator.publicKeyBytes)), { mode: 0o600 });
  const input = await inputFor(operator.address);
  const noop = createNoopSigner(input.operator);
  const publish = getPublishAnchorInstruction(
    {
      config: input.configPda,
      role: input.rolePda,
      operator: noop,
      segment: input.segmentPda,
      batchSequence: input.batchSequence,
      registryVersion: input.registryVersion,
      sourceCursorStart: input.cursorStart,
      sourceCursorEnd: input.cursorEnd,
      merkleRoot: input.merkleRoot,
      manifestHash: input.manifestHash,
      snapshotHash: new Uint8Array(32),
      previousAnchorHash: input.previousAnchorHash,
      leafCount: input.leafCount,
      schemaVersion: input.schemaVersion,
      flags: 0,
      hashAlgorithm: input.hashAlgorithm,
      treeAlgorithm: input.treeAlgorithm,
    },
    { programAddress: input.programId },
  );
  const extra: Instruction = { programAddress: SYSTEM_PROGRAM, accounts: [], data: new Uint8Array([1, 2, 3]) };
  const message = pipe(
    createTransactionMessage({ version: 0 }),
    (draft) => setTransactionMessageFeePayerSigner(noop, draft),
    (draft) =>
      setTransactionMessageLifetimeUsingBlockhash(
        { blockhash: input.blockhash as Blockhash, lastValidBlockHeight: input.lastValidBlockHeight },
        draft,
      ),
    (draft) => appendTransactionMessageInstruction(publish, draft),
    (draft) => appendTransactionMessageInstruction(extra, draft),
  );
  const transaction = compileTransaction(message);
  const { request } = buildRequest(input);
  request.transactionBase64 = Buffer.from(getTransactionEncoder().encode(transaction)).toString("base64");
  request.messageBase64 = derivedMessageBase64(request.transactionBase64);
  rehash(request);
  await expectRefusal("TRANSACTION_MESSAGE_UNEXPECTED", () => signApprovedTransaction(request, keyFile));
});

test("accounts outside the approved publish-anchor set are refused", async () => {
  const operator = keysFor(operatorSecret);
  await writeFile(keyFile, JSON.stringify(keypairJson(operatorSecret, operator.publicKeyBytes)), { mode: 0o600 });
  const { request } = buildRequest(await inputFor(operator.address));
  request.intent.segmentPda = SYSTEM_PROGRAM;
  rehash(request);
  await expectRefusal("TRANSACTION_MESSAGE_UNEXPECTED", () => signApprovedTransaction(request, keyFile));
});

test("the key file must live in a private directory under /dev/shm", async () => {
  const operator = keysFor(operatorSecret);
  const outside = path.join(tmpdir(), `onelayer-live-demo-sign-test-${process.pid}`);
  await mkdir(outside, { mode: 0o700, recursive: true });
  const outsideFile = path.join(outside, "demo-operator.json");
  try {
    await writeFile(outsideFile, JSON.stringify(keypairJson(operatorSecret, operator.publicKeyBytes)), { mode: 0o600 });
    const { request } = buildRequest(await inputFor(operator.address));
    await expectRefusal("KEYFILE_REJECTED", () => signApprovedTransaction(request, outsideFile));
  } finally {
    await rm(outside, { recursive: true, force: true });
  }
});

test("a key file directly in /dev/shm is refused", async () => {
  const operator = keysFor(operatorSecret);
  const loose = `/dev/shm/onelayer-live-demo-sign-test-${process.pid}-loose.json`;
  try {
    await writeFile(loose, JSON.stringify(keypairJson(operatorSecret, operator.publicKeyBytes)), { mode: 0o600 });
    const { request } = buildRequest(await inputFor(operator.address));
    await expectRefusal("KEYFILE_REJECTED", () => signApprovedTransaction(request, loose));
  } finally {
    await rm(loose, { force: true });
  }
});

test("a world-readable key file is refused", async () => {
  const operator = keysFor(operatorSecret);
  const looseFile = path.join(otherDir, "demo-operator.json");
  await writeFile(looseFile, JSON.stringify(keypairJson(operatorSecret, operator.publicKeyBytes)), { mode: 0o600 });
  await chmod(looseFile, 0o644);
  const { request } = buildRequest(await inputFor(operator.address));
  await expectRefusal("KEYFILE_REJECTED", () => signApprovedTransaction(request, looseFile));
});

test("a symlinked key file is refused", async () => {
  const operator = keysFor(operatorSecret);
  await writeFile(keyFile, JSON.stringify(keypairJson(operatorSecret, operator.publicKeyBytes)), { mode: 0o600 });
  const link = path.join(otherDir, "link.json");
  await symlink(keyFile, link);
  const { request } = buildRequest(await inputFor(operator.address));
  await expectRefusal("KEYFILE_REJECTED", () => signApprovedTransaction(request, link));
});

test("a keypair whose public part does not match its seed is refused", async () => {
  await writeFile(keyFile, JSON.stringify(keypairJson(operatorSecret, foreignSecret)), { mode: 0o600 });
  const operator = keysFor(operatorSecret);
  const { request } = buildRequest(await inputFor(operator.address));
  await expectRefusal("KEYPAIR_INVALID", () => signApprovedTransaction(request, keyFile));
});

test("a missing key file is refused", async () => {
  const operator = keysFor(operatorSecret);
  const { request } = buildRequest(await inputFor(operator.address));
  await expectRefusal("KEYFILE_UNREADABLE", () => signApprovedTransaction(request, path.join(keyDir, "absent.json")));
});

test("a malformed request is refused before anything is signed", async () => {
  const operator = keysFor(operatorSecret);
  await writeFile(keyFile, JSON.stringify(keypairJson(operatorSecret, operator.publicKeyBytes)), { mode: 0o600 });
  const { request } = buildRequest(await inputFor(operator.address));
  request.unexpected = 1;
  await expectRefusal("REQUEST_INVALID", () => signApprovedTransaction(request, keyFile));
  const badType = buildRequest(await inputFor(operator.address)).request;
  badType.intent.leafCount = "2";
  await expectRefusal("REQUEST_INVALID", () => signApprovedTransaction(badType, keyFile));
  const result = runCli("not json", keyFile);
  assertRefusal(result, "REQUEST_INVALID_JSON", 2);
  const oversized = runCli(`{"pad":"${"a".repeat(70_000)}"}`, keyFile);
  assertRefusal(oversized, "REQUEST_TOO_LARGE", 2);
});

test("no key material appears on any output channel", async () => {
  const operator = keysFor(operatorSecret);
  const keypairText = JSON.stringify(keypairJson(operatorSecret, operator.publicKeyBytes));
  await writeFile(keyFile, keypairText, { mode: 0o600 });
  const { request } = buildRequest(await inputFor(operator.address));
  const good = runCli(JSON.stringify(request), keyFile);
  const bad = runCli(JSON.stringify({ ...request, approved: false }), keyFile);
  const seedHex = hex(operatorSecret);
  const seedBase64 = Buffer.from(operatorSecret).toString("base64");
  for (const output of [good.stdout, good.stderr, bad.stdout, bad.stderr]) {
    assert.ok(!output.includes(seedHex), "seed hex leaked");
    assert.ok(!output.includes(seedBase64), "seed base64 leaked");
    assert.ok(!output.includes(keypairText), "keypair file leaked");
    assert.ok(!output.includes("302e020100300506032b657004220420"), "pkcs8 prefix leaked");
  }
});

test("the production request shape without messageBase64 signs and passes the server validation", async () => {
  const operator = keysFor(operatorSecret);
  await writeFile(keyFile, JSON.stringify(keypairJson(operatorSecret, operator.publicKeyBytes)), { mode: 0o600 });
  const { request, prepared } = buildRequest(await inputFor(operator.address));
  // The real API response never carries messageBase64; the launcher omits it.
  delete request.messageBase64;
  const signed = await signApprovedTransaction(request, keyFile);
  const signature = validateSignedTransaction(signed, prepared.messageBase64, operator.address);
  assert.match(signature, /^[1-9A-HJ-NP-Za-km-z]{80,90}$/);
  const result = runCli(JSON.stringify(request), keyFile);
  assert.equal(result.status, 0, result.stderr);
  const { signedTransactionBase64 } = JSON.parse(result.stdout) as { signedTransactionBase64: string };
  validateSignedTransaction(signedTransactionBase64, prepared.messageBase64, operator.address);
});

test("the real API review maps to a signable request with the renamed hash fields", async () => {
  const operator = keysFor(operatorSecret);
  await writeFile(keyFile, JSON.stringify(keypairJson(operatorSecret, operator.publicKeyBytes)), { mode: 0o600 });
  const { request, prepared, response } = apiRequestFor(await inputFor(operator.address));
  // P1: the API review names the three hashes merkleRoot/manifestHash/
  // previousAnchorHash; the launcher must rename them to the signer's *Hex
  // fields. The literal names below are what the server actually returns.
  assert.equal(response.review.merkleRoot, request.intent.merkleRootHex);
  assert.equal(response.review.manifestHash, request.intent.manifestHashHex);
  assert.equal(response.review.previousAnchorHash, request.intent.previousAnchorHashHex);
  assert.equal(request.messageBase64, undefined);
  const signed = await signApprovedTransaction(request, keyFile);
  validateSignedTransaction(signed, prepared.messageBase64, operator.address);
});

test("a literal API mapping without the hash-field renames is refused", async () => {
  const operator = keysFor(operatorSecret);
  await writeFile(keyFile, JSON.stringify(keypairJson(operatorSecret, operator.publicKeyBytes)), { mode: 0o600 });
  const { request, response } = apiRequestFor(await inputFor(operator.address));
  // The pre-P1 mistake: the review names are passed through unchanged.
  delete request.intent.merkleRootHex;
  delete request.intent.manifestHashHex;
  delete request.intent.previousAnchorHashHex;
  request.intent.merkleRoot = response.review.merkleRoot;
  request.intent.manifestHash = response.review.manifestHash;
  request.intent.previousAnchorHash = response.review.previousAnchorHash;
  await expectRefusal("REQUEST_INVALID", () => signApprovedTransaction(request, keyFile));
});

test("the ledger day is the real YYYYMMDD utc day, from the parser to the signer", async () => {
  const operator = keysFor(operatorSecret);
  await writeFile(keyFile, JSON.stringify(keypairJson(operatorSecret, operator.publicKeyBytes)), { mode: 0o600 });
  const { request, prepared, response } = apiRequestFor(await inputFor(operator.address));
  // The real demo-api review carries ledgerDay()'s YYYYMMDD; it must survive
  // parsing and reach the signed message unchanged.
  assert.equal(response.review.dayUtc, 20261006);
  assert.equal(parseSignRequest(JSON.stringify(request)).intent.dayUtc, 20261006);
  const signed = await signApprovedTransaction(request, keyFile);
  validateSignedTransaction(signed, prepared.messageBase64, operator.address);

  for (const day of [19700101, 20240229, 20261231, 99991231]) {
    assert.equal(dayUtcOf(day), day);
    const candidate = { ...request, intent: { ...request.intent, dayUtc: day } };
    rehash(candidate);
    assert.equal(parseSignRequest(JSON.stringify(candidate)).intent.dayUtc, day);
  }

  // Legacy ordinal day numbers, out-of-range values and impossible calendar
  // days are refused by the day contract itself: the intent hash is repaired
  // for every candidate, so nothing but the day bound can be the reason.
  for (const day of [20231, 20_665, 100_000, 19700100, 99991232, 20261301, 20260230, 21000229]) {
    const candidate = { ...request, intent: { ...request.intent, dayUtc: day } };
    rehash(candidate);
    await expectRefusal("REQUEST_INVALID", async () => parseSignRequest(JSON.stringify(candidate)));
    await expectRefusal("REQUEST_INVALID", () => signApprovedTransaction(candidate, keyFile));
    assert.throws(() => dayUtcOf(day), (error: unknown) => {
      assert.ok(error instanceof SignerRefusal);
      assert.equal(error.code, "REQUEST_INVALID");
      return true;
    });
  }
});

test("the CLI refuses key problems with exit code 3", async () => {
  const operator = keysFor(operatorSecret);
  await writeFile(keyFile, JSON.stringify(keypairJson(operatorSecret, operator.publicKeyBytes)), { mode: 0o600 });
  const { request } = buildRequest(await inputFor(operator.address));
  assertRefusal(runCli(JSON.stringify(request), path.join(keyDir, "absent.json")), "KEYFILE_UNREADABLE", 3);
  const loose = path.join(otherDir, "loose-cli.json");
  await writeFile(loose, JSON.stringify(keypairJson(operatorSecret, operator.publicKeyBytes)), { mode: 0o600 });
  await chmod(loose, 0o644);
  assertRefusal(runCli(JSON.stringify(request), loose), "KEYFILE_REJECTED", 3);
  const foreign = keysFor(foreignSecret);
  const foreignFile = path.join(otherDir, "foreign-cli.json");
  await writeFile(foreignFile, JSON.stringify(keypairJson(foreignSecret, foreign.publicKeyBytes)), { mode: 0o600 });
  assertRefusal(runCli(JSON.stringify(request), foreignFile), "OPERATOR_MISMATCH", 3);
  const broken = path.join(otherDir, "broken-cli.json");
  await writeFile(broken, JSON.stringify(keypairJson(operatorSecret, foreign.publicKeyBytes)), { mode: 0o600 });
  assertRefusal(runCli(JSON.stringify(request), broken), "KEYPAIR_INVALID", 3);
});

test("a symlinked ancestor directory is refused", async () => {
  const operator = keysFor(operatorSecret);
  await writeFile(keyFile, JSON.stringify(keypairJson(operatorSecret, operator.publicKeyBytes)), { mode: 0o600 });
  const linkDir = path.join(otherDir, "linkdir");
  await symlink(keyDir, linkDir);
  const { request } = buildRequest(await inputFor(operator.address));
  await expectRefusal("KEYFILE_REJECTED", () => signApprovedTransaction(request, path.join(linkDir, "demo-operator.json")));
});

test("an ancestor directory writable by group/other is refused", async () => {
  const operator = keysFor(operatorSecret);
  const looseFile = path.join(otherDir, "demo-operator.json");
  await writeFile(looseFile, JSON.stringify(keypairJson(operatorSecret, operator.publicKeyBytes)), { mode: 0o600 });
  await chmod(otherDir, 0o707);
  try {
    const { request } = buildRequest(await inputFor(operator.address));
    await expectRefusal("KEYFILE_REJECTED", () => signApprovedTransaction(request, looseFile));
  } finally {
    await chmod(otherDir, 0o700);
  }
});

test("a directory at the key file path is refused", async () => {
  const operator = keysFor(operatorSecret);
  const asDirectory = path.join(otherDir, "as-directory");
  await mkdir(asDirectory, { mode: 0o700 });
  const { request } = buildRequest(await inputFor(operator.address));
  await expectRefusal("KEYFILE_REJECTED", () => signApprovedTransaction(request, asDirectory));
});

test("a key in the persistent devnet key store signs", async () => {
  const operator = keysFor(operatorSecret);
  const persistentFile = path.join(storeDir, "demo-operator.json");
  await writeFile(persistentFile, JSON.stringify(keypairJson(operatorSecret, operator.publicKeyBytes)), { mode: 0o600 });
  const { request, prepared } = buildRequest(await inputFor(operator.address));
  const signed = await signApprovedTransaction(request, persistentFile, { home: homeDir });
  validateSignedTransaction(signed, prepared.messageBase64, operator.address);
});

test("an omitted key file resolves the persistent store for the effective home", async () => {
  const operator = keysFor(operatorSecret);
  const persistentFile = path.join(storeDir, "demo-operator.json");
  await writeFile(persistentFile, JSON.stringify(keypairJson(operatorSecret, operator.publicKeyBytes)), { mode: 0o600 });
  const { request, prepared } = buildRequest(await inputFor(operator.address));
  const signed = await signApprovedTransaction(request, undefined, { home: homeDir });
  validateSignedTransaction(signed, prepared.messageBase64, operator.address);
});

test("a read-only 0400 key file in the persistent store is accepted", async () => {
  const operator = keysFor(operatorSecret);
  const readOnlyFile = path.join(storeDir, "read-only.json");
  await writeFile(readOnlyFile, JSON.stringify(keypairJson(operatorSecret, operator.publicKeyBytes)), { mode: 0o600 });
  await chmod(readOnlyFile, 0o400);
  const { request, prepared } = buildRequest(await inputFor(operator.address));
  const signed = await signApprovedTransaction(request, readOnlyFile, { home: homeDir });
  validateSignedTransaction(signed, prepared.messageBase64, operator.address);
});

test("keys outside the persistent store tree are refused", async () => {
  const operator = keysFor(operatorSecret);
  const strayDir = path.join(homeDir, ".local", "state", "stray");
  await mkdir(strayDir, { mode: 0o700, recursive: true });
  const strayFile = path.join(strayDir, "demo-operator.json");
  await writeFile(strayFile, JSON.stringify(keypairJson(operatorSecret, operator.publicKeyBytes)), { mode: 0o600 });
  const { request } = buildRequest(await inputFor(operator.address));
  await expectRefusal("KEYFILE_REJECTED", () => signApprovedTransaction(request, strayFile, { home: homeDir }));
});

test("a key file directly in the demo state directory is refused", async () => {
  const operator = keysFor(operatorSecret);
  const outside = path.join(homeDir, ".local", "state", "onelayer-devnet-demo", "demo-operator.json");
  await writeFile(outside, JSON.stringify(keypairJson(operatorSecret, operator.publicKeyBytes)), { mode: 0o600 });
  const { request } = buildRequest(await inputFor(operator.address));
  await expectRefusal("KEYFILE_REJECTED", () => signApprovedTransaction(request, outside, { home: homeDir }));
});

test("an unsafe system ancestor above the persistent store is refused", async () => {
  const operator = keysFor(operatorSecret);
  const persistentFile = path.join(storeDir, "demo-operator.json");
  await writeFile(persistentFile, JSON.stringify(keypairJson(operatorSecret, operator.publicKeyBytes)), { mode: 0o600 });
  const { request } = buildRequest(await inputFor(operator.address));
  await chmod(homeDir, 0o777);
  try {
    await expectRefusal("KEYFILE_REJECTED", () => signApprovedTransaction(request, persistentFile, { home: homeDir }));
  } finally {
    await chmod(homeDir, 0o700);
  }
});

test("the persistent store path is never widened to arbitrary locations", async () => {
  assert.throws(() => assertKeyFilePolicy(path.join(homeDir, "demo-operator.json"), { home: homeDir }), (error: unknown) => {
    assert.ok(error instanceof Error && (error as { code?: string }).code === "KEYFILE_REJECTED");
    return true;
  });
  assert.throws(() => assertKeyFilePolicy("/tmp/demo-operator.json"), (error: unknown) => {
    assert.ok(error instanceof Error && (error as { code?: string }).code === "KEYFILE_REJECTED");
    return true;
  });
  assert.throws(() => assertKeyFilePolicy("relative/demo-operator.json", { home: homeDir }), (error: unknown) => {
    assert.ok(error instanceof Error && (error as { code?: string }).code === "KEYFILE_REJECTED");
    return true;
  });
  assert.throws(() => assertKeyFilePolicy("/dev/shm/demo-operator.json"), (error: unknown) => {
    assert.ok(error instanceof Error && (error as { code?: string }).code === "KEYFILE_REJECTED");
    return true;
  });
});
