// Local devnet signer for the live-demo launcher (A1).
//
// The launcher's Approve action pipes the exact review/intent bytes the
// operator approved as one JSON object on stdin. This helper refuses anything
// that is not an unsigned OneLayer publish-anchor transaction for the local
// devnet profile: cluster, program, fee payer, accounts and instruction data
// are verified against the approved intent before the private key file is
// read, and the result is re-validated with the server's own
// validateSignedTransaction before anything is printed. Output is exactly one
// signed wire transaction; key material never appears in argv, stdin, stdout,
// stderr or logs.
//
// Keys are read only from the persistent devnet key store
// (~/.local/state/onelayer-devnet-demo/keys/) or the legacy private
// directories under /dev/shm — never from an arbitrary path — through the
// hardened loader in live-demo-key-store.ts.
import { sign as ed25519Sign, type KeyObject } from "node:crypto";
import * as path from "node:path";
import { pathToFileURL } from "node:url";
import {
  address,
  getCompiledTransactionMessageDecoder,
  getTransactionDecoder,
  getTransactionEncoder,
  type Address,
  type CompiledTransactionMessage,
  type CompiledTransactionMessageWithLifetime,
  type Transaction,
} from "@solana/kit";
import {
  getPublishAnchorInstructionDataDecoder,
  ONELAYER_REGISTRY_PROGRAM_ADDRESS,
  PUBLISH_ANCHOR_DISCRIMINATOR,
} from "../../../packages/onchain-client/src/index.ts";
import { validateSignedTransaction } from "../src/admin-transaction.ts";
import { intentHash, type PublishIntent } from "../src/transaction-state.ts";
import {
  defaultKeyFile,
  KeyStoreError,
  loadSigningKey,
  type KeyStoreOptions,
} from "./live-demo-key-store.ts";

// The launcher parses stdout strictly, so Node's own warnings are kept off the
// protocol channels.
process.removeAllListeners("warning");
process.on("warning", () => undefined);

export const DEFAULT_KEY_FILE = defaultKeyFile();
export const MAX_REQUEST_BYTES = 65_536;
export const MAX_TRANSACTION_BYTES = 1_232;
const INSTRUCTION_DATA_BYTES = 8 + 32 + 128 + 4 + 4 + 2;
const BASE58 = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;
const BASE64 = /^[A-Za-z0-9+/]*={0,2}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const DECIMAL = /^(0|[1-9][0-9]{0,19})$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const CLUSTER = "solana:devnet";

export class SignerRefusal extends Error {
  readonly code: string;

  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

export interface PublishIntentFields {
  registryId: string;
  batchSequence: bigint;
  registryVersion: bigint;
  cursorStart: bigint;
  cursorEnd: bigint;
  leafCount: number;
  merkleRootHex: string;
  manifestHashHex: string;
  previousAnchorHashHex: string;
  programId: Address;
  configPda: Address;
  rolePda: Address;
  segmentPda: Address;
  segmentIndex: number;
  dayUtc: number;
  feePayer: Address;
  recentBlockhash: string;
  lastValidBlockHeight: bigint;
}

export interface SignRequest {
  approved: true;
  intentId: string;
  cluster: typeof CLUSTER;
  intentHash: string;
  transactionBase64: string;
  instructionData: string;
  messageBase64?: string;
  intent: PublishIntentFields;
}

function strictObject(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new SignerRefusal("REQUEST_INVALID");
  const record = value as Record<string, unknown>;
  for (const key of Object.keys(record)) if (!keys.includes(key)) throw new SignerRefusal("REQUEST_INVALID");
  return record;
}

function field(record: Record<string, unknown>, name: string): unknown {
  const value = record[name];
  if (value === undefined) throw new SignerRefusal("REQUEST_INVALID");
  return value;
}

function text(value: unknown, pattern: RegExp, max: number): string {
  if (typeof value !== "string" || value.length > max || !pattern.test(value)) throw new SignerRefusal("REQUEST_INVALID");
  return value;
}

function decimal(value: unknown): bigint {
  return BigInt(text(value, DECIMAL, 20));
}

function integer(value: unknown, min: number, max: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < min || value > max) {
    throw new SignerRefusal("REQUEST_INVALID");
  }
  return value;
}

/**
 * The ledger day is the UTC calendar day encoded as `YYYYMMDD` — the same
 * numeric contract as `utc_day` in the registry program, `ledgerDay` in the
 * server and `validDayUtc` in the readiness probe. An ordinal day number can
 * never be an approved publish: the on-chain `WrongLedgerDay` check would
 * reject it, so it is refused here before the key is read.
 */
export function dayUtcOf(value: unknown): number {
  const day = integer(value, 19700101, 99991231);
  const year = Math.floor(day / 10_000);
  const month = Math.floor(day / 100) % 100;
  const date = day % 100;
  const roundTrip = new Date(Date.UTC(year, month - 1, date));
  if (
    roundTrip.getUTCFullYear() !== year ||
    roundTrip.getUTCMonth() !== month - 1 ||
    roundTrip.getUTCDate() !== date
  ) {
    throw new SignerRefusal("REQUEST_INVALID");
  }
  return day;
}

function addressOf(value: unknown): Address {
  const candidate = text(value, BASE58, 44);
  try {
    return address(candidate);
  } catch {
    throw new SignerRefusal("REQUEST_INVALID");
  }
}

function base64Bytes(value: unknown, max: number): Buffer {
  const encoded = text(value, BASE64, max);
  if (encoded.length % 4 !== 0) throw new SignerRefusal("REQUEST_INVALID");
  return Buffer.from(encoded, "base64");
}

export function parseSignRequest(raw: string): SignRequest {
  if (Buffer.byteLength(raw, "utf8") > MAX_REQUEST_BYTES) throw new SignerRefusal("REQUEST_TOO_LARGE");
  let decoded: unknown;
  try {
    decoded = JSON.parse(raw);
  } catch {
    throw new SignerRefusal("REQUEST_INVALID_JSON");
  }
  const request = strictObject(decoded, [
    "approved",
    "intentId",
    "cluster",
    "intentHash",
    "transactionBase64",
    "instructionData",
    "messageBase64",
    "intent",
  ]);
  // The explicit approval marker is part of the request contract; the launcher
  // sets it only after the operator pressed Approve on the review screen.
  if (request.approved !== true) throw new SignerRefusal("APPROVAL_REQUIRED");
  const intentId = text(field(request, "intentId"), UUID, 36);
  const cluster = text(field(request, "cluster"), /^solana:.+$/, 32);
  if (cluster !== CLUSTER) throw new SignerRefusal("CLUSTER_UNSUPPORTED");
  const intent = strictObject(field(request, "intent"), [
    "registryId",
    "batchSequence",
    "registryVersion",
    "cursorStart",
    "cursorEnd",
    "leafCount",
    "merkleRootHex",
    "manifestHashHex",
    "previousAnchorHashHex",
    "programId",
    "configPda",
    "rolePda",
    "segmentPda",
    "segmentIndex",
    "dayUtc",
    "feePayer",
    "recentBlockhash",
    "lastValidBlockHeight",
  ]);
  const programId = addressOf(field(intent, "programId"));
  if (programId !== ONELAYER_REGISTRY_PROGRAM_ADDRESS) throw new SignerRefusal("PROGRAM_UNSUPPORTED");
  const transactionBase64 = text(field(request, "transactionBase64"), BASE64, 4 * Math.ceil(MAX_TRANSACTION_BYTES / 3) + 8);
  const transactionBytes = base64Bytes(transactionBase64, 4 * Math.ceil(MAX_TRANSACTION_BYTES / 3) + 8);
  if (transactionBytes.length === 0 || transactionBytes.length > MAX_TRANSACTION_BYTES) throw new SignerRefusal("REQUEST_INVALID");
  const instructionData = text(field(request, "instructionData"), BASE64, 4 * Math.ceil(INSTRUCTION_DATA_BYTES / 3) + 8);
  if (base64Bytes(instructionData, 4 * Math.ceil(INSTRUCTION_DATA_BYTES / 3) + 8).length !== INSTRUCTION_DATA_BYTES) {
    throw new SignerRefusal("REQUEST_INVALID");
  }
  return {
    approved: true,
    intentId,
    cluster: CLUSTER,
    intentHash: text(field(request, "intentHash"), HEX64, 64),
    transactionBase64,
    instructionData,
    messageBase64: request.messageBase64 === undefined ? undefined : text(request.messageBase64, BASE64, 2_048),
    intent: {
      registryId: text(field(intent, "registryId"), /^[A-Za-z0-9._:-]{1,128}$/, 128),
      batchSequence: decimal(field(intent, "batchSequence")),
      registryVersion: decimal(field(intent, "registryVersion")),
      cursorStart: decimal(field(intent, "cursorStart")),
      cursorEnd: decimal(field(intent, "cursorEnd")),
      leafCount: integer(field(intent, "leafCount"), 1, 10_000),
      merkleRootHex: text(field(intent, "merkleRootHex"), HEX64, 64),
      manifestHashHex: text(field(intent, "manifestHashHex"), HEX64, 64),
      previousAnchorHashHex: text(field(intent, "previousAnchorHashHex"), HEX64, 64),
      programId,
      configPda: addressOf(field(intent, "configPda")),
      rolePda: addressOf(field(intent, "rolePda")),
      segmentPda: addressOf(field(intent, "segmentPda")),
      segmentIndex: integer(field(intent, "segmentIndex"), 0, 2),
      dayUtc: dayUtcOf(field(intent, "dayUtc")),
      feePayer: addressOf(field(intent, "feePayer")),
      recentBlockhash: addressOf(field(intent, "recentBlockhash")),
      lastValidBlockHeight: decimal(field(intent, "lastValidBlockHeight")),
    },
  };
}

function accountRole(
  header: { numSignerAccounts: number; numReadonlySignerAccounts: number; numReadonlyNonSignerAccounts: number },
  index: number,
  total: number,
): { signer: boolean; writable: boolean } {
  const signer = index < header.numSignerAccounts;
  const writable = signer
    ? index < header.numSignerAccounts - header.numReadonlySignerAccounts
    : index < total - header.numReadonlyNonSignerAccounts;
  return { signer, writable };
}

/**
 * Refuses anything that is not the approved publish-anchor message: the signed
 * bytes must be byte-identical to the approved wire transaction, the intent
 * fields must hash to the approved intent hash, and the parsed message must be
 * a single publish-anchor instruction over the approved accounts and arguments.
 */
function checkApprovedMessage(
  transaction: Transaction,
  messageBytes: Buffer,
  request: SignRequest,
): void {
  const messageBase64 = messageBytes.toString("base64");
  if (request.messageBase64 !== undefined && request.messageBase64 !== messageBase64) {
    throw new SignerRefusal("MESSAGE_IDENTITY_MISMATCH");
  }
  const intent = request.intent;
  const publishIntent: PublishIntent = {
    registryId: intent.registryId,
    batchSequence: intent.batchSequence,
    registryVersion: intent.registryVersion,
    cursorStart: intent.cursorStart,
    cursorEnd: intent.cursorEnd,
    leafCount: intent.leafCount,
    merkleRootHex: intent.merkleRootHex,
    manifestHashHex: intent.manifestHashHex,
    previousAnchorHashHex: intent.previousAnchorHashHex,
    programId: intent.programId,
    configPda: intent.configPda,
    rolePda: intent.rolePda,
    segmentPda: intent.segmentPda,
    segmentIndex: intent.segmentIndex,
    dayUtc: intent.dayUtc,
    feePayer: intent.feePayer,
    recentBlockhash: intent.recentBlockhash,
    lastValidBlockHeight: intent.lastValidBlockHeight,
    messageBase64,
  };
  if (Buffer.from(intentHash(publishIntent)).toString("hex") !== request.intentHash) {
    throw new SignerRefusal("INTENT_HASH_MISMATCH");
  }
  for (const signature of Object.values(transaction.signatures)) {
    if (signature !== null && signature !== undefined) throw new SignerRefusal("TRANSACTION_MESSAGE_UNEXPECTED");
  }
  let message: CompiledTransactionMessage & CompiledTransactionMessageWithLifetime;
  try {
    message = getCompiledTransactionMessageDecoder().decode(messageBytes);
  } catch {
    throw new SignerRefusal("TRANSACTION_MESSAGE_UNEXPECTED");
  }
  if (message.version !== 0) throw new SignerRefusal("TRANSACTION_MESSAGE_UNEXPECTED");
  if ((message.addressTableLookups ?? []).length > 0) throw new SignerRefusal("TRANSACTION_MESSAGE_UNEXPECTED");
  if (message.header.numSignerAccounts !== 1 || message.header.numReadonlySignerAccounts !== 0) {
    throw new SignerRefusal("TRANSACTION_MESSAGE_UNEXPECTED");
  }
  if (message.lifetimeToken !== intent.recentBlockhash) throw new SignerRefusal("TRANSACTION_MESSAGE_UNEXPECTED");
  if (message.staticAccounts[0] !== intent.feePayer) throw new SignerRefusal("TRANSACTION_MESSAGE_UNEXPECTED");
  const feePayerRole = accountRole(message.header, 0, message.staticAccounts.length);
  if (!feePayerRole.signer || !feePayerRole.writable) throw new SignerRefusal("TRANSACTION_MESSAGE_UNEXPECTED");
  if (message.instructions.length !== 1) throw new SignerRefusal("TRANSACTION_MESSAGE_UNEXPECTED");
  const [instruction] = message.instructions;
  const accountIndices = instruction.accountIndices ?? [];
  if (accountIndices.length !== 4) throw new SignerRefusal("TRANSACTION_MESSAGE_UNEXPECTED");
  const accountAt = (index: number): Address => {
    const resolved = message.staticAccounts.at(index);
    if (resolved === undefined) throw new SignerRefusal("TRANSACTION_MESSAGE_UNEXPECTED");
    return resolved;
  };
  if (accountAt(instruction.programAddressIndex) !== ONELAYER_REGISTRY_PROGRAM_ADDRESS) {
    throw new SignerRefusal("TRANSACTION_MESSAGE_UNEXPECTED");
  }
  const [configIndex, roleIndex, operatorIndex, segmentIndex] = accountIndices;
  if (
    accountAt(configIndex) !== intent.configPda ||
    accountAt(roleIndex) !== intent.rolePda ||
    accountAt(operatorIndex) !== intent.feePayer ||
    accountAt(segmentIndex) !== intent.segmentPda
  ) {
    throw new SignerRefusal("TRANSACTION_MESSAGE_UNEXPECTED");
  }
  for (const [index, expected] of [
    [configIndex, { signer: false, writable: true }],
    [roleIndex, { signer: false, writable: false }],
    [operatorIndex, { signer: true, writable: false }],
    [segmentIndex, { signer: false, writable: true }],
  ] as Array<[number, { signer: boolean; writable: boolean }]>) {
    const role = accountRole(message.header, index, message.staticAccounts.length);
    if (role.signer !== expected.signer) throw new SignerRefusal("TRANSACTION_MESSAGE_UNEXPECTED");
    // The fee payer is always writable in the message even though the
    // instruction only needs it as a signer.
    if (role.writable !== expected.writable && !(expected.signer && role.writable)) {
      throw new SignerRefusal("TRANSACTION_MESSAGE_UNEXPECTED");
    }
  }
  const data = Buffer.from(instruction.data ?? []);
  if (data.length !== INSTRUCTION_DATA_BYTES || !data.subarray(0, 8).equals(Buffer.from(PUBLISH_ANCHOR_DISCRIMINATOR))) {
    throw new SignerRefusal("TRANSACTION_MESSAGE_UNEXPECTED");
  }
  if (!data.equals(Buffer.from(request.instructionData, "base64"))) throw new SignerRefusal("TRANSACTION_MESSAGE_UNEXPECTED");
  type AnchorArgs = {
    batchSequence: bigint;
    registryVersion: bigint;
    sourceCursorStart: bigint;
    sourceCursorEnd: bigint;
    merkleRoot: Uint8Array;
    manifestHash: Uint8Array;
    previousAnchorHash: Uint8Array;
    leafCount: number;
  };
  let parsedArgs: AnchorArgs;
  try {
    parsedArgs = getPublishAnchorInstructionDataDecoder().decode(data) as unknown as AnchorArgs;
  } catch {
    throw new SignerRefusal("TRANSACTION_MESSAGE_UNEXPECTED");
  }
  const hex = (value: Uint8Array) => Buffer.from(value).toString("hex");
  if (
    parsedArgs.batchSequence !== intent.batchSequence ||
    parsedArgs.registryVersion !== intent.registryVersion ||
    parsedArgs.sourceCursorStart !== intent.cursorStart ||
    parsedArgs.sourceCursorEnd !== intent.cursorEnd ||
    hex(parsedArgs.merkleRoot) !== intent.merkleRootHex ||
    hex(parsedArgs.manifestHash) !== intent.manifestHashHex ||
    hex(parsedArgs.previousAnchorHash) !== intent.previousAnchorHashHex ||
    parsedArgs.leafCount !== intent.leafCount
  ) {
    throw new SignerRefusal("TRANSACTION_MESSAGE_UNEXPECTED");
  }
}

/**
 * Reads the keypair file through the hardened key-store loader. Key bytes are
 * zeroed inside the loader before it returns; only the imported key and its
 * public address leave that module.
 */
async function readSigningKey(keyFile: string, options?: KeyStoreOptions): Promise<{ address: Address; privateKey: KeyObject }> {
  try {
    return await loadSigningKey(keyFile, options);
  } catch (error) {
    if (error instanceof KeyStoreError) throw new SignerRefusal(error.code);
    throw error;
  }
}

/**
 * Signs one approved intent and returns the signed wire transaction (base64).
 * The key file defaults to the persistent devnet store for the effective home
 * directory (or `options.home` for out-of-band seeding and tests).
 */
export async function signApprovedTransaction(
  request: unknown,
  keyFile?: string,
  options?: KeyStoreOptions,
): Promise<string> {
  const parsed = typeof request === "string" ? parseSignRequest(request) : parseSignRequest(JSON.stringify(request));
  let transaction: Transaction;
  try {
    transaction = getTransactionDecoder().decode(Buffer.from(parsed.transactionBase64, "base64"));
  } catch {
    throw new SignerRefusal("TRANSACTION_MALFORMED");
  }
  const messageBytes = Buffer.from(transaction.messageBytes);
  checkApprovedMessage(transaction, messageBytes, parsed);
  const key = await readSigningKey(keyFile ?? defaultKeyFile(options), options);
  if (key.address !== parsed.intent.feePayer) throw new SignerRefusal("OPERATOR_MISMATCH");
  const signature = ed25519Sign(null, messageBytes, key.privateKey);
  const signed = {
    ...transaction,
    signatures: { ...transaction.signatures, [parsed.intent.feePayer]: new Uint8Array(signature) },
  };
  const signedTransactionBase64 = Buffer.from(getTransactionEncoder().encode(signed)).toString("base64");
  // Anything that would be refused at broadcast must never leave this helper,
  // so the server's own validation gates the output.
  validateSignedTransaction(signedTransactionBase64, messageBytes.toString("base64"), parsed.intent.feePayer);
  return signedTransactionBase64;
}

const USAGE = `Usage: live-demo-sign.ts [--key-file FILE]

Signs one approved OneLayer publish-anchor transaction for the local devnet
profile. The approved review/intent bytes are read as one JSON object from
stdin; the signed wire transaction is printed on stdout.

Options:
  --key-file FILE   private Solana keypair file in the persistent devnet key
                    store (~/.local/state/onelayer-devnet-demo/keys) or in a
                    private directory under /dev/shm
                    (default: ${DEFAULT_KEY_FILE})
  -h, --help        show this help

Output (success): {"signedTransactionBase64":"..."}
Output (failure): {"error":{"code":"..."}} on stderr
Exit codes: 0 signed, 2 refused request, 3 refused key, 1 internal error.
`;

async function readStdin(limit: number): Promise<string> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of process.stdin) {
    const buffer = Buffer.from(chunk as Uint8Array);
    total += buffer.length;
    if (total > limit) throw new SignerRefusal("REQUEST_TOO_LARGE");
    chunks.push(buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

const KEY_CODES = new Set(["KEYFILE_REJECTED", "KEYFILE_UNREADABLE", "KEYPAIR_INVALID", "OPERATOR_MISMATCH"]);

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  let keyFile = DEFAULT_KEY_FILE;
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "-h" || argument === "--help") {
      process.stdout.write(USAGE);
      return;
    }
    if (argument === "--key-file") {
      keyFile = args[index + 1] ?? "";
      index += 1;
      if (keyFile === "") throw new SignerRefusal("REQUEST_INVALID");
      continue;
    }
    throw new SignerRefusal("REQUEST_INVALID");
  }
  const raw = await readStdin(MAX_REQUEST_BYTES);
  const signedTransactionBase64 = await signApprovedTransaction(raw, keyFile);
  process.stdout.write(`${JSON.stringify({ signedTransactionBase64 })}\n`);
}

const entry = process.argv[1] === undefined ? "" : pathToFileURL(path.resolve(process.argv[1])).href;
if (entry !== "" && import.meta.url === entry) {
  main().catch((error: unknown) => {
    const code = error instanceof SignerRefusal ? error.code : "SIGNER_INTERNAL_ERROR";
    // Errors carry codes only: nothing from the key, the request or the stack
    // is ever written to the protocol channels.
    process.stderr.write(`${JSON.stringify({ error: { code } })}\n`);
    process.exit(error instanceof SignerRefusal ? (KEY_CODES.has(code) ? 3 : 2) : 1);
  });
}
