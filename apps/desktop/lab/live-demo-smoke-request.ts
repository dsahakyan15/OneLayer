// TEST-ONLY scaffolding for apps/desktop/lab/smoke.py (desktop revision).
//
// Builds one A1 `SignRequest` JSON object for a throwaway operator **public
// address**, so the disposable-install smoke can prove that the installed
// prefix really signs with the real `live-demo-sign.ts` helper. It never reads,
// writes or prints any key material: the caller passes the operator's public
// address and pipes this output to the signer.
//
//   node --experimental-transform-types --disable-warning=ExperimentalWarning \
//     apps/desktop/lab/live-demo-smoke-request.ts --operator <base58>
//
// stdout (success, exactly one line): the SignRequest JSON object
// stderr (failure, exactly one line): {"error":{"code":"<CODE>"}}
// exit codes: 0 ok · 2 usage/request refusal · 1 internal.
//
// The transaction is built exactly like `apps/demo-api/tests/live-demo-sign.test.ts`
// builds its happy-path fixture: one publish-anchor instruction over the real
// devnet program id and its derived PDAs, a fixed fake blockhash and no
// signature. Nothing here contacts a chain.
import {
  findLedgerSegmentPda,
  findRegistryConfigPda,
  findRolePda,
  ONELAYER_REGISTRY_PROGRAM_ADDRESS,
} from "../../../packages/onchain-client/src/index.ts";
import { registryIdHash } from "../../../packages/canonical-ts/src/index.ts";
import { prepareAnchorTransaction } from "../../demo-api/src/admin-transaction.ts";
import { intentHash } from "../../demo-api/src/transaction-state.ts";

const REGISTRY_ID = "gov.registry.land";
const INTENT_ID = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0";
const DAY_UTX = 20_665;
const BLOCKHASH = "11111111111111111111111111111111";
const BASE58 = /^[1-9A-HJ-NP-Za-km-z]{32,44}$/;

function hex(value: Uint8Array): string {
  return Buffer.from(value).toString("hex");
}

function parseOperator(argv: readonly string[]): string {
  if (argv.length !== 2 || argv[0] !== "--operator") throw new UsageRefusal();
  const operator = argv[1];
  if (operator === undefined || !BASE58.test(operator)) throw new UsageRefusal();
  return operator;
}

class UsageRefusal extends Error {}

async function main(): Promise<void> {
  const operator = parseOperator(process.argv.slice(2));
  const programId = ONELAYER_REGISTRY_PROGRAM_ADDRESS;
  const [configPda] = await findRegistryConfigPda(registryIdHash(REGISTRY_ID), { programAddress: programId });
  const [rolePda] = await findRolePda({ config: configPda, operator }, { programAddress: programId });
  const [segmentPda] = await findLedgerSegmentPda(
    { config: configPda, dayUtc: DAY_UTX, segmentIndex: 0 },
    { programAddress: programId },
  );
  const prepared = prepareAnchorTransaction({
    programId,
    configPda,
    rolePda,
    segmentPda,
    operator,
    blockhash: BLOCKHASH,
    lastValidBlockHeight: 1_000n,
    batchSequence: 1n,
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
  });
  const intent = {
    registryId: REGISTRY_ID,
    batchSequence: "1",
    registryVersion: "1",
    cursorStart: "1",
    cursorEnd: "2",
    leafCount: 2,
    merkleRootHex: hex(new Uint8Array(32).fill(0xaa)),
    manifestHashHex: hex(new Uint8Array(32).fill(0xbb)),
    previousAnchorHashHex: hex(new Uint8Array(32).fill(0xcc)),
    programId,
    configPda,
    rolePda,
    segmentPda,
    segmentIndex: 0,
    dayUtc: DAY_UTX,
    feePayer: operator,
    recentBlockhash: BLOCKHASH,
    lastValidBlockHeight: "1000",
  };
  const request = {
    approved: true,
    intentId: INTENT_ID,
    cluster: "solana:devnet",
    intentHash: hex(
      intentHash({
        registryId: REGISTRY_ID,
        batchSequence: 1n,
        registryVersion: 1n,
        cursorStart: 1n,
        cursorEnd: 2n,
        leafCount: 2,
        merkleRootHex: intent.merkleRootHex,
        manifestHashHex: intent.manifestHashHex,
        previousAnchorHashHex: intent.previousAnchorHashHex,
        programId,
        configPda,
        rolePda,
        segmentPda,
        segmentIndex: 0,
        dayUtc: DAY_UTX,
        feePayer: operator,
        recentBlockhash: BLOCKHASH,
        lastValidBlockHeight: 1_000n,
        messageBase64: prepared.messageBase64,
      }),
    ),
    transactionBase64: prepared.transactionBase64,
    instructionData: prepared.instructionDataBase64,
    intent,
  };
  process.stdout.write(JSON.stringify(request) + "\n");
}

const entry = process.argv[1];
if (entry !== undefined) {
  main().catch((error: unknown) => {
    const code = error instanceof UsageRefusal ? "REQUEST_INVALID" : "REQUEST_BUILD_FAILED";
    process.stderr.write(`${JSON.stringify({ error: { code } })}\n`);
    process.exit(error instanceof UsageRefusal ? 2 : 1);
  });
}
