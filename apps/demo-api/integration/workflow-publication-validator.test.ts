// Ticket 09 against a live local validator: the repository's onelayer-registry
// program (built from source), real `SolanaPublisherRpc`, real PostgreSQL.
// Synthetic keys only; nothing leaves localhost.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import {
  address, appendTransactionMessageInstructions, createTransactionMessage, generateKeyPairSigner,
  getBase64EncodedWireTransaction, getSignatureFromTransaction, getTransactionDecoder, getTransactionEncoder, pipe,
  setTransactionMessageFeePayerSigner, setTransactionMessageLifetimeUsingBlockhash, signTransactionMessageWithSigners,
  type Address, type KeyPairSigner,
} from '@solana/kit';
import {
  findLedgerSegmentPda, findRegistryConfigPda, findRolePda, getCreateLedgerSegmentInstruction,
  getGrantOperatorInstructionAsync, getInitializeRegistryInstruction,
} from '../../../packages/onchain-client/src/index.ts';
import { registryIdHash, toHex } from '../../../packages/canonical-ts/src/index.ts';
import { isolatedPostgres } from './support/postgres.ts';
import { buildSbfProgram, rpcCall, startLocalValidator } from './support/solana-validator.ts';
import { appendWorkflowVersion, workflowHash, workflowTransaction } from '../src/registry-workflow.ts';
import { PublicationRpc } from '../src/publication-rpc.ts';
import { WorkflowPublicationStore, type PublicationLease } from '../src/workflow-publication.ts';
import { ledgerDay, WorkflowPublisher, type PublicationSigner, type PublicationStepResult, type SignRequest } from '../src/publication-worker.ts';

const REGISTRY_PROGRAM = '6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo';
const PERM_PUBLISH_ANCHOR = 1 << 0;
const PERM_CREATE_LEDGER = 1 << 1;
const repo = (path: string) => fileURLToPath(new URL(`../../../${path}`, import.meta.url));

async function sendAndFinalize(rpcUrl: string, feePayer: KeyPairSigner, instructions: any[]): Promise<void> {
  const blockhash = await rpcCall(rpcUrl, 'getLatestBlockhash', [{ commitment: 'processed' }]);
  const message = pipe(
    createTransactionMessage({ version: 0 }),
    m => setTransactionMessageFeePayerSigner(feePayer, m),
    m => setTransactionMessageLifetimeUsingBlockhash({ blockhash: blockhash.value.blockhash, lastValidBlockHeight: BigInt(blockhash.value.lastValidBlockHeight) }, m),
    m => appendTransactionMessageInstructions(instructions, m),
  );
  const signed = await signTransactionMessageWithSigners(message as any);
  const signature = getSignatureFromTransaction(signed as any);
  await rpcCall(rpcUrl, 'sendTransaction', [getBase64EncodedWireTransaction(signed as any), { encoding: 'base64', preflightCommitment: 'processed' }]);
  await waitFinalized(rpcUrl, signature);
}

async function waitFinalized(rpcUrl: string, signature: string): Promise<void> {
  const deadline = Date.now() + 120_000;
  for (;;) {
    const status = (await rpcCall(rpcUrl, 'getSignatureStatuses', [[signature], { searchTransactionHistory: true }])).value[0];
    if (status?.err) throw new Error(`transaction failed: ${JSON.stringify(status.err)}`);
    if (status?.confirmationStatus === 'finalized') return;
    if (Date.now() > deadline) throw new Error('transaction did not finalize');
    await new Promise(resolve => setTimeout(resolve, 250));
  }
}

class KitSigner implements PublicationSigner {
  constructor(private readonly signer: KeyPairSigner) {}
  get address(): Address { return this.signer.address; }
  async signTransaction(request: SignRequest): Promise<string> {
    const tx = getTransactionDecoder().decode(Buffer.from(request.transactionBase64, 'base64'));
    const [signatures] = await this.signer.signTransactions([tx as any]);
    return Buffer.from(getTransactionEncoder().encode({ ...tx, signatures: { ...tx.signatures, ...signatures } })).toString('base64');
  }
}

/** Real adapter whose send reaches the validator, then reports a timeout. */
class TimeoutAfterSendRpc extends PublicationRpc {
  timeoutAfterSend = false; sends = 0;
  override async send(tx: string): Promise<string> {
    this.sends += 1;
    const signature = await super.send(tx);
    if (this.timeoutAfterSend) throw new Error('synthetic timeout after send');
    return signature;
  }
}

async function untilFinalized(worker: WorkflowPublisher, lease: PublicationLease, seen: string[]): Promise<Extract<PublicationStepResult, { status: 'FINALIZED' }>> {
  const deadline = Date.now() + 180_000;
  for (;;) {
    const result = await worker.step(lease);
    seen.push(result.status);
    if (result.status === 'FINALIZED') return result;
    if (Date.now() > deadline) throw new Error(`publication did not finalize: ${seen.join(',')}`);
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
}

test('workflow publication finalizes on a live local validator, reconciling a timeout-after-send', { timeout: 20 * 60_000 }, async context => {
  const build = await buildSbfProgram({ crateDir: repo('onchain/programs/onelayer-registry'), libName: 'onelayer_registry', extraInputs: [repo('onchain/Cargo.lock'), repo('onchain/Cargo.toml')] });
  const validator = await startLocalValidator(context, [{ programId: REGISTRY_PROGRAM, so: build.so }]);
  context.diagnostic(`validator ${validator.version}; registry.so sha256=${build.sha256}`);
  const { pool } = await isolatedPostgres(context);
  const programAddress = address(REGISTRY_PROGRAM);
  const governance = await generateKeyPairSigner();
  const operator = await generateKeyPairSigner();
  for (const signer of [governance, operator]) await waitFinalized(validator.rpcUrl, await rpcCall(validator.rpcUrl, 'requestAirdrop', [signer.address, 100_000_000_000]));

  const registryId = `synthetic-publication-${randomBytes(6).toString('hex')}`;
  const [config] = await findRegistryConfigPda(registryIdHash(registryId), { programAddress });
  await sendAndFinalize(validator.rpcUrl, governance, [getInitializeRegistryInstruction({
    config, governance, registryIdHash: registryIdHash(registryId), emergencyAuthority: governance.address,
    schemaVersion: 1, hashAlgorithm: 1, treeAlgorithm: 1, anchorIntervalSeconds: 3600, maxEntriesPerDay: 46,
  }, { programAddress })]);
  await sendAndFinalize(validator.rpcUrl, governance, [await getGrantOperatorInstructionAsync({
    config, operator: operator.address, governanceAuthority: governance,
    permissions: PERM_PUBLISH_ANCHOR | PERM_CREATE_LEDGER, validFrom: 0, validUntil: 0, keyIdHash: new Uint8Array(32),
  }, { programAddress })]);
  const [role] = await findRolePda({ config, operator: operator.address }, { programAddress });
  const dayUtc = ledgerDay(new Date());
  const [segment] = await findLedgerSegmentPda({ config, dayUtc, segmentIndex: 0 }, { programAddress });
  await sendAndFinalize(validator.rpcUrl, operator, [getCreateLedgerSegmentInstruction({
    config, role, operator, segment, dayUtc, segmentIndex: 0, capacity: 46,
  }, { programAddress })]);

  const append = (recordId: string, payload: Record<string, unknown>) => workflowTransaction(pool, c => appendWorkflowVersion(c, {
    registryId, recordId, baseVersion: 0, operation: 'upsert', payload, payloadHash: workflowHash({ operation: 'upsert', payload }),
    creator: 'alice', approver: 'bob', evidence: { synthetic: true },
  }));
  await append('parcel-1', { owner: 'Synthetic A', area: 120 });
  await append('parcel-2', { owner: 'Synthetic B', tags: ['x'] });

  const rpc = new TimeoutAfterSendRpc(validator.rpcUrl, REGISTRY_PROGRAM);
  const worker = new WorkflowPublisher(pool, rpc, new KitSigner(operator), {
    registryId, programId: programAddress, configPda: config, operatorKeyId: 'synthetic-operator',
    keys: { idKey: randomBytes(32), fieldKeyMaster: randomBytes(32) },
  });
  const store = new WorkflowPublicationStore(pool);
  const lease = (await store.claim(registryId, 'worker-a', 300_000))!;
  rpc.timeoutAfterSend = true;
  const seen: string[] = [];
  const first = await worker.step(lease);
  seen.push(first.status);
  assert.equal(first.status, 'UNKNOWN');
  rpc.timeoutAfterSend = false;
  const done = await untilFinalized(worker, lease, seen);
  context.diagnostic(`first operation steps: ${seen.join(' -> ')}`);
  assert.equal(done.signature, 'signature' in first ? first.signature : undefined);
  assert.equal(rpc.sends, 1, 'no resend after a timeout whose transaction landed');
  const onChain = (await rpc.registryConfig(config, 0n)).value;
  assert.equal(onChain!.currentBatchSequence, 1n);
  const anchor = (await pool.query('SELECT anchor_hash,merkle_root FROM wf_publication_anchor')).rows[0];
  assert.equal(anchor.anchor_hash, toHex(Uint8Array.from(onChain!.lastAnchorHash)), 'independently recomputed anchor hash equals the program state');
  const entry = (await rpc.ledgerSegment(segment, 0n)).value!.entries[0];
  assert.equal(toHex(Uint8Array.from(entry.merkleRoot)), anchor.merkle_root);

  await append('parcel-3', { owner: 'Synthetic C' });
  const next = (await store.claim(registryId, 'worker-a', 300_000))!;
  assert.notEqual(next.operationId, lease.operationId);
  const second = await untilFinalized(worker, next, []);
  assert.equal(second.status, 'FINALIZED');
  assert.equal((await rpc.registryConfig(config, 0n)).value!.currentBatchSequence, 2n);
  assert.equal(await store.claim(registryId, 'worker-a'), null);
});
