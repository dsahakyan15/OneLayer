// Test-only harness: играет роль штатного Builder/Publisher (apps/demo-api,
// TypeScript) в disposable окружении e2e-теста Monitor. Monitor этот код не
// вызывает и не импортирует: harness только создаёт реальное состояние
// (PostgreSQL + local validator), которое Monitor затем проверяет сам.
//
// Команды (вывод — одна JSON-строка в stdout):
//   setup   --pg <conn> --rpc <url> --state <file>
//   append  --state <file> --items '<json [{recordId,payload}]>'
//   publish --state <file>
//   faulty-anchor --state <file> --skip <n>   // неисправный Builder: anchor с разрывом cursor
import { createRequire } from 'node:module';
import { randomBytes } from 'node:crypto';
import { readFile, readdir, writeFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

const demoApi = new URL('../../../demo-api/', import.meta.url);
const require = createRequire(new URL('package.json', demoApi));
const kit: any = await import(pathToFileURL(require.resolve('@solana/kit')).href);
const pg: any = require('pg');
const client: any = await import(new URL('../../../../packages/onchain-client/src/index.ts', import.meta.url).href);
const canonical: any = await import(new URL('../../../../packages/canonical-ts/src/index.ts', import.meta.url).href);
const workflow: any = await import(new URL('src/registry-workflow.ts', demoApi).href);
const publicationRpc: any = await import(new URL('src/publication-rpc.ts', demoApi).href);
const publicationStore: any = await import(new URL('src/workflow-publication.ts', demoApi).href);
const publicationWorker: any = await import(new URL('src/publication-worker.ts', demoApi).href);

const REGISTRY_PROGRAM = '6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo';
const PERM_PUBLISH_ANCHOR = 1 << 0;
const PERM_CREATE_LEDGER = 1 << 1;

const args = process.argv.slice(2);
const command = args[0];
const opt = (name: string): string => {
  const i = args.indexOf(`--${name}`);
  if (i < 0 || i + 1 >= args.length) throw new Error(`missing --${name}`);
  return args[i + 1];
};

async function rpcCall(url: string, method: string, params: unknown[] = []): Promise<any> {
  const response = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
  const body: any = await response.json();
  if (body.error) throw new Error(`${method}: ${JSON.stringify(body.error)}`);
  return body.result;
}

async function waitFinalized(url: string, signature: string): Promise<void> {
  const deadline = Date.now() + 120_000;
  for (;;) {
    const status = (await rpcCall(url, 'getSignatureStatuses', [[signature], { searchTransactionHistory: true }])).value[0];
    if (status?.err) throw new Error(`transaction failed: ${JSON.stringify(status.err)}`);
    if (status?.confirmationStatus === 'finalized') return;
    if (Date.now() > deadline) throw new Error('transaction did not finalize');
    await new Promise(resolve => setTimeout(resolve, 250));
  }
}

async function sendAndFinalize(url: string, feePayer: any, instructions: any[]): Promise<string> {
  const blockhash = await rpcCall(url, 'getLatestBlockhash', [{ commitment: 'processed' }]);
  const message = kit.pipe(
    kit.createTransactionMessage({ version: 0 }),
    (m: any) => kit.setTransactionMessageFeePayerSigner(feePayer, m),
    (m: any) => kit.setTransactionMessageLifetimeUsingBlockhash({ blockhash: blockhash.value.blockhash, lastValidBlockHeight: BigInt(blockhash.value.lastValidBlockHeight) }, m),
    (m: any) => kit.appendTransactionMessageInstructions(instructions, m),
  );
  const signed = await kit.signTransactionMessageWithSigners(message);
  const signature = kit.getSignatureFromTransaction(signed);
  await rpcCall(url, 'sendTransaction', [kit.getBase64EncodedWireTransaction(signed), { encoding: 'base64', preflightCommitment: 'processed' }]);
  await waitFinalized(url, signature);
  return signature;
}

const dayUtc = (d = new Date()) => d.getUTCFullYear() * 10000 + (d.getUTCMonth() + 1) * 100 + d.getUTCDate();
const signerOf = (hex: string) => kit.createKeyPairSignerFromPrivateKeyBytes(Buffer.from(hex, 'hex'));

class KitSigner {
  constructor(private readonly signer: any) {}
  get address() { return this.signer.address; }
  async signTransaction(request: any): Promise<string> {
    const tx = kit.getTransactionDecoder().decode(Buffer.from(request.transactionBase64, 'base64'));
    const [signatures] = await this.signer.signTransactions([tx]);
    return Buffer.from(kit.getTransactionEncoder().encode({ ...tx, signatures: { ...tx.signatures, ...signatures } })).toString('base64');
  }
}

async function loadState() { return JSON.parse(await readFile(opt('state'), 'utf8')); }

async function withPool<T>(conn: string, fn: (pool: any) => Promise<T>): Promise<T> {
  const pool = new pg.Pool({ connectionString: conn, max: 4 });
  try { return await fn(pool); } finally { await pool.end(); }
}

async function setup() {
  const conn = opt('pg'); const rpc = opt('rpc');
  await withPool(conn, async pool => {
    const dir = new URL('../../../../db/migrations/', import.meta.url);
    for (const file of (await readdir(dir)).filter(n => n.endsWith('.sql')).sort()) await pool.query(await readFile(new URL(file, dir), 'utf8'));
  });
  const programAddress = kit.address(REGISTRY_PROGRAM);
  const governanceSeed = randomBytes(32).toString('hex');
  const operatorSeed = randomBytes(32).toString('hex');
  const governance = await signerOf(governanceSeed);
  const operator = await signerOf(operatorSeed);
  for (const s of [governance, operator]) await waitFinalized(rpc, await rpcCall(rpc, 'requestAirdrop', [s.address, 100_000_000_000]));
  const registryId = `synthetic-monitor-${randomBytes(6).toString('hex')}`;
  const ridHash = canonical.registryIdHash(registryId);
  const [config] = await client.findRegistryConfigPda(ridHash, { programAddress });
  await sendAndFinalize(rpc, governance, [client.getInitializeRegistryInstruction({
    config, governance, registryIdHash: ridHash, emergencyAuthority: governance.address,
    schemaVersion: 1, hashAlgorithm: 1, treeAlgorithm: 1, anchorIntervalSeconds: 3600, maxEntriesPerDay: 46,
  }, { programAddress })]);
  await sendAndFinalize(rpc, governance, [await client.getGrantOperatorInstructionAsync({
    config, operator: operator.address, governanceAuthority: governance,
    permissions: PERM_PUBLISH_ANCHOR | PERM_CREATE_LEDGER, validFrom: 0, validUntil: 0, keyIdHash: new Uint8Array(32),
  }, { programAddress })]);
  const [role] = await client.findRolePda({ config, operator: operator.address }, { programAddress });
  const day = dayUtc();
  const [segment] = await client.findLedgerSegmentPda({ config, dayUtc: day, segmentIndex: 0 }, { programAddress });
  await sendAndFinalize(rpc, operator, [client.getCreateLedgerSegmentInstruction({ config, role, operator, segment, dayUtc: day, segmentIndex: 0, capacity: 46 }, { programAddress })]);
  const state = {
    pg: conn, rpc, registryId, programId: REGISTRY_PROGRAM, configPda: config, role, segment, day,
    governanceSeed, operatorSeed, idKey: randomBytes(32).toString('hex'), fieldKeyMaster: randomBytes(32).toString('hex'),
  };
  await writeFile(opt('state'), JSON.stringify(state), { mode: 0o600 });
  return { registryId, configPda: config, programId: REGISTRY_PROGRAM, day };
}

async function append() {
  const state = await loadState();
  const items: Array<{ recordId: string; payload: Record<string, unknown> }> = JSON.parse(opt('items'));
  return withPool(state.pg, async pool => {
    const out = [];
    for (const item of items) {
      const head = await pool.query('SELECT version FROM wf_record WHERE registry_id=$1 AND record_id=$2', [state.registryId, item.recordId]);
      const baseVersion = head.rows[0]?.version ?? 0;
      await workflow.workflowTransaction(pool, (c: any) => workflow.appendWorkflowVersion(c, {
        registryId: state.registryId, recordId: item.recordId, baseVersion, operation: 'upsert', payload: item.payload,
        payloadHash: workflow.workflowHash({ operation: 'upsert', payload: item.payload }), creator: 'synthetic-alice', approver: 'synthetic-bob', evidence: { synthetic: true },
      }));
      out.push({ recordId: item.recordId, version: baseVersion + 1 });
    }
    return out;
  });
}

async function publish() {
  const state = await loadState();
  const operator = await signerOf(state.operatorSeed);
  return withPool(state.pg, async pool => {
    const rpc = new publicationRpc.PublicationRpc(state.rpc, state.programId);
    const worker = new publicationWorker.WorkflowPublisher(pool, rpc, new KitSigner(operator), {
      registryId: state.registryId, programId: kit.address(state.programId), configPda: kit.address(state.configPda), operatorKeyId: 'synthetic-operator',
      keys: { idKey: Buffer.from(state.idKey, 'hex'), fieldKeyMaster: Buffer.from(state.fieldKeyMaster, 'hex') },
    });
    const store = new publicationStore.WorkflowPublicationStore(pool);
    const lease = await store.claim(state.registryId, 'harness-builder', 300_000);
    if (!lease) return { status: 'NOTHING_TO_PUBLISH' };
    const seen: string[] = [];
    const deadline = Date.now() + 180_000;
    for (;;) {
      const result = await worker.step(lease);
      seen.push(result.status);
      if (result.status === 'FINALIZED') {
        const anchor = (await pool.query('SELECT batch_sequence::text AS seq, merkle_root FROM wf_publication_anchor WHERE operation_id=$1', [lease.operationId])).rows[0];
        return { status: 'FINALIZED', operationId: lease.operationId, batchSequence: anchor.seq, merkleRoot: anchor.merkle_root, steps: seen };
      }
      if (Date.now() > deadline) throw new Error(`publication did not finalize: ${seen.join(',')}`);
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  });
}

/** Неисправный Builder: публикует корректно связанный anchor с пропуском source cursor,
 *  без membership в БД (обход штатного worker). */
async function faultyAnchor() {
  const state = await loadState();
  const operator = await signerOf(state.operatorSeed);
  const rpc = new publicationRpc.PublicationRpc(state.rpc, state.programId);
  const config = (await rpc.registryConfig(kit.address(state.configPda), 0n)).value;
  const segment = (await rpc.ledgerSegment(kit.address(state.segment), 0n)).value;
  const last = segment.entries.slice(0, segment.entryCount).at(-1);
  const start = (last ? BigInt(last.sourceCursorEnd) : 0n) + 1n + BigInt(opt('skip'));
  const programAddress = kit.address(state.programId);
  const signature = await sendAndFinalize(state.rpc, operator, [client.getPublishAnchorInstruction({
    config: kit.address(state.configPda), role: kit.address(state.role), operator, segment: kit.address(state.segment),
    batchSequence: config.currentBatchSequence + 1n, registryVersion: config.currentRegistryVersion,
    sourceCursorStart: start, sourceCursorEnd: start, merkleRoot: randomBytes(32), manifestHash: randomBytes(32),
    snapshotHash: new Uint8Array(32), previousAnchorHash: Uint8Array.from(config.lastAnchorHash), leafCount: 1,
    schemaVersion: 1, flags: 0, hashAlgorithm: 1, treeAlgorithm: 1,
  }, { programAddress })]);
  return { status: 'FINALIZED', batchSequence: String(config.currentBatchSequence + 1n), cursorStart: String(start), signature };
}

const handlers: Record<string, () => Promise<unknown>> = { setup, append, publish, 'faulty-anchor': faultyAnchor };
if (!handlers[command]) throw new Error(`unknown command ${command}`);
const result = await handlers[command]();
process.stdout.write(JSON.stringify(result, (_k, v) => typeof v === 'bigint' ? v.toString() : v) + '\n');
