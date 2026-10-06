// Shared fixtures for the workflow publication integration tests (ticket 09):
// a finalized-only fake chain that decodes the actual signed wire bytes and
// applies a SUBSET of the registry program's publish checks (blockhash
// validity, signature presence, paused, sequence, previous-anchor chain, ledger
// day). It does not verify ed25519 signatures, roles, segment PDAs or capacity;
// the live-validator test covers the real program.
import assert from 'node:assert/strict';
import { createPrivateKey, createPublicKey, randomBytes, sign as ed25519Sign } from 'node:crypto';
import { Pool } from 'pg';
import {
  getAddressDecoder, getAddressEncoder, getBase58Decoder, getCompiledTransactionMessageDecoder,
  getTransactionDecoder, getTransactionEncoder, type Address,
} from '@solana/kit';
import { anchorHash, registryIdHash } from '../../../../packages/canonical-ts/src/index.ts';
import {
  findLedgerSegmentPda, findRegistryConfigPda, getPublishAnchorInstructionDataDecoder,
  type AnchorEntryV1, type DailyAnchorLedgerSegment, type RegistryConfig,
} from '../../../../packages/onchain-client/src/index.ts';
import { appendWorkflowVersion, workflowHash, workflowTransaction } from '../../src/registry-workflow.ts';
import { ledgerDay, WorkflowPublisher, type PublicationSigner, type PublisherConfig, type SignRequest } from '../../src/publication-worker.ts';
import { ChainReadError, type ChainRead, type PublicationChain, type SignatureStatus } from '../../src/publication-rpc.ts';

export const PROGRAM_ID = '6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo' as Address;
export const REGISTRY = 'synthetic';
export const NOON = BigInt(Date.parse('2026-09-24T12:00:00Z') / 1000);
export const [CONFIG_PDA] = await findRegistryConfigPda(registryIdHash(REGISTRY), { programAddress: PROGRAM_ID });
export const [SEGMENT_PDA] = await findLedgerSegmentPda({ config: CONFIG_PDA, dayUtc: 20260924, segmentIndex: 0 }, { programAddress: PROGRAM_ID });
export const KEYS = { idKey: new Uint8Array(32).fill(7), fieldKeyMaster: new Uint8Array(32).fill(8) };
const b58 = getBase58Decoder();

export class TestSigner implements PublicationSigner {
  readonly address: Address;
  private readonly key = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 3)]), format: 'der', type: 'pkcs8' });
  reject = false; substitute = false; requests: SignRequest[] = [];
  constructor() { this.address = getAddressDecoder().decode(new Uint8Array(createPublicKey(this.key).export({ format: 'der', type: 'spki' })).slice(-32)); }
  async signTransaction(request: SignRequest): Promise<string> {
    this.requests.push(request);
    if (this.reject) throw new Error('operator declined');
    const tx = getTransactionDecoder().decode(Buffer.from(request.transactionBase64, 'base64'));
    const messageBytes = Uint8Array.from(tx.messageBytes);
    // Substitution flips a byte of the instruction data (the final byte is the v0 lookup-table count).
    if (this.substitute) messageBytes[messageBytes.length - 2] ^= 1;
    const signature = new Uint8Array(ed25519Sign(null, Buffer.from(messageBytes), this.key));
    return Buffer.from(getTransactionEncoder().encode({ ...tx, messageBytes: messageBytes as any, signatures: { ...tx.signatures, [this.address]: signature } })).toString('base64');
  }
}

export interface Snapshot { slot: bigint; config: RegistryConfig; segment: DailyAnchorLedgerSegment }

/** Finalized-only fake with slot history, lag and pruning controls. */
export class FakeChain implements PublicationChain {
  slot = 100n;
  time = NOON;
  snapshots: Snapshot[];
  blockhashes = new Map<string, bigint>();
  landed = new Map<string, { slot: bigint; failed: boolean }>();
  sent: string[] = [];
  mode: 'land' | 'drop' | 'land-then-throw' | 'fail' = 'land';
  tamperRoot = false;
  /** Status answers come from a node stuck at this slot. */
  statusLag: bigint | null = null;
  pruned = new Set<string>();
  /** Next N segment reads return an empty ledger (inconsistent node). */
  blankSegmentReads = 0;
  constructor() {
    const config = { version: 1, registryIdHash: registryIdHash(REGISTRY), currentBatchSequence: 0n, currentRegistryVersion: 3n, lastAnchorHash: new Uint8Array(32).fill(0x11), schemaVersion: 1, hashAlgorithm: 1, treeAlgorithm: 1, paused: false } as unknown as RegistryConfig;
    const segment = { registry: CONFIG_PDA, dayUtc: 20260924, segmentIndex: 0, sealed: 0, entryCount: 0, capacity: 46, entries: [] } as unknown as DailyAnchorLedgerSegment;
    this.snapshots = [{ slot: 0n, config, segment }];
  }
  get head(): Snapshot { return this.snapshots[this.snapshots.length - 1]; }
  get config(): RegistryConfig { return this.head.config; }
  get segment(): DailyAnchorLedgerSegment { return this.head.segment; }
  height(slot: bigint) { return 1000n + slot; }
  advance(slots: bigint) { this.slot += slots; }
  mutate(fn: (s: Snapshot) => void) { const next = structuredClone(this.head); this.slot += 1n; next.slot = this.slot; fn(next); this.snapshots.push(next); }
  /** Load-balanced pool: finalizedSlot call number n (and the reads after it) is
   * answered by a node stuck at `nodeLag` when `lagWhen(n)` holds. That node still
   * honours minContextSlot by failing, like a real RPC node. */
  nodeLag: bigint | null = null;
  lagWhen: ((call: number) => boolean) | null = null;
  slotCalls = 0;
  tamperAnchorHash = false;
  private view(): bigint { return this.lagWhen !== null && this.nodeLag !== null && this.lagWhen(this.slotCalls) ? this.nodeLag : this.slot; }
  private at(minContextSlot: bigint): Snapshot {
    const view = this.view();
    if (minContextSlot > view) throw new ChainReadError('RPC_CONTEXT_STALE');
    return structuredClone([...this.snapshots].reverse().find(s => s.slot <= view)!);
  }
  async finalizedSlot(min: bigint) {
    this.slotCalls += 1;
    const view = this.view();
    if (min > view) throw new ChainReadError('RPC_CONTEXT_STALE');
    return view;
  }
  async finalizedBlock(slot: bigint) { return { slot, blockHeight: this.height(slot), blockTime: this.time }; }
  async registryConfig(address: string, min: bigint): Promise<ChainRead<RegistryConfig | null>> { assert.equal(address, CONFIG_PDA); return { value: this.at(min).config, contextSlot: this.view() }; }
  async ledgerSegment(address: string, min: bigint): Promise<ChainRead<DailyAnchorLedgerSegment | null>> {
    const snapshot = this.at(min);
    if (address !== SEGMENT_PDA) return { value: null, contextSlot: this.view() };
    if (this.blankSegmentReads > 0) { this.blankSegmentReads -= 1; return { value: { ...snapshot.segment, entryCount: 0, entries: [] }, contextSlot: this.view() }; }
    return { value: snapshot.segment, contextSlot: this.view() };
  }
  async latestBlockhash(min: bigint) {
    if (min > this.view()) throw new ChainReadError('RPC_CONTEXT_STALE');
    const blockhash = b58.decode(randomBytes(32)); const lastValidBlockHeight = this.height(this.slot) + 150n;
    this.blockhashes.set(blockhash, lastValidBlockHeight); return { blockhash, lastValidBlockHeight };
  }
  async signatureStatuses(signatures: readonly string[]): Promise<ChainRead<Array<SignatureStatus | null>>> {
    const view = this.statusLag ?? this.slot;
    return { contextSlot: view, value: signatures.map(s => {
      const hit = this.landed.get(s);
      return hit && hit.slot <= view && !this.pruned.has(s) ? { slot: hit.slot, finalized: true, failed: hit.failed } : null;
    }) };
  }
  async simulate(tx: string) { const error = this.check(tx, false).error; return { ok: error === null, error, logs: [], unitsConsumed: 1 }; }
  async send(tx: string): Promise<string> {
    this.sent.push(tx);
    const outcome = this.check(tx, true);
    if (this.mode === 'drop') return outcome.signature;
    if (!this.landed.has(outcome.signature)) {
      const failed = this.mode === 'fail' || outcome.error !== null;
      if (!failed) this.execute(outcome.data, outcome.operator);
      else this.slot += 1n;
      this.landed.set(outcome.signature, { slot: this.slot, failed });
    }
    if (this.mode === 'land-then-throw') throw new Error('timeout after send');
    return outcome.signature;
  }
  private check(tx: string, requireSignature: boolean) {
    const decoded = getTransactionDecoder().decode(Buffer.from(tx, 'base64'));
    const message: any = getCompiledTransactionMessageDecoder().decode(decoded.messageBytes);
    const operator = message.staticAccounts[0] as Address;
    const rawSig = decoded.signatures[operator];
    const signature = rawSig ? b58.decode(rawSig) : '';
    const data = getPublishAnchorInstructionDataDecoder().decode(message.instructions[0].data);
    const valid = this.blockhashes.get(message.lifetimeToken);
    let error: string | null = null;
    if (requireSignature && !rawSig) error = 'unsigned';
    else if (valid === undefined || this.height(this.slot) > valid) error = 'BlockhashNotFound';
    else if (this.config.paused) error = 'RegistryPaused';
    else if (data.batchSequence !== this.config.currentBatchSequence + 1n) error = 'BadSequence';
    else if (!Buffer.from(data.previousAnchorHash).equals(Buffer.from(this.config.lastAnchorHash))) error = 'BrokenAnchorChain';
    else if (this.segment.dayUtc !== ledgerDay(new Date(Number(this.time) * 1000))) error = 'WrongLedgerDay';
    return { error, signature, data, operator };
  }
  /** Writes an anchor entry (ours, or a foreign one) and advances program state. */
  execute(data: any, operator: Address) {
    this.mutate(s => {
      const entry = { ...data, merkleRoot: this.tamperRoot ? new Uint8Array(32).fill(0xee) : data.merkleRoot, pad0: new Uint8Array(0), operator, publishedAt: 1_790_000_000n } as AnchorEntryV1;
      s.segment.entries.push(entry); s.segment.entryCount += 1;
      s.config.currentBatchSequence = entry.batchSequence;
      s.config.lastAnchorHash = this.tamperAnchorHash ? new Uint8Array(32).fill(0xdd) : anchorHash({ ...entry, registryIdHash: registryIdHash(REGISTRY), merkleRoot: Uint8Array.from(entry.merkleRoot), manifestHash: Uint8Array.from(entry.manifestHash), snapshotHash: Uint8Array.from(entry.snapshotHash), previousAnchorHash: Uint8Array.from(entry.previousAnchorHash), operatorPubkey: new Uint8Array(getAddressEncoder().encode(operator)) });
    });
  }
}

export const append = (pool: Pool, recordId: string, payload: Record<string, unknown>, baseVersion = 0) =>
  workflowTransaction(pool, c => appendWorkflowVersion(c, { registryId: REGISTRY, recordId, baseVersion, operation: 'upsert', payload, payloadHash: workflowHash({ operation: 'upsert', payload }), creator: 'alice', approver: 'bob', evidence: { synthetic: true } }));
export const publisher = (pool: Pool, chain: FakeChain, signer: PublicationSigner, extra: Partial<PublisherConfig> = {}) =>
  new WorkflowPublisher(pool, chain, signer, { registryId: REGISTRY, programId: PROGRAM_ID, configPda: CONFIG_PDA, operatorKeyId: 'synthetic-operator', keys: KEYS, ...extra });
export const count = async (pool: Pool, sql: string) => Number((await pool.query(sql)).rows[0].count);
export const expire = (pool: Pool) => pool.query("UPDATE wf_publication SET lease_until=clock_timestamp()-interval '1 second' WHERE state='OPEN'");
export const states = async (pool: Pool) => (await pool.query('SELECT t.attempt_no,e.state FROM wf_publication_tx_event e JOIN wf_publication_tx t USING(attempt_id) ORDER BY e.event_id')).rows.map(r => `${r.attempt_no}:${r.state}`);
export const opState = async (pool: Pool, id: string) => (await pool.query('SELECT state,blocked_reason FROM wf_publication WHERE operation_id=$1', [id])).rows[0];

