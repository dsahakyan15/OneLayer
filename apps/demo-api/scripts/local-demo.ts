// Explicit synthetic localhost profile. Persistent private ledger/state; no public RPC.
import { spawn, execFile, type ChildProcess } from 'node:child_process';
import { createHash, sign } from 'node:crypto';
import { mkdir, lstat, stat, open, rm, readFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { createServer } from 'node:net';
import {
  address, appendTransactionMessageInstructions, compileTransaction, createNoopSigner,
  createTransactionMessage, getBase64EncodedWireTransaction, getAddressDecoder, pipe,
  setTransactionMessageFeePayerSigner, setTransactionMessageLifetimeUsingBlockhash,
  type Instruction,
} from '@solana/kit';
import {
  findRegistryConfigPda, findRolePda, findLedgerSegmentPda,
  getInitializeRegistryInstruction, getGrantOperatorInstructionAsync,
  getCreateLedgerSegmentInstruction, getRegistryConfigDecoder, getOperatorRoleDecoder, getDailyAnchorLedgerSegmentDecoder,
} from '../../../packages/onchain-client/src/index.ts';
import { registryIdHash } from '../../../packages/canonical-ts/src/index.ts';
import { buildSbfProgram, rpcCall } from '../integration/support/solana-validator.ts';
import { ensureKeyPair, loadSigningKey, persistentKeyRoot, type LoadedSigningKey } from './live-demo-key-store.ts';
import { ledgerDay } from '../src/publication-worker.ts';

const exec = promisify(execFile);
const repo = fileURLToPath(new URL('../../../', import.meta.url));
const program = address('6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo');
const registry = 'demo.synthetic.local';
const token = createHash('sha256').update(registry).digest('hex').slice(0, 24);
const base = join(homedir(), '.local/state/onelayer-devnet-demo/local-validator');
const state = join(base, 'namespaces', token);
const keyRoot = join(persistentKeyRoot(), 'namespaces', token);
const rpc = 'http://127.0.0.1:18899';
const native = join(repo, 'deploy/devnet-demo/native');
const env: NodeJS.ProcessEnv = {
  ...process.env, ONELAYER_REGISTRY_ID: registry, ONELAYER_NATIVE_STATE_DIR: base,
  ONELAYER_DEMO_RUNTIME_DIR: join(state, 'runtime'), ONELAYER_RPC_URL: rpc,
  ONELAYER_PUBLICATION_CLUSTER: 'solana:local', ONELAYER_SYNTHETIC_PROFILE: 'local-validator',
  ONELAYER_ADMIN_ACCESS_LAB: '1',
  ONELAYER_NATIVE_PG_PORT: '55433',
};
let validator: ChildProcess | undefined;
let nativeStarted = false;
let stopping: Promise<void> | undefined;
let interrupted = false;
const abort = new AbortController();

async function privateDirectory(path: string): Promise<void> {
  await mkdir(path, { recursive: true, mode: 0o700 });
  const info = await lstat(path);
  if (!info.isDirectory() || info.uid !== process.getuid!() || (info.mode & 0o077)) {
    throw new Error('LOCAL_DEMO_PRIVATE_UNIX_STATE_REQUIRED');
  }
}

async function available(port: number): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const server = createServer();
    server.once('error', () => reject(new Error(`LOCAL_DEMO_PORT_BUSY:${port}; stop the owning stack explicitly`)));
    server.listen(port, '127.0.0.1', () => server.close(() => resolve()));
  });
}

async function serviceAlive(name: string): Promise<void> {
  const pid = (await readFile(join(state, 'pids', `${name}.pid`), 'utf8')).trim();
  const expected = (await readFile(join(state, 'pids', `${name}.pid.start`), 'utf8')).trim();
  if (!/^[1-9][0-9]*$/.test(pid)) throw new Error(`LOCAL_DEMO_SERVICE_PID_INVALID:${name}`);
  const processStat = await readFile(`/proc/${pid}/stat`, 'utf8');
  const fields = processStat.slice(processStat.lastIndexOf(')') + 2).trim().split(/\s+/);
  if (fields[0] === 'Z' || fields[19] !== expected) throw new Error(`LOCAL_DEMO_SERVICE_EXITED:${name}`);
}

async function verifyServices(genesis: string, config: string): Promise<void> {
  await Promise.all(['demo-api', 'verifier', 'mvp-web', 'audit', 'monitor'].map(serviceAlive));
  const responses = await Promise.all([
    'http://127.0.0.1:8090/v1/health', 'http://127.0.0.1:8080/v1/health', 'http://127.0.0.1:8091/verify',
  ].map(url => fetch(url, { signal: AbortSignal.timeout(5000) })));
  if (responses.some(response => !response.ok)) throw new Error('LOCAL_DEMO_SERVICE_NOT_READY');
  const health = await responses[0].json() as Record<string, unknown>;
  if (health.registryId !== registry || health.programId !== program || health.configPda !== config || health.cluster !== 'solana:local' || health.genesisHash !== genesis) throw new Error('LOCAL_DEMO_SERVICE_IDENTITY_MISMATCH');
  await Promise.all(responses.slice(1).map(response => response.body?.cancel()));
}

async function finalized(signature: string): Promise<void> {
  const deadline = Date.now() + 120_000;
  while (Date.now() < deadline && !interrupted) {
    const item = (await rpcCall(rpc, 'getSignatureStatuses', [[signature], { searchTransactionHistory: true }])).value[0];
    if (item?.err) throw new Error('LOCAL_DEMO_TRANSACTION_FAILED');
    if (item?.confirmationStatus === 'finalized') return;
    await new Promise(resolve => setTimeout(resolve, 300));
  }
  throw new Error('LOCAL_DEMO_FINALITY_TIMEOUT');
}

async function send(key: LoadedSigningKey, instructions: Instruction[]): Promise<void> {
  // RPC is a literal loopback URL and genesis has been checked before this path.
  const lifetime = (await rpcCall(rpc, 'getLatestBlockhash', [{ commitment: 'confirmed' }])).value;
  const message = pipe(createTransactionMessage({ version: 0 }),
    m => setTransactionMessageFeePayerSigner(createNoopSigner(key.address), m),
    m => setTransactionMessageLifetimeUsingBlockhash({ blockhash: lifetime.blockhash, lastValidBlockHeight: BigInt(lifetime.lastValidBlockHeight) }, m),
    m => appendTransactionMessageInstructions(instructions, m));
  const tx = compileTransaction(message);
  const signed = { ...tx, signatures: { ...tx.signatures, [key.address]: new Uint8Array(sign(null, Buffer.from(tx.messageBytes), key.privateKey)) } };
  const wire = getBase64EncodedWireTransaction(signed as any);
  const simulation = await rpcCall(rpc, 'simulateTransaction', [wire, { encoding: 'base64', sigVerify: true, commitment: 'confirmed' }]);
  if (simulation.value.err) throw new Error('LOCAL_DEMO_SIMULATION_FAILED');
  const signature = await rpcCall(rpc, 'sendTransaction', [wire, { encoding: 'base64', preflightCommitment: 'confirmed' }]);
  await finalized(signature);
}

async function stop(): Promise<void> {
  if (stopping) return stopping;
  stopping = (async () => {
    if (nativeStarted) await exec(native, ['stop'], { env, timeout: 30_000 }).catch(() => console.error('local-demo: service cleanup failed; use native stop with this profile'));
    if (validator?.pid && validator.exitCode === null) {
      validator.kill('SIGTERM');
      const deadline = Date.now() + 10_000;
      while (validator.exitCode === null && validator.signalCode === null && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 100));
      if (validator.exitCode === null && validator.signalCode === null) validator.kill('SIGKILL');
    }
  })();
  return stopping;
}

process.on('SIGINT', () => { interrupted = true; abort.abort(); });
process.on('SIGTERM', () => { interrupted = true; abort.abort(); });
process.umask(0o077);
await privateDirectory(state);
// Exclusive lock is intentionally not auto-deleted after SIGKILL: inspect it,
// rather than killing a reused PID or resetting a retained ledger implicitly.
const lockPath = join(state, 'supervisor.lock');
const lock = await open(lockPath, 'wx', 0o600).catch(() => { throw new Error('LOCAL_DEMO_ALREADY_RUNNING_OR_UNCLEAN_LOCK'); });
await lock.writeFile(String(process.pid));
try {
  for (const port of [18899, 18900, 8080, 8090, 8091, 55433]) await available(port);
  console.log('local-demo: building the source-pinned registry program (localhost only)');
  const build = await buildSbfProgram({ crateDir: join(repo, 'onchain/programs/onelayer-registry'), libName: 'onelayer_registry', extraInputs: [join(repo, 'onchain/Cargo.lock'), join(repo, 'onchain/Cargo.toml')] });
  if (interrupted) throw new Error('LOCAL_DEMO_INTERRUPTED');
  const ledger = join(state, 'ledger');
  // A relocated public synthetic RocksDB cache must stay present; never turn a
  // missing cache into an implicit empty retained ledger. Private identities,
  // genesis, database and authorities remain in the Unix state directory.
  const rocks = await lstat(join(ledger, 'rocksdb')).catch(error => {
    if (error.code === 'ENOENT') return undefined;
    throw error;
  });
  if (rocks?.isSymbolicLink()) {
    const target = await stat(join(ledger, 'rocksdb')).catch(() => undefined);
    if (!target?.isDirectory()) throw new Error('LOCAL_DEMO_LEDGER_CACHE_MISSING');
  }
  const log = await open(join(state, 'validator.log'), constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | constants.O_NOFOLLOW, 0o600);
  const logInfo = await log.stat();
  if (!logInfo.isFile() || logInfo.uid !== process.getuid!() || (logInfo.mode & 0o077)) {
    await log.close();
    throw new Error('LOCAL_DEMO_LOG_UNSAFE');
  }
  // Keep enough transaction history for repeated certificate verification.
  // The active synthetic ledger is retained state, not disposable build cache.
  validator = spawn('solana-test-validator', ['--ledger', ledger, '--quiet', '--bind-address', '127.0.0.1', '--rpc-port', '18899', '--faucet-port', '18901', '--gossip-port', '18902', '--dynamic-port-range', '18903-18940', '--limit-ledger-size', '1000000', '--bpf-program', program, build.so], { stdio: ['ignore', log.fd, log.fd], env: { ...process.env, RUST_LOG: process.env.RUST_LOG ?? 'warn' } });
  await log.close();
  let validatorError = false;
  validator.on('error', () => { validatorError = true; });
  const deadline = Date.now() + 300_000;
  for (;;) {
    if (validatorError || validator.exitCode !== null || interrupted) throw new Error('LOCAL_DEMO_VALIDATOR_EXITED');
    try { if (await rpcCall(rpc, 'getHealth') === 'ok' && await rpcCall(rpc, 'getSlot', [{ commitment: 'finalized' }]) > 0) break; } catch { /* bounded startup */ }
    if (Date.now() > deadline) throw new Error('LOCAL_DEMO_VALIDATOR_START_TIMEOUT');
    await new Promise(resolve => setTimeout(resolve, 300));
  }
  const genesis = await rpcCall(rpc, 'getGenesisHash');
  if (['EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG', '5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d'].includes(genesis)) throw new Error('LOCAL_DEMO_PUBLIC_CHAIN_REFUSED');
  const deployed = (await rpcCall(rpc, 'getAccountInfo', [program, { encoding: 'base64', commitment: 'finalized' }])).value;
  const loader = 'BPFLoaderUpgradeab1e11111111111111111111111';
  const programState = deployed ? Buffer.from(deployed.data[0], 'base64') : Buffer.alloc(0);
  if (!deployed?.executable || deployed.owner !== loader || programState.length !== 36 || programState.readUInt32LE(0) !== 2) throw new Error('LOCAL_DEMO_PROGRAM_ACCOUNT_INVALID');
  // UpgradeableLoaderState::Program stores a ProgramData address; the ELF is
  // after the 45-byte ProgramData metadata, not in the 36-byte Program account.
  // https://github.com/anza-xyz/solana-sdk/blob/master/loader-v3-interface/src/state.rs
  const programDataAddress = getAddressDecoder().decode(programState.subarray(4));
  const programDataAccount = (await rpcCall(rpc, 'getAccountInfo', [programDataAddress, { encoding: 'base64', commitment: 'finalized' }])).value;
  const programData = programDataAccount ? Buffer.from(programDataAccount.data[0], 'base64') : Buffer.alloc(0);
  if (programDataAccount?.owner !== loader || programData.length < 45 || programData.readUInt32LE(0) !== 3 || createHash('sha256').update(programData.subarray(45)).digest('hex') !== build.sha256) throw new Error('LOCAL_DEMO_RETAINED_PROGRAM_DIGEST_MISMATCH');
  console.log('local-demo: retained validator program bytes verified');
  env.ONELAYER_RPC_GENESIS_HASH = genesis;
  for (const name of ['governance.json', 'demo-operator.json']) await ensureKeyPair({ keyFile: join(keyRoot, name) });
  const governance = await loadSigningKey(join(keyRoot, 'governance.json'));
  const operator = await loadSigningKey(join(keyRoot, 'demo-operator.json'));
  for (const key of [governance, operator]) {
    if ((await rpcCall(rpc, 'getBalance', [key.address])).value < 1_000_000_000) await finalized(await rpcCall(rpc, 'requestAirdrop', [key.address, 2_000_000_000]));
  }
  console.log('local-demo: synthetic local authorities funded');
  const [config] = await findRegistryConfigPda(registryIdHash(registry), { programAddress: program });
  const account = (await rpcCall(rpc, 'getAccountInfo', [config, { encoding: 'base64', commitment: 'finalized' }])).value;
  if (!account) {
    await send(governance, [getInitializeRegistryInstruction({ config, governance: createNoopSigner(governance.address), registryIdHash: registryIdHash(registry), emergencyAuthority: governance.address, schemaVersion: 1, hashAlgorithm: 1, treeAlgorithm: 1, anchorIntervalSeconds: 3600, maxEntriesPerDay: 46 }, { programAddress: program })]);
  } else {
    const decoded = getRegistryConfigDecoder().decode(Buffer.from(account.data[0], 'base64'));
    if (account.owner !== program || decoded.governanceAuthority !== governance.address || !Buffer.from(decoded.registryIdHash).equals(Buffer.from(registryIdHash(registry)))) throw new Error('LOCAL_DEMO_RETAINED_REGISTRY_MISMATCH');
  }
  console.log('local-demo: registry configuration ready');
  const [role] = await findRolePda({ config, operator: operator.address }, { programAddress: program });
  const roleAccount = (await rpcCall(rpc, 'getAccountInfo', [role, { encoding: 'base64', commitment: 'finalized' }])).value;
  if (!roleAccount) {
    await send(governance, [await getGrantOperatorInstructionAsync({ config, operator: operator.address, governanceAuthority: createNoopSigner(governance.address), permissions: 3, validFrom: 0, validUntil: 0, keyIdHash: new Uint8Array(32) }, { programAddress: program })]);
  }
  if (roleAccount) {
    const roleData = getOperatorRoleDecoder().decode(Buffer.from(roleAccount.data[0], 'base64'));
    if (roleAccount.owner !== program || roleData.registry !== config || roleData.operator !== operator.address || (roleData.permissions & 3) !== 3 || roleData.revokedAt !== 0n || roleData.validFrom !== 0n || roleData.validUntil !== 0n) throw new Error('LOCAL_DEMO_RETAINED_OPERATOR_ROLE_MISMATCH');
  }
  const dayUtc = ledgerDay(new Date());
  const [segment] = await findLedgerSegmentPda({ config, dayUtc, segmentIndex: 0 }, { programAddress: program });
  const segmentAccount = (await rpcCall(rpc, 'getAccountInfo', [segment, { encoding: 'base64', commitment: 'finalized' }])).value;
  if (!segmentAccount) await send(operator, [getCreateLedgerSegmentInstruction({ config, role, operator: createNoopSigner(operator.address), segment, dayUtc, segmentIndex: 0, capacity: 46 }, { programAddress: program })]);
  if (segmentAccount) {
    const segmentData = getDailyAnchorLedgerSegmentDecoder().decode(Buffer.from(segmentAccount.data[0], 'base64'));
    if (segmentAccount.owner !== program || segmentData.registry !== config || segmentData.dayUtc !== dayUtc || segmentData.segmentIndex !== 0) throw new Error('LOCAL_DEMO_RETAINED_LEDGER_MISMATCH');
  }
  console.log(`local-demo: synthetic namespace ${registry}; genesis ${genesis}; program sha256 ${build.sha256}`);
  nativeStarted = true; // includes cleanup if startup fails after spawning one service
  await exec(native, ['start'], { env, signal: abort.signal, timeout: 300_000, maxBuffer: 8 * 1024 * 1024 });
  const health = await (await fetch('http://127.0.0.1:8090/v1/health', { signal: AbortSignal.timeout(5000) })).json() as any;
  if (health.registryId !== registry || health.programId !== program || health.configPda !== config || health.cluster !== 'solana:local' || health.genesisHash !== genesis) throw new Error('LOCAL_DEMO_SERVICE_IDENTITY_MISMATCH');
  console.log('local-demo: READY; API :8090, verifier :8080, web :8091. Ctrl+C stops this profile; ledger/database/keys are retained.');
  if (process.env.ONELAYER_LIVE_DEMO_NO_LAUNCHER !== '1') {
    await exec(join(repo, 'apps/desktop/launcher'), [], { env, signal: abort.signal, timeout: 24 * 60 * 60_000, maxBuffer: 1024 * 1024 });
  } else {
    let failedReadinessChecks = 0;
    let nextReadinessCheck = 0;
    while (!interrupted) {
      if (validator.exitCode !== null || validator.signalCode !== null) throw new Error('LOCAL_DEMO_VALIDATOR_EXITED');
      if (Date.now() >= nextReadinessCheck) {
        try {
          await verifyServices(genesis, config);
          failedReadinessChecks = 0;
        } catch {
          failedReadinessChecks += 1;
          console.error(`local-demo: readiness failed (${failedReadinessChecks}/3); retained state is preserved`);
          if (failedReadinessChecks >= 3) throw new Error('LOCAL_DEMO_SERVICES_UNAVAILABLE');
        }
        nextReadinessCheck = Date.now() + 5000;
      }
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  }
} finally {
  await stop();
  await lock.close();
  await rm(lockPath, { force: true });
}
