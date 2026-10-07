// Ticket 12 end-to-end: the actual `onelayer-monitor` process against a
// disposable PostgreSQL (dedicated read-only role) and a disposable local
// Solana validator, with injected tamper workload and measured detection
// latency (out-of-process, real sample count).
//
// Run explicitly (not part of `npm test`):
//   node --test --experimental-transform-types apps/monitor/tests/e2e/monitor-runtime.test.ts
// Environment: localhost only; the harness never touches devnet/mainnet.

import assert from "node:assert/strict";
import { execFile, spawn, type ChildProcess } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { createRequire } from "node:module";
import { test, type TestContext } from "node:test";
import { promisify } from "node:util";
import { buildSbfProgram, startLocalValidator } from "../../../../apps/demo-api/integration/support/solana-validator.ts";

const exec = promisify(execFile);
const REPO = new URL("../../../../", import.meta.url).pathname;
const require = createRequire(join(REPO, "apps/demo-api/package.json"));
const pgModule = require("pg") as {
  Pool: new (options: { connectionString: string; max: number }) => {
    query(text: string, values?: unknown[]): Promise<{ rows: Record<string, any>[] }>;
    end(): Promise<void>;
  };
};
const quote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;

/** Disposable PG WITHOUT migrations: the builder harness applies db/migrations. */
async function barePostgres(context: TestContext): Promise<{ pool: InstanceType<typeof pgModule.Pool>; connectionString: string; dir: string }> {
  const bin = (await exec("pg_config", ["--bindir"])).stdout.trim();
  const dir = await mkdtemp(join(tmpdir(), "onelayer-monitor-pg-"));
  const data = join(dir, "data");
  let started = false;
  context.after(async () => {
    try {
      if (started) await exec(join(bin, "pg_ctl"), ["-D", data, "-m", "immediate", "-w", "stop"]);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
  await exec(join(bin, "initdb"), ["-D", data, "-A", "trust", "-U", "onelayer_test", "--no-locale"]);
  await exec(join(bin, "pg_ctl"), ["-D", data, "-l", join(dir, "postgres.log"), "-w", "-t", "15", "-o", `-h '' -k ${quote(dir)} -p 5432`, "start"]);
  started = true;
  const connectionString = `postgresql://onelayer_test@localhost/postgres?host=${encodeURIComponent(dir)}&port=5432`;
  const pool = new pgModule.Pool({ connectionString, max: 5 });
  return { pool, connectionString, dir };
}
const REGISTRY_PROGRAM = "6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo";
const WORKLOAD_SAMPLES = 20;

function monitorBinaryPath(): string {
  const targetDir = process.env.CARGO_TARGET_DIR ?? join(REPO, "target");
  return join(targetDir, "debug", "onelayer-monitor");
}

async function ensureMonitorBinary(): Promise<string> {
  if (process.env.ONELAYER_MONITOR_BIN) return process.env.ONELAYER_MONITOR_BIN;
  const binary = monitorBinaryPath();
  if (existsSync(binary)) return binary;
  await exec("cargo", ["build", "-p", "onelayer-monitor"], { cwd: REPO, maxBuffer: 64 * 1024 * 1024, timeout: 15 * 60_000 });
  return binary;
}

async function runHarness(command: string, args: string[]): Promise<Record<string, unknown>> {
  const { stdout } = await exec(
    "node",
    ["--experimental-transform-types", join(REPO, "apps/monitor/tests/harness/builder.mts"), command, ...args],
    { cwd: REPO, maxBuffer: 32 * 1024 * 1024, timeout: 300_000 },
  );
  const line = stdout.trim().split("\n").at(-1)!;
  return JSON.parse(line) as Record<string, unknown>;
}

async function runMonitor(binary: string, command: string, config: string, extra: string[] = []): Promise<{ code: number; stdout: string; stderr: string }> {
  try {
    const { stdout, stderr } = await exec(binary, [command, "--config", config, ...extra], { maxBuffer: 32 * 1024 * 1024, timeout: 300_000 });
    return { code: 0, stdout, stderr };
  } catch (error) {
    const failure = error as { code?: number; stdout?: string; stderr?: string };
    return { code: failure.code ?? 1, stdout: failure.stdout ?? "", stderr: failure.stderr ?? "" };
  }
}

function startMonitorRun(binary: string, config: string): { process: ChildProcess; lines: string[]; waitFor(predicate: (line: Record<string, unknown>) => boolean, timeoutMs?: number, fromIndex?: number): Promise<Record<string, unknown>> } {
  const child = spawn(binary, ["run", "--config", config], { stdio: ["ignore", "pipe", "pipe"] });
  const lines: string[] = [];
  const waiters: Array<{ predicate: (line: Record<string, unknown>) => boolean; resolve: (line: Record<string, unknown>) => void; fromIndex: number }> = [];
  const reader = createInterface({ input: child.stdout! });
  reader.on("line", (line) => {
    lines.push(line);
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(line) as Record<string, unknown>;
    } catch {
      return;
    }
    for (let i = waiters.length - 1; i >= 0; i -= 1) {
      if (lines.length - 1 >= waiters[i].fromIndex && waiters[i].predicate(parsed)) {
        waiters[i].resolve(parsed);
        waiters.splice(i, 1);
      }
    }
  });
  const waitFor = (predicate: (line: Record<string, unknown>) => boolean, timeoutMs = 60_000, fromIndex = lines.length) =>
    new Promise<Record<string, unknown>>((resolve, reject) => {
      const existing = lines
        .slice(fromIndex)
        .map((line) => JSON.parse(line) as Record<string, unknown>)
        .find(predicate);
      if (existing !== undefined) {
        resolve(existing);
        return;
      }
      const waiter = { predicate, resolve, fromIndex };
      waiters.push(waiter);
      setTimeout(() => {
        const index = waiters.indexOf(waiter);
        if (index >= 0) {
          waiters.splice(index, 1);
          reject(new Error(`monitor output wait timed out; last lines:\n${lines.slice(-5).join("\n")}`));
        }
      }, timeoutMs).unref();
    });
  return { process: child, lines, waitFor };
}

test("monitor runtime: read-only source, injected tamper workload, p95 latency", async (t: TestContext) => {
  const binary = await ensureMonitorBinary();
  const build = await buildSbfProgram({
    crateDir: join(REPO, "onchain/programs/onelayer-registry"),
    libName: "onelayer_registry",
    extraInputs: [join(REPO, "onchain/Cargo.lock"), join(REPO, "onchain/Cargo.toml")],
  });
  const validator = await startLocalValidator(t, [{ programId: REGISTRY_PROGRAM, so: build.so }]);
  t.diagnostic(`validator ${validator.version}; registry.so sha256=${build.sha256}; monitor=${binary}`);
  const pg = await barePostgres(t);

  const dir = await mkdtemp(join(tmpdir(), "onelayer-monitor-e2e-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const stateFile = join(dir, "state.json");
  const setup = await runHarness("setup", ["--pg", pg.connectionString, "--rpc", validator.rpcUrl, "--state", stateFile]);
  await pg.pool.query(await readFile(join(REPO, "apps/monitor/sql/monitor_readonly_role.sql"), "utf8"));
  const registryId = String(setup.registryId);
  const state = JSON.parse(await readFile(stateFile, "utf8")) as { idKey: string; fieldKeyMaster: string };

  // 20 versions of one record, published as a single finalized batch.
  const items = Array.from({ length: WORKLOAD_SAMPLES }, (_, index) => ({
    recordId: "parcel-a",
    payload: { owner: `Synthetic ${index}`, area: 100 + index },
  }));
  await runHarness("append", ["--state", stateFile, "--items", JSON.stringify(items)]);
  const publication = await runHarness("publish", ["--state", stateFile]);
  t.diagnostic(`published batch ${publication.batchSequence} root ${publication.merkleRoot}`);
  assert.equal(publication.status, "FINALIZED");

  const keysFile = join(dir, "keys.json");
  await writeFile(keysFile, JSON.stringify({ idKey: state.idKey, fieldKeyMaster: state.fieldKeyMaster }), { mode: 0o600 });
  const evidenceDir = join(dir, "evidence");
  const configFile = join(dir, "monitor.json");
  await writeFile(
    configFile,
    JSON.stringify({
      registryId,
      programId: REGISTRY_PROGRAM,
      configPda: setup.configPda,
      rpcUrl: validator.rpcUrl,
      sourceDsn: `host=${pg.dir} port=5432 user=onelayer_monitor dbname=postgres`,
      keysFile,
      evidenceDir,
      evidenceFloorFile: join(dir, "evidence.floor.json"),
      pollIntervalMs: 300,
    }),
    { mode: 0o600 },
  );

  await t.test("clean cycle verifies the finalized batch with no findings", async () => {
    const result = await runMonitor(binary, "once", configFile);
    assert.equal(result.code, 0, result.stderr);
    const report = JSON.parse(result.stdout.trim().split("\n").at(-1)!) as { verifiedBatches: number; newFindings: string[]; active: number };
    assert.equal(report.verifiedBatches, 1);
    assert.deepEqual(report.newFindings, []);
    assert.equal(report.active, 0);
  });

  await t.test("monitor credentials cannot write to the protected source", async () => {
    const monitorPool = new pgModule.Pool({
      connectionString: `postgresql://onelayer_monitor@localhost/postgres?host=${encodeURIComponent(pg.dir)}&port=5432`,
      max: 1,
    });
    try {
      await assert.rejects(
        () => monitorPool.query("UPDATE wf_version SET payload = '{}'::jsonb WHERE false"),
        (error: unknown) => String((error as Error).message).length > 0,
      );
      await assert.rejects(() => monitorPool.query("DELETE FROM wf_outbox WHERE false"), /read-only|permission denied/i);
    } finally {
      await monitorPool.end();
    }
  });

  const samples: number[] = [];
  await t.test(`injected workload: ${WORKLOAD_SAMPLES} tampers detected out-of-process`, async () => {
    const monitor = startMonitorRun(binary, configFile);
    t.after(() => {
      monitor.process.kill("SIGKILL");
    });
    try {
      // Baseline cycle first (observations pinned).
      await monitor.waitFor((line) => Array.isArray(line.newFindings) && (line.newFindings as unknown[]).length === 0 && Number(line.verifiedBatches) >= 1);

      // Simulate a compromised DB: application immutability triggers disabled,
      // then field-level tampering outside the approved process.
      await pg.pool.query("ALTER TABLE wf_version DISABLE TRIGGER USER");
      try {
        for (let index = 0; index < WORKLOAD_SAMPLES; index += 1) {
          const version = index + 1;
          const fromIndex = monitor.lines.length;
          await pg.pool.query(
            "UPDATE wf_version SET payload = jsonb_set(payload, '{owner}', to_jsonb($1::text)) WHERE registry_id=$2 AND record_id='parcel-a' AND version=$3",
            [`Tampered ${index}`, registryId, version],
          );
          const injectedAt = Date.now();
          const line = await monitor.waitFor(
            (candidate) => Array.isArray(candidate.newFindings) && (candidate.newFindings as unknown[]).length > 0,
            60_000,
            fromIndex,
          );
          const latency = Date.now() - injectedAt;
          samples.push(latency);
          assert.ok(
            (line.newFindings as string[]).some((kind) => ["SOURCE_FIELD_CHANGED", "OBSERVED_VERSION_CHANGED", "ANCHORED_ROOT_MISMATCH"].includes(kind)),
            `unexpected finding kinds: ${JSON.stringify(line.newFindings)}`,
          );
        }
      } finally {
        await pg.pool.query("ALTER TABLE wf_version ENABLE TRIGGER USER");
      }
    } finally {
      monitor.process.kill("SIGKILL");
      await new Promise<void>((resolve) => monitor.process.once("exit", () => resolve()));
    }
    assert.equal(samples.length, WORKLOAD_SAMPLES, "honest sample count: every injection detected");
    const sorted = [...samples].sort((a, b) => a - b);
    const p95 = sorted[Math.max(0, Math.ceil(0.95 * sorted.length) - 1)];
    t.diagnostic(
      `detection latency ms: min=${sorted[0]} p50=${sorted[Math.floor(sorted.length / 2)]} p95=${p95} max=${sorted.at(-1)} samples=${sorted.length} poll=300ms`,
    );
    assert.ok(p95 < 15 * 60_000, `p95 ${p95}ms exceeds the 15 minute target`);
  });

  await t.test("broken Builder (cursor gap) is detected", async () => {
    await runHarness("faulty-anchor", ["--state", stateFile, "--skip", "1"]);
    const result = await runMonitor(binary, "once", configFile);
    assert.equal(result.code, 3, `active findings should exit 3: ${result.stderr}`);
    const report = JSON.parse(result.stdout.trim().split("\n").at(-1)!) as { newFindings: string[] };
    assert.ok(report.newFindings.includes("CURSOR_GAP"), JSON.stringify(report.newFindings));
  });

  await t.test("evidence tail truncation is refused by verify-evidence and run", async () => {
    const eventsPath = join(evidenceDir, "evidence.jsonl");
    const original = await readFile(eventsPath, "utf8");
    const lines = original.trimEnd().split("\n");
    await writeFile(eventsPath, `${lines.slice(0, -1).join("\n")}\n`);
    try {
      const verify = await runMonitor(binary, "verify-evidence", configFile, ["--dir", evidenceDir]);
      assert.equal(verify.code, 2);
      assert.match(verify.stdout, /EVIDENCE_TAIL_ROLLBACK/);
      const run = await runMonitor(binary, "once", configFile);
      assert.equal(run.code, 1);
      assert.match(run.stderr, /EVIDENCE_TAIL_ROLLBACK/);
    } finally {
      await writeFile(eventsPath, original);
    }
    const recovered = await runMonitor(binary, "verify-evidence", configFile, ["--dir", evidenceDir]);
    assert.equal(recovered.code, 0, recovered.stdout);
  });

  await t.test("evidence floor deletion is refused with a non-empty journal", async () => {
    const floorPath = join(dir, "evidence.floor.json");
    const originalFloor = await readFile(floorPath, "utf8");
    await rm(floorPath);
    try {
      const verify = await runMonitor(binary, "verify-evidence", configFile, ["--dir", evidenceDir]);
      assert.equal(verify.code, 2);
      assert.match(verify.stdout, /EVIDENCE_FLOOR_MISSING/);
      const run = await runMonitor(binary, "once", configFile);
      assert.equal(run.code, 1);
      assert.match(run.stderr, /EVIDENCE_FLOOR_MISSING/);
    } finally {
      await writeFile(floorPath, originalFloor);
    }
    const recovered = await runMonitor(binary, "verify-evidence", configFile, ["--dir", evidenceDir]);
    assert.equal(recovered.code, 0, recovered.stdout);
  });
});
