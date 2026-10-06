import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test, { type TestContext } from "node:test";
import { Pool } from "pg";
import { PostgresIncidentStore } from "../src/incident-store.ts";

const exec = promisify(execFile);
const quote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;

/** An isolated Unix-socket cluster: never connects to an existing application
 * database and never reads DATABASE_URL or production credentials. */
async function disposableCluster(context: TestContext): Promise<Pool> {
  const bin = (await exec("pg_config", ["--bindir"])).stdout.trim();
  const dir = await mkdtemp(join(tmpdir(), "onelayer-incident-pg-"));
  const data = join(dir, "data");
  let started = false;
  let pool: Pool | undefined;
  context.after(async () => {
    try { await pool?.end(); }
    finally {
      try { if (started) await exec(join(bin, "pg_ctl"), ["-D", data, "-m", "immediate", "-w", "stop"]); }
      finally { await rm(dir, { recursive: true, force: true }); }
    }
  });
  await exec(join(bin, "initdb"), ["-D", data, "-A", "trust", "-U", "onelayer_test", "--no-locale"]);
  await exec(join(bin, "pg_ctl"), ["-D", data, "-l", join(dir, "postgres.log"), "-w", "-t", "15", "-o", `-h '' -k ${quote(dir)} -p 5432`, "start"]);
  started = true;
  pool = new Pool({ host: dir, port: 5432, user: "onelayer_test", database: "postgres", max: 5 });
  return pool;
}

const migrations = new URL("../../../db/migrations/", import.meta.url);
async function applyMigrations(db: Pool, filter: (name: string) => boolean): Promise<void> {
  for (const migration of (await readdir(migrations)).filter(name => name.endsWith(".sql") && filter(name)).sort()) {
    // Same shape as the native runner: one migration, one transaction.
    await db.query(`BEGIN; ${await readFile(new URL(migration, migrations), "utf8")}; COMMIT;`);
  }
}

test("incident migration and projection transactions preserve completeness atomically", { timeout: 60_000 }, async context => {
  const db = await disposableCluster(context);
  await applyMigrations(db, name => name < "0007");
  await db.query("INSERT INTO incident_index_state (registry_id, registry_config, indexed_through_slot, last_signature) VALUES ('synthetic', 'config', 100, 'old-cursor')");
  await db.query("INSERT INTO incident_index_notice VALUES ('synthetic',0,1,9,3,'RESOLVED',10,20)");
  await applyMigrations(db, name => name.startsWith("0007_"));
  assert.equal((await db.query("SELECT count(*) FROM incident_index_notice")).rows[0].count, "0");
  assert.deepEqual((await db.query("SELECT indexed_through_slot::text, last_signature FROM incident_index_state")).rows[0], { indexed_through_slot: "0", last_signature: null });

  const store = new PostgresIncidentStore(db, "config");
  await store.transaction("synthetic", async tx => {
    await tx.loadState("synthetic");
    await tx.applyOpened("synthetic", { incidentSequence: 0n, firstSuspectBatch: 1n, lastSuspectBatch: 9n, incidentType: 3, status: "OPEN", openedSlot: 10n, resolvedSlot: null });
    await tx.saveState("synthetic", { indexedThroughSlot: 100n, lastSignature: "opened" });
  });
  await assert.rejects(store.transaction("synthetic", async tx => {
    await tx.applyResolved("synthetic", 0n, 110n, "CONFIRMED");
    await tx.saveState("synthetic", { indexedThroughSlot: 120n, lastSignature: "uncommitted" });
    // A different connection must still see the entire old projection.
    assert.equal((await store.listNotices("synthetic", 5n))[0].status, "OPEN");
    assert.equal((await db.query("SELECT indexed_through_slot FROM incident_index_state WHERE registry_id='synthetic'")).rows[0].indexed_through_slot, "100");
    throw new Error("synthetic scan failure");
  }), /synthetic scan failure/);
  assert.equal((await store.listNotices("synthetic", 5n))[0].status, "OPEN");
  assert.equal((await store.loadState("synthetic")).lastSignature, "opened");

  const locked = Promise.withResolvers<void>();
  const release = Promise.withResolvers<void>();
  const first = store.transaction("synthetic", async tx => {
    await tx.loadState("synthetic");
    locked.resolve();
    await release.promise;
    await tx.applyResolved("synthetic", 0n, 150n, "CONFIRMED");
    await tx.saveState("synthetic", { indexedThroughSlot: 200n, lastSignature: "first" });
  });
  await locked.promise;
  const second = store.transaction("synthetic", async tx => {
    const state = await tx.loadState("synthetic");
    await tx.saveState("synthetic", { indexedThroughSlot: state.indexedThroughSlot + 1n, lastSignature: "second" });
  });
  release.resolve();
  await Promise.all([first, second]);
  assert.deepEqual(await store.loadState("synthetic"), { indexedThroughSlot: 201n, lastSignature: "second" });
  assert.equal((await store.listNotices("synthetic", 5n))[0].status, "CONFIRMED");
  await assert.rejects(store.transaction("synthetic", tx => tx.applyResolved("synthetic", 999n, 300n, "RESOLVED")), /no indexed opening/);
  await assert.rejects(store.transaction("synthetic", tx => tx.transaction("synthetic", async () => undefined)), /nested/);
  await assert.rejects(new PostgresIncidentStore(db, "other-config").loadState("synthetic"), /different registry config/);
});

const U64_MAX = 0xffff_ffff_ffff_ffffn;

test("0014 keeps an existing projection exactly and stores the full u64 suspect range", { timeout: 60_000 }, async context => {
  const db = await disposableCluster(context);
  await applyMigrations(db, name => name < "0014");
  // A populated projection under the old BIGINT schema, including the largest
  // value the old schema could hold.
  const I64_MAX = 0x7fff_ffff_ffff_ffffn;
  await db.query("INSERT INTO incident_index_state (registry_id, registry_config, indexed_through_slot, last_signature) VALUES ('synthetic', 'config', 500, 'cursor-500')");
  await db.query(`INSERT INTO incident_index_notice VALUES
    ('synthetic',0,1,9,3,'OPEN',10,NULL),
    ('synthetic',1,5,5,1,'CONFIRMED',11,12),
    ('synthetic',2,7,${I64_MAX},2,'FALSE_POSITIVE',13,14),
    ('synthetic',3,20,30,4,'RESOLVED',15,16)`);
  // Old BIGINT schema rejects exactly the values D1 is about.
  await assert.rejects(db.query("INSERT INTO incident_index_notice VALUES ('synthetic',9,0,1,1,'OPEN',1,NULL)"), /check constraint/);
  await assert.rejects(db.query(`INSERT INTO incident_index_notice VALUES ('synthetic',9,1,${U64_MAX},1,'OPEN',1,NULL)`), /out of range/);
  const store = new PostgresIncidentStore(db, "config");
  const before = await store.listNotices("synthetic");

  await applyMigrations(db, name => name.startsWith("0014_"));
  assert.deepEqual(await store.listNotices("synthetic"), before, "rows are preserved exactly");
  assert.deepEqual(await store.loadState("synthetic"), { indexedThroughSlot: 500n, lastSignature: "cursor-500" }, "watermark is preserved");
  const checks = async () => (await db.query(
    "SELECT conname, pg_get_constraintdef(oid) AS def FROM pg_constraint WHERE conrelid = 'incident_index_notice'::regclass AND contype = 'c' ORDER BY conname",
  )).rows.map(row => `${row.conname}: ${row.def}`);
  const expectedChecks = [
    // Unrelated, untouched 0003 check (generated name).
    "incident_index_notice_check1: CHECK (((resolved_slot IS NULL) OR (resolved_slot >= opened_slot)))",
    "incident_index_notice_first_suspect_batch_u64: CHECK (((first_suspect_batch >= (0)::numeric) AND (first_suspect_batch <= '18446744073709551615'::numeric)))",
    "incident_index_notice_incident_sequence_check: CHECK ((incident_sequence >= 0))",
    "incident_index_notice_incident_type_check: CHECK ((incident_type >= 0))",
    "incident_index_notice_last_suspect_batch_u64: CHECK (((last_suspect_batch >= (0)::numeric) AND (last_suspect_batch <= '18446744073709551615'::numeric)))",
    "incident_index_notice_opened_slot_check: CHECK ((opened_slot > 0))",
    "incident_index_notice_status_check: CHECK ((status = ANY (ARRAY['OPEN'::text, 'CONFIRMED'::text, 'FALSE_POSITIVE'::text, 'RESOLVED'::text])))",
    "incident_index_notice_suspect_range_ordered: CHECK ((first_suspect_batch <= last_suspect_batch))",
  ];
  assert.deepEqual(await checks(), expectedChecks, "exact CHECK set after 0014");
  // Re-running 0014 is harmless: same constraints, same rows, same watermark.
  await applyMigrations(db, name => name.startsWith("0014_"));
  assert.deepEqual(await checks(), expectedChecks, "exact CHECK set after re-run");
  assert.deepEqual(await store.listNotices("synthetic"), before);
  assert.deepEqual(await store.loadState("synthetic"), { indexedThroughSlot: 500n, lastSignature: "cursor-500" });
  const types = await db.query("SELECT column_name, data_type, numeric_precision, numeric_scale FROM information_schema.columns WHERE table_name='incident_index_notice' AND column_name LIKE '%suspect_batch' ORDER BY column_name");
  assert.deepEqual(types.rows.map(row => [row.column_name, row.data_type, row.numeric_precision, row.numeric_scale]), [
    ["first_suspect_batch", "numeric", 20, 0], ["last_suspect_batch", "numeric", 20, 0],
  ]);

  // Boundary values round-trip exactly through the store (no Number anywhere).
  await store.transaction("synthetic", async tx => {
    await tx.applyOpened("synthetic", { incidentSequence: 4n, firstSuspectBatch: 0n, lastSuspectBatch: 0n, incidentType: 1, status: "OPEN", openedSlot: 20n, resolvedSlot: null });
    await tx.applyOpened("synthetic", { incidentSequence: 5n, firstSuspectBatch: 0n, lastSuspectBatch: U64_MAX, incidentType: 2, status: "OPEN", openedSlot: 21n, resolvedSlot: null });
    await tx.applyOpened("synthetic", { incidentSequence: 6n, firstSuspectBatch: U64_MAX, lastSuspectBatch: U64_MAX, incidentType: 3, status: "OPEN", openedSlot: 22n, resolvedSlot: null });
    await tx.applyOpened("synthetic", { incidentSequence: 7n, firstSuspectBatch: I64_MAX + 1n, lastSuspectBatch: U64_MAX - 1n, incidentType: 4, status: "OPEN", openedSlot: 23n, resolvedSlot: null });
    await tx.applyResolved("synthetic", 7n, 24n, "FALSE_POSITIVE");
  });
  const all = new Map((await store.listNotices("synthetic")).map(n => [n.incidentSequence, n]));
  assert.deepEqual([4n, 5n, 6n, 7n].map(seq => [all.get(seq)!.firstSuspectBatch, all.get(seq)!.lastSuspectBatch]), [
    [0n, 0n], [0n, U64_MAX], [U64_MAX, U64_MAX], [I64_MAX + 1n, U64_MAX - 1n],
  ]);
  assert.equal(all.get(7n)!.status, "FALSE_POSITIVE");
  const seqsAt = async (batch: bigint) => (await store.listNotices("synthetic", batch)).map(n => n.incidentSequence);
  assert.deepEqual(await seqsAt(0n), [4n, 5n]);
  assert.deepEqual(await seqsAt(U64_MAX), [5n, 6n]);
  assert.deepEqual(await seqsAt(I64_MAX), [2n, 5n]);
  assert.deepEqual(await seqsAt(I64_MAX + 1n), [5n, 7n]);
  assert.deepEqual(await seqsAt(6n), [0n, 5n]);

  // The new domain is exactly u64 with an ordered range.
  await assert.rejects(store.transaction("synthetic", tx => tx.applyOpened("synthetic", { incidentSequence: 8n, firstSuspectBatch: 0n, lastSuspectBatch: U64_MAX + 1n, incidentType: 1, status: "OPEN", openedSlot: 30n, resolvedSlot: null })), /suspect_batch_u64|overflow/);
  await assert.rejects(store.transaction("synthetic", tx => tx.applyOpened("synthetic", { incidentSequence: 8n, firstSuspectBatch: -1n, lastSuspectBatch: 3n, incidentType: 1, status: "OPEN", openedSlot: 30n, resolvedSlot: null })), /suspect_batch_u64/);
  await assert.rejects(store.transaction("synthetic", tx => tx.applyOpened("synthetic", { incidentSequence: 8n, firstSuspectBatch: 5n, lastSuspectBatch: 4n, incidentType: 1, status: "OPEN", openedSlot: 30n, resolvedSlot: null })), /suspect_range_ordered/);
  assert.equal((await store.listNotices("synthetic")).length, 8);
});

