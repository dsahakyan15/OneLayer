import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import { bindSnapshotKeyVersion } from "../src/snapshot-key-store.ts";
import { isolatedPostgres } from "./support/postgres.ts";

const exec = promisify(execFile);
const registry = "gov.registry.land";

test("snapshot key binding survives process restart, rotates by new version and refuses replacement", { timeout: 90_000 }, async context => {
  const { pool, connectionString, dir } = await isolatedPostgres(context);
  const keyFile = join(dir, "writer-key");
  const key = Buffer.alloc(32, 0x19);
  await writeFile(keyFile, key, { mode: 0o600 });
  const childSource = join(dir, "binding-child.mjs");
  // Imports stay in the repository so pg resolves from its locked dependency.
  await writeFile(childSource, `
import pg from ${JSON.stringify(new URL("../node_modules/pg/lib/index.js", import.meta.url).href)};
import { loadSnapshotKeyConfig } from ${JSON.stringify(new URL("../src/snapshot-key-config.ts", import.meta.url).href)};
import { bindSnapshotKeyVersion } from ${JSON.stringify(new URL("../src/snapshot-key-store.ts", import.meta.url).href)};
const config = loadSnapshotKeyConfig();
const pool = new pg.Pool({ connectionString: process.env.TEST_DATABASE_URL });
try { await bindSnapshotKeyVersion(pool, "gov.registry.land", config); }
finally { config.kek.fill(0); await pool.end(); }
`);
  const run = () => exec(process.execPath, ["--experimental-transform-types", childSource], {
    env: { ...process.env, TEST_DATABASE_URL: connectionString,
      ONELAYER_SNAPSHOT_KEK_FILE: keyFile, ONELAYER_SNAPSHOT_KEY_VERSION: "lab-key-v1" },
    timeout: 30_000,
  });
  await run();
  await run();
  assert.equal((await pool.query("SELECT count(*)::text AS count FROM snapshot_key_version")).rows[0].count, "1");
  await writeFile(keyFile, Buffer.alloc(32, 0x29));
  await assert.rejects(run(), error => {
    assert.match(String(error), /SNAPSHOT_KEY_VERSION_CONFLICT/);
    assert.ok(!String(error).includes(key.toString("hex")));
    return true;
  });
  await bindSnapshotKeyVersion(pool, registry, { kek: Buffer.alloc(32, 0x29), keyEncryptionVersion: "lab-key-v2" });
  await bindSnapshotKeyVersion(pool, registry, { kek: key, keyEncryptionVersion: "lab-key-v1" });
  assert.deepEqual((await pool.query("SELECT key_encryption_version FROM snapshot_key_version ORDER BY key_encryption_version"))
    .rows.map(row => row.key_encryption_version), ["lab-key-v1", "lab-key-v2"]);
  for (const sql of ["UPDATE snapshot_key_version SET key_material_fingerprint=decode(repeat('00',32),'hex')",
    "DELETE FROM snapshot_key_version", "TRUNCATE snapshot_key_version"]) {
    await assert.rejects(pool.query(sql), /bindings are immutable/);
  }
});

test("concurrent writers cannot claim different material for one key version", { timeout: 90_000 }, async context => {
  const { pool } = await isolatedPostgres(context);
  const configs = [0x19, 0x29].map(byte => ({ kek: Buffer.alloc(32, byte), keyEncryptionVersion: "lab-race-v1" }));
  const results = await Promise.allSettled(configs.map(config => bindSnapshotKeyVersion(pool, registry, config)));
  assert.equal(results.filter(result => result.status === "fulfilled").length, 1);
  const refused = results.find(result => result.status === "rejected");
  assert.ok(refused?.status === "rejected");
  assert.equal(refused.reason.message, "SNAPSHOT_KEY_VERSION_CONFLICT");
  assert.equal((await pool.query("SELECT count(*)::text AS count FROM snapshot_key_version")).rows[0].count, "1");
});

test("runtime can bind and read key versions but has no destructive table privileges", { timeout: 90_000 }, async context => {
  const { pool } = await isolatedPostgres(context);
  const privileges = await pool.query(`SELECT
    has_table_privilege('onelayer_runtime','snapshot_key_version','SELECT') AS can_read,
    has_table_privilege('onelayer_runtime','snapshot_key_version','INSERT') AS can_insert,
    has_table_privilege('onelayer_runtime','snapshot_key_version','UPDATE') AS can_update,
    has_table_privilege('onelayer_runtime','snapshot_key_version','DELETE') AS can_delete,
    has_table_privilege('onelayer_runtime','snapshot_key_version','TRUNCATE') AS can_truncate`);
  assert.deepEqual(privileges.rows[0], {
    can_read: true, can_insert: true, can_update: false, can_delete: false, can_truncate: false,
  });
  const runtime = await pool.connect();
  try {
    await runtime.query("SET ROLE onelayer_runtime");
    const config = { kek: Buffer.alloc(32, 0x39), keyEncryptionVersion: "runtime-v1" };
    await bindSnapshotKeyVersion(runtime, registry, config);
    await bindSnapshotKeyVersion(runtime, registry, config);
    assert.equal((await runtime.query("SELECT count(*)::text AS count FROM snapshot_key_version")).rows[0].count, "1");
    for (const sql of ["UPDATE snapshot_key_version SET registered_at=clock_timestamp()",
      "DELETE FROM snapshot_key_version", "TRUNCATE snapshot_key_version"]) {
      await assert.rejects(runtime.query(sql), (error: unknown) =>
        typeof error === "object" && error !== null && "code" in error && error.code === "42501");
    }
  } finally {
    try { await runtime.query("RESET ROLE"); } finally { runtime.release(); }
  }
});
