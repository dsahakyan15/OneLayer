// Review 04 MAJOR-1 / MINOR-2: recovery and snapshot anchors may rely on the
// absence of on-chain incidents only when the incident index is complete
// through the anchor slot and recently refreshed.
import assert from "node:assert/strict";
import test from "node:test";
import { routeAdmin, type AdminContext, latestSnapshotAnchor, selectRecoveryAnchor } from "../src/admin.ts";
import { PostgresIncidentStore } from "../src/incident-store.ts";
import { SessionStore, parseCredentials, SESSION_COOKIE } from "../src/admin-session.ts";
import { isolatedPostgres } from "./support/postgres.ts";

const REGISTRY = "synthetic-recovery-anchor";

test("recovery/snapshot anchors require a complete, fresh incident index without blocking notices", { timeout: 60_000 }, async context => {
  const { pool } = await isolatedPostgres(context);
  for (const [batch, slot] of [[1, 100], [2, 200], [3, 300]]) {
    await pool.query(
      `INSERT INTO demo_anchor (registry_id, batch_sequence, registry_version, merkle_root, manifest_hash, anchor_hash,
         program_id, segment_pda, transaction_signature, anchor_slot, commitment, finalized_at)
       VALUES ($1, $2, $2, $3, $3, $3, 'program', 'segment', $4, $5, 'finalized', now())`,
      [REGISTRY, batch, Buffer.alloc(32, batch), `signature-${batch}`, slot],
    );
  }
  const recovery = () => selectRecoveryAnchor(pool, REGISTRY).then(anchor => anchor.batchSequence, error => `${error.status} ${error.code}`);
  const snapshotFinal = async () => (await latestSnapshotAnchor(pool, REGISTRY)).finalized;
  const setState = (slot: number, ageSeconds = 0) => pool.query(
    "UPDATE incident_index_state SET indexed_through_slot = $2, updated_at = now() - make_interval(secs => $3) WHERE registry_id = $1",
    [REGISTRY, slot, ageSeconds],
  );

  // Never indexed: nothing qualifies.
  assert.equal(await recovery(), "409 RECOVERY_ANCHOR_UNAVAILABLE");
  assert.equal(await snapshotFinal(), false);

  const store = new PostgresIncidentStore(pool, "config");
  await store.loadState(REGISTRY);
  // Complete only through slot 250: batch 3 (slot 300) is not yet covered.
  await setState(250);
  assert.equal(await recovery(), "2");
  assert.equal(await snapshotFinal(), false);

  await setState(400);
  assert.equal(await recovery(), "3");
  assert.equal(await snapshotFinal(), true);

  // ADR-0008: closing an investigation cannot rehabilitate its suspect batch.
  await store.transaction(REGISTRY, tx => tx.applyOpened(REGISTRY, { incidentSequence: 0n, firstSuspectBatch: 3n, lastSuspectBatch: 3n, incidentType: 1, status: "OPEN", openedSlot: 350n, resolvedSlot: null }));
  assert.equal(await recovery(), "2");
  assert.equal(await snapshotFinal(), false);
  await store.transaction(REGISTRY, tx => tx.applyResolved(REGISTRY, 0n, 360n, "CONFIRMED"));
  assert.equal(await recovery(), "2");
  assert.equal(await snapshotFinal(), false);
  await store.transaction(REGISTRY, tx => tx.applyResolved(REGISTRY, 0n, 370n, "RESOLVED"));
  assert.equal(await recovery(), "2", "RESOLVED must not become the recovery anchor");
  assert.equal(await snapshotFinal(), false, "RESOLVED must not become a trusted snapshot");
  const sessions = new SessionStore(parseCredentials(JSON.stringify({ auditor: { password: "synthetic-auditor-password-012345", registryIds: [REGISTRY] }, operator: "synthetic-operator-password-012345" })));
  const session = await sessions.login("auditor", "synthetic-auditor-password-012345");
  assert.ok(session);
  const dashboard = () => routeAdmin({ pool, sessions, registryId: REGISTRY } as unknown as AdminContext, {
    method: "GET", path: "/v1/admin/dashboard", query: new URLSearchParams(), body: null,
    cookieHeader: `${SESSION_COOKIE}=${session.sessionId}`, csrfHeader: undefined, idempotencyKey: undefined,
  });
  const blockedDashboard = await dashboard();
  assert.equal(blockedDashboard.status, 200);
  assert.equal((blockedDashboard.body as { openIncidents: string }).openIncidents, "1");
  await pool.query("UPDATE incident_index_notice SET status = 'FALSE_POSITIVE' WHERE registry_id = $1", [REGISTRY]);
  assert.equal(((await dashboard()).body as { openIncidents: string }).openIncidents, "0");
  assert.equal(await recovery(), "3");
  assert.equal(await snapshotFinal(), true);

  // An unscoped local finding remains blocking after administrative closure.
  await pool.query(`INSERT INTO integrity_incident
    (incident_id, registry_id, incident_type, severity, status, evidence_object_key, opened_at)
    VALUES ('00000000-0000-4000-8000-000000000004', $1, 'SYNTHETIC', 'HIGH', 'RESOLVED', 'synthetic', now())`, [REGISTRY]);
  assert.equal(await recovery(), "409 RECOVERY_ANCHOR_UNAVAILABLE");
  assert.equal(await snapshotFinal(), false);
  await pool.query("DELETE FROM integrity_incident WHERE registry_id = $1", [REGISTRY]);

  // Stuck index: the watermark covers every anchor slot, but the last complete
  // refresh is old, so a notice opened on-chain since then (e.g. for batch 3)
  // would be invisible. Fail closed.
  await pool.query("DELETE FROM incident_index_notice WHERE registry_id = $1", [REGISTRY]);
  await setState(400, 10 * 60);
  assert.equal(await recovery(), "409 RECOVERY_ANCHOR_UNAVAILABLE");
  assert.equal(await snapshotFinal(), false);
  await setState(400, 60);
  assert.equal(await recovery(), "3");
});
