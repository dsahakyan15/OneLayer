import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { once } from "node:events";
import { writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { join } from "node:path";
import test from "node:test";
import { isolatedPostgres } from "../../apps/demo-api/integration/support/postgres.ts";
import { startTestIdp } from "../../apps/demo-api/integration/support/test-idp.ts";
import { PostgresSessionStore } from "../../apps/demo-api/src/postgres-session.ts";
import type { AdminPermission, AdminRole } from "../../apps/demo-api/src/admin-permissions.ts";

// Real loopback sockets: the installed API process serves OIDC login and the
// registry workflow. Grants come from PostgreSQL sessions provisioned here,
// never from request bodies or test booleans. No chain RPC is exercised; the
// preloaded network guard refuses any non-loopback fetch before the API's RPC
// adapter captures fetch, so periodic refreshes cannot leave the test.

const REGISTRY_ID = "gov.registry.land";
const WEB_ORIGIN = "http://127.0.0.1:8091";
const PROGRAM_ID = "6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo";

type ResourceActions = readonly ("records.read" | "records.write" | "certificates.read" | "certificates.export")[];
type Session = { cookie: string; csrfToken: string; username: string; role: string };

const scopePolicy = (actions: ResourceActions, recordIds: string[] | "all" = "all") => ({
  version: 1,
  grants: [{ registryId: REGISTRY_ID, recordIds, fieldPaths: "all", actions }],
});

const cookieFrom = (response: Response, name: string): string | undefined =>
  response.headers.getSetCookie().map(cookie => cookie.split(";")[0]).find(cookie => cookie.startsWith(`${name}=`));

test("registry workflow over live OIDC HTTP: independent approval, domain refusals and revocation", { timeout: 90_000 }, async context => {
  const { pool, connectionString, dir } = await isolatedPostgres(context);
  const idp = await startTestIdp();
  context.after(() => idp.close());
  const listener = createServer();
  listener.listen(0, "127.0.0.1");
  await once(listener, "listening");
  const address = listener.address();
  assert.ok(address && typeof address !== "string");
  const port = address.port;
  await new Promise<void>(resolve => listener.close(() => resolve()));
  const origin = `http://127.0.0.1:${port}`;

  const sessions = new PostgresSessionStore(pool, [], { oidcOnly: true });
  const provision = async (username: string, role: AdminRole, permissions: readonly AdminPermission[], actions: ResourceActions) => {
    await sessions.provisionOidcAccount({ username, issuer: idp.issuer, subject: `${username}-subject`,
      access: { role, permissions, registryIds: [REGISTRY_ID] }, resourcePolicy: scopePolicy(actions) }, "synthetic-harness");
    await sessions.enrollDevice(username, `${username}-device`, "synthetic-harness");
  };
  await provision("writer", "registry_worker", ["records.read", "records.draft"], ["records.read", "records.write"]);
  await provision("approver", "registry_approver", ["records.read", "records.approve"], ["records.read", "records.write"]);
  await provision("reader", "auditor", ["records.read"], ["records.read"]);
  // Separation of duties: the identity store refuses to mint a writer who may
  // also approve, so a self-approving writer cannot exist by permission alone.
  // The workflow contributor guard itself is exercised over the module surface
  // in apps/demo-api/integration/registry-workflow.test.ts; here the live API
  // refuses the same account at the permission layer. Both are asserted below.
  await assert.rejects(sessions.provisionOidcAccount({ username: "self-approver", issuer: idp.issuer, subject: "self-approver-subject",
    access: { role: "registry_worker", permissions: ["records.read", "records.draft", "records.approve"], registryIds: [REGISTRY_ID] },
    resourcePolicy: scopePolicy(["records.read", "records.write"]) }, "synthetic-harness"), /permission exceeds demo role policy/);

  // Installed before the RPC adapter captures fetch; the guard prints its ready
  // marker so startup can prove it is active in the child.
  const networkGuard = new URL("../helpers/local-network-only.mjs", import.meta.url).href;
  await Promise.all([
    writeFile(join(dir, "database"), connectionString),
    writeFile(join(dir, "issuer"), "09".repeat(32)),
    writeFile(join(dir, "oidc.json"), JSON.stringify(idp.config(`${origin}/v2/admin/oidc/callback`))),
  ]);
  const child = spawn(process.execPath, ["--import", networkGuard, "--experimental-transform-types", "src/main.ts"], {
    cwd: new URL("../../apps/demo-api/", import.meta.url),
    env: {
      ...process.env, PORT: String(port),
      ONELAYER_DATABASE_URL_FILE: join(dir, "database"), ONELAYER_ISSUER_SECRET_FILE: join(dir, "issuer"),
      ONELAYER_OIDC_CONFIG_FILE: join(dir, "oidc.json"), ONELAYER_SESSION_BACKEND: "postgres",
      ONELAYER_INTERNAL_AUTH: "service-principal", ONELAYER_RPC_URL: "https://api.devnet.solana.com",
      ONELAYER_VERIFIER_URL: "http://127.0.0.1:1", ONELAYER_PUBLIC_BASE_URL: origin,
      ONELAYER_PUBLIC_WEB_URL: WEB_ORIGIN, ONELAYER_PROGRAM_ID: PROGRAM_ID,
    }, stdio: ["ignore", "pipe", "pipe"],
  });
  context.after(async () => {
    if (child.exitCode === null && child.signalCode === null) {
      const closed = once(child, "close");
      child.kill("SIGKILL");
      await closed;
    }
  });
  await new Promise<void>((resolve, reject) => {
    // Bounded diagnostics: only the tail is kept, and no session or CSRF value
    // ever enters it. Faults are reported, not silently skipped.
    let output = "";
    const diagnostic = () => output.slice(-4096);
    const timer = setTimeout(() => reject(new Error(`workflow API startup timed out: ${diagnostic()}`)), 45_000);
    const onExit = () => { clearTimeout(timer); reject(new Error(`workflow API exited before listening: ${diagnostic()}`)); };
    child.once("exit", onExit);
    child.once("error", error => { clearTimeout(timer); reject(error); });
    child.stderr.on("data", data => { output = (output + String(data)).slice(-4096); });
    child.stdout.on("data", data => {
      output = (output + String(data)).slice(-4096);
      if (output.includes("demo API listening")) {
        assert.ok(output.includes("synthetic outbound guard ready"), "test network guard must be installed before API startup");
        clearTimeout(timer);
        child.removeListener("exit", onExit);
        resolve();
      }
    });
  });

  const api = async (path: string, init: RequestInit = {}) => {
    const response = await fetch(`${origin}${path}`, init);
    const text = await response.text();
    let body: unknown = null;
    try { body = text === "" ? null : JSON.parse(text); } catch { body = text; }
    return { status: response.status, body, response };
  };
  const startLogin = async (subject: string, deviceId: string) => {
    // Claims are set per login; the authorize hop talks only to the pinned test
    // issuer and never carries a backend cookie.
    idp.controls.claims = { sub: subject, device_id: deviceId };
    const started = await api("/v2/admin/oidc/start", { method: "POST", headers: { origin: WEB_ORIGIN } });
    assert.equal(started.status, 200);
    const binding = cookieFrom(started.response, "onelayer_oidc_binding");
    assert.ok(binding, "OIDC binding cookie missing");
    const { state, code } = await idp.authorize((started.body as { authorizationUrl: string }).authorizationUrl);
    return await api(`/v2/admin/oidc/callback?state=${encodeURIComponent(state)}&code=${encodeURIComponent(code)}`,
      { redirect: "manual", headers: { cookie: binding } });
  };
  const login = async (subject: string, deviceId: string): Promise<Session> => {
    const callback = await startLogin(subject, deviceId);
    assert.equal(callback.status, 303);
    const cookie = cookieFrom(callback.response, "onelayer_admin_session");
    assert.ok(cookie, "session cookie missing");
    const dto = await api("/v1/admin/session", { headers: { cookie } });
    assert.equal(dto.status, 200);
    const body = dto.body as { username: string; role: string; csrfToken: string };
    return { cookie, csrfToken: body.csrfToken, username: body.username, role: body.role };
  };
  const workflow = (session: Session, method: string, path: string, body?: Record<string, unknown>,
      options: { key?: string; csrf?: string | null } = {}) => {
    const headers: Record<string, string> = { cookie: session.cookie };
    if (method !== "GET") headers["x-onelayer-csrf"] = options.csrf === null ? "" : (options.csrf ?? session.csrfToken);
    if (method === "POST") headers["idempotency-key"] = options.key ?? randomUUID();
    if (body !== undefined) headers["content-type"] = "application/json";
    return api(`/v2/admin/workflow/${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  };
  const evidenceCounts = async () => (await pool.query(`SELECT
    (SELECT count(*)::int FROM wf_draft) AS drafts, (SELECT count(*)::int FROM wf_revision) AS revisions,
    (SELECT count(*)::int FROM wf_version) AS versions, (SELECT count(*)::int FROM wf_outbox) AS outbox,
    (SELECT count(*)::int FROM wf_audit) AS audits, (SELECT count(*)::int FROM wf_request) AS requests`)).rows[0];

  assert.deepEqual((await api("/v2/admin/oidc/config")).body, { enabled: true });
  const wrongOrigin = await api("/v2/admin/oidc/start", { method: "POST", headers: { origin: "http://127.0.0.1:9" } });
  assert.equal(wrongOrigin.status, 403);
  assert.deepEqual(wrongOrigin.body, { code: "ORIGIN_FORBIDDEN" });

  const writer = await login("writer-subject", "writer-device");
  const approver = await login("approver-subject", "approver-device");
  const reader = await login("reader-subject", "reader-device");
  assert.deepEqual((await api("/v1/admin/session", { headers: { cookie: writer.cookie } })).body, {
    role: "registry_worker", username: "writer", csrfToken: writer.csrfToken,
    permissions: ["records.read", "records.draft"], registryIds: [REGISTRY_ID], deploymentRegistryId: REGISTRY_ID,
  });
  assert.deepEqual((await api("/v1/admin/session", { headers: { cookie: approver.cookie } })).body, {
    role: "registry_approver", username: "approver", csrfToken: approver.csrfToken,
    permissions: ["records.read", "records.approve"], registryIds: [REGISTRY_ID], deploymentRegistryId: REGISTRY_ID,
  });
  assert.deepEqual((await api("/v1/admin/session", { headers: { cookie: reader.cookie } })).body, {
    role: "auditor", username: "reader", csrfToken: reader.csrfToken,
    permissions: ["records.read"], registryIds: [REGISTRY_ID], deploymentRegistryId: REGISTRY_ID,
  });

  // Second self-approval layer: even a direct DB grant outside the role ceiling
  // cannot resolve into a session, so the workflow contributor guard cannot be
  // bypassed by widening a writer's grants. Restored before the flow continues.
  await pool.query("UPDATE demo_admin_account SET permissions=$2 WHERE username=$1",
    ["writer", ["records.read", "records.draft", "records.approve"]]);
  const overPrivileged = await startLogin("writer-subject", "writer-device");
  assert.equal(overPrivileged.status, 503);
  assert.deepEqual(overPrivileged.body, { code: "IDENTITY_UNAVAILABLE" });
  await pool.query("UPDATE demo_admin_account SET permissions=$2 WHERE username=$1",
    ["writer", ["records.read", "records.draft"]]);

  const floor = await evidenceCounts();
  const refusedCsrf = await workflow(writer, "POST", "drafts", { recordId: "http-flow", baseVersion: 0, operation: "upsert", payload: { owner: "writer" } }, { csrf: "wrong" });
  assert.equal(refusedCsrf.status, 403);
  assert.deepEqual(refusedCsrf.body, { code: "CSRF_TOKEN_INVALID" });
  assert.deepEqual(await evidenceCounts(), floor);

  const createBody = { recordId: "http-flow", baseVersion: 0, operation: "upsert", payload: { owner: "writer", name: "first" } };
  const prepareBody = { path: "/v2/admin/workflow/drafts", body: createBody };
  assert.equal((await workflow(writer, "POST", "attempts", prepareBody, { csrf: "wrong" })).status, 403);
  assert.equal((await pool.query("SELECT count(*)::int AS n FROM wf_attempt")).rows[0].n, 0);
  assert.equal((await workflow(reader, "POST", "attempts", prepareBody)).status, 403);
  const prepared = await workflow(writer, "POST", "attempts", prepareBody);
  assert.equal(prepared.status, 200);
  const receipt = prepared.body as { attemptId: string; idempotencyKey: string };
  const created = await workflow(writer, "POST", "drafts", createBody, { key: receipt.idempotencyKey });
  assert.deepEqual((await workflow(writer, "POST", "drafts", createBody, { key: receipt.idempotencyKey })).body, created.body);
  const recovered = await workflow(writer, "GET", "attempts");
  assert.equal(recovered.status, 200);
  assert.equal((recovered.body as { attempts: { draftId: string; state: string }[] }).attempts[0].draftId, (created.body as { draftId: string }).draftId);
  assert.equal((recovered.body as { attempts: { state: string }[] }).attempts[0].state, "COMPLETED");
  assert.deepEqual((await workflow(approver, "GET", "attempts")).body, { attempts: [] });
  assert.equal((await workflow(writer, "POST", `attempts/${receipt.attemptId}/ack`, {}, { csrf: "wrong" })).status, 403);
  assert.equal((await workflow(writer, "POST", `attempts/${receipt.attemptId}/ack`, {})).status, 200);
  assert.deepEqual((await workflow(writer, "GET", "attempts")).body, { attempts: [] });
  assert.equal(created.status, 201);
  const draft = created.body as { draftId: string; revision: number; payloadHash: string; baseVersion: number; state: string };
  assert.equal(draft.revision, 1);
  assert.equal(draft.baseVersion, 0);
  assert.equal(draft.state, "DRAFT");
  assert.match(draft.payloadHash, /^[0-9a-f]{64}$/);
  const edited = await workflow(writer, "POST", `drafts/${draft.draftId}/edit`, { expectedRevision: 1, operation: "upsert", payload: { owner: "writer", name: "second" } });
  assert.equal(edited.status, 200);
  const revision = edited.body as typeof draft;
  assert.equal(revision.revision, 2);
  assert.equal(revision.state, "DRAFT");

  // Refusals must not leave revisions, outbox events or audit rows behind.
  const afterEdit = await evidenceCounts();
  const staleEdit = await workflow(writer, "POST", `drafts/${draft.draftId}/edit`, { expectedRevision: 1, operation: "upsert", payload: { owner: "writer", name: "stale" } });
  assert.equal(staleEdit.status, 409);
  assert.deepEqual(staleEdit.body, { error: "REVISION_CONFLICT" });
  assert.deepEqual(await evidenceCounts(), afterEdit);
  const readerEdit = await workflow(reader, "POST", `drafts/${draft.draftId}/edit`, { expectedRevision: revision.revision, operation: "upsert", payload: { owner: "reader" } });
  assert.equal(readerEdit.status, 403);
  assert.deepEqual(readerEdit.body, { error: "PERMISSION_FORBIDDEN" });
  const readerCreate = await workflow(reader, "POST", "drafts", { recordId: "http-flow", baseVersion: 0, operation: "upsert", payload: { owner: "reader" } });
  assert.equal(readerCreate.status, 403);
  assert.deepEqual(readerCreate.body, { error: "PERMISSION_FORBIDDEN" });
  assert.deepEqual(await evidenceCounts(), afterEdit);

  const binding = { expectedRevision: revision.revision, payloadHash: revision.payloadHash, baseVersion: revision.baseVersion };
  const submitted = await workflow(writer, "POST", `drafts/${draft.draftId}/submit`, binding);
  assert.equal(submitted.status, 200);
  assert.equal((submitted.body as { state: string }).state, "SUBMITTED");
  const afterSubmit = await evidenceCounts();
  // The creator's own approve is refused by the backend on the live socket.
  const selfApproval = await workflow(writer, "POST", `drafts/${draft.draftId}/approve`, binding);
  assert.equal(selfApproval.status, 403);
  assert.deepEqual(selfApproval.body, { error: "PERMISSION_FORBIDDEN" });
  // An approver cannot become a contributor either: editing needs records.draft.
  const approverEdit = await workflow(approver, "POST", `drafts/${draft.draftId}/edit`, { expectedRevision: revision.revision, operation: "upsert", payload: { owner: "approver" } });
  assert.equal(approverEdit.status, 403);
  assert.deepEqual(approverEdit.body, { error: "PERMISSION_FORBIDDEN" });
  assert.deepEqual(await evidenceCounts(), afterSubmit);
  const wrongHash = await workflow(approver, "POST", `drafts/${draft.draftId}/approve`, { ...binding, payloadHash: "0".repeat(64) });
  assert.equal(wrongHash.status, 409);
  assert.deepEqual(wrongHash.body, { error: "APPROVAL_BINDING_MISMATCH" });
  assert.deepEqual(await evidenceCounts(), afterSubmit);
  const approved = await workflow(approver, "POST", `drafts/${draft.draftId}/approve`, binding);
  assert.equal(approved.status, 200);

  const commitKey = randomUUID();
  const committed = await workflow(writer, "POST", `drafts/${draft.draftId}/commit`, binding, { key: commitKey });
  assert.equal(committed.status, 200);
  const committedBody = committed.body as { state: string; committed: { recordId: string; version: number; payloadHash: string } };
  assert.equal(committedBody.state, "COMMITTED");
  assert.deepEqual(committedBody.committed, { recordId: "http-flow", version: 1, payloadHash: revision.payloadHash });
  const afterCommit = await evidenceCounts();
  // A replayed Idempotency-Key returns the stored result without new evidence.
  const replay = await workflow(writer, "POST", `drafts/${draft.draftId}/commit`, binding, { key: commitKey });
  assert.equal(replay.status, 200);
  assert.deepEqual(replay.body, committed.body);
  assert.deepEqual(await evidenceCounts(), afterCommit);
  assert.equal((await pool.query("SELECT count(*)::int AS n FROM wf_audit WHERE action='COMMIT' AND details->>'draftId'=$1", [draft.draftId])).rows[0].n, 1);

  const latest = await workflow(writer, "GET", "records/http-flow/versions/latest");
  assert.equal(latest.status, 200);
  assert.deepEqual(latest.body, { recordId: "http-flow", version: 1, payload: { owner: "writer", name: "second" },
    payloadHash: revision.payloadHash, operation: "upsert", state: "COMMITTED" });
  const missingVersion = await workflow(writer, "GET", "records/http-flow/versions/99");
  assert.equal(missingVersion.status, 404);
  assert.deepEqual(missingVersion.body, { error: "RECORD_VERSION_NOT_FOUND" });

  // A second committed record so an out-of-scope object can be compared with an
  // absent one for the same session.
  const secondCreated = await workflow(writer, "POST", "drafts", { recordId: "other-record", baseVersion: 0, operation: "upsert", payload: { owner: "writer", name: "other" } });
  assert.equal(secondCreated.status, 201);
  const secondDraft = secondCreated.body as typeof draft;
  const secondBinding = { expectedRevision: secondDraft.revision, payloadHash: secondDraft.payloadHash, baseVersion: secondDraft.baseVersion };
  assert.equal((await workflow(writer, "POST", `drafts/${secondDraft.draftId}/submit`, secondBinding)).status, 200);
  assert.equal((await workflow(approver, "POST", `drafts/${secondDraft.draftId}/approve`, secondBinding)).status, 200);
  assert.equal((await workflow(writer, "POST", `drafts/${secondDraft.draftId}/commit`, secondBinding)).status, 200);
  const visibleBefore = await workflow(reader, "GET", "records/http-flow/versions/latest");
  assert.equal(visibleBefore.status, 200);

  await sessions.updateResourcePolicy("reader", scopePolicy(["records.read"], ["http-flow"]), "synthetic-harness");
  const scopedReader = await login("reader-subject", "reader-device");
  const scopedVersion = await workflow(scopedReader, "GET", "records/other-record/versions/1");
  assert.equal(scopedVersion.status, 404);
  assert.deepEqual(scopedVersion.body, { error: "RECORD_VERSION_NOT_FOUND" });
  const scopedDraft = await workflow(scopedReader, "GET", `drafts/${secondDraft.draftId}`);
  assert.equal(scopedDraft.status, 404);
  assert.deepEqual(scopedDraft.body, { error: "DRAFT_NOT_FOUND" });
  const absentDraft = await workflow(scopedReader, "GET", `drafts/${randomUUID()}`);
  assert.equal(absentDraft.status, scopedDraft.status);
  assert.deepEqual(absentDraft.body, scopedDraft.body);
  assert.equal((await workflow(scopedReader, "GET", "records/http-flow/versions/latest")).status, 200);

  // Revocation invalidates cookies that were already issued.
  await sessions.revokeDevice("writer-device", "synthetic-harness");
  const revokedWriter = await api("/v1/admin/session", { headers: { cookie: writer.cookie } });
  assert.equal(revokedWriter.status, 401);
  assert.deepEqual(revokedWriter.body, { code: "SESSION_REQUIRED" });
  assert.equal((await workflow(writer, "GET", "records/http-flow/versions/latest")).status, 401);
  assert.equal((await workflow(writer, "GET", "attempts")).status, 401);
  const writerRelogin = await startLogin("writer-subject", "writer-device");
  assert.equal(writerRelogin.status, 401);
  assert.deepEqual(writerRelogin.body, { code: "OIDC_AUTHENTICATION_FAILED" });
  await sessions.revokeUser("approver", "synthetic-harness");
  const revokedApprover = await api("/v1/admin/session", { headers: { cookie: approver.cookie } });
  assert.equal(revokedApprover.status, 401);
  assert.deepEqual(revokedApprover.body, { code: "SESSION_REQUIRED" });
  const approverRelogin = await startLogin("approver-subject", "approver-device");
  assert.equal(approverRelogin.status, 401);

  // Backend evidence: two records committed, one outbox event each, and the
  // refusals above added nothing to the workflow tables.
  const final = await evidenceCounts();
  assert.equal(final.versions, 2);
  assert.equal(final.outbox, 2);
  assert.equal((await pool.query("SELECT count(*)::int AS n FROM wf_outbox WHERE registry_id=$1", [REGISTRY_ID])).rows[0].n, 2);
});
