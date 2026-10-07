import test from 'node:test';
import assert from 'node:assert/strict';
import { Pool } from 'pg';
import { PostgresSessionStore } from '../src/postgres-session.ts';
import { OidcClient } from '../src/oidc.ts';
import { isolatedPostgres } from './support/postgres.ts';
import { startTestIdp } from './support/test-idp.ts';
import { routeAdmin, type AdminContext, type AdminRequest } from '../src/admin.ts';

const policy = { version: 1, grants: [{registryId:'gov.registry.land',recordIds:['one'],fieldPaths:['name'],actions:['records.read']}] };
test('OIDC test IdP and real PostgreSQL enforce user/device admission, durable revocation and mode isolation', async t => {
  let pool: Pool | undefined;
  t.after(async () => { await pool?.end(); });
  const db = await isolatedPostgres(t);
  const idp = await startTestIdp(); t.after(() => idp.close());
  pool = new Pool({connectionString:db.connectionString});
  const store = new PostgresSessionStore(db.pool,[],{oidcOnly:true});
  const replica = new PostgresSessionStore(pool,[],{oidcOnly:true});
  const client = new OidcClient(idp.config());
  const login = async () => { const start = client.start(); return store.loginOidc(await client.complete({...await idp.authorize(start.authorizationUrl),browserBinding:start.browserBinding})); };
  assert.equal(await login(),null);
  const input = {username:'alice',issuer:idp.issuer,subject:'test-user',access:{role:'registry_worker' as const},resourcePolicy:policy};
  await store.provisionOidcAccount(input,'local-maintainer');
  await assert.rejects(store.provisionOidcAccount(input,'local-maintainer'), /ACCOUNT_ALREADY_EXISTS/);
  assert.equal(await login(),null);
  await store.enrollDevice('alice','test-device','local-maintainer');
  await assert.rejects(store.enrollDevice('alice','test-device','local-maintainer'),/DEVICE_ALREADY_EXISTS/);
  const session = (await login())!; assert.ok(session);
  assert.ok(session.expiresAt <= Date.now()+300_000);
  assert.equal((await replica.get(session.sessionId))?.username,'alice');
  assert.equal(await new PostgresSessionStore(pool,[]).get(session.sessionId),null);
  assert.equal(await store.login('alice','password'),null);
  for (const claims of [{sub:'stranger'}, {device_id:'unknown'}, {iss:'https://foreign.example'}]) {
    if (claims.iss) { assert.equal(await store.loginOidc({issuer:claims.iss,subject:'test-user',deviceId:'test-device',expiresAt:Date.now()+60000}),null); continue; }
    idp.controls.claims=claims; assert.equal(await login(),null);
  }
  idp.controls.claims={};
  await store.updateResourcePolicy('alice',{version:1,grants:[]},'local-maintainer');
  assert.equal(await replica.get(session.sessionId),null);
  const events=(await db.pool.query("SELECT action,access FROM demo_admin_access_event WHERE action IN ('ACCOUNT_PROVISIONED','RESOURCE_POLICY_CHANGED') ORDER BY event_id")).rows;
  assert.deepEqual(events.map(event => event.access.resourcePolicy),[policy,{version:1,grants:[]}]);
  const restricted=(await login())!; assert.deepEqual(restricted.resourcePolicy,{version:1,grants:[]});
  await store.revokeDevice('test-device','local-maintainer');
  assert.equal(await replica.get(restricted.sessionId),null); assert.equal(await login(),null);
  await store.enrollDevice('alice','second-device','local-maintainer'); idp.controls.claims={device_id:'second-device'};
  const second=(await login())!;
  await store.updateAccess('alice',{role:'auditor'},'local-maintainer');
  assert.equal(await replica.get(second.sessionId),null);
  const afterRole=(await login())!; assert.equal(afterRole.role,'auditor');
  await store.revokeUser('alice','local-maintainer');
  assert.equal(await replica.get(afterRole.sessionId),null); assert.equal(await login(),null);
});

test('OIDC provisioning and device revoke roll back when audit fails; concurrent login cannot evade revoke', async t => {
  const {pool} = await isolatedPostgres(t);
  const store = new PostgresSessionStore(pool,[],{oidcOnly:true});
  const input={username:'alice',issuer:'https://idp.example',subject:'subject',access:{role:'auditor' as const},resourcePolicy:policy};
  await pool.query(`CREATE FUNCTION fail_identity_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic audit failure'; END $$;
    CREATE TRIGGER fail_identity_audit BEFORE INSERT ON demo_admin_access_event FOR EACH ROW EXECUTE FUNCTION fail_identity_audit()`);
  await assert.rejects(store.provisionOidcAccount(input,'maintainer'));
  assert.equal((await pool.query('SELECT count(*) FROM demo_admin_account')).rows[0].count,'0');
  await pool.query('ALTER TABLE demo_admin_access_event DISABLE TRIGGER fail_identity_audit');
  await store.provisionOidcAccount(input,'maintainer'); await store.enrollDevice('alice','device','maintainer');
  await assert.rejects(pool.query("UPDATE demo_admin_account SET oidc_subject=NULL WHERE username='alice'"), /oidc_identity_binding/);
  await assert.rejects(pool.query(`INSERT INTO demo_admin_session(token_hash,username,access_revision,csrf_token,expires_at,auth_method,device_id,device_revision)
    VALUES(decode(repeat('aa',32),'hex'),'alice',1,'csrf',clock_timestamp()+interval '1 minute','oidc','device',NULL)`), /session_device_binding/);

  const identity={issuer:input.issuer,subject:input.subject,deviceId:'device',expiresAt:Date.now()+60000};
  const session=(await store.loginOidc(identity))!;
  await pool.query('ALTER TABLE demo_admin_access_event ENABLE TRIGGER fail_identity_audit');
  await assert.rejects(store.revokeDevice('device','maintainer'));
  assert.ok(await store.get(session.sessionId));
  await pool.query('ALTER TABLE demo_admin_access_event DISABLE TRIGGER fail_identity_audit');
  const [racing]=await Promise.all([store.loginOidc(identity),store.revokeDevice('device','maintainer')]);
  if (racing) assert.equal(await store.get(racing.sessionId),null);
  assert.equal(await store.loginOidc(identity),null);
  assert.equal(await store.loginOidc({...identity,expiresAt:Date.now()-1}),null);
});

test('authenticated access delegation rejects self elevation, foreign scopes, critical roles and stale revisions atomically', async t => {
  const {pool} = await isolatedPostgres(t);
  const store = new PostgresSessionStore(pool,[],{oidcOnly:true});
  const provision = async (username:string, role:'identity_admin'|'registry_worker'|'chief_admin', registryIds=['gov.registry.land']) => {
    await store.provisionOidcAccount({username,issuer:'https://idp.example',subject:username,access:{role,registryIds},resourcePolicy:{version:1,grants:[]}},'bootstrap');
    await store.enrollDevice(username,username+'-device','bootstrap');
    return (await store.loginOidc({issuer:'https://idp.example',subject:username,deviceId:username+'-device',expiresAt:Date.now()+60000}))!;
  };
  const admin=await provision('admin','identity_admin');
  const worker=await provision('worker','registry_worker');
  const routeContext={pool,sessions:store,oidc:{browserOrigin:'https://desktop.example'}} as unknown as AdminContext;
  const request:AdminRequest={method:'PATCH',path:'/v2/admin/accounts/worker/access',query:new URLSearchParams(),
    body:{role:'registry_approver',expectedRevision:'1'},cookieHeader:`onelayer_admin_session=${admin.sessionId}`,
    csrfHeader:admin.csrfToken,originHeader:'https://desktop.example',idempotencyKey:undefined};
  assert.equal((await routeAdmin(routeContext,{...request,csrfHeader:undefined})).status,403);
  assert.equal((await routeAdmin(routeContext,{...request,originHeader:'https://hostile.example'})).status,403);
  assert.equal((await routeAdmin(routeContext,{...request,body:{...request.body,actor:'chief'}})).status,400);
  await provision('foreign','registry_worker',['foreign.registry']);
  await provision('chief','chief_admin');
  const change=(username:string,role:any='registry_approver',revision='1',registryIds?:string[])=>store.changeAccessAsSession(admin.sessionId,username,{role,registryIds},revision);
  await assert.rejects(change('admin'),/SELF_ACCESS_CHANGE_FORBIDDEN/);
  await assert.rejects(change('foreign'),/ACCOUNT_NOT_FOUND/);
  await assert.rejects(change('absent'),/ACCOUNT_NOT_FOUND/);
  await assert.rejects(change('chief'),/ACCOUNT_NOT_FOUND/);
  await assert.rejects(change('worker','identity_admin'),/ROLE_ASSIGNMENT_FORBIDDEN/);
  await assert.rejects(change('worker','registry_worker','1',['foreign.registry']),/PERMISSION_FORBIDDEN/);
  await assert.rejects(change('worker','registry_worker','2'),/ACCESS_REVISION_CONFLICT/);
  await assert.rejects(store.changeAccessAsSession(worker.sessionId,'admin',{role:'registry_worker'},'1'),/PERMISSION_FORBIDDEN/);
  assert.ok(await store.get(worker.sessionId));
  await pool.query(`CREATE FUNCTION fail_delegate_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic'; END $$;
    CREATE TRIGGER fail_delegate_audit BEFORE INSERT ON demo_admin_access_event FOR EACH ROW EXECUTE FUNCTION fail_delegate_audit()`);
  await assert.rejects(change('worker'),/IDENTITY_UNAVAILABLE/);
  assert.ok(await store.get(worker.sessionId));
  await pool.query('DROP TRIGGER fail_delegate_audit ON demo_admin_access_event');
  assert.equal((await routeAdmin(routeContext,request)).status,204);
  assert.equal(await store.get(worker.sessionId),null);
  assert.equal((await pool.query("SELECT role FROM demo_admin_account WHERE username='worker'")).rows[0].role,'registry_approver');
  assert.equal((await pool.query("SELECT actor FROM demo_admin_access_event WHERE action='ACCESS_CHANGED'")).rows[0].actor,'admin');
  await assert.rejects(change('worker'),/ACCESS_REVISION_CONFLICT/);
  await store.revokeDevice('admin-device','bootstrap');
  await assert.rejects(change('worker','registry_worker','2'),/SESSION_REQUIRED/);
});
