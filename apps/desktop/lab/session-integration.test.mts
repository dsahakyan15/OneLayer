import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { mkdtemp, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { isolatedPostgres } from '../../demo-api/integration/support/postgres.ts';
import { startTestIdp } from '../../demo-api/integration/support/test-idp.ts';
import { PostgresSessionStore } from '../../demo-api/src/postgres-session.ts';
import { OidcClient } from '../../demo-api/src/oidc.ts';
import { routeAdmin, type AdminContext } from '../../demo-api/src/admin.ts';

test('installed native lab uses real IdP/backend/PostgreSQL and shows logout, revocation and offline states', {timeout: 60_000}, async t => {
  const {pool} = await isolatedPostgres(t);
  const idp = await startTestIdp(); t.after(() => idp.close());
  const sessions = new PostgresSessionStore(pool, [], {oidcOnly: true});
  await sessions.provisionOidcAccount({username:'native-lab-user',issuer:idp.issuer,subject:'test-user',
    access:{role:'registry_worker',registryIds:['gov.registry.land']},resourcePolicy:{version:1,grants:[]}},'synthetic-harness');
  await sessions.enrollDevice('native-lab-user','test-device','synthetic-harness');
  let context: AdminContext;
  const server = createServer(async (req,res) => {
    try {
      const url = new URL(req.url!, 'http://localhost');
      const result = await routeAdmin(context, {method:req.method!,path:url.pathname,query:url.searchParams,
        body:null,cookieHeader:req.headers.cookie,csrfHeader:req.headers['x-onelayer-csrf'] as string|undefined,
        originHeader:req.headers.origin,idempotencyKey:undefined});
      if(result.setCookie) res.setHeader('set-cookie',result.setCookie);
      if(result.location) res.setHeader('location',result.location);
      res.writeHead(result.status, {'content-type':'application/json','cache-control':'no-store'});
      res.end(result.status===204 ? undefined : JSON.stringify(result.body));
    } catch {res.writeHead(500); res.end();}
  });
  await new Promise<void>(resolve => server.listen(0,'127.0.0.1',resolve));
  const close = async () => {server.closeAllConnections(); if(server.listening) await new Promise<void>(resolve => server.close(() => resolve()));};
  t.after(close);
  const address=server.address(); assert.ok(address && typeof address!=='string');
  const origin=`http://127.0.0.1:${address.port}`;
  context={pool,sessions,registryId:'gov.registry.land',oidc:{client:new OidcClient(idp.config(`${origin}/v2/admin/oidc/callback`)),
    login:identity=>sessions.loginOidc(identity),browserOrigin:origin,secureCookies:false}} as AdminContext;
  const directory=await mkdtemp(join(tmpdir(),'onelayer-native-session-')); t.after(()=>rm(directory,{recursive:true,force:true}));
  const prefix=join(directory,'installed lab');
  await promisify(execFile)('/usr/bin/python3',[fileURLToPath(new URL('./install.py',import.meta.url)),prefix]);
  const screenshot=process.env.ONELAYER_NATIVE_LAB_SCREENSHOT ?? join(directory,'authenticated.png');
  const child=spawn(join(prefix,'bin/onelayer-desktop-lab'),['--lab-backend',origin,'--lab-issuer',idp.issuer,
    '--integration-smoke','--screenshot',screenshot],{stdio:['pipe','pipe','pipe']});
  let stderr=''; child.stderr.on('data', chunk=>{stderr+=String(chunk);});
  t.after(()=>{child.kill();});
  const lines=createInterface({input:child.stdout})[Symbol.asyncIterator]();
  const next=async(state:string) => {
    for (;;) {
      let timer: NodeJS.Timeout | undefined;
      const line=await Promise.race([lines.next(),new Promise<never>((_,reject)=>{
        timer=setTimeout(()=>reject(new Error(`Native state timeout: ${state}; ${stderr}`)),10_000);
      })]).finally(()=>clearTimeout(timer));
      assert.equal(line.done,false,`Native exited early: ${stderr}`);
      const event=JSON.parse(line.value!);
      if(event.state==='loading') continue;
      assert.equal(event.state,state);
      assert.deepEqual(Object.keys(event).sort(),['state','summary','synthetic']);
      if(event.summary) assert.deepEqual(event.summary,{username:'native-lab-user',role:'registry_worker'});
      return event;
    }
  };
  const command=async(value:string,state:string)=>{child.stdin.write(value+'\n');return next(state);};
  await next('signed-out');
  await command('login','authenticated');
  assert.ok((await stat(screenshot)).size>1000);
  assert.equal((await pool.query('SELECT count(*) FROM demo_admin_session')).rows[0].count,'1');
  await command('refresh','authenticated');
  await command('logout','signed-out');
  assert.equal((await pool.query('SELECT count(*) FROM demo_admin_session')).rows[0].count,'0');
  await command('refresh','expired');
  await command('login','authenticated');
  await sessions.revokeDevice('test-device','synthetic-harness');
  await command('refresh','expired');
  await command('login','expired');
  await close();
  await command('refresh','offline');
  const exit = new Promise<number|null>(resolve=>child.once('exit',resolve));
  child.stdin.write('close\n');
  assert.equal(await exit,0);
  assert.equal(stderr,'');
});
