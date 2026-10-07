import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { readFile, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { join } from "node:path";
import test from "node:test";
import { isolatedPostgres } from "../../apps/demo-api/integration/support/postgres.ts";
import { startTestIdp } from "../../apps/demo-api/integration/support/test-idp.ts";
import { decodeCertificatePackage } from "../../apps/verifier/src/certificate-codec.ts";
import { createVerifierServer } from "../../apps/verifier/src/server.ts";
import { registryIdHash } from "../../packages/canonical-ts/src/index.ts";
import { ServicePrincipalStore } from "../../apps/demo-api/src/service-principal.ts";
import { HttpLifecycleIndex, HttpPublicLookup } from "../../apps/verifier/src/http-adapters.ts";

test("verifier adapters read scoped metadata from the real OIDC API and fail after revoke", { timeout: 90_000 }, async context => {
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
  // Installed before the RPC adapter captures fetch; periodic refresh remains
  // unable to dispatch public-chain traffic even on slow integration runs.
  const networkGuard = new URL("../helpers/local-network-only.mjs", import.meta.url).href;
  await Promise.all([
    writeFile(join(dir, "database"), connectionString),
    writeFile(join(dir, "issuer"), "09".repeat(32)),
    writeFile(join(dir, "oidc.json"), JSON.stringify(idp.config(`${origin}/v2/admin/oidc/callback`))),
  ]);
  await pool.query(await readFile(new URL("../../db/fixtures/devnet-demo.sql", import.meta.url), "utf8"));
  for (const registry of ["gov.registry.land", "other.registry"]) {
    await pool.query(`INSERT INTO demo_anchor
      (registry_id,batch_sequence,registry_version,merkle_root,manifest_hash,anchor_hash,
       program_id,segment_pda,transaction_signature,anchor_slot,commitment,finalized_at)
      VALUES ($1,1,1,decode(repeat('11',32),'hex'),decode(repeat('22',32),'hex'),
              decode(repeat('33',32),'hex'),'synthetic-program','synthetic-segment',
              'synthetic-signature',10,'finalized',now())`, [registry]);
  }
  const vectors = JSON.parse(await readFile(new URL("../../spec/vectors/certificate.json", import.meta.url), "utf8"));
  const vector = vectors.vectors.find((entry: any) => entry.expected.result === "VALID");
  const packageBytes = Buffer.from(vector.expected.certificate_package_cbor, "hex");
  const signed = decodeCertificatePackage(packageBytes);
  assert.equal(signed.body.registryId, "gov.registry.land");
  const localId = Buffer.from(signed.body.certificateId).toString("hex"), foreignId = "b".repeat(32);
  for (const [id, registry] of [[localId, "gov.registry.land"], [foreignId, "other.registry"]]) {
    await pool.query(`INSERT INTO demo_certificate
      (certificate_id,registry_id,batch_sequence,certificate_hash,package_base64url,qr_url,status,record_version,issued_at)
      VALUES ($1,$2,1,decode(repeat('44',32),'hex'),'c3ludGhldGlj',
              'http://127.0.0.1/synthetic-only','ACTIVE',$3,now())`, [id, registry, signed.body.recordVersion.toString()]);
  }
  const principals = new ServicePrincipalStore(pool);
  const serviceToken = await principals.provision("svc.verifier.e2e", {
    actions: ["certificates.read", "anchors.read"], registryIds: ["gov.registry.land"],
  }, "synthetic-harness", 1);
  const child = spawn(process.execPath, ["--import", networkGuard, "--experimental-transform-types", "src/main.ts"], {
    cwd: new URL("../../apps/demo-api/", import.meta.url),
    env: {
      ...process.env, PORT: String(port),
      ONELAYER_DATABASE_URL_FILE: join(dir, "database"), ONELAYER_ISSUER_SECRET_FILE: join(dir, "issuer"),
      ONELAYER_OIDC_CONFIG_FILE: join(dir, "oidc.json"), ONELAYER_SESSION_BACKEND: "postgres",
      ONELAYER_INTERNAL_AUTH: "service-principal", ONELAYER_RPC_URL: "https://api.devnet.solana.com",
      ONELAYER_VERIFIER_URL: "http://127.0.0.1:1", ONELAYER_PUBLIC_BASE_URL: origin,
      ONELAYER_PUBLIC_WEB_URL: "http://127.0.0.1:8091",
      ONELAYER_PROGRAM_ID: "6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo",
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
    let output = "";
    const diagnostic = () => output.replaceAll(serviceToken, "[redacted]");
    const timer = setTimeout(() => reject(new Error(`synthetic API startup timed out: ${diagnostic()}`)), 45_000);
    const onExit = () => { clearTimeout(timer); reject(new Error(`synthetic API exited before listening: ${diagnostic()}`)); };
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
  const lifecycle = new HttpLifecycleIndex(origin, { serviceToken });
  const lookup = new HttpPublicLookup(origin, { serviceToken });
  assert.deepEqual(await lifecycle.query("gov.registry.land", localId), {
    registryId: "gov.registry.land", certificateId: localId,
    certificateStatus: "ACTIVE", currentRecordVersion: signed.body.recordVersion,
  });
  const status = await lookup.getCertificateStatus(localId) as Record<string, unknown>;
  assert.equal(status.certificate_id, localId);
  assert.equal(status.status, "ACTIVE");
  const anchor = await lookup.getAnchor(1n) as Record<string, unknown>;
  assert.equal(anchor.registry_id, "gov.registry.land");
  assert.equal(anchor.anchor_slot, "10");
  assert.equal(await lookup.getCertificateStatus(foreignId), null);
  assert.equal(await lifecycle.query("gov.registry.land", foreignId), null);
  const exported = await fetch(`${origin}/v1/certificates/${localId}/package`, {
    headers: { authorization: `Bearer ${serviceToken}` },
  });
  assert.equal(exported.status, 401);
  await assert.rejects(new HttpPublicLookup(origin).getCertificateStatus(localId), /upstream HTTP 401/);
  // Real HTTP verifier + real API lifecycle transport, canonical signed
  // fixture, controlled ChainReader. This tests verdict/transport composition,
  // not an on-chain issuance flow or authenticated lifecycle completeness.
  const body = signed.body;
  const verifier = createVerifierServer({
    lookup,
    verifyOptions: { lifecycle, trustPolicy: {
      version: 1, revision: 1, validUntil: "2099-01-01T00:00:00Z",
      genesisHash: "synthetic-genesis", registryId: body.registryId,
      programIdHex: Buffer.from(body.anchor.solanaProgramId).toString("hex"),
      configPdaHex: "08".repeat(32), schemaVersions: [1],
      registryVersions: [body.anchor.registryVersion.toString()],
      issuers: [{ keyId: body.issuerKeyId, publicKeyHex: Buffer.from(body.issuerPublicKey).toString("hex"),
        algorithm: "Ed25519", validFrom: "2020-01-01T00:00:00Z", validUntil: "2099-01-01T00:00:00Z", revoked: false }],
    } },
    chain: {
      async getGenesisHash() { return "synthetic-genesis"; },
      async getRegistryConfig() { return { configPda: new Uint8Array(32).fill(8),
        programId: body.anchor.solanaProgramId, registryIdHash: registryIdHash(body.registryId), paused: false }; },
      async getAnchor() { return { registryConfigPda: new Uint8Array(32).fill(8),
        programId: body.anchor.solanaProgramId, segmentPda: body.anchor.segmentPda,
        derivedSegmentPda: body.anchor.segmentPda, batchSequence: body.anchor.batchSequence,
        registryVersion: body.anchor.registryVersion, merkleRoot: body.anchor.merkleRoot,
        manifestHash: body.anchor.manifestHash, transactionSignature: body.anchor.transactionSignature,
        slot: body.anchor.anchorSlot, commitment: "finalized" as const }; },
      async getFinalizedHeadSlot() { return body.anchor.anchorSlot + 10n; },
    },
    incidents: { async query(registryId) { return { registryId,
      indexedThroughSlot: body.anchor.anchorSlot + 5n, incidents: [] }; } },
  });
  await new Promise<void>(resolve => verifier.listen(0, "127.0.0.1", resolve));
  context.after(() => new Promise<void>((resolve, reject) => verifier.close(error => error ? reject(error) : resolve())));
  const verifierAddress = verifier.address();
  assert.ok(verifierAddress && typeof verifierAddress !== "string");
  const verify = async () => {
    const response = await fetch(`http://127.0.0.1:${verifierAddress.port}/v2/verify`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ certificatePackage: packageBytes.toString("base64url"), requiredCommitment: "finalized" }),
    });
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.equal(result.resultVersion, 2);
    assert.equal(result.proofs.status, "VERIFIED");
    assert.notEqual(result.status, "CURRENT");
    return result;
  };
  const advisoryActive = await verify();
  assert.equal(advisoryActive.status, "UNKNOWN");
  assert.equal(advisoryActive.lifecycle.status, "UNAUTHENTICATED");
  await pool.query("UPDATE demo_certificate SET status='REVOKED' WHERE certificate_id=$1", [localId]);
  assert.equal((await verify()).status, "REVOKED");
  await pool.query("UPDATE demo_certificate SET status='ACTIVE', record_version=$2 WHERE certificate_id=$1",
    [localId, (body.recordVersion + 1n).toString()]);
  assert.equal((await verify()).status, "HISTORICAL");
  await principals.revoke("svc.verifier.e2e", "synthetic-harness");
  await assert.rejects(lookup.getAnchor(1n), /upstream HTTP 401/);
  await assert.rejects(lifecycle.query("gov.registry.land", localId), /upstream HTTP 401/);
  const afterRevoke = await verify();
  assert.equal(afterRevoke.status, "UNKNOWN");
  assert.equal(afterRevoke.lifecycle.status, "UNKNOWN");
  assert.equal(afterRevoke.lifecycle.code, "LIFECYCLE_UNAVAILABLE");
  assert.equal(afterRevoke.lifecycle.reported, undefined);
});
