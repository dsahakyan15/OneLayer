import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test from "node:test";
import { parseTrustPolicy } from "../src/trust-policy.ts";

const exec = promisify(execFile);
test("demo provisioning pins configured issuer and never silently rotates existing trust", async context => {
  const dir = await mkdtemp(join(tmpdir(), "onelayer-policy-"));
  context.after(() => rm(dir, { recursive: true, force: true }));
  const issuerFile = join(dir, "synthetic-issuer");
  await mkdir(join(dir, "policy"), { mode: 0o700 });
  const policyFile = join(dir, "policy", "policy.json");
  const stateFile = join(dir, "verifier-state", "accepted.json");
  await writeFile(issuerFile, "09".repeat(32));
  const run = () => exec(process.execPath, ["--experimental-transform-types", fileURLToPath(new URL("../scripts/create-demo-trust-policy.ts", import.meta.url)), issuerFile, policyFile, stateFile]);
  await run();
  const original = await readFile(policyFile, "utf8");
  const policy = parseTrustPolicy(JSON.parse(original), 1);
  assert.equal(policy.genesisHash, "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG");
  assert.equal(policy.issuers[0].keyId, "synthetic-demo-issuer-1");
  assert.ok(Date.parse(policy.validUntil) > Date.now());
  assert.doesNotMatch(original, new RegExp("09".repeat(32)));
  assert.equal(JSON.parse(await readFile(stateFile, "utf8")).revision, 1, "provisioning bootstraps the anti-rollback watermark");
  assert.equal((await stat(join(dir, "verifier-state"))).mode & 0o777, 0o700, "state lives in its own private directory");
  await run();
  assert.equal(await readFile(policyFile, "utf8"), original);
  // Bootstrap is one-time: a vanished watermark is not recreated for a retained policy.
  await rename(stateFile, `${stateFile}.lost`);
  await assert.rejects(run(), /watermark .* is missing .*fail-closed/);
  await assert.rejects(stat(stateFile), { code: "ENOENT" });
  assert.equal(await readFile(policyFile, "utf8"), original);
  await rename(`${stateFile}.lost`, stateFile); // documented recovery: restore the watermark
  await run();
  await writeFile(issuerFile, "0a".repeat(32));
  await assert.rejects(run(), /not authorize.*not overwritten/);
  assert.equal(await readFile(policyFile, "utf8"), original);
  await writeFile(issuerFile, "09".repeat(32));
  const expired = JSON.stringify({ ...policy, validUntil: "2020-01-01T00:00:00Z" });
  await writeFile(policyFile, expired);
  await assert.rejects(run(), /expired/);
  assert.equal(await readFile(policyFile, "utf8"), expired);
  // Documented rotation step: move the expired policy aside and provision again.
  await rename(policyFile, `${policyFile}.expired`);
  await run();
  const rotated = parseTrustPolicy(JSON.parse(await readFile(policyFile, "utf8")), 1);
  assert.equal(rotated.revision, 2, "rotation continues from the accepted watermark");
  assert.equal(JSON.parse(await readFile(stateFile, "utf8")).revision, 2);
});
