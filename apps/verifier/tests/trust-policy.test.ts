import assert from "node:assert/strict";
import test from "node:test";
import { parseTrustPolicy } from "../src/trust-policy.ts";

const policy = {
  version: 1, revision: 3, validUntil: "2099-01-01T00:00:00Z", genesisHash: "synthetic-genesis",
  registryId: "synthetic", programIdHex: "01".repeat(32), configPdaHex: "02".repeat(32), schemaVersions: [1], registryVersions: ["1"],
  issuers: [{ keyId: "synthetic", publicKeyHex: "03".repeat(32), algorithm: "Ed25519", validFrom: "2020-01-01T00:00:00Z", validUntil: "2099-01-01T00:00:00Z", revoked: false }],
};

test("deployment revision floor rejects older policy; accepted policy is detached from input", () => {
  assert.throws(() => parseTrustPolicy(policy, 4), /revision/);
  assert.throws(() => parseTrustPolicy(policy, 0), /revision/);
  const parsed = parseTrustPolicy(policy, 3);
  parsed.issuers[0].revoked = true;
  assert.equal(policy.issuers[0].revoked, false);
});

test("strict policy parser rejects ambiguity and malformed trust material", () => {
  for (const mutation of [
    { version: 2 }, { registryVersions: ["01"] }, { schemaVersions: [2] }, { revision: 0 },
    { extraField: true }, { programIdHex: "01" }, { validUntil: "2099-02-30T00:00:00Z" },
    { issuers: [] }, { issuers: [policy.issuers[0], policy.issuers[0]] },
    { issuers: [{ ...policy.issuers[0], algorithm: "RSA" }] },
    { issuers: [{ ...policy.issuers[0], revoked: "false" }] },
  ]) assert.throws(() => parseTrustPolicy({ ...policy, ...mutation }, 1));
});

test('initial unsigned registry version zero is trustable without accepting ambiguous or negative values', () => {
  assert.deepEqual(parseTrustPolicy({...policy,registryVersions:['0']},3).registryVersions,['0']);
  for (const value of ['00','-1','+0','0.0','18446744073709551616']) {
    assert.throws(()=>parseTrustPolicy({...policy,registryVersions:[value]},3),/registry versions/);
  }
});
