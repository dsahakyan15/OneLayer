// H5 unit coverage for the independent approval receipt: issue/verify roundtrip
// and the tamper matrix (binding swaps, identity, expiry, wrong key, domain).
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  PublicationApprovalIssuer,
  PublicationApprovalError,
  publicationApprovalReceiptHash,
  verifyPublicationApproval,
  type PublicationApprovalClaims,
  type PublicationApprovalExpectation,
} from "../src/publication-approval.ts";
import { ensureKeyPair } from "../scripts/live-demo-key-store.ts";

const CLUSTER = "solana:synthetic";
const GENESIS = "1".repeat(32);
const OPERATION = "22222222-2222-2222-2222-222222222222";
const INTENT = "ab".repeat(32);
const PLAN = "cd".repeat(32);
const NOW = () => new Date("2026-10-07T00:00:00Z");

async function issuer(home: string, name: string, now = NOW) {
  const keyFile = join(home, ".local", "state", "onelayer-devnet-demo", "keys", name);
  await ensureKeyPair({ home, keyFile });
  return PublicationApprovalIssuer.create(keyFile, { cluster: CLUSTER, genesisHash: GENESIS, now }, { home });
}

const code = (value: string) => (error: unknown) => error instanceof PublicationApprovalError && error.code === value;

test("approval receipt roundtrips and every swapped field is refused", async () => {
  const home = await mkdtemp(join(tmpdir(), "onelayer-approval-"));
  try {
    const approvals = await issuer(home, "approval-issuer.json");
    const binding = { operationId: OPERATION, intentHash: INTENT, attemptPlanHash: PLAN };
    const receipt = approvals.issue(binding, "alice", "device-1");
    const expected: PublicationApprovalExpectation = {
      ...binding, approvalPublicKey: approvals.publicKey, cluster: CLUSTER, genesisHash: GENESIS, now: NOW,
    };
    const claims = verifyPublicationApproval(receipt, expected);
    assert.equal(claims.receiptId, receipt.claims.receiptId);
    assert.equal(claims.actor, "alice");
    assert.match(publicationApprovalReceiptHash(receipt), /^[0-9a-f]{64}$/);
    assert.notEqual(publicationApprovalReceiptHash(receipt), publicationApprovalReceiptHash({ ...receipt, signature: Buffer.alloc(64).toString("base64") }));

    // Binding swaps: a receipt cannot authorize a different operation/intent/plan.
    assert.throws(() => verifyPublicationApproval(receipt, { ...expected, operationId: "33333333-3333-3333-3333-333333333333" }), code("PUBLICATION_APPROVAL_MISMATCH"));
    assert.throws(() => verifyPublicationApproval(receipt, { ...expected, intentHash: "ee".repeat(32) }), code("PUBLICATION_APPROVAL_MISMATCH"));
    assert.throws(() => verifyPublicationApproval(receipt, { ...expected, attemptPlanHash: "ff".repeat(32) }), code("PUBLICATION_APPROVAL_MISMATCH"));
    // Identity swaps.
    assert.throws(() => verifyPublicationApproval(receipt, { ...expected, cluster: "solana:devnet" }), code("PUBLICATION_APPROVAL_IDENTITY"));
    assert.throws(() => verifyPublicationApproval(receipt, { ...expected, genesisHash: "2".repeat(32) }), code("PUBLICATION_APPROVAL_IDENTITY"));
    // Wrong issuer key: a self-minted receipt from a different key is refused.
    const other = await issuer(home, "other-issuer.json");
    assert.throws(() => verifyPublicationApproval(other.issue(binding, "alice", "device-1"), expected), code("PUBLICATION_APPROVAL_SIGNATURE"));
    // A tampered signature is refused.
    assert.throws(() => verifyPublicationApproval({ ...receipt, signature: Buffer.alloc(64, 7).toString("base64") }, expected), code("PUBLICATION_APPROVAL_SIGNATURE"));
    // Domain/version are part of the signed claims.
    const claimsClone: PublicationApprovalClaims = { ...receipt.claims, version: 1, domain: receipt.claims.domain };
    assert.throws(() => verifyPublicationApproval({ claims: { ...claimsClone, domain: "ONELAYER:OTHER:V1" }, signature: receipt.signature }, expected), code("PUBLICATION_APPROVAL_INVALID"));
    // Expiry and not-yet-valid.
    assert.throws(() => verifyPublicationApproval(receipt, { ...expected, now: () => new Date("2026-10-07T01:00:00Z") }), code("PUBLICATION_APPROVAL_EXPIRED"));
    assert.throws(() => verifyPublicationApproval(receipt, { ...expected, now: () => new Date("2026-10-06T00:00:00Z") }), code("PUBLICATION_APPROVAL_NOT_YET_VALID"));
    // Missing/blank identity at issuance is refused.
    assert.throws(() => approvals.issue(binding, "", "device-1"), code("PUBLICATION_APPROVAL_ACTOR_REQUIRED"));
    assert.throws(() => approvals.issue(binding, "alice", ""), code("PUBLICATION_APPROVAL_ACTOR_REQUIRED"));
    // A malformed binding is refused.
    assert.throws(() => approvals.issue({ ...binding, operationId: "nope" }, "alice", "device-1"), code("PUBLICATION_APPROVAL_INVALID"));
  } finally {
    await rm(home, { recursive: true, force: true });
  }
});
