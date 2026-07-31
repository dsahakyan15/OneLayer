import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { ANCHOR_ENTRY_SIZE, SEGMENT_ACCOUNT_SIZE, SEGMENT_HEADER_SIZE } from "../../verifier/src/solana-account.ts";
import { SolanaAnchorSource } from "../src/solana-source.ts";

function fixture(): Uint8Array {
  const bytes = new Uint8Array(SEGMENT_ACCOUNT_SIZE);
  bytes.set(createHash("sha256").update("account:DailyAnchorLedgerSegment").digest().subarray(0, 8));
  const view = new DataView(bytes.buffer);
  view.setUint8(8, 1);
  view.setUint16(8 + 42, 1, true);
  view.setUint16(8 + 44, 46, true);
  const entry = 8 + SEGMENT_HEADER_SIZE;
  view.setBigUint64(entry, 7n, true);
  view.setBigUint64(entry + 8, 9n, true);
  bytes.fill(3, entry + 32, entry + 64);
  bytes.fill(4, entry + 64, entry + 96);
  assert.equal(entry + ANCHOR_ENTRY_SIZE <= bytes.length, true);
  return bytes;
}

test("monitor reads finalized anchor account and transaction directly from Solana RPC", async () => {
  const methods: string[] = [];
  const request = async (_input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const body = JSON.parse(String(init?.body));
    methods.push(body.method);
    const result = body.method === "getAccountInfo"
      ? { context: { slot: 1_050 }, value: { owner: "program-id", data: [Buffer.from(fixture()).toString("base64"), "base64"] } }
      : { slot: 1_000, meta: { err: null } };
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, result }));
  };
  const source = new SolanaAnchorSource("https://rpc.invalid", request);
  const observed = await source.getAnchor({ programId: "program-id", segmentPda: "segment-pda", batchSequence: 7n, transactionSignature: "signature", anchorSlot: 1_000n });
  assert.equal(observed.registryVersion, 9n);
  assert.deepEqual(Buffer.from(observed.merkleRoot), Buffer.alloc(32, 3));
  assert.deepEqual(methods, ["getAccountInfo", "getTransaction"]);
});
