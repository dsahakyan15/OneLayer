import assert from "node:assert/strict";
import test from "node:test";
import { safeIndexedThroughSlot } from "../src/solana-index.ts";

function rpc(result: unknown, status = 200): typeof fetch {
  return (async () => new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result }), {
    status,
    headers: { "content-type": "application/json" },
  })) as typeof fetch;
}

test("incident index watermark trails finalized head by a race-safe margin", async () => {
  assert.equal(await safeIndexedThroughSlot("https://api.devnet.solana.com", 1_000n, rpc(2_000)), 1_968n);
});

test("incident index watermark never predates the anchored batch", async () => {
  assert.equal(await safeIndexedThroughSlot("https://api.devnet.solana.com", 1_995n, rpc(2_000)), 1_995n);
});

test("incident index rejects malformed finalized slot responses", async () => {
  await assert.rejects(() => safeIndexedThroughSlot("https://api.devnet.solana.com", 1_000n, rpc("2000")), /invalid/);
});
