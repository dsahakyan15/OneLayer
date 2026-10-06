import assert from "node:assert/strict";
import { test } from "node:test";
import { SolanaIncidentRpc } from "../src/solana-rpc.ts";

function rpcFixture(handler: (method: string, params: any[]) => unknown) {
  return new SolanaIncidentRpc("https://synthetic.invalid", (async (_url, init) => {
    const { method, params } = JSON.parse(String(init?.body));
    return new Response(JSON.stringify({ result: handler(method, params) }), { status: 200 });
  }) as typeof fetch);
}

test("signature pagination includes incidents older than 100 and 200 signatures", async () => {
  const entries = Array.from({ length: 205 }, (_, i) => ({ signature: `sig-${205 - i}`, slot: 205 - i }));
  const requested: unknown[] = [];
  const rpc = rpcFixture((_method, params) => {
    const options = params[1];
    requested.push(options);
    const start = options.before ? entries.findIndex((e) => e.signature === options.before) + 1 : 0;
    return entries.slice(start, start + options.limit);
  });
  const result = await rpc.getSignaturesForAddress("registry", "sig-1");
  assert.equal(result.length, 204);
  assert.equal(result.at(-1)?.signature, "sig-2");
  assert.equal(requested.length, 3);
});

test("missing historical cursor rejects incomplete/pruned pagination", async () => {
  const rpc = rpcFixture((_method, params) => params[1].before ? [] : [{ signature: "new", slot: 10 }]);
  await assert.rejects(() => rpc.getSignaturesForAddress("registry", "missing-old"), /cursor.*unavailable/);
});

test("repeated page is rejected instead of looping or marking complete", async () => {
  const rpc = rpcFixture(() => [{ signature: "repeated", slot: 10 }]);
  await assert.rejects(() => rpc.getSignaturesForAddress("registry", null), /did not advance/);
});

test("short page is followed to exhaustion during initial scan", async () => {
  let requests = 0;
  const rpc = rpcFixture(() => ++requests === 1 ? [{ signature: "first", slot: 10 }] : []);
  assert.equal((await rpc.getSignaturesForAddress("registry", null)).length, 1);
  assert.equal(requests, 2);
});

test("missing transaction metadata or logs cannot look like no incidents", async () => {
  for (const result of [{ slot: 10 }, { slot: 10, meta: { err: null, logMessages: null } }]) {
    const rpc = rpcFixture(() => result);
    await assert.rejects(() => rpc.getTransactionLogs("signature"), /metadata|logs/);
  }
});

// Wire-layout fixtures keep the account validation tests independent of encoders.
import { address, getAddressEncoder } from "@solana/kit";
import { findIncidentNoticePda, findRegistryConfigPda, REGISTRY_CONFIG_DISCRIMINATOR, INCIDENT_NOTICE_DISCRIMINATOR } from "../../../packages/onchain-client/src/index.ts";
import { registryIdHash } from "../../../packages/canonical-ts/src/index.ts";

test("finalized incident accounts bind owner, identity, PDA, sequence and freshness", async () => {
  const programId = address("6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo");
  const hash = registryIdHash("gov.registry.land");
  const [configAddress] = await findRegistryConfigPda(hash, { programAddress: programId });
  const [noticeAddress, bump] = await findIncidentNoticePda({ config: configAddress, incidentSequence: 0n }, { programAddress: programId });
  const configBytes = new Uint8Array(getAddressEncoder().encode(configAddress));
  const registry = { registryId: "gov.registry.land", programId, configAddress, configBytes };
  const config = Buffer.alloc(277);
  config.set(REGISTRY_CONFIG_DISCRIMINATOR); config[8] = 1; config.set(hash, 10);
  config.writeBigUInt64LE(1n, 154);
  const notice = Buffer.alloc(181);
  notice.set(INCIDENT_NOTICE_DISCRIMINATOR); notice[8] = 1; notice[9] = bump;
  notice.set(configBytes, 10); notice.writeBigUInt64LE(1n, 50); notice.writeBigUInt64LE(9n, 58);
  notice.writeUInt16LE(3, 66); notice[68] = 2;
  const account = (bytes: Buffer, owner = programId as string) => ({ owner, data: [bytes.toString("base64"), "base64"] });
  const run = (change: (method: string, result: any) => void = () => {}) => rpcFixture((method, params) => {
    assert.equal(params[1].commitment, "finalized");
    assert.equal(params[1].minContextSlot, 1000);
    const result = method === "getAccountInfo" ? { context: { slot: 1000 }, value: account(config) } : { context: { slot: 1000 }, value: [account(notice)] };
    if (method === "getMultipleAccounts") assert.deepEqual(params[0], [noticeAddress]);
    change(method, result);
    return result;
  }).getIncidentSnapshot(registry, 1000n);
  assert.deepEqual(await run(), { incidentCount: 1n, notices: [{ incidentSequence: 0n, firstSuspectBatch: 1n, lastSuspectBatch: 9n, incidentType: 3, status: "CONFIRMED" }] });
  notice.writeBigUInt64LE(0n, 50);
  assert.equal((await run()).notices[0].firstSuspectBatch, 0n);
  notice.writeBigUInt64LE(1n, 50);
  for (const target of ["getAccountInfo", "getMultipleAccounts"]) {
    await assert.rejects(run((method, result) => { if (method === target) result.context.slot = 999; }), /stale/);
    await assert.rejects(run((method, result) => {
      if (method === target) (Array.isArray(result.value) ? result.value[0] : result.value).owner = "foreign";
    }), /owner/);
  }
  await assert.rejects(run((method, result) => { if (method === "getMultipleAccounts") result.value = [null]; }), /owner/);
  for (const offset of [0, 8, 9, 10, 42, 50, 68]) {
    await assert.rejects(run((method, result) => {
      if (method === "getMultipleAccounts") {
        const altered = Buffer.from(notice); altered[offset] ^= 255;
        result.value = [account(altered)];
      }
    }), /binding|discriminator/);
  }
});

test("every RPC request of a full refresh is pinned to finalized commitment and the observed head", async () => {
  const { refreshIncidentIndex } = await import("../src/incident-index.ts");
  const { eventDiscriminator } = await import("../src/incident-events.ts");
  const programId = address("6A2LSwaJKdwVAEggAfHjZVAKb2ATWM7AXBrgDEqczEo");
  const hash = registryIdHash("gov.registry.land");
  const [configAddress] = await findRegistryConfigPda(hash, { programAddress: programId });
  const [, bump] = await findIncidentNoticePda({ config: configAddress, incidentSequence: 0n }, { programAddress: programId });
  const configBytes = new Uint8Array(getAddressEncoder().encode(configAddress));
  const config = Buffer.alloc(277);
  config.set(REGISTRY_CONFIG_DISCRIMINATOR); config[8] = 1; config.set(hash, 10); config.writeBigUInt64LE(1n, 154);
  const notice = Buffer.alloc(181);
  notice.set(INCIDENT_NOTICE_DISCRIMINATOR); notice[8] = 1; notice[9] = bump;
  notice.set(configBytes, 10); notice.writeBigUInt64LE(1n, 50); notice.writeBigUInt64LE(9n, 58);
  notice.writeUInt16LE(3, 66); notice[68] = 1;
  const event = Buffer.alloc(98);
  event.set(eventDiscriminator("IncidentOpened")); event.set(configBytes, 8);
  event.writeBigUInt64LE(1n, 48); event.writeBigUInt64LE(9n, 56); event.writeUInt16LE(3, 64);
  const account = (bytes: Buffer) => ({ owner: programId, data: [bytes.toString("base64"), "base64"] });
  const HEAD = 1_000;
  const requests: Array<[string, any[]]> = [];
  const rpc = rpcFixture((method, params) => {
    requests.push([method, params]);
    switch (method) {
      case "getSlot": return HEAD;
      case "getSignaturesForAddress": return params[1].before ? [] : [{ signature: "sig-open", slot: 800 }];
      case "getTransaction": return { slot: 800, meta: { err: null, logMessages: [`Program ${programId} invoke [1]`, `Program data: ${event.toString("base64")}`, `Program ${programId} success`] } };
      case "getAccountInfo": return { context: { slot: HEAD }, value: account(config) };
      case "getMultipleAccounts": return { context: { slot: HEAD }, value: [account(notice)] };
      default: throw new Error(`unexpected ${method}`);
    }
  });
  const saved: unknown[] = [];
  const notices: any[] = [];
  const store: any = {
    transaction: (_id: string, action: (s: unknown) => Promise<unknown>) => action(store),
    loadState: async () => ({ indexedThroughSlot: 0n, lastSignature: null }),
    applyOpened: async (_id: string, n: unknown) => { notices.push(n); },
    applyResolved: async () => assert.fail("no resolution expected"),
    saveState: async (_id: string, state: unknown) => { saved.push(state); },
    listNotices: async () => notices,
  };
  const result = await refreshIncidentIndex({ registryId: "gov.registry.land", programId, configAddress, configBytes }, rpc, store);
  assert.deepEqual(saved, [{ indexedThroughSlot: 1000n, lastSignature: "sig-open" }]);
  assert.equal(result.indexedThroughSlot, 1000n, "watermark is exactly the finalized head read before the scan");
  assert.deepEqual(requests.map(([method]) => method), ["getSlot", "getSignaturesForAddress", "getSignaturesForAddress", "getTransaction", "getAccountInfo", "getMultipleAccounts"]);
  for (const [method, params] of requests) {
    const options = params.find((param: unknown) => typeof param === "object" && param !== null && !Array.isArray(param));
    assert.equal(options?.commitment, "finalized", `${method} must use finalized commitment`);
    if (method === "getAccountInfo" || method === "getMultipleAccounts") assert.equal(options.minContextSlot, HEAD, `${method} must be at least the observed head`);
  }
});
