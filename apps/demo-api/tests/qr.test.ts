import assert from "node:assert/strict";
import test from "node:test";
import { qrHashHex } from "../src/qr.ts";
import { workingRegistryStatus } from "../src/registry-status.ts";

test("QR hash accepts canonical unpadded base64url and returns hex", () => {
  const hash = Buffer.from("3ab6aeb37e85a952dd817cb66b881753928ce176e037c571a4560f09ee726b0e", "hex");
  assert.equal(qrHashHex(hash.toString("base64url")), hash.toString("hex"));
});

test("QR hash rejects padded, short, and non-base64url values", () => {
  assert.equal(qrHashHex(`${Buffer.alloc(32).toString("base64url")}=`), null);
  assert.equal(qrHashHex(Buffer.alloc(31).toString("base64url")), null);
  assert.equal(qrHashHex("not/a/qr/hash"), null);
});

test("QR policy allows only an unpaused registry", async () => {
  const reader = { async getRegistryConfig() { return { paused: false }; } };
  assert.equal(await workingRegistryStatus(reader, "config"), "WORKING");
});

test("QR policy rejects a paused or unavailable registry", async () => {
  const paused = { async getRegistryConfig() { return { paused: true }; } };
  const unavailable = { async getRegistryConfig() { throw new Error("RPC unavailable"); } };
  assert.equal(await workingRegistryStatus(paused, "config"), "PAUSED");
  assert.equal(await workingRegistryStatus(unavailable, "config"), "UNAVAILABLE");
});
