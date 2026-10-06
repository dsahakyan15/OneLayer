// Test-only preload, before the API captures fetch in its RPC adapter.
// Long-running integration processes must never dispatch public-chain traffic.
const originalFetch = globalThis.fetch;
globalThis.fetch = async (input, init) => {
  const url = new URL(typeof input === "string" || input instanceof URL ? input : input.url);
  if (url.protocol !== "http:" || url.hostname !== "127.0.0.1") {
    throw new Error("synthetic harness refuses non-loopback fetch");
  }
  return originalFetch(input, { ...init, redirect: "error" });
};
let refused = false;
try { await fetch("https://api.devnet.solana.com"); }
catch (error) { refused = error.message === "synthetic harness refuses non-loopback fetch"; }
if (!refused) throw new Error("synthetic outbound guard failed");
process.stdout.write("synthetic outbound guard ready\n");
