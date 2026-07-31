const FINALIZED_HEAD_SAFETY_SLOTS = 32n;

interface JsonRpcResponse {
  result?: unknown;
  error?: { message?: unknown };
}

export async function safeIndexedThroughSlot(
  rpcUrl: string,
  anchorSlot: bigint,
  fetchImpl: typeof fetch = fetch,
): Promise<bigint> {
  const response = await fetchImpl(rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "getSlot", params: [{ commitment: "finalized" }] }),
  });
  if (!response.ok) throw new Error(`finalized slot RPC failed with HTTP ${response.status}`);
  const payload = await response.json() as JsonRpcResponse;
  if (payload.error !== undefined) throw new Error(`finalized slot RPC failed: ${String(payload.error.message ?? "unknown error")}`);
  if (typeof payload.result !== "number" || !Number.isSafeInteger(payload.result) || payload.result < 0) {
    throw new TypeError("finalized slot RPC result is invalid");
  }
  const finalizedHead = BigInt(payload.result);
  const safeHead = finalizedHead > FINALIZED_HEAD_SAFETY_SLOTS
    ? finalizedHead - FINALIZED_HEAD_SAFETY_SLOTS
    : 0n;
  return safeHead > anchorSlot ? safeHead : anchorSlot;
}
