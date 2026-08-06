import { HttpIncidentIndex, HttpLifecycleIndex, HttpPublicLookup } from "./http-adapters.ts";
import { createVerifierServer } from "./server.ts";
import { SolanaRpcChainReader } from "./solana-rpc.ts";

function required(name: string): string {
  const value = process.env[name];
  if (value === undefined || value.length === 0) throw new Error(`${name} is required`);
  return value;
}

const port = Number(process.env.PORT ?? "8080");
if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error("PORT is invalid");
const maxIndexLagSlots = BigInt(process.env.ONELAYER_MAX_INDEX_LAG_SLOTS ?? "300");
if (maxIndexLagSlots < 0n) throw new Error("ONELAYER_MAX_INDEX_LAG_SLOTS is invalid");
const chain = new SolanaRpcChainReader(required("ONELAYER_RPC_URL"));

const server = createVerifierServer({
  chain,
  incidents: new HttpIncidentIndex(required("ONELAYER_INCIDENT_INDEX_URL")),
  lookup: new HttpPublicLookup(required("ONELAYER_LOOKUP_URL")),
  corsAllowedOrigin: process.env.ONELAYER_CORS_ALLOWED_ORIGIN,
  verifyOptions: {
    maxIndexLagSlots,
    lifecycle: new HttpLifecycleIndex(required("ONELAYER_LOOKUP_URL")),
  },
});

server.listen(port, "0.0.0.0", () => {
  process.stdout.write(`verifier listening on 0.0.0.0:${port}\n`);
});
