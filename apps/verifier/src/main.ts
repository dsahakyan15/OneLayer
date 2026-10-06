import { loadTrustPolicy, startTrustRefresh, trustOptionsFromEnv } from "./trust-state.ts";
import { HttpIncidentIndex, HttpLifecycleIndex, HttpPublicLookup } from "./http-adapters.ts";
import { createVerifierServer } from "./server.ts";
import { readServiceToken } from "./service-auth.ts";
import { SolanaRpcChainReader } from "./solana-rpc.ts";
import type { VerifyOptions } from "./verify.ts";

function required(name: string): string {
  const value = process.env[name];
  if (value === undefined || value.length === 0) throw new Error(`${name} is required`);
  return value;
}

// Optional scoped service tokens for the two upstream URLs. A configured file
// that is missing, unreadable, empty or malformed fails startup; there is no
// anonymous fallback for a configured credential. Unset variables keep the
// anonymous demo behaviour.
const lookupServiceToken = readServiceToken(process.env, "ONELAYER_LOOKUP_SERVICE_TOKEN_FILE");
const incidentServiceToken = readServiceToken(process.env, "ONELAYER_INCIDENT_SERVICE_TOKEN_FILE");

// Fails closed (process exits) on configuration ambiguity, unavailable, unsigned-when-required,
// foreign-deployment, expired, rolled-back or conflicting trust material, or unsafe/unusable state.
const trustOptions = trustOptionsFromEnv(process.env);
const { policy: trustPolicy } = await loadTrustPolicy(trustOptions);

const port = Number(process.env.PORT ?? "8080");
if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error("PORT is invalid");
const maxIndexLagSlots = BigInt(process.env.ONELAYER_MAX_INDEX_LAG_SLOTS ?? "300");
if (maxIndexLagSlots < 0n) throw new Error("ONELAYER_MAX_INDEX_LAG_SLOTS is invalid");
const chain = new SolanaRpcChainReader(required("ONELAYER_RPC_URL"));

// The server reads this object on every request; the refresher swaps trustPolicy in place.
const verifyOptions: VerifyOptions = {
  trustPolicy,
  maxIndexLagSlots,
  lifecycle: new HttpLifecycleIndex(required("ONELAYER_LOOKUP_URL"), { serviceToken: lookupServiceToken }),
};
const server = createVerifierServer({
  chain,
  incidents: new HttpIncidentIndex(required("ONELAYER_INCIDENT_INDEX_URL"), { serviceToken: incidentServiceToken }),
  lookup: new HttpPublicLookup(required("ONELAYER_LOOKUP_URL"), { serviceToken: lookupServiceToken }),
  corsAllowedOrigin: process.env.ONELAYER_CORS_ALLOWED_ORIGIN,
  verifyOptions,
});

// Signed mode: the floor is freshness-bounded, so it is re-validated while running;
// a failure withdraws the policy (verification fails closed) until it recovers.
if (trustOptions.mode.kind === "signed") {
  startTrustRefresh(trustOptions, verifyOptions, {
    onFailure: error => process.stderr.write(`trust material rejected; verification disabled: ${error.message}\n`),
  });
}

server.listen(port, "127.0.0.1", () => {
  process.stdout.write(`verifier listening on 127.0.0.1:${port}\n`);
});
