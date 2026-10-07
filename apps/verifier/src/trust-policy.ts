import type { CertificateBody } from "../../../packages/canonical-ts/src/index.ts";

/** Deployment-owned authorization; never construct this from an untrusted package. */
export interface TrustPolicy {
  version: 1;
  revision: number;
  validUntil: string;
  genesisHash: string;
  registryId: string;
  programIdHex: string;
  configPdaHex: string;
  schemaVersions: number[];
  registryVersions: string[];
  issuers: Array<{
    keyId: string;
    publicKeyHex: string;
    algorithm: "Ed25519";
    validFrom: string;
    validUntil: string;
    /** Revocation rejects all signatures, including purported historical issuance. */
    revoked: boolean;
  }>;
}

function object(value: unknown, keys: string[]): Record<string, any> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new TypeError("invalid trust policy object");
  const result = value as Record<string, any>;
  if (Object.keys(result).sort().join(",") !== keys.sort().join(",")) throw new TypeError("invalid trust policy fields");
  return result;
}
function text(value: unknown): value is string { return typeof value === "string" && value.length > 0; }
function hex(value: unknown): boolean { return typeof value === "string" && /^[0-9a-f]{64}$/.test(value); }
export function timestamp(value: unknown): number {
  if (typeof value !== "string" || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(value)) throw new TypeError("invalid trust timestamp");
  const ms = Date.parse(value);
  if (!Number.isFinite(ms) || new Date(ms).toISOString() !== value.replace("Z", ".000Z")) throw new TypeError("invalid trust timestamp");
  return ms;
}

export function parseTrustPolicy(value: unknown, minimumRevision: number): TrustPolicy {
  const p = object(value, ["version", "revision", "validUntil", "genesisHash", "registryId", "programIdHex", "configPdaHex", "schemaVersions", "registryVersions", "issuers"]);
  if (!Number.isSafeInteger(minimumRevision) || minimumRevision < 1 || p.version !== 1 || !Number.isSafeInteger(p.revision) || p.revision < minimumRevision) throw new TypeError("trust policy version/revision rejected");
  timestamp(p.validUntil);
  if (!text(p.genesisHash) || !text(p.registryId) || !hex(p.programIdHex) || !hex(p.configPdaHex)) throw new TypeError("invalid trust binding");
  if (!Array.isArray(p.schemaVersions) || p.schemaVersions.length === 0 || p.schemaVersions.some((v: unknown) => v !== 1)) throw new TypeError("unsupported schema policy");
  if (!Array.isArray(p.registryVersions) || p.registryVersions.length === 0 || p.registryVersions.some((v: unknown) => typeof v !== "string" || !/^(0|[1-9][0-9]*)$/.test(v) || BigInt(v) > 18446744073709551615n)) throw new TypeError("invalid registry versions");
  if (!Array.isArray(p.issuers) || p.issuers.length === 0) throw new TypeError("missing trusted issuers");
  const ids = new Set<string>();
  for (const value of p.issuers) {
    const key = object(value, ["keyId", "publicKeyHex", "algorithm", "validFrom", "validUntil", "revoked"]);
    if (!text(key.keyId) || ids.has(key.keyId) || !hex(key.publicKeyHex) || key.algorithm !== "Ed25519" || typeof key.revoked !== "boolean") throw new TypeError("invalid trusted issuer");
    ids.add(key.keyId);
    if (timestamp(key.validFrom) >= timestamp(key.validUntil)) throw new TypeError("invalid issuer validity interval");
  }
  return structuredClone(p) as TrustPolicy;
}

export function authorizeCertificate(body: CertificateBody, policy: TrustPolicy | undefined, now = Date.now()): string | null {
  if (policy === undefined) return "TRUST_POLICY_UNAVAILABLE";
  try { parseTrustPolicy(policy, 1); } catch { return "TRUST_POLICY_INVALID"; }
  if (!Number.isFinite(now) || now >= Date.parse(policy.validUntil)) return "TRUST_POLICY_EXPIRED";
  if (body.registryId !== policy.registryId) return "REGISTRY_UNTRUSTED";
  if (Buffer.from(body.anchor.solanaProgramId).toString("hex") !== policy.programIdHex) return "PROGRAM_UNTRUSTED";
  if (!policy.schemaVersions.includes(body.schemaVersion) || !policy.registryVersions.includes(body.anchor.registryVersion.toString())) return "VERSION_UNTRUSTED";
  const issuer = policy.issuers.find((key) => key.keyId === body.issuerKeyId && key.publicKeyHex === Buffer.from(body.issuerPublicKey).toString("hex"));
  if (!issuer) return "ISSUER_UNTRUSTED";
  if (issuer.revoked) return "ISSUER_REVOKED";
  let issued: number;
  try { issued = timestamp(body.issuedAt); } catch { return "ISSUER_TIME_INVALID"; }
  if (issued > now || issued < Date.parse(issuer.validFrom) || issued >= Date.parse(issuer.validUntil)) return "ISSUER_TIME_INVALID";
  return null;
}
