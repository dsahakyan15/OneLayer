import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { decodeCertificatePackageBase64url } from "./certificate-codec.ts";
import {
  verifyCertificate,
  type ChainReader,
  type IncidentIndex,
  type VerifyOptions,
} from "./verify.ts";

const MAX_REQUEST_BYTES = 1_048_576;

export interface PublicLookup {
  getAnchor(batchSequence: bigint): Promise<unknown | null>;
  getCertificateStatus(certificateId: string): Promise<unknown | null>;
}

export interface VerifierServices {
  chain: ChainReader;
  incidents: IncidentIndex;
  lookup: PublicLookup;
  verifyOptions?: VerifyOptions;
  corsAllowedOrigin?: string;
}

function writeJson(response: ServerResponse, status: number, body: unknown): void {
  const encoded = JSON.stringify(body, (_key, value) => typeof value === "bigint" ? value.toString() : value);
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(encoded),
    "cache-control": "no-store",
  });
  response.end(encoded);
}

async function readJson(request: IncomingMessage): Promise<Record<string, unknown>> {
  const declared = Number(request.headers["content-length"] ?? 0);
  if (!Number.isSafeInteger(declared) || declared < 0 || declared > MAX_REQUEST_BYTES) {
    throw new RangeError("REQUEST_TOO_LARGE");
  }
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    length += bytes.length;
    if (length > MAX_REQUEST_BYTES) throw new RangeError("REQUEST_TOO_LARGE");
    chunks.push(bytes);
  }
  const value: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("REQUEST_FORMAT_INVALID");
  }
  return value as Record<string, unknown>;
}

function parseUnsigned(value: string | null, name: string): bigint {
  if (value === null || !/^(?:0|[1-9][0-9]*)$/.test(value)) throw new TypeError(`${name} is invalid`);
  const parsed = BigInt(value);
  if (parsed > 0xffff_ffff_ffff_ffffn) throw new RangeError(`${name} is out of range`);
  return parsed;
}

async function handle(request: IncomingMessage, response: ServerResponse, services: VerifierServices): Promise<void> {
  const url = new URL(request.url ?? "/", "http://verifier.local");
  if (request.method === "GET" && url.pathname === "/v1/health") {
    writeJson(response, 200, { status: "ok" });
    return;
  }

  if (request.method === "POST" && url.pathname === "/v1/verify") {
    const body = await readJson(request);
    if (typeof body.certificatePackage !== "string") throw new TypeError("certificatePackage is required");
    if (body.requiredCommitment !== undefined && body.requiredCommitment !== "finalized") {
      writeJson(response, 400, { code: "ANCHOR_NOT_FINALIZED", message: "requiredCommitment must be finalized" });
      return;
    }
    const signed = decodeCertificatePackageBase64url(body.certificatePackage);
    const result = await verifyCertificate(signed, services.chain, services.incidents, services.verifyOptions);
    writeJson(response, result.status === "INVALID" ? 422 : 200, result);
    return;
  }

  if (request.method === "GET" && url.pathname.startsWith("/v1/anchors/")) {
    const sequence = parseUnsigned(url.pathname.slice("/v1/anchors/".length), "batchSequence");
    const anchor = await services.lookup.getAnchor(sequence);
    writeJson(response, anchor === null ? 404 : 200, anchor ?? { code: "ANCHOR_NOT_FOUND" });
    return;
  }

  if (request.method === "GET" && url.pathname === "/v1/incidents") {
    const registryId = url.searchParams.get("registryId");
    if (registryId === null || registryId.length === 0) throw new TypeError("registryId is required");
    const batchSequence = parseUnsigned(url.searchParams.get("batchSequence"), "batchSequence");
    const incidents = await services.incidents.query(registryId, batchSequence);
    writeJson(response, incidents === null ? 503 : 200, incidents ?? { code: "INCIDENT_INDEX_UNAVAILABLE" });
    return;
  }

  if (request.method === "GET" && url.pathname.startsWith("/v1/certificates/") && url.pathname.endsWith("/status")) {
    const certificateId = decodeURIComponent(
      url.pathname.slice("/v1/certificates/".length, -"/status".length),
    );
    if (!/^[0-9a-f]{32}$/.test(certificateId)) throw new TypeError("certificateId is invalid");
    const status = await services.lookup.getCertificateStatus(certificateId);
    writeJson(response, status === null ? 404 : 200, status ?? { code: "CERTIFICATE_NOT_FOUND" });
    return;
  }

  writeJson(response, 404, { code: "NOT_FOUND" });
}

export function createVerifierServer(services: VerifierServices): Server {
  return createServer((request, response) => {
    const origin = request.headers.origin;
    if (services.corsAllowedOrigin !== undefined && origin === services.corsAllowedOrigin) {
      response.setHeader("access-control-allow-origin", origin);
      response.setHeader("access-control-allow-methods", "GET, POST, OPTIONS");
      response.setHeader("access-control-allow-headers", "content-type");
      response.setHeader("vary", "origin");
    }
    if (request.method === "OPTIONS") {
      response.writeHead(origin === services.corsAllowedOrigin ? 204 : 403, { "cache-control": "no-store" });
      response.end();
      return;
    }
    handle(request, response, services).catch((error: unknown) => {
      const code = error instanceof RangeError && error.message === "REQUEST_TOO_LARGE"
        ? "REQUEST_TOO_LARGE"
        : "REQUEST_FORMAT_INVALID";
      writeJson(response, code === "REQUEST_TOO_LARGE" ? 413 : 400, { code, message: code });
    });
  });
}
