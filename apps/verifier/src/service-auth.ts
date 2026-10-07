// Credentials and origin rules for the verifier's outbound reads of the public
// lookup API. The API side owns the durable scoped service principals (see
// docs/admin-access-contract.md, "Service principals for internal routes"); the
// verifier only holds the raw bearer for its own two URLs, one token per URL,
// and never logs it.
import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";

/**
 * Exact service-principal bearer shape: `olsp_` + 22-char base64url credential
 * ID + `.` + 43-char base64url secret. Same shape the API's `parseServiceBearer`
 * enforces; a token that does not match cannot authenticate and must not be
 * sent to an upstream that would then see a malformed credential.
 */
const SERVICE_TOKEN_PATTERN = /^olsp_[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$/;
/** A raw token is 70 bytes; anything past this cap is a configuration error. */
const MAX_TOKEN_FILE_BYTES = 4096;

export class ServiceTokenFileError extends Error {}

/** Rejects a token that is not exactly the service-principal bearer shape. */
export function validatedServiceToken(value: string): string {
  if (typeof value !== "string" || !SERVICE_TOKEN_PATTERN.test(value)) {
    throw new TypeError("service token is invalid");
  }
  return value;
}

/** Loads a configured token file, or returns undefined when the variable is unset. */
export function readServiceToken(env: NodeJS.ProcessEnv, name: string): string | undefined {
  const path = env[name];
  if (path === undefined) return undefined;
  if (path.length === 0) throw new ServiceTokenFileError(`${name} is empty`);
  let token!: string;
  try {
    // O_NONBLOCK so a configured FIFO (or any non-regular file) cannot block
    // startup before fstat rejects it; regular files read exactly as before.
    const handle = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK);
    try {
      if (!fstatSync(handle).isFile()) throw new ServiceTokenFileError(`${name} is not a regular file`);
      const bytes = Buffer.alloc(MAX_TOKEN_FILE_BYTES + 1);
      const read = readSync(handle, bytes, 0, bytes.length, 0);
      if (read > MAX_TOKEN_FILE_BYTES) throw new ServiceTokenFileError(`${name} is larger than ${MAX_TOKEN_FILE_BYTES} bytes`);
      token = bytes.subarray(0, read).toString("utf8").trim();
    } finally {
      closeSync(handle);
    }
  } catch (error) {
    if (error instanceof ServiceTokenFileError) throw error;
    throw new ServiceTokenFileError(`${name} cannot be read`);
  }
  if (!SERVICE_TOKEN_PATTERN.test(token)) throw new ServiceTokenFileError(`${name} does not contain a valid service token`);
  return token;
}

/**
 * Validates the base URL of one upstream lookup endpoint. Any userinfo, path,
 * query or fragment is refused because it makes the request target ambiguous;
 * with a token configured the origin must be HTTPS, or HTTP on an explicit
 * loopback address, so a bearer is never sent over a plaintext non-loopback
 * hop. Loopback is checked by parsing the host, so `127.0.0.1.evil.example`
 * and `localhost.evil.example` are not accepted as loopback.
 */
export function validatedBaseUrl(raw: string, options: { serviceToken?: string } = {}): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new TypeError("upstream base URL is invalid");
  }
  if (url.username.length > 0 || url.password.length > 0 || url.pathname !== "/" || url.search.length > 0 || url.hash.length > 0) {
    throw new TypeError("upstream base URL must not contain userinfo, a path, a query or a fragment");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") throw new TypeError("upstream base URL must use HTTP or HTTPS");
  if (options.serviceToken === undefined) return url;
  if (url.protocol === "https:" || isLoopbackHost(url.hostname)) return url;
  throw new TypeError("token-authenticated upstream must use HTTPS or an explicit loopback HTTP origin");
}

/** `[::1]` is normalized by `URL` to `[::1]`; accept the full 127/8 block and `localhost`. */
function isLoopbackHost(hostname: string): boolean {
  const host = hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
  if (host === "localhost" || host === "::1") return true;
  const octets = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  return octets !== null && octets.slice(1).every(part => Number(part) <= 255) && octets[1] === "127";
}

const REGISTRY_ID_PATTERN = /^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$/;
const CERTIFICATE_ID_PATTERN = /^[0-9a-f]{32}$/;
const UNSIGNED_PATTERN = /^(?:0|[1-9][0-9]*)$/;
const MAX_U64 = 0xffff_ffff_ffff_ffffn;

/**
 * The registry ID travels in a query parameter (`URLSearchParams` encodes it),
 * so the anonymous demo adapters keep the pre-existing permissive semantics.
 * Token-authenticated reads use the stricter character set above; it rejects
 * separators, whitespace and control characters without imposing the API's
 * dotted registry grammar on callers.
 */
export function assertRegistryId(value: string, strict: boolean): void {
  if (typeof value !== "string" || (strict && !REGISTRY_ID_PATTERN.test(value))) {
    throw new TypeError("registryId is invalid");
  }
}

/** Certificate IDs are exactly 32 lowercase hex characters on every API route. */
export function assertCertificateId(value: string): void {
  if (typeof value !== "string" || !CERTIFICATE_ID_PATTERN.test(value)) throw new TypeError("certificateId is invalid");
}

/** u64 decimal string used by both the anchor and batch-sequence path/query params. */
export function assertUnsigned(value: string, name: string): string {
  if (!UNSIGNED_PATTERN.test(value) || BigInt(value) > MAX_U64) throw new TypeError(`${name} is invalid`);
  return value;
}
