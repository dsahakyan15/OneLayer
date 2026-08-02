"use client";

// Browser-side access to the same-origin proxies. The CSRF token lives in
// component state for the lifetime of the page; the session itself is an
// HttpOnly cookie the browser never reads.

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message?: string) {
    super(message ?? code);
    this.status = status;
    this.code = code;
  }
}

async function parse(response: Response): Promise<any> {
  if (response.status === 204) return null;
  const text = await response.text();
  let body: any = null;
  try {
    body = text.length === 0 ? null : JSON.parse(text);
  } catch {
    throw new ApiError(response.status, "RESPONSE_NOT_JSON", text.slice(0, 200));
  }
  if (!response.ok) throw new ApiError(response.status, body?.code ?? "REQUEST_FAILED", body?.message);
  return body;
}

export interface AdminRequestOptions {
  method?: string;
  body?: unknown;
  csrfToken?: string;
  idempotencyKey?: string;
}

export async function admin(path: string, options: AdminRequestOptions = {}): Promise<any> {
  const headers: Record<string, string> = {};
  if (options.body !== undefined) headers["content-type"] = "application/json";
  if (options.csrfToken !== undefined) headers["x-onelayer-csrf"] = options.csrfToken;
  if (options.idempotencyKey !== undefined) headers["idempotency-key"] = options.idempotencyKey;
  return parse(await fetch(`/api/admin${path}`, {
    method: options.method ?? "GET",
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
    cache: "no-store",
  }));
}

export async function publicApi(path: string): Promise<any> {
  return parse(await fetch(`/api/public${path}`, { cache: "no-store" }));
}

export async function verify(certificatePackage: string): Promise<any> {
  return parse(await fetch("/api/verify/verify", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ certificatePackage, requiredCommitment: "finalized" }),
    cache: "no-store",
  }));
}
