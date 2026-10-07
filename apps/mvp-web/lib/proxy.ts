// Same-origin server-side proxy (§5.4 transport). The browser never talks to
// upstream services directly, so no new CORS surface is opened, and the
// upstream session cookie is passed through unchanged.
import { NextResponse } from "next/server";

const FORWARDED_REQUEST_HEADERS = ["content-type", "cookie", "x-onelayer-csrf", "idempotency-key", "origin"];
const FORWARDED_RESPONSE_HEADERS = ["content-type", "set-cookie", "location"];

export function upstream(variable: string): string {
  const value = process.env[variable];
  if (value === undefined || value.length === 0) throw new Error(`${variable} is required`);
  return value;
}

export async function proxy(
  request: Request,
  baseUrl: string,
  path: string[],
  search: string,
): Promise<NextResponse> {
  const target = new URL(`/${path.join("/")}${search}`, baseUrl);
  const headers = new Headers();
  for (const name of FORWARDED_REQUEST_HEADERS) {
    const value = request.headers.get(name);
    if (value !== null) headers.set(name, value);
  }
  const hasBody = request.method !== "GET" && request.method !== "HEAD";
  let response: Response;
  try {
    response = await fetch(target, {
      method: request.method,
      headers,
      body: hasBody ? await request.text() : undefined,
      redirect: "manual",
      cache: "no-store",
    });
  } catch {
    return NextResponse.json({ code: "UPSTREAM_UNAVAILABLE" }, { status: 503 });
  }
  const proxied = new NextResponse(response.status === 204 ? null : await response.arrayBuffer(), {
    status: response.status,
  });
  for (const name of FORWARDED_RESPONSE_HEADERS) {
    const value = name === "set-cookie" ? response.headers.getSetCookie().join(", ") : response.headers.get(name);
    if (value !== null && value !== "") proxied.headers.set(name, value);
  }
  proxied.headers.set("cache-control", "no-store");
  return proxied;
}
