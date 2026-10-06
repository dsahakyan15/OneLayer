import { NextResponse, type NextRequest } from "next/server";
import { proxy, upstream } from "../../../../lib/proxy";

export const dynamic = "force-dynamic";

/**
 * Exact allowlist of verifier routes reachable from the browser. `v2/verify` is
 * the current envelope the client calls; `v1/verify` stays reachable for
 * compatibility with legacy consumers. Every other path is refused here instead
 * of being forwarded upstream.
 */
const ROUTES: Record<string, readonly string[]> = {
  "v1/verify": ["v1", "verify"],
  "v2/verify": ["v2", "verify"],
};

async function handle(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  const { path } = await context.params;
  const target = ROUTES[path.join("/")];
  if (target === undefined) return NextResponse.json({ code: "NOT_FOUND" }, { status: 404 });
  return proxy(request, upstream("ONELAYER_VERIFIER_URL"), [...target], request.nextUrl.search);
}

export const POST = handle;
