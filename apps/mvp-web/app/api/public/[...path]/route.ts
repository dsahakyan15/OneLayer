import type { NextRequest } from "next/server";
import { proxy, upstream } from "../../../../lib/proxy";

export const dynamic = "force-dynamic";

/** Public read-only lookups (certificate package, QR image, incident index). */
async function handle(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  const { path } = await context.params;
  return proxy(request, upstream("ONELAYER_ADMIN_API_URL"), ["v1", ...path], request.nextUrl.search);
}

export const GET = handle;
