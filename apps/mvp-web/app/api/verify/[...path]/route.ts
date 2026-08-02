import type { NextRequest } from "next/server";
import { proxy, upstream } from "../../../../lib/proxy";

export const dynamic = "force-dynamic";

async function handle(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
  const { path } = await context.params;
  return proxy(request, upstream("ONELAYER_VERIFIER_URL"), ["v1", ...path], request.nextUrl.search);
}

export const GET = handle;
export const POST = handle;
