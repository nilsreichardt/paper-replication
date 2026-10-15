import { NextResponse } from "next/server";
import { insertRequestLog, maybeCleanupExpiredLogs } from "@/lib/db";
import {
  isReservedRootSegment,
  mapSearchParams,
  parseRequestBody,
  sanitizeHeaders
} from "@/lib/request-utils";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

type Params = {
  binId: string;
  rest?: string[];
};

async function handleRequest(request: Request, context: { params: Promise<Params> }) {
  const { binId } = await context.params;

  if (!binId || isReservedRootSegment(binId)) {
    return NextResponse.json({ error: "Not found" }, { status: 404 });
  }

  const parsedUrl = new URL(request.url);
  const body = await parseRequestBody(request);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);

  const inserted = await insertRequestLog({
    binId,
    method: request.method,
    path: parsedUrl.pathname,
    query: mapSearchParams(parsedUrl.searchParams),
    headers: sanitizeHeaders(request.headers),
    contentType: body.contentType,
    bodyText: body.bodyText,
    bodyBase64: body.bodyBase64,
    truncated: body.truncated,
    receivedAt: now.toISOString(),
    expiresAt: expiresAt.toISOString()
  });

  void maybeCleanupExpiredLogs().catch(() => {
    // Cleanup runs best-effort in the background.
  });

  return NextResponse.json(
    {
      ok: true,
      id: inserted.id,
      receivedAt: inserted.receivedAt
    },
    { status: 200 }
  );
}

export const GET = handleRequest;
export const POST = handleRequest;
export const PUT = handleRequest;
export const PATCH = handleRequest;
export const DELETE = handleRequest;
export const OPTIONS = handleRequest;
export const HEAD = handleRequest;
