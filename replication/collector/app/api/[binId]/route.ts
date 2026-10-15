import { NextResponse } from "next/server";
import { deleteRequestLogs, listRequestLogs } from "@/lib/db";
import { clampLimit, isReservedRootSegment } from "@/lib/request-utils";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(request: Request, context: { params: Promise<{ binId: string }> }) {
  const { binId } = await context.params;

  if (!binId || isReservedRootSegment(binId)) {
    return NextResponse.json({ error: "Invalid bin id" }, { status: 400 });
  }

  const url = new URL(request.url);
  const limit = clampLimit(url.searchParams.get("limit"), 100, 200);
  const before = url.searchParams.get("before") || undefined;

  if (before && Number.isNaN(Date.parse(before))) {
    return NextResponse.json({ error: "Invalid before timestamp" }, { status: 400 });
  }

  const items = await listRequestLogs(binId, limit, before);

  return NextResponse.json({
    binId,
    items,
    nextBefore: items.length === limit ? items.at(-1)?.receivedAt ?? null : null
  });
}

export async function DELETE(_request: Request, context: { params: Promise<{ binId: string }> }) {
  const { binId } = await context.params;

  if (!binId || isReservedRootSegment(binId)) {
    return NextResponse.json({ error: "Invalid bin id" }, { status: 400 });
  }

  const deleted = await deleteRequestLogs(binId);

  return NextResponse.json({
    ok: true,
    binId,
    deleted
  });
}
