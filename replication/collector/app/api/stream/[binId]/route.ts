import { listRequestLogsSince } from "@/lib/db";
import { isReservedRootSegment } from "@/lib/request-utils";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const encoder = new TextEncoder();
const STREAM_LIFETIME_MS = 55_000;
const POLL_INTERVAL_MS = 2_000;
const MIN_UUID = "00000000-0000-0000-0000-000000000000";

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function toSseData(event: string, payload: unknown): Uint8Array {
  return encoder.encode(`event: ${event}\ndata: ${JSON.stringify(payload)}\n\n`);
}

function toSseComment(comment: string): Uint8Array {
  return encoder.encode(`: ${comment}\n\n`);
}

export async function GET(request: Request, context: { params: Promise<{ binId: string }> }) {
  const { binId } = await context.params;

  if (!binId || isReservedRootSegment(binId)) {
    return new Response("invalid bin", { status: 400 });
  }

  let lastTimestamp = new Date().toISOString();
  let lastId = MIN_UUID;
  const startedAt = Date.now();

  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      void (async () => {
        controller.enqueue(encoder.encode("retry: 1200\n\n"));

        while (Date.now() - startedAt < STREAM_LIFETIME_MS) {
          if (request.signal.aborted) {
            break;
          }

          try {
            const items = await listRequestLogsSince(binId, lastTimestamp, lastId, 100);
            for (const item of items) {
              controller.enqueue(toSseData("request", item));
              lastTimestamp = item.receivedAt;
              lastId = item.id;
            }
            controller.enqueue(toSseComment("heartbeat"));
          } catch {
            controller.enqueue(toSseData("error", { message: "stream query failed" }));
          }

          await sleep(POLL_INTERVAL_MS);
        }

        controller.close();
      })();
    }
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive"
    }
  });
}
