import { neon } from "@neondatabase/serverless";
import type { RequestInsert, RequestLog } from "@/lib/types";

function getSqlClient() {
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) {
    throw new Error("DATABASE_URL is required");
  }
  return neon(databaseUrl);
}

type RequestRow = {
  id: string;
  bin_id: string;
  method: string;
  path: string;
  query: Record<string, string | string[]>;
  headers: Record<string, string>;
  content_type: string | null;
  body_text: string | null;
  body_base64: string | null;
  truncated: boolean;
  received_at: string;
  expires_at: string;
};

function toRequestLog(row: RequestRow): RequestLog {
  return {
    id: row.id,
    binId: row.bin_id,
    method: row.method,
    path: row.path,
    query: row.query,
    headers: row.headers,
    contentType: row.content_type,
    bodyText: row.body_text,
    bodyBase64: row.body_base64,
    truncated: row.truncated,
    receivedAt: row.received_at,
    expiresAt: row.expires_at
  };
}

export async function insertRequestLog(input: RequestInsert): Promise<RequestLog> {
  const sql = getSqlClient();
  const rows = (await sql`
    INSERT INTO requests (
      bin_id,
      method,
      path,
      query,
      headers,
      content_type,
      body_text,
      body_base64,
      truncated,
      received_at,
      expires_at
    ) VALUES (
      ${input.binId},
      ${input.method},
      ${input.path},
      ${JSON.stringify(input.query)}::jsonb,
      ${JSON.stringify(input.headers)}::jsonb,
      ${input.contentType},
      ${input.bodyText},
      ${input.bodyBase64},
      ${input.truncated},
      ${input.receivedAt}::timestamptz,
      ${input.expiresAt}::timestamptz
    )
    RETURNING *
  `) as RequestRow[];

  return toRequestLog(rows[0]);
}

export async function listRequestLogs(binId: string, limit: number, before?: string): Promise<RequestLog[]> {
  const sql = getSqlClient();
  const rows = (before
    ? await sql`
      SELECT *
      FROM requests
      WHERE bin_id = ${binId}
        AND received_at >= NOW() - INTERVAL '30 days'
        AND received_at < ${before}::timestamptz
      ORDER BY received_at DESC, id DESC
      LIMIT ${limit}
    `
    : await sql`
      SELECT *
      FROM requests
      WHERE bin_id = ${binId}
        AND received_at >= NOW() - INTERVAL '30 days'
      ORDER BY received_at DESC, id DESC
      LIMIT ${limit}
    `) as RequestRow[];

  return rows.map(toRequestLog);
}

export async function listRequestLogsSince(
  binId: string,
  since: string,
  sinceId: string,
  limit: number
): Promise<RequestLog[]> {
  const sql = getSqlClient();
  const rows = (await sql`
    SELECT *
    FROM requests
    WHERE bin_id = ${binId}
      AND received_at >= NOW() - INTERVAL '30 days'
      AND (
        received_at > ${since}::timestamptz
        OR (received_at = ${since}::timestamptz AND id > ${sinceId}::uuid)
      )
    ORDER BY received_at ASC, id ASC
    LIMIT ${limit}
  `) as RequestRow[];

  return rows.map(toRequestLog);
}

export async function cleanupExpiredLogs(): Promise<number> {
  const sql = getSqlClient();
  const rows = (await sql`
    WITH deleted AS (
      DELETE FROM requests
      WHERE expires_at < NOW()
      RETURNING 1
    )
    SELECT COUNT(*)::int AS deleted_count FROM deleted
  `) as { deleted_count: number }[];

  return rows[0]?.deleted_count ?? 0;
}

export async function deleteRequestLogs(binId: string): Promise<number> {
  const sql = getSqlClient();
  const rows = (await sql`
    WITH deleted AS (
      DELETE FROM requests
      WHERE bin_id = ${binId}
      RETURNING 1
    )
    SELECT COUNT(*)::int AS deleted_count FROM deleted
  `) as { deleted_count: number }[];

  return rows[0]?.deleted_count ?? 0;
}

export async function maybeCleanupExpiredLogs(): Promise<void> {
  if (Math.random() > 0.05) {
    return;
  }

  await cleanupExpiredLogs();
}
