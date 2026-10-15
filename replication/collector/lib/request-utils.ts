const MAX_BODY_BYTES = 256 * 1024;

export type ParsedBody = {
  contentType: string | null;
  bodyText: string | null;
  bodyBase64: string | null;
  truncated: boolean;
};

const TEXTUAL_CONTENT_TYPES = [
  "application/json",
  "application/xml",
  "application/javascript",
  "application/x-www-form-urlencoded"
];

export function isReservedRootSegment(segment: string): boolean {
  return segment === "api" || segment === "console";
}

export function mapSearchParams(params: URLSearchParams): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {};
  for (const [key, value] of params.entries()) {
    const existing = out[key];
    if (existing === undefined) {
      out[key] = value;
      continue;
    }
    if (Array.isArray(existing)) {
      existing.push(value);
      continue;
    }
    out[key] = [existing, value];
  }
  return out;
}

export function sanitizeHeaders(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of headers.entries()) {
    const lowerKey = key.toLowerCase();
    if (
      lowerKey.startsWith("x-vercel-") ||
      lowerKey === "forwarded" ||
      lowerKey === "x-real-ip" ||
      lowerKey.startsWith("x-forwarded-")
    ) {
      continue;
    }
    out[key] = value;
  }
  return out;
}

function isTextualContentType(contentType: string | null): boolean {
  if (!contentType) {
    return false;
  }
  const normalized = contentType.toLowerCase();
  if (normalized.startsWith("text/")) {
    return true;
  }
  return TEXTUAL_CONTENT_TYPES.some((part) => normalized.includes(part));
}

export async function parseRequestBody(request: Request): Promise<ParsedBody> {
  const contentType = request.headers.get("content-type");
  const bodyBytes = new Uint8Array(await request.arrayBuffer());

  if (bodyBytes.length === 0) {
    return {
      contentType,
      bodyText: null,
      bodyBase64: null,
      truncated: false
    };
  }

  const truncated = bodyBytes.length > MAX_BODY_BYTES;
  const safeBytes = truncated ? bodyBytes.slice(0, MAX_BODY_BYTES) : bodyBytes;

  if (isTextualContentType(contentType)) {
    return {
      contentType,
      bodyText: new TextDecoder("utf-8", { fatal: false }).decode(safeBytes),
      bodyBase64: null,
      truncated
    };
  }

  return {
    contentType,
    bodyText: null,
    bodyBase64: Buffer.from(safeBytes).toString("base64"),
    truncated
  };
}

export function clampLimit(raw: string | null, fallback: number, max: number): number {
  if (!raw) {
    return fallback;
  }
  const parsed = Number.parseInt(raw, 10);
  if (Number.isNaN(parsed)) {
    return fallback;
  }
  return Math.max(1, Math.min(parsed, max));
}
