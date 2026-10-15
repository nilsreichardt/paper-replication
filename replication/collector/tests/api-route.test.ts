import { beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/db", () => ({
  listRequestLogs: vi.fn(),
  deleteRequestLogs: vi.fn(),
  insertRequestLog: vi.fn(),
  maybeCleanupExpiredLogs: vi.fn(),
  cleanupExpiredLogs: vi.fn(),
  listRequestLogsSince: vi.fn()
}));

import { DELETE as deleteLogs, GET as getLogs } from "@/app/api/[binId]/route";
import { GET as getCleanup } from "@/app/api/internal/cleanup/route";
import { POST as ingestPost } from "@/app/[binId]/[[...rest]]/route";
import {
  cleanupExpiredLogs,
  deleteRequestLogs,
  insertRequestLog,
  listRequestLogs,
  maybeCleanupExpiredLogs
} from "@/lib/db";

const listRequestLogsMock = vi.mocked(listRequestLogs);
const deleteRequestLogsMock = vi.mocked(deleteRequestLogs);
const insertRequestLogMock = vi.mocked(insertRequestLog);
const maybeCleanupMock = vi.mocked(maybeCleanupExpiredLogs);
const cleanupExpiredMock = vi.mocked(cleanupExpiredLogs);

describe("route handlers", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it("returns paginated api payload", async () => {
    listRequestLogsMock.mockResolvedValue([
      {
        id: "1",
        binId: "demo",
        method: "POST",
        path: "/demo",
        query: {},
        headers: {},
        contentType: "application/json",
        bodyText: "{}",
        bodyBase64: null,
        truncated: false,
        receivedAt: "2026-01-01T00:00:00.000Z",
        expiresAt: "2026-01-02T00:00:00.000Z"
      }
    ]);

    const request = new Request("https://example.com/api/demo?limit=1");
    const response = await getLogs(request, { params: Promise.resolve({ binId: "demo" }) });
    const json = await response.json();

    expect(response.status).toBe(200);
    expect(json.binId).toBe("demo");
    expect(json.items).toHaveLength(1);
    expect(json.nextBefore).toBe("2026-01-01T00:00:00.000Z");
  });

  it("stores an incoming webhook request", async () => {
    insertRequestLogMock.mockResolvedValue({
      id: "abc",
      binId: "demo",
      method: "POST",
      path: "/demo",
      query: { x: "1" },
      headers: {},
      contentType: "application/json",
      bodyText: "{\"ok\":true}",
      bodyBase64: null,
      truncated: false,
      receivedAt: "2026-01-01T00:00:00.000Z",
      expiresAt: "2026-01-02T00:00:00.000Z"
    });
    maybeCleanupMock.mockResolvedValue();

    const request = new Request("https://example.com/demo?x=1", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{\"ok\":true}"
    });

    const response = await ingestPost(request, {
      params: Promise.resolve({ binId: "demo", rest: [] })
    });
    const json = await response.json();

    expect(response.status).toBe(200);
    expect(json.ok).toBe(true);
    expect(insertRequestLogMock).toHaveBeenCalledTimes(1);
  });

  it("deletes all logs for a bin", async () => {
    deleteRequestLogsMock.mockResolvedValue(4);

    const response = await deleteLogs(new Request("https://example.com/api/demo", { method: "DELETE" }), {
      params: Promise.resolve({ binId: "demo" })
    });
    const json = await response.json();

    expect(response.status).toBe(200);
    expect(json.ok).toBe(true);
    expect(json.deleted).toBe(4);
    expect(deleteRequestLogsMock).toHaveBeenCalledWith("demo");
  });

  it("protects cleanup endpoint with cron secret", async () => {
    cleanupExpiredMock.mockResolvedValue(3);
    process.env.CRON_SECRET = "secret";

    const unauthorized = await getCleanup(new Request("https://example.com/api/internal/cleanup"));
    expect(unauthorized.status).toBe(401);

    const authorized = await getCleanup(
      new Request("https://example.com/api/internal/cleanup", {
        headers: { authorization: "Bearer secret" }
      })
    );
    const json = await authorized.json();

    expect(authorized.status).toBe(200);
    expect(json.deleted).toBe(3);
  });
});
