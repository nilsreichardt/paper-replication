"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { PaginatedResult, RequestLog } from "@/lib/types";

type Props = {
  binId: string;
};

type DetailPanelProps = {
  title: string;
  value: string;
  copied: boolean;
  onCopy: () => void;
};

function formatTime(iso: string): string {
  return new Date(iso).toLocaleString();
}

function prettyJson(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

function DetailPanel({ title, value, copied, onCopy }: DetailPanelProps) {
  return (
    <section className="detail-panel">
      <div className="detail-panel-header">
        <h3>{title}</h3>
        <button className="detail-copy-button" type="button" onClick={onCopy} aria-label={`Copy ${title}`}>
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre>{value}</pre>
    </section>
  );
}

export function ConsoleClient({ binId }: Props) {
  const [items, setItems] = useState<RequestLog[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [status, setStatus] = useState("connecting");
  const [polling, setPolling] = useState(false);
  const [copiedPanel, setCopiedPanel] = useState<string | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);
  const ids = useRef<Set<string>>(new Set());

  const loadPage = useCallback(async () => {
    const response = await fetch(`/api/${encodeURIComponent(binId)}?limit=100`, {
      cache: "no-store"
    });

    if (!response.ok) {
      throw new Error(`Failed to load logs: ${response.status}`);
    }

    const payload = (await response.json()) as PaginatedResult;
    ids.current = new Set(payload.items.map((item) => item.id));
    setItems(payload.items);
  }, [binId]);

  const appendLiveItems = useCallback((incoming: RequestLog[]) => {
    if (incoming.length === 0) {
      return;
    }

    setItems((prev) => {
      const merged = [...incoming.filter((item) => !ids.current.has(item.id)), ...prev];
      for (const item of incoming) {
        ids.current.add(item.id);
      }
      return merged.slice(0, 300);
    });
  }, []);

  useEffect(() => {
    let source: EventSource | null = null;
    let pollTimer: ReturnType<typeof setInterval> | null = null;
    let closed = false;
    let failures = 0;

    const startPollingFallback = () => {
      if (pollTimer) {
        return;
      }
      setPolling(true);
      setStatus("polling");
      pollTimer = setInterval(async () => {
        try {
          await loadPage();
        } catch {
          // Ignore periodic failures during fallback mode.
        }
      }, 2000);
    };

    const openStream = () => {
      source = new EventSource(`/api/stream/${encodeURIComponent(binId)}`);
      setStatus("live");

      source.addEventListener("request", (event) => {
        failures = 0;
        const parsed = JSON.parse((event as MessageEvent).data) as RequestLog;
        appendLiveItems([parsed]);
      });

      source.onerror = () => {
        failures += 1;
        source?.close();
        source = null;

        if (closed) {
          return;
        }

        if (failures >= 3) {
          startPollingFallback();
          return;
        }

        setStatus("reconnecting");
        setTimeout(openStream, 1200);
      };
    };

    void loadPage()
      .then(() => openStream())
      .catch(() => {
        setStatus("error");
        startPollingFallback();
      });

    return () => {
      closed = true;
      source?.close();
      if (pollTimer) {
        clearInterval(pollTimer);
      }
    };
  }, [appendLiveItems, binId, loadPage]);

  const selected = useMemo(() => items.find((item) => item.id === selectedId) ?? null, [items, selectedId]);

  const copyPanelValue = useCallback(async (panel: string, value: string) => {
    await navigator.clipboard.writeText(value);
    setCopiedPanel(panel);
    window.setTimeout(() => {
      setCopiedPanel((current) => (current === panel ? null : current));
    }, 1200);
  }, []);

  const deleteAllLogs = useCallback(async () => {
    const confirmed = window.confirm(`Delete all stored logs for "${binId}"?`);
    if (!confirmed) {
      return;
    }

    setIsDeleting(true);
    try {
      const response = await fetch(`/api/${encodeURIComponent(binId)}`, {
        method: "DELETE"
      });

      if (!response.ok) {
        throw new Error(`Failed to delete logs: ${response.status}`);
      }

      ids.current = new Set();
      setItems([]);
      setSelectedId(null);
    } finally {
      setIsDeleting(false);
    }
  }, [binId]);

  return (
    <main>
      <div className="card grid">
        <div className="toolbar">
          <div>
            <h1 style={{ margin: 0 }}>Console: {binId}</h1>
            <small>
              Status: <span className="badge">{status}</span>
              {polling ? " (fallback active)" : ""}
            </small>
          </div>
          <div className="toolbar-actions">
            <button
              onClick={() => {
                void loadPage();
              }}
            >
              Refresh
            </button>
            <button className="danger-button" type="button" onClick={() => void deleteAllLogs()} disabled={isDeleting}>
              {isDeleting ? "Deleting..." : "Delete all logs"}
            </button>
          </div>
        </div>
        <div>
          <small>
            Send requests to <code>/{binId}</code> and inspect payloads here.
          </small>
        </div>
        <details className="info-box">
          <summary>Redacted headers</summary>
          <small>
            Some headers are removed before storage and display, including <code>x-vercel-*</code>,{" "}
            <code>forwarded</code>, <code>x-forwarded-*</code>, and <code>x-real-ip</code>.
          </small>
        </details>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Method</th>
                <th>Path</th>
                <th>Content-Type</th>
                <th>Body</th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.id}>
                  <td>{formatTime(item.receivedAt)}</td>
                  <td>
                    <span className="badge">{item.method}</span>
                  </td>
                  <td>{item.path}</td>
                  <td>{item.contentType ?? "-"}</td>
                  <td>
                    <button onClick={() => setSelectedId(item.id)}>View</button>
                  </td>
                </tr>
              ))}
              {items.length === 0 ? (
                <tr>
                  <td colSpan={5}>
                    <small>No requests in the last 30 days.</small>
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </div>

      {selected ? (
        <aside className="drawer">
          <div className="toolbar">
            <h2 style={{ margin: 0 }}>Request Detail</h2>
            <button onClick={() => setSelectedId(null)}>Close</button>
          </div>
          <p>
            <strong>{selected.method}</strong> {selected.path}
          </p>
          <p>
            <small>Received: {formatTime(selected.receivedAt)}</small>
          </p>
          <DetailPanel
            title="Query"
            value={prettyJson(selected.query)}
            copied={copiedPanel === "query"}
            onCopy={() => {
              void copyPanelValue("query", prettyJson(selected.query));
            }}
          />
          <DetailPanel
            title="Headers"
            value={prettyJson(selected.headers)}
            copied={copiedPanel === "headers"}
            onCopy={() => {
              void copyPanelValue("headers", prettyJson(selected.headers));
            }}
          />
          <DetailPanel
            title="Body"
            value={selected.bodyText ?? (selected.bodyBase64 ? `[base64]\n${selected.bodyBase64}` : "<empty>")}
            copied={copiedPanel === "body"}
            onCopy={() => {
              void copyPanelValue(
                "body",
                selected.bodyText ?? (selected.bodyBase64 ? `[base64]\n${selected.bodyBase64}` : "<empty>")
              );
            }}
          />
          {selected.truncated ? (
            <p>
              <small>Body was truncated at 256 KB.</small>
            </p>
          ) : null}
        </aside>
      ) : null}
    </main>
  );
}
