import { useEffect, useState } from "react";

import * as api from "../api";
import type { SecurityEvent } from "../types";

const PAGE_SIZE = 25;

interface PageData {
  items: SecurityEvent[];
  total: number;
  page: number;
  totalPages: number;
}

export default function EventsPage() {
  const [page, setPage] = useState(1);
  const [data, setData] = useState<PageData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);

  useEffect(() => {
    setLoading(true);
    void (async () => {
      try {
        const result = await api.getEvents(page, PAGE_SIZE);
        setData({
          items: result.items,
          total: result.total,
          page: result.page,
          totalPages: result.totalPages,
        });
        setError(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to load events");
      } finally {
        setLoading(false);
      }
    })();
  }, [page]);

  const severityColor = (s: string) => {
    if (s === "HIGH") return "red";
    if (s === "MEDIUM") return "orange";
    return "green";
  };

  if (loading && !data) {
    return <div className="page-container">Loading events…</div>;
  }
  if (error) {
    return (
      <div className="page-container" style={{ color: "#c00" }}>
        Error: {error}
      </div>
    );
  }
  if (!data) return null;

  const filtered = data.items.filter((e) => {
    const q = search.toLowerCase();
    const matchesSearch =
      e.title.toLowerCase().includes(q) ||
      e.description.toLowerCase().includes(q) ||
      e.assetHostname.toLowerCase().includes(q);
    const matchesSeverity = severityFilter === "ALL" || e.severity === severityFilter;
    return matchesSearch && matchesSeverity;
  });

  return (
    <div className="page-container">
      <h1>Security Events</h1>

      <div style={{ marginBottom: 16, display: "flex", gap: 12, alignItems: "center" }}>
        <input
          type="text"
          placeholder="Filter this page…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{ width: "100%", maxWidth: 400 }}
        />
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          style={{ width: 140 }}
        >
          <option value="ALL">All Severities</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
      </div>

      {search && (
        <p>
          Filtering for: <strong>{search}</strong> ({filtered.length} on this page)
        </p>
      )}

      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Title</th>
            <th>Asset</th>
            <th>Source IP</th>
            <th>Timestamp</th>
          </tr>
        </thead>
        <tbody>
          {filtered.map((event) => (
            <tr
              key={event.id}
              onClick={() => setSelectedEvent(event)}
              style={{ cursor: "pointer" }}
            >
              <td style={{ color: severityColor(event.severity), fontWeight: 600 }}>
                {event.severity}
              </td>
              <td>{event.title}</td>
              <td style={{ fontFamily: "monospace", fontSize: 13 }}>
                {event.assetHostname}
              </td>
              <td style={{ fontFamily: "monospace", fontSize: 13 }}>
                {event.sourceIp}
              </td>
              <td style={{ fontSize: 13 }}>
                {new Date(event.timestamp).toLocaleString()}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {filtered.length === 0 && (
        <p style={{ color: "#999" }}>No events match the filter on this page.</p>
      )}

      <div
        style={{
          marginTop: 16,
          display: "flex",
          gap: 12,
          alignItems: "center",
        }}
      >
        <button
          onClick={() => setPage((p) => Math.max(1, p - 1))}
          disabled={page === 1 || loading}
        >
          ← Prev
        </button>
        <span style={{ fontSize: 13, color: "#555" }}>
          Page {data.page} of {data.totalPages} · {data.total} events total
        </span>
        <button
          onClick={() => setPage((p) => Math.min(data.totalPages, p + 1))}
          disabled={page >= data.totalPages || loading}
        >
          Next →
        </button>
      </div>

      <div style={{ marginTop: 12 }}>
        <button
          onClick={() => {
            const blob = new Blob([JSON.stringify(filtered, null, 2)], {
              type: "application/json",
            });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = "penguwave_events_export.json";
            a.click();
            URL.revokeObjectURL(url);
          }}
          style={{ fontSize: 13 }}
        >
          Export current page (JSON)
        </button>
      </div>

      {selectedEvent && (
        <div className="event-detail">
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <h2>{selectedEvent.title}</h2>
            <button onClick={() => setSelectedEvent(null)} style={{ cursor: "pointer" }}>
              Close
            </button>
          </div>
          <p>
            <strong>Severity:</strong>{" "}
            <span style={{ color: severityColor(selectedEvent.severity) }}>
              {selectedEvent.severity}
            </span>
          </p>
          <p>
            <strong>Description:</strong>
          </p>
          <div style={{ whiteSpace: "pre-wrap" }}>{selectedEvent.description}</div>
          <p>
            <strong>Asset:</strong> {selectedEvent.assetHostname} ({selectedEvent.assetIp})
          </p>
          <p>
            <strong>Source IP:</strong> {selectedEvent.sourceIp}
          </p>
          <p>
            <strong>Tags:</strong> {selectedEvent.tags.join(", ")}
          </p>
          <p>
            <strong>Timestamp:</strong>{" "}
            {new Date(selectedEvent.timestamp).toLocaleString()}
          </p>
          <h3>Raw Event Data</h3>
          <pre>{JSON.stringify(selectedEvent, null, 2)}</pre>
        </div>
      )}
    </div>
  );
}
