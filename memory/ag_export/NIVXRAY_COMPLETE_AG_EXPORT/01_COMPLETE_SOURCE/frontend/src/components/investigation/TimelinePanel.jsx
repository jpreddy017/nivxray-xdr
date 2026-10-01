/**
 * TimelinePanel — Workspace Timeline Graph MVP (2026-08-11).
 *
 * Read-only projection of the existing canonical investigation
 * evidence. Renders a chronological event list; each event exposes
 * host/user/process/file context and clicks to expand into the
 * underlying P0.2 evidence chain.
 *
 * Contract:
 *   · Consumes `POST /api/die/timeline` (never mutates
 *     `/api/die/investigation-results`).
 *   · Only events with real timestamps are rendered.  Narrative-only
 *     MITRE mentions do NOT appear here — they remain in the MITRE
 *     panels.  This mirrors the backend projection.
 *   · Every emitted event carries `evidence_ref` from the same P0.2
 *     evidence-chain gate the Workspace already renders.
 */
import React, { useEffect, useState, useMemo } from "react";
import api from "@/lib/api";

const S = {
  wrap:   { padding: 12, background: "var(--bg-card, #0f1420)", borderRadius: 8,
            border: "1px solid var(--border-subtle, #1f2937)", color: "var(--fg, #e5e7eb)" },
  header: { display: "flex", alignItems: "baseline", justifyContent: "space-between",
            gap: 12, marginBottom: 10, flexWrap: "wrap" },
  title:  { fontSize: 15, fontWeight: 600, letterSpacing: 0.2 },
  sub:    { fontSize: 12, opacity: 0.7 },
  span:   { fontSize: 11, opacity: 0.7, fontFamily: "ui-monospace, SFMono-Regular, monospace" },
  status: { fontSize: 12, opacity: 0.7, padding: "8px 0" },
  empty:  { fontSize: 12, opacity: 0.75, padding: "8px 0" },
  list:   { display: "flex", flexDirection: "column", gap: 8, marginTop: 4 },
  row:    { display: "grid", gridTemplateColumns: "140px 90px 1fr", gap: 10,
            padding: "10px 12px", borderRadius: 6, background: "rgba(255,255,255,0.02)",
            border: "1px solid var(--border-subtle, #1f2937)", cursor: "pointer" },
  ts:     { fontSize: 11.5, fontFamily: "ui-monospace, SFMono-Regular, monospace",
            color: "var(--fg-muted, #9ca3af)" },
  badge:  { fontSize: 10.5, padding: "2px 8px", borderRadius: 999, textAlign: "center",
            fontWeight: 600, letterSpacing: 0.3, alignSelf: "start" },
  body:   { display: "flex", flexDirection: "column", gap: 4, minWidth: 0 },
  main:   { fontSize: 13, fontWeight: 500, whiteSpace: "nowrap", overflow: "hidden",
            textOverflow: "ellipsis" },
  meta:   { display: "flex", gap: 12, flexWrap: "wrap", fontSize: 11.5, opacity: 0.75 },
  metaK:  { opacity: 0.55 },
  detail: { marginTop: 8, padding: 10, borderRadius: 6, background: "rgba(0,0,0,0.25)",
            border: "1px dashed var(--border-subtle, #1f2937)", fontSize: 11.5,
            fontFamily: "ui-monospace, SFMono-Regular, monospace",
            whiteSpace: "pre-wrap", wordBreak: "break-all", lineHeight: 1.5 },
  err:    { fontSize: 12, color: "#f87171", padding: "8px 0" },
  reload: { fontSize: 11, padding: "4px 10px", borderRadius: 4, cursor: "pointer",
            background: "transparent", border: "1px solid var(--border-subtle, #374151)",
            color: "inherit" },
};

const CONFIDENCE_STYLE = {
  high:   { background: "rgba(239, 68, 68, 0.20)",  color: "#fca5a5" },
  medium: { background: "rgba(234, 179, 8, 0.20)",  color: "#fde68a" },
  low:    { background: "rgba(148, 163, 184, 0.20)", color: "#cbd5e1" },
};

function ConfidenceBadge({ level }) {
  const style = CONFIDENCE_STYLE[level] || CONFIDENCE_STYLE.low;
  return (
    <span style={{ ...S.badge, ...style }} data-testid={`timeline-conf-${level}`}>
      {level || "unknown"}
    </span>
  );
}

function EventDetail({ ev }) {
  const lines = [];
  const push = (label, val) => {
    if (val === undefined || val === null || val === "") return;
    lines.push(`${label.padEnd(14)}  ${typeof val === "object" ? JSON.stringify(val) : String(val)}`);
  };
  push("timestamp",   ev.timestamp);
  push("source",      ev.source);
  push("event_type",  ev.event_type);
  push("event_or_rule", ev.event_or_rule);
  push("host",        ev.host);
  push("user",        ev.user);
  push("process",     ev.process);
  push("parent",      ev.parent_process);
  push("command_line", ev.command_line);
  if (ev.file_context)     push("file", `${ev.file_context.path || ev.file_context.name || ""}${ev.file_context.sha256 ? " · " + ev.file_context.sha256 : ""}`);
  if (ev.network_context)  push("network", ev.network_context);
  if (ev.registry_context) push("registry", ev.registry_context);
  push("evidence_ref", ev.evidence_ref);
  push("confidence",   ev.confidence);
  if ((ev.mitre || []).length) {
    push("mitre", ev.mitre.map(m => `${m.id} · ${m.name}`).join(", "));
  }
  return <div style={S.detail} data-testid="timeline-event-detail">{lines.join("\n")}</div>;
}

function TimelineRow({ ev, idx, open, onToggle }) {
  return (
    <div>
      <div
        style={S.row}
        role="button"
        tabIndex={0}
        data-testid={`timeline-event-row-${idx}`}
        onClick={onToggle}
        onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && onToggle()}
      >
        <div style={S.ts} title={ev.timestamp}>{ev.timestamp}</div>
        <ConfidenceBadge level={ev.confidence} />
        <div style={S.body}>
          <div style={S.main}>
            {ev.event_type} {ev.process ? ` · ${ev.process}` : ""} {ev.host ? ` · ${ev.host}` : ""}
          </div>
          <div style={S.meta}>
            {ev.user && <span><span style={S.metaK}>user</span> {ev.user}</span>}
            {ev.mitre?.length ? (
              <span><span style={S.metaK}>mitre</span> {ev.mitre.map(m => m.id).join(", ")}</span>
            ) : null}
            {ev.evidence_ref && (
              <span data-testid={`timeline-evref-${idx}`}>
                <span style={S.metaK}>ev</span> {ev.evidence_ref}
              </span>
            )}
          </div>
        </div>
      </div>
      {open && <EventDetail ev={ev} />}
    </div>
  );
}

export default function TimelinePanel({ rawInput }) {
  const [status, setStatus]   = useState("idle");   // idle · loading · ready · error
  const [error, setError]     = useState(null);
  const [payload, setPayload] = useState(null);
  const [openIdx, setOpenIdx] = useState(-1);

  const fetchTimeline = React.useCallback(() => {
    if (!rawInput || !rawInput.trim()) {
      setPayload(null); setStatus("idle"); return;
    }
    setStatus("loading"); setError(null);
    api.post("/die/timeline", { input: rawInput })
      .then(r => { setPayload(r.data); setStatus("ready"); })
      .catch(err => {
        setError(String(err?.response?.data?.detail || err?.message || err));
        setStatus("error");
      });
  }, [rawInput]);

  useEffect(() => { fetchTimeline(); }, [fetchTimeline]);

  const events = payload?.events || [];
  const summary = useMemo(() => {
    if (!payload) return null;
    const parts = [];
    if (payload.event_count) parts.push(`${payload.event_count} events`);
    if (payload.hosts?.length) parts.push(`${payload.hosts.length} hosts`);
    if (payload.users?.length) parts.push(`${payload.users.length} users`);
    return parts.join(" · ");
  }, [payload]);

  return (
    <div style={S.wrap} data-testid="timeline-panel">
      <div style={S.header}>
        <div>
          <div style={S.title}>Workspace Timeline</div>
          <div style={S.sub}>
            Read-only projection over canonical investigation evidence.
            Click an event to expand its evidence chain.
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          {payload?.span_start && (
            <span style={S.span} data-testid="timeline-span">
              {payload.span_start} → {payload.span_end}
            </span>
          )}
          <button
            style={S.reload}
            onClick={fetchTimeline}
            disabled={status === "loading"}
            data-testid="timeline-reload"
          >
            {status === "loading" ? "…" : "Reload"}
          </button>
        </div>
      </div>

      {status === "idle"    && <div style={S.empty} data-testid="timeline-idle">Paste or upload input to view the timeline.</div>}
      {status === "loading" && <div style={S.status} data-testid="timeline-loading">Projecting timeline…</div>}
      {status === "error"   && <div style={S.err}    data-testid="timeline-error">Timeline unavailable: {error}</div>}

      {status === "ready" && events.length === 0 && (
        <div style={S.empty} data-testid="timeline-empty">
          No timestamped events available for this input. Narrative-only
          MITRE techniques appear in the MITRE / Attack Chain panels.
        </div>
      )}

      {status === "ready" && events.length > 0 && (
        <>
          {summary && <div style={S.sub} data-testid="timeline-summary">{summary}</div>}
          <div style={S.list} data-testid="timeline-list">
            {events.map((ev, i) => (
              <TimelineRow
                key={`${ev.timestamp}-${ev.evidence_ref || i}`}
                ev={ev}
                idx={i}
                open={openIdx === i}
                onToggle={() => setOpenIdx(openIdx === i ? -1 : i)}
              />
            ))}
          </div>
        </>
      )}
    </div>
  );
}
