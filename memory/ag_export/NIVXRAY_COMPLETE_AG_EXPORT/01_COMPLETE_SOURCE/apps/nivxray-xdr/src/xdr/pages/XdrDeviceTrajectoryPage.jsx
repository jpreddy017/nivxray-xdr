/**
 * XdrDeviceTrajectoryPage · Slice 6 — Native XDR Device Trajectory
 *
 * 3-pane analyst canvas at `/xdr/endpoints/:device/trajectory`.
 *   Left  — Device Activity inventory (per-lane counts + top entities).
 *   Center— Hybrid Canvas + SVG timeline (density + interactive markers).
 *   Right — Activity Details for the selected event, with Slice 1 pivots.
 *
 * Consumes:
 *   GET /api/edr/device-trajectory?device=<host>&hours=<hours>
 * which is a READ-ONLY aggregation over existing workspace_cases.
 * No fake events.  Empty windows are surfaced honestly.
 */
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  Loader2, HardDrive, ChevronLeft, RefreshCcw,
  ShieldAlert, GitBranch, FileText, Wifi, Terminal, Layers,
} from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import TrajectoryTimelineCanvas from "@/xdr/components/TrajectoryTimelineCanvas";
import Pivot from "@/xdr/components/Pivot";
import { getDeviceTrajectory } from "@/nivxforge/edrApi";

const WINDOWS = [
  { key: 1,   label: "1h"  },
  { key: 6,   label: "6h"  },
  { key: 12,  label: "12h" },
  { key: 24,  label: "24h" },
  { key: 72,  label: "3d"  },
  { key: 168, label: "7d"  },
];

const LANE_ICONS = {
  system:   Layers,
  process:  GitBranch,
  file:     FileText,
  network:  Wifi,
  registry: Terminal,
};

function fmtTs(iso) {
  if (!iso) return "—";
  try { return new Date(iso).toISOString().replace("T", " ").slice(0, 19) + "Z"; }
  catch { return iso; }
}
function fmtRelative(iso, now = Date.now()) {
  if (!iso) return "";
  const t = new Date(iso).getTime();
  const delta = Math.max(0, now - t);
  const mins = Math.floor(delta / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export default function XdrDeviceTrajectoryPage() {
  const { device } = useParams();
  const navigate = useNavigate();
  const [hours, setHours]     = useState(24);
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);
  const [selectedId, setSelectedId] = useState(null);
  const [activeLanes, setActiveLanes] = useState(
    () => new Set(["system", "process", "file", "network", "registry"]),
  );

  const decoded = decodeURIComponent(device || "");

  const load = useCallback(async () => {
    if (!decoded) return;
    setLoading(true); setError(null);
    try {
      const res = await getDeviceTrajectory(decoded, hours);
      setData(res);
      // Preserve selection if still in view; otherwise clear.
      if (selectedId && !(res.events || []).some((e) => e.id === selectedId)) {
        setSelectedId(null);
      }
    } catch (e) {
      setError(e?.response?.data?.detail || e?.message || "Failed to load trajectory.");
      setData(null);
    } finally {
      setLoading(false);
    }
  }, [decoded, hours]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => { load(); }, [load]);

  const lanes      = data?.lanes || ["system","process","file","network","registry"];
  const laneCounts = data?.lane_counts || {};
  const events     = data?.events || [];
  const incidents  = data?.incidents || [];

  const selectedEvent = useMemo(
    () => events.find((e) => e.id === selectedId) || null,
    [events, selectedId],
  );

  const toggleLane = (lane) => {
    setActiveLanes((prev) => {
      const next = new Set(prev);
      if (next.has(lane)) next.delete(lane);
      else next.add(lane);
      return next;
    });
  };

  const topEntitiesByLane = useMemo(() => {
    const buckets = {};
    for (const lane of lanes) buckets[lane] = [];
    for (const e of events) {
      if (!buckets[e.lane]) buckets[e.lane] = [];
      buckets[e.lane].push(e);
    }
    // Trim to 6 per lane, newest first.
    for (const k of Object.keys(buckets)) {
      buckets[k] = buckets[k]
        .slice()
        .sort((a, b) => (b.timestamp || "").localeCompare(a.timestamp || ""))
        .slice(0, 6);
    }
    return buckets;
  }, [lanes, events]);

  return (
    <XdrShell>
      {/* ── Sub-header ─────────────────────────────────────── */}
      <div style={{ display: "flex", alignItems: "center", gap: 10,
                      flexWrap: "wrap", marginBottom: 8 }}
            data-testid="xdr-trajectory-header">
        <button
          className="btn ghost"
          style={{ padding: "4px 8px" }}
          onClick={() => navigate("/xdr/endpoints")}
          data-testid="xdr-trajectory-back"
        >
          <ChevronLeft size={12} /> Endpoints
        </button>
        <h1 className="page-h1" style={{ margin: 0 }}
             data-testid="xdr-trajectory-heading">
          <HardDrive size={14} style={{ color: "var(--mint)",
                                              verticalAlign: "middle",
                                              marginRight: 8 }} />
          {decoded}
        </h1>
        <span className="mono" style={{ color: "var(--faint)" }}>
          · Device Trajectory
        </span>
        <div style={{ flex: 1 }} />
        <div style={{ display: "flex", gap: 4 }}
             data-testid="xdr-trajectory-window-controls">
          {WINDOWS.map((w) => (
            <button
              key={w.key}
              className={`btn qf ${hours === w.key ? "primary" : ""}`}
              onClick={() => setHours(w.key)}
              data-testid={`xdr-trajectory-window-${w.key}`}
              title={`Last ${w.label}`}
            >
              {w.label}
            </button>
          ))}
        </div>
        <button
          className="btn"
          style={{ padding: "4px 10px" }}
          onClick={load}
          data-testid="xdr-trajectory-refresh"
          title="Refresh"
        >
          <RefreshCcw size={11} /> Refresh
        </button>
      </div>
      <div className="page-sub" data-testid="xdr-trajectory-subtitle">
        Native XDR canvas · aggregated from{" "}
        <span style={{ color: "var(--cyan)" }}>
          workspace_cases.verdict_stage2.evidence[] · ActivityInventory
        </span>{" "}
        · window <b>Last {WINDOWS.find((w)=>w.key===hours)?.label || `${hours}h`}</b>
      </div>

      {/* ── Body: 3-pane layout ────────────────────────────── */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "260px 1fr 340px",
          gap: 12,
          minHeight: 520,
        }}
        data-testid="xdr-trajectory-panes"
      >
        {/* Left pane — Device Activity Inventory */}
        <aside className="panel" style={{ padding: 10, overflow: "auto" }}
                data-testid="xdr-trajectory-left">
          <div className="section-title" style={{ marginBottom: 8 }}>
            Device Activity
          </div>
          {lanes.map((lane) => {
            const Icon = LANE_ICONS[lane] || Layers;
            const count = laneCounts[lane] || 0;
            const active = activeLanes.has(lane);
            const items = topEntitiesByLane[lane] || [];
            return (
              <div key={lane} style={{ marginBottom: 10 }}
                   data-testid={`xdr-trajectory-lane-${lane}`}>
                <button
                  className="btn"
                  style={{
                    width: "100%", justifyContent: "flex-start",
                    padding: "5px 8px",
                    borderColor: active ? "var(--mint)" : "var(--border)",
                    color: active ? "var(--mint)" : "var(--text-dim)",
                  }}
                  onClick={() => toggleLane(lane)}
                  data-testid={`xdr-trajectory-lane-toggle-${lane}`}
                  title={active ? "Hide from canvas" : "Show on canvas"}
                >
                  <Icon size={12} />
                  <span style={{ flex: 1, textAlign: "left", textTransform: "uppercase",
                                    letterSpacing: ".3px" }}>
                    {lane}
                  </span>
                  <span className="mono" style={{ color: "var(--faint)" }}>
                    {count}
                  </span>
                </button>
                {items.length > 0 && active && (
                  <div style={{ marginTop: 4, paddingLeft: 4 }}>
                    {items.map((it) => (
                      <button
                        key={it.id}
                        type="button"
                        className="btn ghost"
                        style={{
                          width: "100%", justifyContent: "flex-start",
                          padding: "3px 6px", borderRadius: 3, borderColor: "transparent",
                          color: selectedId === it.id ? "var(--mint)" : "var(--text-dim)",
                          background: selectedId === it.id ? "rgba(60,232,184,0.06)" : "transparent",
                        }}
                        onClick={() => setSelectedId(it.id)}
                        data-testid={`xdr-trajectory-lane-item-${it.id}`}
                        title={it.title}
                      >
                        <span className="mono" style={{
                          flex: 1, textAlign: "left", overflow: "hidden",
                          textOverflow: "ellipsis", whiteSpace: "nowrap",
                          fontSize: 10.8,
                        }}>
                          {(it.title || it.rule_id || "event").slice(0, 30)}
                        </span>
                        <span className="mono" style={{
                          color: "var(--faint)", fontSize: 9.5,
                        }}>
                          {fmtRelative(it.timestamp)}
                        </span>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
          <div style={{
            borderTop: "1px solid var(--border)", marginTop: 8, paddingTop: 8,
          }}>
            <div className="section-title" style={{ marginBottom: 6 }}>
              Incidents in window ({incidents.length})
            </div>
            {incidents.length === 0 && (
              <div style={{ fontSize: 10.5, color: "var(--faint)" }}
                   data-testid="xdr-trajectory-incidents-empty">
                NO MATCHING EVIDENCE
              </div>
            )}
            {incidents.slice(0, 6).map((inc) => (
              <Link
                key={inc.incident_id}
                to={`/xdr/incidents/${inc.incident_id}`}
                className="btn ghost"
                style={{
                  width: "100%", justifyContent: "flex-start",
                  padding: "3px 6px", borderRadius: 3, borderColor: "transparent",
                  color: "var(--cyan)", textDecoration: "none",
                }}
                data-testid={`xdr-trajectory-incident-link-${inc.incident_id}`}
                title={inc.name || inc.incident_id}
              >
                <span className="mono" style={{
                  flex: 1, textAlign: "left", overflow: "hidden",
                  textOverflow: "ellipsis", whiteSpace: "nowrap",
                  fontSize: 10.8,
                }}>
                  {(inc.name || inc.incident_id || "").slice(0, 28)}
                </span>
                <span className="mono" style={{
                  color: "var(--faint)", fontSize: 9.5,
                }}>
                  {(inc.verdict || "?").slice(0, 4).toUpperCase()}
                </span>
              </Link>
            ))}
          </div>
        </aside>

        {/* Center pane — Timeline Canvas */}
        <section className="panel"
                    style={{ overflow: "hidden", position: "relative", padding: 0 }}
                    data-testid="xdr-trajectory-center">
          <div style={{
            padding: "8px 12px", borderBottom: "1px solid var(--border)",
            display: "flex", alignItems: "center", gap: 10,
            background: "var(--panel2)",
          }}>
            <div className="section-title">Timeline · Canvas</div>
            <div style={{ flex: 1 }} />
            <span className="mono" style={{ color: "var(--faint)", fontSize: 10.5 }}
                   data-testid="xdr-trajectory-event-count">
              {events.filter((e) => activeLanes.has(e.lane)).length} events
            </span>
          </div>
          {loading && (
            <div className="x-empty" data-testid="xdr-trajectory-loading">
              <Loader2 size={13} className="spin"
                        style={{ verticalAlign: "middle", marginRight: 6 }} />
              Loading trajectory…
            </div>
          )}
          {!loading && error && (
            <div className="x-empty" style={{ color: "#ff9494" }}
                  data-testid="xdr-trajectory-error">{String(error)}</div>
          )}
          {!loading && !error && data && events.length === 0 && (
            <div className="x-empty" data-testid="xdr-trajectory-empty">
              <b>NO MATCHING EVIDENCE</b>
              <div style={{ marginTop: 4 }}>
                No detections or activity for {decoded} in the selected window.
              </div>
            </div>
          )}
          {!loading && !error && data && events.length > 0 && (
            <div style={{ padding: 8 }}>
              <TrajectoryTimelineCanvas
                events={events}
                lanes={lanes}
                laneCounts={laneCounts}
                windowStart={data.window_start}
                windowEnd={data.window_end}
                activeLanes={activeLanes}
                selectedId={selectedId}
                onSelect={(evt) => setSelectedId(evt.id)}
              />
            </div>
          )}
        </section>

        {/* Right pane — Activity Details */}
        <aside className="panel" style={{ padding: 12, overflow: "auto" }}
                data-testid="xdr-trajectory-right">
          <div className="section-title" style={{ marginBottom: 10 }}>
            Activity Details
          </div>
          {!selectedEvent && (
            <div className="x-empty" style={{ padding: 20 }}
                  data-testid="xdr-trajectory-details-empty">
              Select an event on the canvas to see details.
            </div>
          )}
          {selectedEvent && (
            <ActivityDetails
              event={selectedEvent}
              deviceHost={decoded}
              onClose={() => setSelectedId(null)}
            />
          )}
        </aside>
      </div>
    </XdrShell>
  );
}

// ── Activity details pane ─────────────────────────────────────────
function ActivityDetails({ event, deviceHost, onClose }) {
  const ctx = { incident_id: event.incident_id };
  const isDetection = event.kind === "detection";

  return (
    <div data-testid={`xdr-trajectory-details-${event.id}`}
          style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      <div style={{ display: "flex", alignItems: "flex-start", gap: 8 }}>
        {isDetection
          ? <ShieldAlert size={14} style={{ color: "var(--amber)", marginTop: 2 }} />
          : <GitBranch  size={14} style={{ color: "var(--cyan)",  marginTop: 2 }} />}
        <div style={{ flex: 1 }}>
          <div style={{ color: "var(--text)", fontWeight: 700, fontSize: 13 }}>
            {event.title || event.rule_id || "Event"}
          </div>
          <div className="mono" style={{ color: "var(--faint)", fontSize: 10.5,
                                                marginTop: 2 }}>
            {event.lane.toUpperCase()} · {event.kind.toUpperCase()}
          </div>
        </div>
        <button
          className="btn ghost" style={{ padding: 4 }}
          onClick={onClose} title="Close"
          data-testid="xdr-trajectory-details-close"
        >
          ×
        </button>
      </div>

      <DetailRow k="Timestamp"
                    v={<span className="mono">{fmtTs(event.timestamp)}</span>} />
      {event.last_seen && (
        <DetailRow k="Last seen"
                      v={<span className="mono">{fmtTs(event.last_seen)}</span>} />
      )}
      {isDetection && (
        <>
          <DetailRow k="Severity"
                        v={<span className={`badge sev-${event.severity || "info"}`}>
                             {event.severity || "info"}
                           </span>} />
          <DetailRow k="Rule"
                        v={<Pivot kind="rule" value={event.rule_id}
                                    ctx={ctx}
                                    testid={`xdr-trajectory-pivot-rule-${event.id}`} />} />
          <DetailRow k="Detected by"
                        v={<span className="mono" style={{ color: "var(--mint)" }}>
                             {event.detected_by || "—"}
                           </span>} />
          <DetailRow k="Disposition"
                        v={<span className="mono" style={{
                                textTransform: "uppercase",
                                color: event.disposition === "malicious"
                                        ? "#ff9494" : "var(--text-dim)",
                              }}>
                             {event.disposition || "—"}
                           </span>} />
        </>
      )}
      <DetailRow k="Device"
                    v={<Pivot kind="host" value={event.device || deviceHost}
                                ctx={ctx}
                                testid={`xdr-trajectory-pivot-host-${event.id}`} />} />
      {event.process && (
        <DetailRow k="Process"
                      v={<Pivot kind="process" value={event.process} ctx={ctx}
                                  testid={`xdr-trajectory-pivot-process-${event.id}`} />} />
      )}
      {event.file && (
        <DetailRow k="File"
                      v={<Pivot kind="file" value={event.file} ctx={ctx}
                                  testid={`xdr-trajectory-pivot-file-${event.id}`} />} />
      )}
      {event.path && (
        <DetailRow k="Path"
                      v={<span className="mono" style={{ color: "var(--text-dim)",
                                                                fontSize: 10.5 }}
                                    title={event.path}>{event.path}</span>} />
      )}
      {event.user && (
        <DetailRow k="User"
                      v={<span className="mono">{event.user}</span>} />
      )}
      {event.command_line && (
        <DetailRow k="Command"
                      v={<span className="mono" style={{
                            color: "var(--text-dim)", fontSize: 10.5,
                            display: "block", wordBreak: "break-all",
                          }} title={event.command_line}>
                            {event.command_line.length > 200
                              ? event.command_line.slice(0, 200) + "…"
                              : event.command_line}
                          </span>} />
      )}
      <DetailRow k="Incident"
                    v={<Link
                          to={`/xdr/incidents/${event.incident_id}`}
                          className="mono"
                          style={{ color: "var(--cyan)", textDecoration: "none" }}
                          data-testid={`xdr-trajectory-details-incident-${event.id}`}
                        >
                          {event.incident_id}
                        </Link>} />
    </div>
  );
}

function DetailRow({ k, v }) {
  return (
    <div style={{ display: "grid", gridTemplateColumns: "84px 1fr", gap: 8,
                    alignItems: "baseline" }}>
      <div style={{ color: "var(--faint)", fontSize: 9.5, fontWeight: 800,
                      textTransform: "uppercase", letterSpacing: ".3px" }}>{k}</div>
      <div style={{ color: "var(--text-dim)", fontSize: 11.5 }}>{v}</div>
    </div>
  );
}
