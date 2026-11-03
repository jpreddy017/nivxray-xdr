/**
 * NivXForge EDR · Dashboard body (approved mockup composition).
 *
 * Two questions share this screen and are deliberately NOT mixed:
 *   · Fleet status is the latest read of the fleet. Choosing a historical
 *     range never relabels today's blind endpoints as a past measurement.
 *   · Sightings, activity and event history are historical, selected on the
 *     time the ENDPOINT observed them.
 *
 * Counting happens before limiting, and every cap says what it capped.
 */
import { Calendar, Camera, FileText, FolderOpen, Laptop, Loader2,
         Monitor, Play, RefreshCw, Search, Terminal, TriangleAlert } from "lucide-react";
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";

import { TelemetryFreshnessBanner } from "@/nivxforge/components/TelemetryFreshness";
import { dashboardBoard, dashboardFleet } from "@/nivxforge/edrApi";

const DAY = 86400000;
const utc = (iso, len = 19) => {
  if (!iso) return "—";
  try { return new Date(iso).toISOString().replace("T", " ").slice(0, len) + "Z"; }
  catch { return String(iso); }
};
const dayLabel = (ms) => new Date(ms).toISOString().slice(0, 10);

const TREEMAP = ["#2f7fd1", "#2f9e8f", "#4a68c4", "#2f8fae", "#5b5fb5",
                 "#3b8f6b", "#6a6f7a", "#44719e", "#4f8f8f", "#5d6f9e"];

const Panel = ({ title, right, children, testid, style }) => (
  <section data-testid={testid}
           style={{ border: "1px solid rgba(140,150,165,.22)", borderRadius: 10,
                    padding: "14px 16px", background: "rgba(255,255,255,.015)",
                    minWidth: 0, ...style }}>
    <div style={{ display: "flex", justifyContent: "space-between",
                  alignItems: "center", gap: 12, marginBottom: 12 }}>
      <h2 style={{ fontSize: 14, margin: 0, letterSpacing: "-.005em" }}>{title}</h2>
      {right}
    </div>
    {children}
  </section>
);

export default function EdrDashboardBody({ device = null }) {
  // 14-day default, per the settled decision; the picker reaches older ranges.
  const [range, setRange] = useState(() => {
    const end = Date.now();
    return { start: end - 14 * DAY, end };
  });
  const [sha, setSha] = useState(null);
  const [pathFilter, setPathFilter] = useState("");
  const [activity, setActivity] = useState("ALL");
  const [auto, setAuto] = useState(false);
  const [diag, setDiag] = useState(false);

  const [fleet, setFleet] = useState(null);
  const [board, setBoard] = useState(null);
  const [lastOk, setLastOk] = useState(null);
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState(false);

  // A slow answer for the previous customer or range must never repopulate the
  // board, so every read carries a sequence number and late ones are dropped.
  const seq = useRef(0);

  const load = useCallback(() => {
    const mine = ++seq.current;
    setBusy(true);
    const start = new Date(range.start).toISOString();
    const end = new Date(range.end).toISOString();
    Promise.allSettled([
      dashboardFleet(),
      dashboardBoard({ start, end, sha256: sha, path_contains: pathFilter,
                       activity, limit: 100 }),
    ]).then(([f, b]) => {
      if (mine !== seq.current) return;          // a newer read won
      if (f.status === "fulfilled") setFleet(f.value.fleet);
      else setFleet({ unavailable: String(f.reason?.response?.data?.detail?.reason
                                          || f.reason?.message || f.reason) });
      if (b.status === "fulfilled") {
        setBoard(b.value);
        setErr(b.value.ok ? null : b.value);
        if (b.value.ok) setLastOk(new Date().toISOString());
      } else {
        setErr({ reason: String(b.reason?.response?.data?.detail?.reason
                                || b.reason?.message || b.reason) });
      }
    }).finally(() => { if (mine === seq.current) setBusy(false); });
  }, [range.start, range.end, sha, pathFilter, activity]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (!auto) return;
    const t = setInterval(load, 60000);          // once per minute
    return () => clearInterval(t);
  }, [auto, load]);

  // Six tiles are readable; ten truncate their own labels.
  const files = (board?.files || []).slice(0, 6);
  const sel = board?.selected_file || null;
  const total = files.reduce((n, f) => n + f.sightings, 0) || 1;
  const maxAct = Math.max(1, ...Object.values(sel?.activities || { x: 1 }));

  const investigateHref = (r) => {
    const q = new URLSearchParams({ device: r.endpoint_id, at: r.observed_at });
    if (r.sha256) q.set("sha256", r.sha256);
    if (r.raw_id) q.set("sighting", r.raw_id);
    if (board?.tenant_id) q.set("tenant", board.tenant_id);
    // Returning lands back on the same board: range, file and filters are the
    // dashboard's own URL-free state, so nothing is lost by opening a new tab.
    return `/edr/device-trajectory?${q.toString()}`;
  };

  const activities = useMemo(
    () => ["ALL", ...(board?.activities_available || [])], [board]);

  return (
    <div data-testid="edr-dashboard" style={{ display: "grid", gap: 12 }}>
      {/* ── controls ─────────────────────────────────────────────────────── */}
      <div style={{ display: "flex", justifyContent: "space-between",
                    alignItems: "center", gap: 12, flexWrap: "wrap" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
          <button className="x-btn" onClick={load} data-testid="dash-refresh"
                  style={{ fontSize: 12.5, height: 34 }}>
            {busy ? <Loader2 size={13} className="x-spin" /> : <RefreshCw size={13} />} Refresh
          </button>
          <label style={{ display: "flex", alignItems: "center", gap: 7, fontSize: 12.5 }}>
            <input type="checkbox" checked={auto} data-testid="dash-auto-refresh"
                   onChange={(e) => setAuto(e.target.checked)} />
            Auto-refresh
          </label>
          <span style={{ fontSize: 11.5, opacity: 0.6 }} data-testid="dash-last-ok">
            {lastOk ? `Last successful refresh ${utc(lastOk, 16)}` : "Not refreshed yet"}
          </span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <Calendar size={14} style={{ opacity: 0.6 }} />
          <input type="date" value={dayLabel(range.start)} data-testid="dash-range-start"
                 onChange={(e) => setRange((r) => ({
                   ...r, start: Date.parse(`${e.target.value}T00:00:00Z`) }))}
                 style={{ fontSize: 12.5, height: 34 }} />
          <span style={{ opacity: 0.5 }}>–</span>
          <input type="date" value={dayLabel(range.end)} data-testid="dash-range-end"
                 onChange={(e) => setRange((r) => ({
                   ...r, end: Date.parse(`${e.target.value}T23:59:59Z`) }))}
                 style={{ fontSize: 12.5, height: 34 }} />
          <span style={{ fontSize: 11.5, opacity: 0.6 }}>UTC</span>
          <button className="x-btn" data-testid="dash-range-14d" style={{ fontSize: 11.5, height: 34 }}
                  onClick={() => setRange({ start: Date.now() - 14 * DAY, end: Date.now() })}>
            14 days
          </button>
        </div>
      </div>

      {/* ── fleet condition band: CURRENT state, never the date range ────── */}
      {fleet && (
        <div data-testid="dash-fleet-band" data-condition={fleet.condition || "UNAVAILABLE"}
             style={{ display: "flex", alignItems: "center", gap: 10,
                      border: `1px solid ${fleet.condition === "DELIVERING"
                        ? "rgba(63,174,125,.45)" : "rgba(208,135,0,.55)"}`,
                      background: fleet.condition === "DELIVERING"
                        ? "rgba(63,174,125,.07)" : "rgba(208,135,0,.08)",
                      borderRadius: 8, padding: "9px 14px", fontSize: 13 }}>
          <TriangleAlert size={15} style={{ color: "var(--amber, #d08700)", flexShrink: 0 }} />
          <span style={{ fontWeight: 600 }}>
            {fleet.unavailable ? "Fleet state unavailable" : fleet.headline}
          </span>
          <span style={{ opacity: 0.65, fontSize: 12 }}>
            {fleet.unavailable
              ? `· ${fleet.unavailable}`
              : `· latest fleet read ${utc(fleet.last_read_at, 16)}, not the selected date range`}
          </span>
          <button type="button" data-testid="dash-diagnostics"
                  aria-expanded={diag} onClick={() => setDiag((d) => !d)}
                  style={{ marginLeft: "auto", fontSize: 12.5, background: "none",
                           border: 0, cursor: "pointer", color: "inherit",
                           textDecoration: "underline" }}>
            Diagnostics
          </button>
        </div>
      )}

      {/* The existing pipeline explanation, in full, on request. */}
      {diag && (
        <div data-testid="dash-diagnostics-panel">
          <TelemetryFreshnessBanner endpoint={device} />
        </div>
      )}

      {err && (
        <div className="x-error" data-testid="dash-error">
          {err.note || err.reason || "the board could not be read"}
          {lastOk && ` · showing data from the last successful refresh ${utc(lastOk, 16)}`}
        </div>
      )}

      {/* ── main row 38 / 38 / 24 ────────────────────────────────────────── */}
      <div style={{ display: "grid", gap: 12,
                    gridTemplateColumns: "minmax(0,38fr) minmax(0,38fr) minmax(0,24fr)" }}>
        <Panel testid="dash-files" title="Sightings by file"
               right={<span style={{ fontSize: 11.5, opacity: 0.6 }}
                            data-testid="dash-files-note">{board
                              ? `Top ${files.length} files by sightings${
                                  board.files_total > files.length
                                    ? ` of ${board.files_total} in range` : ""}`
                              : ""}</span>}>
          {!files.length ? (
            <div className="x-empty" data-testid="dash-files-empty">
              No sighting carries a file digest in this range. The read succeeded.
            </div>
          ) : (
            <div style={{ display: "flex", height: 232, gap: 2 }} data-testid="dash-treemap">
              {files.map((f, i) => (
                <button key={f.sha256} type="button"
                        data-testid={`dash-file-${i}`} data-sha256={f.sha256}
                        data-selected={f.sha256 === sel?.sha256 ? "1" : "0"}
                        aria-pressed={f.sha256 === sel?.sha256}
                        title={`${f.name} · ${f.sightings} sightings · ${f.sha256}`}
                        onClick={() => setSha(f.sha256)}
                        style={{ flex: `${Math.max(f.sightings / total, 0.05)} 1 0`,
                                 minWidth: 46, border: f.sha256 === sel?.sha256
                                   ? "2px solid #cfe6ff" : "1px solid rgba(0,0,0,.25)",
                                 borderRadius: 4, cursor: "pointer", color: "#f2f6fb",
                                 background: TREEMAP[i % TREEMAP.length],
                                 display: "flex", flexDirection: "column",
                                 alignItems: "flex-start", justifyContent: "flex-end",
                                 padding: "10px 11px", overflow: "hidden", textAlign: "left" }}>
                  <span style={{ fontSize: 14, fontWeight: 600, whiteSpace: "nowrap" }}>{f.name}</span>
                  <span style={{ fontSize: 13, opacity: 0.92 }}>{f.sightings}</span>
                </button>
              ))}
            </div>
          )}
        </Panel>

        <Panel testid="dash-activity"
               title={sel ? `Activity for ${sel.name}` : "Activity"}>
          {!sel ? (
            <div className="x-empty">Select a file to see its recorded activity.</div>
          ) : (
            <>
              <div style={{ display: "grid", gap: 10 }} data-testid="dash-activity-bars">
                {Object.entries(sel.activities).map(([k, v]) => (
                  <div key={k} style={{ display: "flex", alignItems: "center", gap: 10 }}
                       data-testid={`dash-activity-${k.replace(/\s+/g, "-").toLowerCase()}`}
                       data-count={v}>
                    <span style={{ width: 128, fontSize: 12.5, flexShrink: 0 }}>{k}</span>
                    <span style={{ flex: 1, height: 13, background: "rgba(140,150,165,.14)",
                                   borderRadius: 3, overflow: "hidden" }}>
                      <span style={{ display: "block", height: "100%",
                                     width: `${Math.max(2, (v / maxAct) * 100)}%`,
                                     background: "#2f7fd1" }} />
                    </span>
                    <span className="mono" style={{ width: 54, textAlign: "right", fontSize: 12.5 }}>{v}</span>
                  </div>
                ))}
              </div>
              <div style={{ borderTop: "1px solid rgba(140,150,165,.18)", marginTop: 14,
                            paddingTop: 12, display: "grid", gap: 8, fontSize: 12.5 }}>
                <span style={{ display: "flex", alignItems: "center", gap: 9 }} data-testid="dash-paths">
                  <FolderOpen size={14} style={{ opacity: 0.65 }} />
                  {sel.recorded_paths} recorded path{sel.recorded_paths === 1 ? "" : "s"}
                </span>
                <span style={{ display: "flex", alignItems: "center", gap: 9 }} data-testid="dash-computers">
                  <Monitor size={14} style={{ opacity: 0.65 }} />
                  {sel.computers} computer{sel.computers === 1 ? "" : "s"}
                </span>
              </div>
              <p style={{ fontSize: 11, opacity: 0.6, marginTop: 10, lineHeight: 1.6 }}
                 data-testid="dash-observation-note">{sel.observation_note}</p>
            </>
          )}
        </Panel>

        <div style={{ display: "grid", gap: 12, alignContent: "start", minWidth: 0 }}>
          <Panel testid="dash-fleet-status" title="Fleet status">
            {fleet?.unavailable ? (
              <div className="x-empty" data-testid="dash-fleet-unavailable">
                Unavailable · {fleet.unavailable}
              </div>
            ) : fleet ? (
              <>
                <dl style={{ display: "grid", gridTemplateColumns: "1fr auto",
                             gap: "7px 10px", margin: 0, fontSize: 13 }}>
                  {[["Enrolled", fleet.enrolled], ["Delivering", fleet.delivering],
                    ["Stale", fleet.stale], ["Blind", fleet.blind]].map(([k, v]) => (
                      <React.Fragment key={k}>
                        <dt style={{ opacity: 0.75 }}>{k}</dt>
                        <dd className="mono" data-testid={`dash-fleet-${k.toLowerCase()}`}
                            style={{ margin: 0, textAlign: "right" }}>{v}</dd>
                      </React.Fragment>))}
                </dl>
                <p style={{ fontSize: 11, opacity: 0.6, marginTop: 10 }} data-testid="dash-fleet-read">
                  Last successful read {utc(fleet.last_read_at, 16)}
                </p>
              </>
            ) : <div className="x-empty">Reading fleet state…</div>}
          </Panel>

          <Panel testid="dash-tools" title="Investigation tools">
            <div style={{ display: "grid", gap: 9, fontSize: 13 }}>
              {[[FileText, "Files", "/edr/files"],
                [Laptop, "Device Trajectory", "/edr/device-trajectory"],
                [Camera, "Forensic Snapshots", "/edr/forensics"],
                [Play, "Live Query", "/edr/live-query"],
                [Search, "Search", "/edr/search"]].map(([Icon, label, to]) => (
                  <Link key={to} to={to} data-testid={`dash-tool-${label.replace(/\s+/g, "-").toLowerCase()}`}
                        style={{ display: "flex", alignItems: "center", gap: 9 }}>
                    <Icon size={14} style={{ opacity: 0.7 }} /> {label}
                  </Link>))}
            </div>
            <p style={{ fontSize: 11, opacity: 0.55, marginTop: 10 }}>
              Snapshots and Live Query ask a computer directly, so they open with the
              computer you select there.
            </p>
          </Panel>
        </div>
      </div>

      {/* ── event history ────────────────────────────────────────────────── */}
      <Panel testid="dash-events" title="Event history"
             right={<span style={{ fontSize: 11.5, opacity: 0.65 }} data-testid="dash-events-note">
               {board?.events_note || ""}
             </span>}>
        <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 10,
                      flexWrap: "wrap" }}>
          <input value={pathFilter} onChange={(e) => setPathFilter(e.target.value)}
                 data-testid="dash-path-filter" aria-label="Filter by path"
                 placeholder="Filter by path (e.g. /usr/bin/sleep)" className="mono"
                 style={{ maxWidth: 360, fontSize: 12.5, height: 34 }} />
          <label style={{ fontSize: 12.5, display: "flex", alignItems: "center", gap: 7 }}>
            Activity:
            <select value={activity} onChange={(e) => setActivity(e.target.value)}
                    data-testid="dash-activity-filter" style={{ fontSize: 12.5, height: 34 }}>
              {activities.map((a) => (
                <option key={a} value={a}>{a === "ALL" ? "All activities" : a}</option>
              ))}
            </select>
          </label>
          {sha && (
            <button className="x-btn" data-testid="dash-clear-file" style={{ fontSize: 11.5, height: 34 }}
                    onClick={() => setSha(null)}>
              Clear file selection
            </button>
          )}
        </div>
        {!board?.events?.length ? (
          <div className="x-empty" data-testid="dash-events-empty">
            {board?.ok === false
              ? board.note
              : "No sighting matches this range and these filters. The read succeeded and returned nothing."}
          </div>
        ) : (
          <table data-testid="dash-events-table"
                 style={{ width: "100%", borderCollapse: "collapse", fontSize: 14,
                          tableLayout: "fixed" }}>
            <thead>
              <tr style={{ textAlign: "left", fontSize: 11.5, opacity: 0.62 }}>
                <th style={{ padding: "7px 12px 9px 0", width: 180 }}>Observed (UTC)</th>
                <th style={{ padding: "7px 12px 9px 0", width: 200 }}>Computer</th>
                <th style={{ padding: "7px 12px 9px 0" }}>Path</th>
                <th style={{ padding: "7px 12px 9px 0", width: 150 }}>Activity</th>
                <th style={{ padding: "7px 12px 9px 0", width: 80 }}>PID</th>
                <th style={{ padding: "7px 0 9px 0", width: 110 }}>Investigate</th>
              </tr>
            </thead>
            <tbody>
              {board.events.map((r) => (
                <tr key={r.raw_id} data-testid={`dash-event-${r.raw_id}`} data-raw-id={r.raw_id}
                    style={{ borderTop: "1px solid rgba(140,150,165,.16)", height: 34 }}>
                  <td className="mono" style={{ padding: "6px 12px 6px 0" }}>{utc(r.observed_at)}</td>
                  <td className="mono" style={{ padding: "6px 12px 6px 0", overflow: "hidden",
                                                textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                      title={r.endpoint_id}>{r.endpoint_id}</td>
                  <td className="mono" style={{ padding: "6px 12px 6px 0", overflow: "hidden",
                                                textOverflow: "ellipsis", whiteSpace: "nowrap" }}
                      title={r.path || "no path recorded"}>{r.path || "—"}</td>
                  <td style={{ padding: "6px 12px 6px 0" }}>{r.activity_label}</td>
                  <td className="mono" style={{ padding: "6px 12px 6px 0" }}>{r.pid ?? "—"}</td>
                  <td style={{ padding: "6px 0" }}>
                    <Link to={investigateHref(r)} target="_blank" rel="noopener noreferrer"
                          data-testid={`dash-investigate-${r.raw_id}`}>Investigate ›</Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {board?.scan && (
          <p style={{ fontSize: 11, opacity: 0.58, marginTop: 10, lineHeight: 1.6 }}
             data-testid="dash-scan-note">
            {board.scan.note} · {board.scan.observed_basis}
          </p>
        )}
      </Panel>
    </div>
  );
}
