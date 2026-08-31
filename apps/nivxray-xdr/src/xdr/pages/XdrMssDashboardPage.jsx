/**
 * XdrMssDashboardPage · `/xdr/mss-dashboard`
 *
 * NivXRay SOC Command Center — the operational "what's happening in
 * my SOC right now" surface.  Complements (does NOT replace) the
 * Analyst Operations dashboard at `/xdr/dashboard`.
 *
 * Sections (per owner directive · 2026-02-31):
 *   A. Triage KPI tiles                    → /api/xdr/mss/kpis
 *   B. State + priority distribution       → /api/xdr/mss/state-distribution
 *   C. Open High Priority SOC Queue        → /api/xdr/mss/soc-queue
 *   D. Analyst workload                    → /api/xdr/mss/analyst-workload
 *   E. Customer operations                 → /api/xdr/mss/customer-operations
 *   F. Auto-Investigation status           → /api/xdr/mss/auto-investigation
 *   G. Detection & MITRE overview          → /api/xdr/mss/detection-overview
 *   H. Recent activity                     → /api/xdr/mss/recent-activity
 *
 * Anti-fabrication rules:
 *   - Every count carries a `source` string.
 *   - Unavailable data renders a `SOURCE: UNAVAILABLE` chip, never a
 *     fabricated zero.
 *   - The page never invokes an investigation engine.
 */
import React, { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  AlertOctagon, AlertTriangle, Zap, UserX, UserCheck, MessageCircle,
  PauseCircle, Timer, Sparkles, Activity, RefreshCw, PieChart,
} from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import {
  getMssKpis, getMssStateDistribution, getMssSocQueue,
  getMssAnalystWorkload, getMssCustomerOperations,
  getMssAutoInvestigation, getMssDetectionOverview, getMssRecentActivity,
} from "@/lib/incidentsApi";


const LENS_ICON = {
  critical: AlertOctagon, high_priority: AlertTriangle, high_fidelity: Zap,
  unassigned: UserX, in_progress_mine: UserCheck,
  customer_response: MessageCircle, on_hold: PauseCircle, aging: Timer,
  recently_created: Sparkles, recently_updated: Activity,
};
const TONE = {
  red:   { fg: "#f87171", bg: "rgba(248,113,113,0.10)", ring: "rgba(248,113,113,0.35)" },
  amber: { fg: "#fbbf24", bg: "rgba(251,191,36,0.10)",  ring: "rgba(251,191,36,0.35)" },
  cyan:  { fg: "#22d3ee", bg: "rgba(34,211,238,0.10)",  ring: "rgba(34,211,238,0.30)" },
  mint:  { fg: "#4ade80", bg: "rgba(74,222,128,0.10)",  ring: "rgba(74,222,128,0.30)" },
};
const STATE_COLOR = {
  new:         "#22d3ee",
  in_progress: "#fbbf24",
  on_hold:     "#f472b6",
  resolved:    "#4ade80",
  closed:      "#a3a3a3",
};
const PRIO_COLOR = {
  P1: "#f87171", P2: "#fb923c", P3: "#fbbf24",
  P4: "#4ade80", P5: "#a3a3a3", unset: "#525252",
};


export default function XdrMssDashboardPage() {
  const navigate = useNavigate();
  const [kpi,   setKpi]   = useState(null);
  const [dist,  setDist]  = useState(null);
  const [queue, setQueue] = useState(null);
  const [work,  setWork]  = useState(null);
  const [cust,  setCust]  = useState(null);
  const [auto,  setAuto]  = useState(null);
  const [det,   setDet]   = useState(null);
  const [act,   setAct]   = useState(null);
  const [loading, setL]   = useState(true);
  const [error, setError] = useState(null);

  const load = useCallback(async () => {
    setL(true); setError(null);
    try {
      const [k, d, q, w, c, a, dt, ac] = await Promise.all([
        getMssKpis(), getMssStateDistribution(), getMssSocQueue(10),
        getMssAnalystWorkload(), getMssCustomerOperations(),
        getMssAutoInvestigation(), getMssDetectionOverview(),
        getMssRecentActivity(12),
      ]);
      setKpi(k); setDist(d); setQueue(q); setWork(w); setCust(c);
      setAuto(a); setDet(dt); setAct(ac);
    } catch (e) {
      setError(e?.response?.data?.detail || e?.message || "Load failed.");
    } finally { setL(false); }
  }, []);
  useEffect(() => { load(); }, [load]);

  return (
    <XdrShell activeTop="dashboards">
      <div style={headerRow}>
        <div>
          <h1 className="page-h1" data-testid="xdr-mss-dashboard-heading">
            MSS Dashboard
          </h1>
          <div className="page-sub" data-testid="xdr-mss-dashboard-sub">
            NivXRay SOC Command Center — triage · workload · customer
            operations · auto-investigation · detection & MITRE overview.
            Every count is a projection of real incident data.
          </div>
        </div>
        <button className="btn ghost"
                   data-testid="xdr-mss-dashboard-refresh"
                   onClick={load} disabled={loading}
                   style={{ padding: "6px 10px", fontSize: 11,
                            fontFamily: "var(--mono)" }}>
          <RefreshCw size={11}
                        style={loading ? { animation: "spin 0.9s linear infinite" } : {}} />
          {" "}Refresh
        </button>
      </div>

      {error && (
        <div className="x-empty"
              data-testid="xdr-mss-dashboard-error"
              style={{ color: "#ff9494" }}>{String(error)}</div>
      )}

      {loading && !kpi && (
        <div className="x-empty"
              data-testid="xdr-mss-dashboard-loading">LOADING…</div>
      )}

      {/* ═════════════ A · KPI TILES (10 lens tiles) ═════════════ */}
      {kpi?.groups?.map((g) => (
        <section key={g.id}
                    data-testid={`xdr-mss-kpi-group-${g.id}`}
                    style={{ marginTop: 18 }}>
          <div style={sectionLabel}>{g.label}</div>
          <div style={kpiGrid}>
            {g.tiles.map((t) => {
              const Icon = LENS_ICON[t.id] || AlertOctagon;
              const tone = TONE[t.tone] || TONE.cyan;
              return (
                <button key={t.id}
                             data-testid={`xdr-mss-kpi-tile-${t.id}`}
                             data-tile-count={t.count}
                             data-tile-source={t.count_source}
                             onClick={() => navigate(t.lens_href)}
                             style={{ ...kpiTile,
                                        borderColor: tone.ring,
                                        background: tone.bg }}>
                  <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                    <Icon size={12} style={{ color: tone.fg }} />
                    <span style={kpiLabel}>{t.label}</span>
                  </div>
                  <div style={{ ...kpiCount, color: tone.fg }}>{t.count}</div>
                  {t.count_source === "empty" && (
                    <div style={emptyChip}>NO SCOPE</div>
                  )}
                </button>
              );
            })}
          </div>
        </section>
      ))}

      {/* ═════════════ B · STATE / PRIORITY DISTRIBUTION ═════════════ */}
      {dist && (
        <section data-testid="xdr-mss-state-distribution" style={panelBox}>
          <div style={panelHeader}>
            <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <PieChart size={12} /> INCIDENT DISTRIBUTION
            </span>
            <span style={sourceChip} data-testid="xdr-mss-state-distribution-source">
              source: {dist.source} · total {dist.total}
            </span>
          </div>
          <div style={distRow}>
            <div style={{ flex: 1 }}>
              <div style={distTitle}>BY STATE</div>
              <BarStack data={Object.entries(dist.states).map(([k, v]) =>
                ({ key: k, count: v, color: STATE_COLOR[k] || "#525252" }))} />
            </div>
            <div style={{ flex: 1 }}>
              <div style={distTitle}>BY PRIORITY</div>
              <BarStack data={Object.entries(dist.priorities).map(([k, v]) =>
                ({ key: k, count: v, color: PRIO_COLOR[k] || "#525252" }))} />
            </div>
          </div>
        </section>
      )}

      {/* ═════════════ C · OPEN HIGH PRIORITY QUEUE ═════════════ */}
      {queue && (
        <section data-testid="xdr-mss-soc-queue" style={panelBox}>
          <div style={panelHeader}>
            <span>OPEN HIGH PRIORITY · {queue.count} rows</span>
            <span style={sourceChip} data-testid="xdr-mss-soc-queue-source">
              source: {queue.source}
            </span>
          </div>
          {queue.rows.length === 0 ? (
            <div className="x-empty"
                  data-testid="xdr-mss-soc-queue-empty">
              NO OPEN HIGH-PRIORITY INCIDENTS — honest empty state.
            </div>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table style={tbl}>
                <thead>
                  <tr>
                    {["ID","Title","Priority","Severity","Customer","Source",
                       "State","Owner","SLA","Verdict","Updated"].map(h =>
                      <th key={h} style={th}>{h}</th>)}
                  </tr>
                </thead>
                <tbody>
                  {queue.rows.map(r => (
                    <tr key={r.id}
                           data-testid={`xdr-mss-soc-queue-row-${r.id}`}
                           style={tr}
                           onClick={() => navigate(`/xdr/incidents/${r.id}`)}>
                      <td style={{ ...td, fontFamily: "var(--mono)" }}>{r.id?.slice(0,10)}…</td>
                      <td style={td}>{r.name}</td>
                      <td style={{ ...td, color: PRIO_COLOR[r.priority] || "var(--text)" }}>{r.priority}</td>
                      <td style={td}>{r.severity || "—"}</td>
                      <td style={td}>{r.customer}</td>
                      <td style={td}>{r.detection_source}</td>
                      <td style={{ ...td, color: STATE_COLOR[r.state] || "var(--text)" }}>{r.state}</td>
                      <td style={td}>{r.assignee || "—"}</td>
                      <td style={td}>{r.sla_due_at?.slice(0,16).replace("T"," ") || "—"}</td>
                      <td style={td}>{r.verdict || "—"}</td>
                      <td style={td}>{r.updated_at?.slice(0,16).replace("T"," ") || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      {/* ═════════════ D · ANALYST WORKLOAD ═════════════ */}
      <div style={twoCol}>
        {work && (
          <section data-testid="xdr-mss-analyst-workload" style={panelBox}>
            <div style={panelHeader}>
              <span>ANALYST WORKLOAD · {work.count}</span>
              <span style={sourceChip}>source: {work.source}</span>
            </div>
            {work.rows.length === 0 ? (
              <div className="x-empty"
                    data-testid="xdr-mss-analyst-workload-empty">
                NO OPEN ASSIGNMENTS
              </div>
            ) : (
              <table style={tbl}>
                <thead>
                  <tr>{["Analyst","Assigned","P1/P2","On Hold","SLA Risk"].map(h =>
                    <th key={h} style={th}>{h}</th>)}</tr>
                </thead>
                <tbody>
                  {work.rows.map(r => (
                    <tr key={r.analyst}
                           data-testid={`xdr-mss-analyst-workload-row-${r.analyst}`}
                           style={tr}
                           onClick={() => navigate(r.queue_href)}>
                      <td style={{ ...td, fontFamily: "var(--mono)" }}>{r.analyst}</td>
                      <td style={td}>{r.assigned}</td>
                      <td style={td}>{r.p1_p2}</td>
                      <td style={td}>{r.on_hold}</td>
                      <td style={{ ...td,
                        color: r.sla_risk > 0 ? "#f87171" : "var(--text-dim)" }}>
                        {r.sla_risk}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>
        )}

        {/* ═════════════ E · CUSTOMER OPERATIONS ═════════════ */}
        {cust && (
          <section data-testid="xdr-mss-customer-operations" style={panelBox}>
            <div style={panelHeader}>
              <span>CUSTOMER OPERATIONS · {cust.count}</span>
              <span style={sourceChip}>source: {cust.source}</span>
            </div>
            {cust.rows.length === 0 ? (
              <div className="x-empty"
                    data-testid="xdr-mss-customer-operations-empty">
                NO CUSTOMER DATA
              </div>
            ) : (
              <table style={tbl}>
                <thead>
                  <tr>{["Customer","Open","Critical","High","SLA","Unassigned"].map(h =>
                    <th key={h} style={th}>{h}</th>)}</tr>
                </thead>
                <tbody>
                  {cust.rows.map(r => (
                    <tr key={r.customer}
                           data-testid={`xdr-mss-customer-operations-row-${r.customer}`}
                           style={tr}>
                      <td style={{ ...td, fontFamily: "var(--mono)" }}>{r.customer}</td>
                      <td style={td}>{r.open}</td>
                      <td style={{ ...td, color: r.critical > 0 ? "#f87171" : "var(--text-dim)" }}>{r.critical}</td>
                      <td style={td}>{r.high_prio}</td>
                      <td style={{ ...td, color: r.sla_risk > 0 ? "#f87171" : "var(--text-dim)" }}>{r.sla_risk}</td>
                      <td style={{ ...td, color: r.unassigned > 0 ? "#fbbf24" : "var(--text-dim)" }}>{r.unassigned}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </section>
        )}
      </div>

      {/* ═════════════ F · AUTO-INVESTIGATION ═════════════ */}
      {auto && (
        <section data-testid="xdr-mss-auto-investigation" style={panelBox}>
          <div style={panelHeader}>
            <span>AUTO-INVESTIGATION</span>
            <span style={{
              ...sourceChip,
              color: auto.source === "unavailable" ? "#fbbf24" : "var(--text-dim)",
            }} data-testid="xdr-mss-auto-investigation-source">
              source: {auto.source}
              {auto.reason ? ` · ${auto.reason}` : ""}
            </span>
          </div>
          {auto.source === "unavailable" ? (
            <div className="x-empty"
                  data-testid="xdr-mss-auto-investigation-empty"
                  style={{ marginTop: 6 }}>
              <b>AWAITING PHASE 4 ENGINE-EXECUTION LEDGER</b> —
              this section is intentionally empty until the
              `engine_executions` collection ships.  It will NEVER
              show fabricated engine activity.
            </div>
          ) : (
            <>
              <div style={statusRow}>
                {["running","completed","awaiting_evidence","failed"].map(k => (
                  <div key={k} style={statusPill}
                          data-testid={`xdr-mss-auto-investigation-status-${k}`}>
                    <div style={statusPillLabel}>{k.replace("_", " ").toUpperCase()}</div>
                    <div style={statusPillValue}>{auto.status?.[k] ?? 0}</div>
                  </div>
                ))}
              </div>
              {auto.engines?.length > 0 && (
                <table style={tbl}>
                  <thead>
                    <tr>{["Engine","Runs","OK"].map(h => <th key={h} style={th}>{h}</th>)}</tr>
                  </thead>
                  <tbody>
                    {auto.engines.map(e => (
                      <tr key={e.engine} style={tr}
                            data-testid={`xdr-mss-auto-investigation-engine-${e.engine}`}>
                        <td style={{ ...td, fontFamily: "var(--mono)" }}>{e.engine}</td>
                        <td style={td}>{e.runs}</td>
                        <td style={td}>{e.ok}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </>
          )}
        </section>
      )}

      {/* ═════════════ G · DETECTION & MITRE ═════════════ */}
      <div style={twoCol}>
        {det && (
          <section data-testid="xdr-mss-detection-sources" style={panelBox}>
            <div style={panelHeader}>
              <span>TOP DETECTION SOURCES</span>
              <span style={sourceChip}>source: {det.source}</span>
            </div>
            {det.detection_sources.length === 0 ? (
              <div className="x-empty">NO DETECTION-SOURCE DATA</div>
            ) : (
              <BarList rows={det.detection_sources.map(x =>
                ({ label: x.source, count: x.count }))} color="#22d3ee" />
            )}
          </section>
        )}
        {det && (
          <section data-testid="xdr-mss-top-techniques" style={panelBox}>
            <div style={panelHeader}>
              <span>TOP MITRE TECHNIQUES</span>
              <span style={sourceChip}>source: {det.source}</span>
            </div>
            {det.top_techniques.length === 0 ? (
              <div className="x-empty"
                    data-testid="xdr-mss-top-techniques-empty">
                NO TECHNIQUES IN EVIDENCE — honest empty state.  Incidents
                without ATT&CK-tagged evidence contribute nothing here.
              </div>
            ) : (
              <BarList rows={det.top_techniques.map(x =>
                ({ label: x.technique_id, count: x.count }))} color="#fbbf24" />
            )}
          </section>
        )}
      </div>

      {/* ═════════════ H · RECENT ACTIVITY ═════════════ */}
      {act && (
        <section data-testid="xdr-mss-recent-activity" style={panelBox}>
          <div style={panelHeader}>
            <span>RECENT ACTIVITY · {act.count}</span>
            <span style={sourceChip}>source: {act.source}</span>
          </div>
          {act.events.length === 0 ? (
            <div className="x-empty">NO RECENT ACTIVITY</div>
          ) : (
            <ul style={activityList}>
              {act.events.map((e, i) => (
                <li key={`${e.incident_id}-${i}`}
                       style={activityRow}
                       data-testid={`xdr-mss-recent-activity-row-${i}`}
                       onClick={() => navigate(`/xdr/incidents/${e.incident_id}`)}>
                  <span style={activityAt}>{e.at?.slice(0,16).replace("T"," ")}</span>
                  <span style={{ ...activityId, fontFamily: "var(--mono)" }}>{e.incident_id?.slice(0,10)}…</span>
                  <span style={activityActor}>{e.actor}</span>
                  <span style={activityAction}>{e.action}</span>
                  <span style={activityName}>{e.incident_name}</span>
                </li>
              ))}
            </ul>
          )}
        </section>
      )}

      <div style={invariantNote}
             data-testid="xdr-mss-invariant">
        MSS Dashboard is a pure projection of workspace_cases · every
        metric declares its source · engine activity is derived from
        persisted execution provenance (Phase 4) or reported as
        UNAVAILABLE · NO fabricated intelligence.
      </div>

      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </XdrShell>
  );
}


// ── Sub-components ─────────────────────────────────────────────────
function BarStack({ data }) {
  const total = data.reduce((a, d) => a + (d.count || 0), 0) || 1;
  return (
    <div>
      <div style={{ display: "flex", height: 10, width: "100%",
                     borderRadius: 3, overflow: "hidden",
                     background: "rgba(255,255,255,0.04)" }}>
        {data.map(d => d.count > 0 && (
          <div key={d.key}
                 title={`${d.key}: ${d.count}`}
                 style={{ width: `${(d.count / total) * 100}%`,
                          background: d.color }} />
        ))}
      </div>
      <div style={{ display: "grid",
                     gridTemplateColumns: "repeat(auto-fill,minmax(90px,1fr))",
                     gap: 6, marginTop: 8 }}>
        {data.map(d => (
          <div key={d.key} style={{ fontFamily: "var(--mono)", fontSize: 10 }}>
            <span style={{ display: "inline-block", width: 8, height: 8,
                             marginRight: 6, borderRadius: 2,
                             background: d.color }} />
            <span style={{ color: "var(--text-dim)" }}>{d.key}: </span>
            <span style={{ color: "var(--text)", fontWeight: 700 }}>{d.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function BarList({ rows, color }) {
  const max = Math.max(...rows.map(r => r.count), 1);
  return (
    <ul style={{ listStyle: "none", padding: 0, margin: 0 }}>
      {rows.map(r => (
        <li key={r.label} style={{ display: "flex", alignItems: "center",
                                     gap: 8, padding: "4px 0" }}>
          <span style={{ flex: "0 0 140px", fontFamily: "var(--mono)",
                           fontSize: 11, color: "var(--text)",
                           whiteSpace: "nowrap", overflow: "hidden",
                           textOverflow: "ellipsis" }}>
            {r.label}
          </span>
          <span style={{ flex: 1, height: 8, background: "rgba(255,255,255,0.05)",
                           borderRadius: 2, overflow: "hidden" }}>
            <span style={{ display: "block", height: "100%",
                             width: `${(r.count / max) * 100}%`,
                             background: color }} />
          </span>
          <span style={{ flex: "0 0 34px", textAlign: "right",
                           fontFamily: "var(--mono)", fontSize: 11,
                           color: "var(--text)", fontWeight: 700 }}>
            {r.count}
          </span>
        </li>
      ))}
    </ul>
  );
}


// ── Styles ─────────────────────────────────────────────────────────
const headerRow = { display: "flex", justifyContent: "space-between",
                       alignItems: "flex-start", gap: 12, marginBottom: 4 };
const sectionLabel = { fontFamily: "var(--mono)", fontSize: 10,
                          letterSpacing: 1.4, color: "var(--text-dim)",
                          marginBottom: 8, paddingLeft: 2 };
const kpiGrid = { display: "grid",
                     gridTemplateColumns: "repeat(auto-fill, minmax(160px, 1fr))",
                     gap: 8 };
const kpiTile = { textAlign: "left", padding: "10px 12px",
                     border: "1px solid", borderRadius: 5, cursor: "pointer",
                     fontFamily: "inherit", color: "var(--text)" };
const kpiLabel = { fontFamily: "var(--mono)", fontSize: 10,
                      letterSpacing: 0.6, fontWeight: 700, color: "var(--text)" };
const kpiCount = { fontFamily: "var(--mono)", fontSize: 24,
                      fontWeight: 800, marginTop: 4, lineHeight: 1.05 };
const emptyChip = { display: "inline-block", marginTop: 4, padding: "1px 6px",
                       borderRadius: 3, fontSize: 8, letterSpacing: 1,
                       color: "var(--faint)", fontFamily: "var(--mono)",
                       border: "1px solid rgba(200,200,220,0.20)" };
const panelBox = { border: "1px solid rgba(120,130,150,0.20)",
                      borderRadius: 6, padding: "12px 14px", marginTop: 14,
                      background: "rgba(255,255,255,0.02)" };
const panelHeader = { display: "flex", justifyContent: "space-between",
                         alignItems: "center", gap: 12, marginBottom: 8,
                         fontFamily: "var(--mono)", fontSize: 11,
                         letterSpacing: 0.8, fontWeight: 700,
                         color: "var(--text)" };
const sourceChip = { fontFamily: "var(--mono)", fontSize: 9,
                        letterSpacing: 0.6, color: "var(--text-dim)",
                        fontWeight: 500 };
const distRow = { display: "grid", gridTemplateColumns: "1fr 1fr",
                     gap: 20 };
const distTitle = { fontFamily: "var(--mono)", fontSize: 9,
                       letterSpacing: 1.2, color: "var(--text-dim)",
                       marginBottom: 6 };
const twoCol = { display: "grid",
                    gridTemplateColumns: "repeat(auto-fit, minmax(360px, 1fr))",
                    gap: 14 };
const tbl = { width: "100%", borderCollapse: "collapse", fontSize: 11,
                 fontFamily: "var(--mono)" };
const th = { textAlign: "left", padding: "6px 8px",
                borderBottom: "1px solid rgba(120,130,150,0.20)",
                color: "var(--text-dim)", fontWeight: 600,
                letterSpacing: 0.5, fontSize: 10 };
const tr = { cursor: "pointer" };
const td = { padding: "6px 8px",
                borderBottom: "1px solid rgba(120,130,150,0.08)",
                color: "var(--text)" };
const statusRow = { display: "grid",
                       gridTemplateColumns: "repeat(4, 1fr)",
                       gap: 8, marginBottom: 8 };
const statusPill = { padding: "8px 10px", borderRadius: 4,
                        border: "1px solid rgba(120,130,150,0.22)",
                        background: "rgba(255,255,255,0.02)" };
const statusPillLabel = { fontFamily: "var(--mono)", fontSize: 9,
                              letterSpacing: 1, color: "var(--text-dim)" };
const statusPillValue = { fontFamily: "var(--mono)", fontSize: 20,
                              fontWeight: 800, marginTop: 2,
                              color: "var(--text)" };
const activityList = { listStyle: "none", padding: 0, margin: 0 };
const activityRow = { display: "grid",
                         gridTemplateColumns: "150px 110px 180px 160px 1fr",
                         gap: 8, padding: "6px 4px",
                         borderBottom: "1px solid rgba(120,130,150,0.08)",
                         fontSize: 11, fontFamily: "var(--mono)",
                         cursor: "pointer" };
const activityAt = { color: "var(--text-dim)" };
const activityId = { color: "var(--text)", fontWeight: 700 };
const activityActor = { color: "var(--text-dim)",
                           overflow: "hidden",
                           textOverflow: "ellipsis",
                           whiteSpace: "nowrap" };
const activityAction = { color: "var(--purple)" };
const activityName = { color: "var(--text)",
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap" };
const invariantNote = { marginTop: 22, padding: "10px 12px",
                            border: "1px dashed rgba(120,130,150,0.35)",
                            borderRadius: 4, fontFamily: "var(--mono)",
                            fontSize: 10, color: "var(--text-dim)",
                            letterSpacing: 0.25, lineHeight: 1.55 };
