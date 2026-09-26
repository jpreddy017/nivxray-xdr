/**
 * XdrMssDashboardPage · `/xdr/mss-dashboard`
 *
 * SOC Command Center — Phase A.2 visual maturity.
 * Composed on the light workspace canvas using the shared
 * `.nx-*` primitives so the operational dashboard family
 * shares the same visual language as Platform Overview while
 * carrying its own composition (attention → distribution →
 * priority queue → workload → customer ops → detection →
 * activity).
 *
 * Honest data contract preserved: nothing is fabricated.
 * When a data source is `unavailable`, we render a designed
 * truth-state block, not a wall of zeroes.
 */
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  AlertOctagon, AlertTriangle, Zap, UserX, UserCheck,
  Timer, RefreshCw, Radar, Search,
} from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import {
  NxPageShell, NxSurface, NxKpi, NxEmptyBlock as NxEmpty, NxPill, NxHBar, NxDonut,
} from "@/xdr/nx";
import IntelligenceControlPanel from "@/xdr/components/IntelligenceControlPanel";
import {
  getMssKpis, getMssStateDistribution, getMssSocQueue,
  getMssAnalystWorkload, getMssCustomerOperations,
  getMssAutoInvestigation, getMssDetectionOverview, getMssRecentActivity,
} from "@/lib/incidentsApi";


const LENS_META = {
  critical:          { icon: AlertOctagon,   tone: "critical", label: "Critical" },
  high_priority:     { icon: AlertTriangle,  tone: "high",     label: "High Priority" },
  high_fidelity:     { icon: Zap,            tone: "purple",   label: "High Fidelity" },
  unassigned:        { icon: UserX,          tone: "medium",   label: "Unassigned" },
  in_progress_mine:  { icon: UserCheck,      tone: "info",     label: "My Queue" },
  aging:             { icon: Timer,          tone: "high",     label: "Aging" },
};

const STATE_TONE = {
  new:         "info",
  in_progress: "amber",
  on_hold:     "purple",
  resolved:    "benign",
  closed:      "faint",
};
const PRIO_TONE = {
  P1: "critical", P2: "amber", P3: "amber", P4: "benign", P5: "faint",
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
      setError(e?.response?.data?.detail || e?.message || "Failed to load MSS dashboard.");
    } finally { setL(false); }
  }, []);
  useEffect(() => { load(); }, [load]);

  // Flatten KPI tiles from the API groups so we can promote 6 top
  // attention tiles onto the hero strip without changing the API.
  const flatTiles = useMemo(() => {
    if (!kpi?.groups) return {};
    const out = {};
    kpi.groups.forEach(g => g.tiles.forEach(t => { out[t.id] = t; }));
    return out;
  }, [kpi]);

  return (
    <XdrShell activeTop="dashboards">
      <NxPageShell
        testid="xdr-mss-dashboard"
        eyebrow="Command Center"
        title="MSS Dashboard"
        description="Triage, workload, customer operations and detection coverage in one operational view."
        action={
          <button
            className="rl-btn"
            data-testid="xdr-mss-dashboard-refresh"
            onClick={load}
            disabled={loading}
          >
            <RefreshCw size={12}
              style={loading ? { animation: "nx-spin 0.9s linear infinite" } : {}} />
            Refresh
          </button>
        }
      >
        {error && (
          <NxEmpty
            icon={AlertOctagon}
            title="MSS dashboard failed to load"
            body={String(error)}
            testid="xdr-mss-dashboard-error"
          />
        )}

        {/* ── NivXRay XDR Intelligence · Global Governance ─────── */}
        <div style={{ marginBottom: 14 }} data-testid="xdr-mss-intelligence-slot">
          <IntelligenceControlPanel scope="global" />
        </div>

        {/* ── Attention strip · 6 top operational lenses ──────────── */}
        <div className="nx-attn nx-attn-6" data-testid="xdr-mss-attn">
          {["critical","high_priority","unassigned","in_progress_mine",
            "aging","high_fidelity"].map((id) => {
            const t = flatTiles[id];
            const meta = LENS_META[id];
            const hasScope = t && t.count_source !== "empty";
            return (
              <div
                key={id}
                onClick={() => t && navigate(t.lens_href)}
                style={{ cursor: t ? "pointer" : "default" }}
                data-testid={`xdr-mss-attn-${id}`}
              >
                <NxKpi
                  icon={meta.icon}
                  tone={meta.tone}
                  label={meta.label}
                  value={hasScope ? t.count : "—"}
                  sub={t?.lens_href ? "Open queue" : (loading ? "Loading…" : "No scope")}
                />
              </div>
            );
          })}
        </div>

        {/* ── Row 1 · Distribution + Priority Queue ─────────────── */}
        <div className="nx-row" style={{
          gridTemplateColumns: "minmax(0, 0.55fr) minmax(0, 1fr)",
        }}>
          <NxSurface
            title="Incident Distribution"
            subtitle="Open incidents by state and priority"
            testid="xdr-mss-state-distribution"
          >
            {!dist ? <QuietLoad /> : (
              <div style={{ display: "grid", gap: 18 }}>
                <DistributionBlock
                  label="By state"
                  entries={Object.entries(dist.states)}
                  toneMap={STATE_TONE}
                  total={dist.total}
                />
                <DistributionBlock
                  label="By priority"
                  entries={Object.entries(dist.priorities)}
                  toneMap={PRIO_TONE}
                  total={dist.total}
                />
              </div>
            )}
          </NxSurface>

          <NxSurface
            title="Open High-Priority Queue"
            subtitle={queue ? `${queue.count} incident${queue.count === 1 ? "" : "s"} awaiting action` : "Loading…"}
            testid="xdr-mss-soc-queue"
          >
            {!queue ? <QuietLoad /> : queue.rows.length === 0 ? (
              <NxEmpty
                icon={UserCheck}
                title="No open high-priority incidents"
                body="Great — nothing is currently P1/P2 in the open queue. Aging or high-fidelity incidents (if any) still appear in the attention strip above."
              />
            ) : (
              <table className="nx-work-table" data-testid="xdr-mss-soc-queue-table">
                <thead>
                  <tr>
                    <th>Incident</th>
                    <th>Priority</th>
                    <th>State</th>
                    <th>Owner</th>
                    <th>Customer</th>
                    <th>SLA</th>
                    <th>Updated</th>
                  </tr>
                </thead>
                <tbody>
                  {queue.rows.slice(0, 8).map(r => (
                    <tr key={r.id}
                        onClick={() => navigate(`/xdr/incidents/${r.id}`)}
                        data-testid={`xdr-mss-soc-queue-row-${r.id}`}>
                      <td>{r.name || <span style={{ color: "var(--nx-muted)" }}>(unnamed)</span>}</td>
                      <td><NxPill tone={PRIO_TONE[r.priority] || "faint"}>{r.priority || "—"}</NxPill></td>
                      <td><NxPill tone={STATE_TONE[r.state] || "faint"}>{r.state || "—"}</NxPill></td>
                      <td className="mono">{r.assignee || <span style={{ color: "var(--nx-medium)", fontFamily: "var(--sans)", fontWeight: 700 }}>Unassigned</span>}</td>
                      <td className="mono">{r.customer || "—"}</td>
                      <td className="mono">{fmtTs(r.sla_due_at)}</td>
                      <td className="mono">{fmtTs(r.updated_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </NxSurface>
        </div>

        {/* ── Row 2 · Workload + Customer Ops ───────────────────── */}
        <div className="nx-row nx-row-2">
          <NxSurface
            title="Analyst Workload"
            subtitle="Assignments and SLA exposure per analyst"
            testid="xdr-mss-analyst-workload"
          >
            {!work ? <QuietLoad /> : work.rows.length === 0 ? (
              <NxEmpty
                title="No open assignments"
                body="Nothing is currently assigned to an analyst. New incidents will appear here as they are owned."
              />
            ) : (
              <table className="nx-work-table">
                <thead>
                  <tr>
                    <th>Analyst</th>
                    <th className="num">Assigned</th>
                    <th className="num">P1 / P2</th>
                    <th className="num">On Hold</th>
                    <th className="num">SLA Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {work.rows.map(r => (
                    <tr key={r.analyst}
                        onClick={() => navigate(r.queue_href)}>
                      <td className="mono">{r.analyst}</td>
                      <td className="num">{r.assigned}</td>
                      <td className="num">{r.p1_p2}</td>
                      <td className="num">{r.on_hold}</td>
                      <td className="num" style={{ color: r.sla_risk > 0 ? "var(--nx-critical)" : "var(--nx-text-dim)" }}>
                        {r.sla_risk}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </NxSurface>

          <NxSurface
            title="Customer Operations"
            subtitle="Per-customer open volume and exposure"
            testid="xdr-mss-customer-operations"
          >
            {!cust ? <QuietLoad /> : cust.rows.length === 0 ? (
              <NxEmpty
                title="No customer data yet"
                body="Customer-tagged incidents will appear here once your tenants start generating investigations."
              />
            ) : (
              <table className="nx-work-table">
                <thead>
                  <tr>
                    <th>Customer</th>
                    <th className="num">Open</th>
                    <th className="num">Critical</th>
                    <th className="num">High</th>
                    <th className="num">SLA Risk</th>
                    <th className="num">Unassigned</th>
                  </tr>
                </thead>
                <tbody>
                  {cust.rows.map(r => (
                    <tr key={r.customer}>
                      <td className="mono">{r.customer}</td>
                      <td className="num">{r.open}</td>
                      <td className="num" style={{ color: r.critical > 0 ? "var(--nx-critical)" : "var(--nx-text-dim)" }}>{r.critical}</td>
                      <td className="num">{r.high_prio}</td>
                      <td className="num" style={{ color: r.sla_risk > 0 ? "var(--nx-critical)" : "var(--nx-text-dim)" }}>{r.sla_risk}</td>
                      <td className="num" style={{ color: r.unassigned > 0 ? "var(--nx-medium)" : "var(--nx-text-dim)" }}>{r.unassigned}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </NxSurface>
        </div>

        {/* ── Row 3 · Detection Sources + MITRE + Activity ──────── */}
        <div className="nx-row nx-row-3">
          <NxSurface
            title="Top Detection Sources"
            subtitle="What is triggering investigations"
            testid="xdr-mss-detection-sources"
          >
            {!det ? <QuietLoad /> : det.detection_sources.length === 0 ? (
              <NxEmpty title="No detection-source data"
                          body="Detection sources appear here once incidents carry a source label." />
            ) : (
              <NxHBar
                items={det.detection_sources.slice(0, 8).map(x =>
                  ({ key: x.source, label: shortSource(x.source), value: x.count, tone: "blue" }))}
              />
            )}
          </NxSurface>

          <NxSurface
            title="Top MITRE Techniques"
            subtitle="Techniques observed in evidence"
            testid="xdr-mss-top-techniques"
          >
            {!det ? <QuietLoad /> : det.top_techniques.length === 0 ? (
              <NxEmpty
                icon={Radar}
                title="No techniques in evidence yet"
                body="Incidents without ATT&CK-tagged evidence contribute nothing here. Techniques will accrue as investigations progress."
              />
            ) : (
              <NxHBar
                items={det.top_techniques.slice(0, 8).map(x =>
                  ({ key: x.technique_id, label: x.technique_id, value: x.count, tone: "amber" }))}
              />
            )}
          </NxSurface>

          <NxSurface
            title="Recent Activity"
            subtitle="Latest analyst actions across incidents"
            testid="xdr-mss-recent-activity"
          >
            {!act ? <QuietLoad /> : act.events.length === 0 ? (
              <NxEmpty title="No recent activity" body="Analyst actions will stream here as they happen." />
            ) : (
              <ul style={{ listStyle: "none", padding: 0, margin: 0,
                              display: "flex", flexDirection: "column", gap: 8 }}>
                {act.events.slice(0, 10).map((e, i) => (
                  <li
                    key={`${e.incident_id}-${i}`}
                    onClick={() => navigate(`/xdr/incidents/${e.incident_id}`)}
                    style={{
                      display: "grid",
                      gridTemplateColumns: "80px 1fr auto",
                      gap: 10, alignItems: "baseline",
                      padding: "8px 10px",
                      background: "var(--nx-surf-inset)",
                      border: "1px solid var(--nx-bd-quiet)",
                      borderRadius: 6,
                      cursor: "pointer",
                      fontFamily: "var(--sans)", fontSize: 12,
                    }}
                    data-testid={`xdr-mss-recent-activity-row-${i}`}
                  >
                    <span style={{
                      fontFamily: "var(--mono)", fontSize: 11,
                      color: "var(--nx-muted)",
                    }}>
                      {fmtRelative(e.at)}
                    </span>
                    <span style={{ minWidth: 0, overflow: "hidden",
                                     textOverflow: "ellipsis",
                                     whiteSpace: "nowrap",
                                     color: "var(--nx-text)" }}>
                      <span style={{ color: "var(--nx-purple)",
                                       fontWeight: 600 }}>
                        {humanAction(e.action)}
                      </span>
                      {" — "}
                      <span style={{ color: "var(--nx-text-dim)" }}>
                        {e.incident_name || e.incident_id?.slice(0, 10) + "…"}
                      </span>
                    </span>
                    <span style={{ fontFamily: "var(--mono)", fontSize: 11,
                                     color: "var(--nx-text-dim)" }}>
                      {e.actor}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </NxSurface>
        </div>

        {/* ── Row 4 · Auto-Investigation ────────────────────────── */}
        {auto && (
          <NxSurface
            title="Auto-Investigation"
            subtitle="Automated investigation activity across the platform"
            testid="xdr-mss-auto-investigation"
          >
            {auto.source === "unavailable" ? (
              <NxEmpty
                icon={Search}
                title="Auto-investigation activity not yet available"
                body={
                  auto.reason
                    ? `${auto.reason}. Automated investigation activity will surface here as it is recorded.`
                    : "Automated investigation activity will surface here as it is recorded."
                }
              />
            ) : (
              <>
                <div className="nx-attn nx-attn-4"
                        style={{ margin: "0 0 12px" }}>
                  {["running","completed","awaiting_evidence","failed"].map(k => (
                    <NxKpi
                      key={k}
                      label={k.replace("_", " ")}
                      value={auto.status?.[k] ?? 0}
                      tone={k === "failed" ? "critical"
                              : k === "running" ? "info"
                              : k === "completed" ? "benign"
                              : "medium"}
                      testid={`xdr-mss-auto-status-${k}`}
                    />
                  ))}
                </div>
                {auto.engines?.length > 0 && (
                  <table className="nx-work-table">
                    <thead>
                      <tr><th>Engine</th><th className="num">Runs</th><th className="num">OK</th></tr>
                    </thead>
                    <tbody>
                      {auto.engines.map(e => (
                        <tr key={e.engine}
                            data-testid={`xdr-mss-auto-engine-${e.engine}`}>
                          <td className="mono">{e.engine}</td>
                          <td className="num">{e.runs}</td>
                          <td className="num">{e.ok}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </>
            )}
          </NxSurface>
        )}

        <footer className="nx-honest">
          NivXRay is evidence-first and deterministic. Counts are sourced
          from authoritative incident records and refreshed on schedule.
        </footer>
      </NxPageShell>

      <style>{`@keyframes nx-spin { to { transform: rotate(360deg); } }`}</style>
    </XdrShell>
  );
}


/* ── Small helpers ───────────────────────────────────────────── */

function QuietLoad() {
  return (
    <div style={{
      padding: "12px 4px",
      color: "var(--nx-muted)",
      fontFamily: "var(--sans)",
      fontSize: 12,
    }}>Loading…</div>
  );
}

function DistributionBlock({ label, entries, toneMap, total }) {
  const items = entries
    .filter(([, v]) => v > 0)
    .map(([k, v]) => ({ key: k, label: k, value: v, tone: toneMap[k] || "faint" }));
  return (
    <div>
      <div style={{
        fontFamily: "var(--sans)", fontSize: 10, fontWeight: 800,
        letterSpacing: 0.5, textTransform: "uppercase",
        color: "var(--nx-muted)", marginBottom: 8,
      }}>{label}</div>
      {items.length === 0 ? (
        <div style={{ fontSize: 12, color: "var(--nx-text-dim)",
                       fontFamily: "var(--sans)" }}>
          No incidents in this segment
        </div>
      ) : (
        <NxHBar items={items} />
      )}
    </div>
  );
}

function fmtTs(iso) {
  if (!iso) return "—";
  return String(iso).slice(0, 16).replace("T", " ");
}
function fmtRelative(iso) {
  if (!iso) return "—";
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return "—";
  const sec = Math.max(0, Math.floor((Date.now() - t) / 1000));
  if (sec < 60) return `${sec}s`;
  if (sec < 3600) return `${Math.floor(sec/60)}m`;
  if (sec < 86400) return `${Math.floor(sec/3600)}h`;
  return `${Math.floor(sec/86400)}d`;
}
function humanAction(a) {
  if (!a) return "activity";
  return String(a).replace(/_/g, " ");
}
function shortSource(src) {
  if (!src) return "—";
  const s = String(src);
  return s.length > 18 ? s.slice(0, 16) + "…" : s;
}
