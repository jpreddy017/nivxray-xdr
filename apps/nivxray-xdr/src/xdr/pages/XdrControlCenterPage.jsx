/**
 * `/xdr/control-center` — SOC Control Center.
 *
 * Replaces the card-heavy MSS Dashboard. Cisco XDR's Control Center is the
 * information-architecture reference: the FIRST VIEWPORT answers
 *
 *    what needs attention · which incidents matter most · which tenants
 *    are affected · what requires analyst action · what security,
 *    telemetry and response condition needs attention
 *
 * and everything below it is depth, not decoration. The previous KPI-card
 * wall is gone; the attention strip is one dense row and the work itself
 * (priority queue, tenants, action queues) owns the space.
 *
 * Every value traces to an authoritative API field. Nothing is computed
 * from a fixture and nothing missing is printed as zero — a fact the
 * platform does not hold reads NOT AVAILABLE / NOT OBSERVED with its
 * reason.
 */
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  AlertOctagon, AlertTriangle, RefreshCw, Timer, UserCheck, UserX, Zap,
} from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import IntelligenceStatusChip from "@/xdr/intelligence/IntelligenceStatusChip";
import {
  getMssKpis, getMssSocQueue, getMssCustomerOperations,
  getMssStateDistribution, getMssDetectionOverview, getMssRecentActivity,
} from "@/lib/incidentsApi";
import { getResponseEngineHealth, getPendingApprovals } from "@/nivxforge/edrApi";
import "@/xdr/nx/nx-cc.css";
import { apiErrorText } from "@/xdr/nx/apiError";

const ATTN = [
  { id: "critical",         label: "Critical",    icon: AlertOctagon,  tone: "critical" },
  { id: "high_priority",    label: "High",        icon: AlertTriangle, tone: "high" },
  { id: "unassigned",       label: "Unassigned",  icon: UserX,         tone: "high" },
  { id: "aging",            label: "Aging",       icon: Timer,         tone: "high" },
  { id: "in_progress_mine", label: "My queue",    icon: UserCheck,     tone: "quiet" },
  { id: "high_fidelity",    label: "High fidelity", icon: Zap,         tone: "quiet" },
];

const ts = (iso) => (iso ? String(iso).slice(0, 16).replace("T", " ") : null);
const ago = (iso) => {
  const t = Date.parse(iso || "");
  if (!Number.isFinite(t)) return "—";
  const s = Math.max(0, Math.floor((Date.now() - t) / 1000));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h`;
  return `${Math.floor(s / 86400)}d`;
};

const NA = ({ children }) => (
  <span className="cc-tb__na">{children || "NOT AVAILABLE"}</span>
);

export default function XdrControlCenterPage() {
  const navigate = useNavigate();
  const [kpi, setKpi] = useState(null);
  const [queue, setQueue] = useState(null);
  const [cust, setCust] = useState(null);
  const [dist, setDist] = useState(null);
  const [det, setDet] = useState(null);
  const [act, setAct] = useState(null);
  const [respond, setRespond] = useState(null);
  const [approvals, setApprovals] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    const settle = (p) => p.then((v) => ({ ok: true, v }))
                            .catch((e) => ({ ok: false,
                              e: apiErrorText(e) }));
    try {
      const [k, q, c, d, dt, a, rh, pa] = await Promise.all([
        settle(getMssKpis()), settle(getMssSocQueue(14)),
        settle(getMssCustomerOperations()), settle(getMssStateDistribution()),
        settle(getMssDetectionOverview()), settle(getMssRecentActivity(10)),
        settle(getResponseEngineHealth()), settle(getPendingApprovals()),
      ]);
      if (!k.ok && !q.ok) setError(k.e || q.e);
      setKpi(k.ok ? k.v : null);
      setQueue(q.ok ? q.v : { error: q.e });
      setCust(c.ok ? c.v : { error: c.e });
      setDist(d.ok ? d.v : { error: d.e });
      setDet(dt.ok ? dt.v : { error: dt.e });
      setAct(a.ok ? a.v : { error: a.e });
      setRespond(rh.ok ? rh.v : { error: rh.e });
      setApprovals(pa.ok ? pa.v : { error: pa.e });
    } finally { setLoading(false); }
  }, []);
  useEffect(() => { load(); }, [load]);

  const tiles = useMemo(() => {
    const out = {};
    (kpi?.groups || []).forEach((g) => (g.tiles || [])
      .forEach((t) => { out[t.id] = t; }));
    return out;
  }, [kpi]);

  const respondState = respond?.error
    ? "unknown" : respond?.reachable ? "ok" : "bad";
  const pendingCount = typeof approvals?.count === "number" ? approvals.count : null;

  return (
    <XdrShell>
      <div className="cc" data-testid="xdr-control-center"
           style={{ padding: "12px 16px 24px" }}>
        {/* ── Identity row ─────────────────────────────────────── */}
        <div style={{ display: "flex", alignItems: "baseline", gap: 12,
                      flexWrap: "wrap" }}>
          <h1 style={{ margin: 0, fontSize: 19, fontWeight: 700 }}
              data-testid="xdr-control-center-title">
            Control Center
          </h1>
          <span style={{ fontSize: 11, color: "var(--nx-muted, var(--muted))" }}>
            {loading ? "Reading the authoritative records…"
              : "Operational condition across your authorized scope"}
          </span>
          <div style={{ marginLeft: "auto", display: "flex", gap: 10,
                        alignItems: "center" }}>
            <IntelligenceStatusChip />
            <button className="cx-pill" onClick={load} disabled={loading}
                    data-testid="xdr-control-center-refresh">
              <RefreshCw size={11} /> Refresh
            </button>
          </div>
        </div>

        {error && (
          <div className="cc-cond" data-testid="xdr-control-center-error"
               style={{ color: "var(--nx-critical, #E5484D)" }}>
            Control Center could not read the incident authority — {String(error)}
          </div>
        )}

        {/* ── 1 · What needs attention ─────────────────────────── */}
        <div className="cc-attn" data-testid="cc-attention">
          {ATTN.map(({ id, label, icon: Icon, tone }) => {
            const t = tiles[id];
            const scoped = t && t.count_source !== "empty";
            const n = scoped ? t.count : null;
            return (
              <button key={id} className="cc-attn__i"
                      data-zero={!t || !t.lens_href ? "1" : undefined}
                      data-testid={`cc-attn-${id}`}
                      onClick={() => t?.lens_href && navigate(t.lens_href)}>
                <span className="cc-attn__k"><Icon size={11} /> {label}</span>
                <span className="cc-attn__v"
                      data-tone={n ? tone : "quiet"}
                      data-testid={`cc-attn-${id}-value`}>
                  {n == null ? "—" : n}
                </span>
                <span className="cc-attn__s">
                  {!t ? (loading ? "reading…" : "NOT AVAILABLE")
                    : t.lens_href ? "Open queue" : "no scope"}
                </span>
              </button>
            );
          })}
        </div>

        {/* ── 2 · Platform condition · security / telemetry / response ── */}
        <div className="cc-cond" data-testid="cc-condition">
          <span className="cc-cond__i">
            <span className="cc-cond__k">Response engine</span>
            <span className="cc-cond__v" data-state={respondState}
                  data-testid="cc-cond-response">
              {respond?.error ? "NOT EVALUATED"
                : respond?.configured === false ? "NOT CONFIGURED"
                : respond?.reachable ? (respond.state || "REACHABLE")
                : "UNREACHABLE"}
            </span>
          </span>
          <span className="cc-cond__i">
            <span className="cc-cond__k">Awaiting approval</span>
            <span className="cc-cond__v"
                  data-state={pendingCount ? "warn" : pendingCount === 0 ? "ok" : "unknown"}
                  data-testid="cc-cond-approvals">
              {pendingCount == null ? "NOT AVAILABLE" : pendingCount}
            </span>
          </span>
          <span className="cc-cond__i">
            <span className="cc-cond__k">Open incidents</span>
            <span className="cc-cond__v"
                  data-state={dist?.total ? "warn" : "unknown"}
                  data-testid="cc-cond-open">
              {typeof dist?.total === "number" ? dist.total : "NOT AVAILABLE"}
            </span>
          </span>
          <span className="cc-cond__i">
            <span className="cc-cond__k">Tenants in scope</span>
            <span className="cc-cond__v" data-state="ok"
                  data-testid="cc-cond-tenants">
              {Array.isArray(cust?.rows) ? cust.rows.length : "NOT AVAILABLE"}
            </span>
          </span>
          <span className="cc-cond__i">
            <span className="cc-cond__k">Telemetry health</span>
            <span className="cc-cond__v" data-state="unknown"
                  data-testid="cc-cond-telemetry">
              per-source · Data Sources
            </span>
          </span>
          {pendingCount > 0 && (
            <button className="cx-pill" style={{ marginLeft: "auto" }}
                    data-testid="cc-cond-approvals-open"
                    onClick={() => navigate("/xdr/respond/approvals")}>
              Review {pendingCount} pending approval(s)
            </button>
          )}
        </div>

        {/* ── 3 · Which incidents matter most + who is affected ── */}
        <div className="cc-grid">
          <div className="cc-card" data-testid="cc-needs-attention">
            <div className="cc-card__h">
              <span className="cc-card__t">Needs attention</span>
              <span className="cc-card__s">
                {queue?.error ? "not available"
                  : typeof queue?.count === "number"
                    ? `${queue.count} open P1/P2 incident(s)` : "reading…"}
              </span>
              <button className="cc-card__a cx-pill"
                      data-testid="cc-open-incidents"
                      onClick={() => navigate("/xdr/incidents")}>
                Open queue
              </button>
            </div>
            <div className="cc-card__b">
              {queue?.error ? (
                <div className="cc-empty" data-testid="cc-needs-attention-error">
                  <b>NOT AVAILABLE</b> — {String(queue.error)}
                </div>
              ) : !queue ? (
                <div className="cc-empty">Reading the incident authority…</div>
              ) : (queue.rows || []).length === 0 ? (
                <div className="cc-empty" data-testid="cc-needs-attention-empty">
                  <b>NOTHING REQUIRES ATTENTION</b> — no open P1/P2 incident
                  exists in this scope. This is an observed state, not an
                  empty page: aging and unassigned work still appears in the
                  attention strip above.
                </div>
              ) : (
                <table className="cc-tb" data-testid="cc-needs-attention-table">
                  <thead>
                    <tr>
                      <th>Incident</th><th>Pri</th><th>State</th>
                      <th>Owner</th><th>Tenant</th><th>SLA</th><th>Updated</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(queue.rows || []).slice(0, 10).map((r) => (
                      <tr key={r.id} onClick={() => navigate(`/xdr/incidents/${r.id}`)}
                          data-testid={`cc-needs-attention-row-${r.id}`}>
                        <td>
                          <span className="cc-tb__sev" data-s={r.priority} />
                          {r.name || <NA>UNNAMED</NA>}
                        </td>
                        <td className="mono">{r.priority || <NA>—</NA>}</td>
                        <td className="mono">
                          {String(r.state || "").replace("_", " ") || <NA>—</NA>}
                        </td>
                        <td className="mono">
                          {r.assignee || <NA>UNASSIGNED</NA>}
                        </td>
                        <td className="mono">{r.customer || <NA>NOT ATTRIBUTED</NA>}</td>
                        <td className="mono">{ts(r.sla_due_at) || <NA>NOT SET</NA>}</td>
                        <td className="mono">{ago(r.updated_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <div className="cc-card" data-testid="cc-tenants">
              <div className="cc-card__h">
                <span className="cc-card__t">Tenants affected</span>
                <span className="cc-card__s">open · critical · SLA risk</span>
                <button className="cc-card__a cx-pill"
                        data-testid="cc-open-clients"
                        onClick={() => navigate("/xdr/clients")}>
                  Clients
                </button>
              </div>
              <div className="cc-card__b">
                {cust?.error ? (
                  <div className="cc-empty"><b>NOT AVAILABLE</b> — {String(cust.error)}</div>
                ) : !cust ? <div className="cc-empty">Reading…</div>
                  : (cust.rows || []).length === 0 ? (
                    <div className="cc-empty" data-testid="cc-tenants-empty">
                      <b>NO TENANT IN SCOPE</b> — your authorization resolves
                      to no customer with incidents.
                    </div>
                  ) : (
                    <table className="cc-tb" data-testid="cc-tenants-table">
                      <thead>
                        <tr><th>Tenant</th><th className="num">Open</th>
                          <th className="num">Crit</th>
                          <th className="num">SLA</th>
                          <th className="num">Unass.</th></tr>
                      </thead>
                      <tbody>
                        {(cust.rows || []).slice(0, 8).map((r) => (
                          <tr key={r.customer}
                              data-testid={`cc-tenant-row-${r.customer}`}
                              onClick={() => navigate(
                                `/xdr/incidents?customer=${encodeURIComponent(r.customer)}`)}>
                            <td className="mono">{r.customer}</td>
                            <td className="num">{r.open}</td>
                            <td className="num"
                                style={{ color: r.critical > 0
                                  ? "var(--nx-critical, #E5484D)" : undefined }}>
                              {r.critical}
                            </td>
                            <td className="num">{r.sla_risk}</td>
                            <td className="num">{r.unassigned}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
              </div>
            </div>

            <div className="cc-card" data-testid="cc-assets">
              <div className="cc-card__h">
                <span className="cc-card__t">Assets affected</span>
              </div>
              <div className="cc-card__b cc-card__b--pad">
                <div className="cc-empty" style={{ padding: 0 }}
                     data-testid="cc-assets-state">
                  <b>NOT AVAILABLE</b> — the incident queue projection carries
                  no asset attribution, so no cross-incident asset impact roll-up
                  exists to report. Asset impact is resolved per investigation
                  in <b>Investigate ▸ Entities</b>, and inventory lives in{" "}
                  <b>Assets</b>. This is a missing capability, not zero
                  affected assets.
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* ── 4 · Distribution · what is driving detections · activity ── */}
        <div className="cc-grid cc-grid--3">
          <div className="cc-card" data-testid="cc-distribution">
            <div className="cc-card__h">
              <span className="cc-card__t">Priority &amp; state</span>
              <span className="cc-card__s">
                {typeof dist?.total === "number" ? `${dist.total} open` : "—"}
              </span>
            </div>
            <div className="cc-card__b">
              {dist?.error ? (
                <div className="cc-empty"><b>NOT AVAILABLE</b> — {String(dist.error)}</div>
              ) : !dist ? <div className="cc-empty">Reading…</div> : (
                <>
                  <Bars label="By priority" entries={dist.priorities} total={dist.total}
                        tone={(k) => (k === "P1" ? "critical" : k === "P2" ? "high" : "")} />
                  <Bars label="By state" entries={dist.states} total={dist.total}
                        tone={() => ""} />
                </>
              )}
            </div>
          </div>

          <div className="cc-card" data-testid="cc-detection-drivers">
            <div className="cc-card__h">
              <span className="cc-card__t">What is driving detections</span>
            </div>
            <div className="cc-card__b">
              {det?.error ? (
                <div className="cc-empty"><b>NOT AVAILABLE</b> — {String(det.error)}</div>
              ) : !det ? <div className="cc-empty">Reading…</div>
                : (det.detection_sources || []).length === 0 ? (
                  <div className="cc-empty" data-testid="cc-detection-drivers-empty">
                    <b>NOT OBSERVED</b> — no incident in scope carries a
                    detection-source label.
                  </div>
                ) : (
                  <div className="cc-bars">
                    {(det.detection_sources || []).slice(0, 6).map((x) => (
                      <Bar key={x.source} k={x.source} v={x.count}
                           max={det.detection_sources[0].count} tone="" />
                    ))}
                    {(det.top_techniques || []).length > 0 && (
                      <>
                        <div className="cc-cond__k" style={{ marginTop: 6 }}>
                          Top ATT&amp;CK techniques
                        </div>
                        {(det.top_techniques || []).slice(0, 4).map((x) => (
                          <Bar key={x.technique_id} k={x.technique_id} v={x.count}
                               max={det.top_techniques[0].count} tone="high" />
                        ))}
                      </>
                    )}
                  </div>
                )}
            </div>
          </div>

          <div className="cc-card" data-testid="cc-activity">
            <div className="cc-card__h">
              <span className="cc-card__t">Analyst activity</span>
            </div>
            <div className="cc-card__b">
              {act?.error ? (
                <div className="cc-empty"><b>NOT AVAILABLE</b> — {String(act.error)}</div>
              ) : !act ? <div className="cc-empty">Reading…</div>
                : (act.events || []).length === 0 ? (
                  <div className="cc-empty" data-testid="cc-activity-empty">
                    <b>NOT OBSERVED</b> — no analyst action is recorded against
                    any incident in this scope.
                  </div>
                ) : (
                  <ul className="cc-feed" data-testid="cc-activity-feed">
                    {(act.events || []).slice(0, 9).map((e, i) => (
                      <li key={`${e.incident_id}-${i}`}
                          data-testid={`cc-activity-row-${i}`}
                          onClick={() => navigate(`/xdr/incidents/${e.incident_id}`)}>
                        <span className="cc-feed__t">{ago(e.at)}</span>
                        <span className="cc-feed__x">
                          <b>{String(e.action || "activity").replace(/_/g, " ")}</b>
                          {" — "}
                          {e.incident_name || e.incident_id}
                        </span>
                      </li>
                    ))}
                  </ul>
                )}
            </div>
          </div>
        </div>
      </div>
    </XdrShell>
  );
}

function Bars({ label, entries, total, tone }) {
  const items = Object.entries(entries || {}).filter(([, v]) => v > 0);
  const max = items.reduce((m, [, v]) => Math.max(m, v), 0) || 1;
  return (
    <div className="cc-bars">
      <div className="cc-cond__k">{label}</div>
      {items.length === 0
        ? <div className="cc-tb__na" style={{ fontSize: 10.8 }}>
            NOT OBSERVED in this scope
          </div>
        : items.map(([k, v]) => (
            <Bar key={k} k={k} v={v} max={max} tone={tone(k)} pct={total} />
          ))}
    </div>
  );
}

function Bar({ k, v, max, tone }) {
  return (
    <div className="cc-bar" data-testid={`cc-bar-${k}`}>
      <span className="cc-bar__k" title={k}>{k}</span>
      <span className="cc-bar__t">
        <span className="cc-bar__f" data-tone={tone || undefined}
              style={{ width: `${Math.max(3, (v / max) * 100)}%` }} />
      </span>
      <span className="cc-bar__n">{v}</span>
    </div>
  );
}
