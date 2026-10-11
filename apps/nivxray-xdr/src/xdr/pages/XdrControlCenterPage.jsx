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
import React, { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  RefreshCw, Timer,
} from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import IntelligenceStatusChip from "@/xdr/intelligence/IntelligenceStatusChip";
import {
  getMssKpis, getMssSocQueue, getMssCustomerOperations,
  getMssStateDistribution, getMssDetectionOverview, getMssRecentActivity,
} from "@/lib/incidentsApi";
import { getResponseEngineHealth, getPendingApprovals } from "@/nivxforge/edrApi";
import "@/xdr/nx/nx-cc.css";
import PriorityIncidentQueue from "./PriorityIncidentQueue";
import SecurityOverviewKpis from "./SecurityOverviewKpis";
import { projectionState } from "./controlCenterState";
import { apiErrorText } from "@/xdr/nx/apiError";
import { NxDataTable, NxState, opsLabel } from "@/xdr/nx";

const ago = (iso) => {
  const t = Date.parse(iso || "");
  if (!Number.isFinite(t)) return "—";
  const s = Math.max(0, Math.floor((Date.now() - t) / 1000));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h`;
  return `${Math.floor(s / 86400)}d`;
};

//: Absence is stated in the product's own words. The machine token stays
//: on the element (`data-nx-state`) so it is still one hover away.
const NA = ({ children, state = "NOT_AVAILABLE" }) => (
  <span className="cc-tb__na" data-nx-state={state} title={state}>
    {children || opsLabel(state)}
  </span>
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
                              e: apiErrorText(e), status: e?.response?.status }));
    try {
      const [k, q, c, d, dt, a, rh, pa] = await Promise.all([
        settle(getMssKpis()), settle(getMssSocQueue(14)),
        settle(getMssCustomerOperations()), settle(getMssStateDistribution()),
        settle(getMssDetectionOverview()), settle(getMssRecentActivity(10)),
        settle(getResponseEngineHealth()), settle(getPendingApprovals()),
      ]);
      if (!k.ok) setError(k.e || q.e);
      setKpi(k.ok ? k.v : { error: k.e, status: k.status });
      setQueue(q.ok ? q.v : { error: q.e, status: q.status });
      setCust(c.ok ? c.v : { error: c.e, status: c.status });
      setDist(d.ok ? d.v : { error: d.e });
      setDet(dt.ok ? dt.v : { error: dt.e });
      setAct(a.ok ? a.v : { error: a.e });
      setRespond(rh.ok ? rh.v : { error: rh.e });
      setApprovals(pa.ok ? pa.v : { error: pa.e });
    } finally { setLoading(false); }
  }, []);
  useEffect(() => { load(); }, [load]);

  const respondState = !respond || respond.error || respond.configured === false
    ? "unknown" : respond.reachable ? "ok" : "bad";
  const customerState = projectionState(cust);
  const pendingCount = typeof approvals?.count === "number" ? approvals.count : null;

  return (
    <XdrShell>
      <div className="cc" data-testid="xdr-control-center"
           style={{ padding: "0 0 16px" }}>
        <header className="cc-header" aria-labelledby="cc-page-title">
          <div className="cc-header__identity">
            <h1 id="cc-page-title" data-testid="xdr-control-center-title">
              Control Center
            </h1>
          </div>
          <div className="cc-header__actions">
            <IntelligenceStatusChip />
            <button className="cc-header__refresh" onClick={load} disabled={loading}
                    aria-label="Refresh Control Center"
                    data-testid="xdr-control-center-refresh">
              <RefreshCw size={14} aria-hidden="true" />
              {loading ? "Refreshing…" : "Refresh"}
            </button>
          </div>
          <div className="cc-header__context" data-testid="cc-time-scope">
            <Timer size={13} aria-hidden="true" />
            <span>Authorized scope · Reporting window varies by panel</span>
          </div>
        </header>

        {error && (
          <div className="cc-cond" data-testid="xdr-control-center-error"
               style={{ color: "var(--nx-critical, #E5484D)" }}>
            Attention summary unavailable — {String(error)}
          </div>
        )}

        {/* ── 1 · What needs attention ─────────────────────────── */}
        <SecurityOverviewKpis data={kpi} loading={loading} onNavigate={navigate} />

        {/* ── 2 · Platform condition · security / telemetry / response ── */}
        <div className="cc-cond" data-testid="cc-condition">
          <span className="cc-cond__i">
            <span className="cc-cond__k">Response engine</span>
            <span className="cc-cond__v" data-state={respondState}
                  data-testid="cc-cond-response">
              {opsLabel(!respond || respond.error ? "NOT_AVAILABLE"
                : respond?.configured === false ? "NOT_CONFIGURED"
                : respond?.reachable ? (respond.state || "RECEIVING")
                : "OFFLINE")}
            </span>
          </span>
          <span className="cc-cond__i">
            <span className="cc-cond__k">Awaiting approval</span>
            <span className="cc-cond__v"
                  data-state={pendingCount ? "warn" : pendingCount === 0 ? "ok" : "unknown"}
                  data-testid="cc-cond-approvals">
              {pendingCount == null ? opsLabel("NOT_AVAILABLE") : pendingCount}
            </span>
          </span>
          <span className="cc-cond__i">
            <span className="cc-cond__k">Incidents in scope</span>
            <span className="cc-cond__v"
                  data-state={dist?.total ? "warn" : "unknown"}
                  data-testid="cc-cond-open">
              {typeof dist?.total === "number" ? dist.total
                : opsLabel("NOT_AVAILABLE")}
            </span>
          </span>
          <span className="cc-cond__i">
            <span className="cc-cond__k">Tenants with incidents</span>
            <span className="cc-cond__v" data-state={customerState === "ready" ? "ok" : "unknown"}
                  title="Incident-bearing tenants returned by this projection (maximum 25); not the authorized tenant inventory."
                  data-testid="cc-cond-tenants">
              {["ready", "empty"].includes(customerState) ? cust.rows.length
                : opsLabel("NOT_AVAILABLE")}
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
        <PriorityIncidentQueue data={queue} loading={loading} onNavigate={navigate} />
        <div className="cc-dashboard-grid">
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
                {!["ready", "empty"].includes(customerState) ? (
                  <ProjectionNotice state={customerState} error={cust?.error}
                                    testid="cc-tenants-error" />
                ) : customerState === "empty" ? (
                    <div className="cc-empty" data-testid="cc-tenants-empty">
                      <b>No incident-bearing tenants returned</b> — this result
                      does not establish how many tenants you are authorized to access.
                    </div>
                  ) : (
                    <NxDataTable rows={(cust.rows || []).slice(0, 8)}
                                 rowKey={(r) => r.customer} searchable={false}
                                 pageSize={8}
                                 onRowClick={(r) => navigate(
                                   `/xdr/incidents?customer=${encodeURIComponent(r.customer)}`)}
                                 testid="cc-tenants-table"
                                 emptyTitle="No customer in scope carries an incident"
                                 columns={[
                      { key: "customer", header: "Customer",
                        value: (r) => r.customer,
                        render: (r) => (
                          <span className="nx-mono"
                                data-testid={`cc-tenant-row-${r.customer}`}>
                            {r.customer}
                          </span>) },
                      { key: "open", header: "Open", width: "80px",
                        align: "right", value: (r) => r.open },
                      { key: "critical", header: "Critical", width: "90px",
                        align: "right", value: (r) => r.critical,
                        render: (r) => (
                          <span style={{ color: r.critical > 0
                            ? "var(--nx-critical)" : undefined }}>
                            {r.critical}
                          </span>) },
                      { key: "sla_risk", header: "SLA risk", width: "90px",
                        align: "right", value: (r) => r.sla_risk },
                      { key: "unassigned", header: "Unassigned", width: "110px",
                        align: "right", value: (r) => r.unassigned },
                    ]} />
                  )}
              </div>
            </div>

        {/* Existing supporting panels share the same dashboard grid. */}
            <div className="cc-card" data-testid="cc-assets">
              <div className="cc-card__h">
                <span className="cc-card__t">Assets affected</span>
              </div>
              <div className="cc-card__b cc-card__b--pad">
                <div className="cc-empty" style={{ padding: 0 }}
                     data-testid="cc-assets-state">
                  <b>Not available</b> — cross-incident asset attribution is
                  not provided. View per-incident impact in <b>Investigate ▸ Entities</b>
                  {" "}or inventory in <b>Assets</b>. This does not mean zero affected assets.
                </div>
              </div>
            </div>
          <div className="cc-card" data-testid="cc-distribution">
            <div className="cc-card__h">
              <span className="cc-card__t">Priority &amp; state</span>
              <span className="cc-card__s">
                {typeof dist?.total === "number" ? `${dist.total} incidents` : "—"}
              </span>
            </div>
            <div className="cc-card__b">
              {dist?.error ? (
                <div className="cc-empty"><b>Not available</b> — {String(dist.error)}</div>
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
                <div className="cc-empty"><b>Not available</b> — {String(det.error)}</div>
              ) : !det ? <div className="cc-empty">Reading…</div>
                : (det.detection_sources || []).length === 0 ? (
                  <div className="cc-empty" data-testid="cc-detection-drivers-empty">
                    <b>Not observed</b> — no incident in scope carries a
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
                <div className="cc-empty"><b>Not available</b> — {String(act.error)}</div>
              ) : !act ? <div className="cc-empty">Reading…</div>
                : (act.events || []).length === 0 ? (
                  <div className="cc-empty" data-testid="cc-activity-empty">
                    <b>Not observed</b> — no analyst action is recorded against
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
            Not observed in this scope
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

function ProjectionNotice({ state, error, testid }) {
  const titles = {
    loading: "Reading…", denied: "Access denied", unavailable: "Not available",
    no_scope: "No queryable scope returned",
  };
  const details = {
    denied: "The API denied this request. Review your authorized scope or session.",
    unavailable: "The response is unavailable or incomplete; no empty-data conclusion can be drawn.",
    no_scope: "The API marked the scope empty. This is not evidence of zero incidents across your estate.",
  };
  return <div className="cc-empty" data-testid={testid} data-read-state={state}>
    <b>{titles[state] || "Not available"}</b>
    {state !== "loading" && <> — {error || details[state]}</>}
  </div>;
}
