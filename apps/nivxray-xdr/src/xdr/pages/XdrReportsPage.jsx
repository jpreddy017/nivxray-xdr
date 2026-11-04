/**
 * `/xdr/reports` — Investigation report library.
 *
 * NivXRay composes ONE authoritative investigation report per incident
 * (`GET /api/incidents/{id}/report`, PDF projection at
 * `/report/pdf`). This landing is the library over that capability: the
 * incidents the principal is authorized to see, each with its report.
 *
 * It invents no report type. Executive, scheduled and cross-incident
 * reporting do not exist in this backend and are stated as such rather
 * than mocked.
 */
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { FileText, RefreshCw, Download } from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import {
  NxInvSection, NxInvTable, NxInvEmpty, NxInvTech, NxInvValue, ABSENCE,
} from "@/xdr/nx";
import "@/xdr/nx/nx-inv.css";
import "@/xdr/nx/nx-workspace.css";
import { listIncidents } from "@/lib/incidentsApi";
import { API_BASE } from "@/lib/api";
import "@/xdr/nx/nx-cc.css";
import { apiErrorText } from "@/xdr/nx/apiError";

const UNSUPPORTED = [
  { k: "Scheduled reports", state: "NOT AVAILABLE",
    why: "no scheduler owns report delivery in this backend" },
  { k: "Executive / board summary", state: "NOT AVAILABLE",
    why: "no cross-incident executive composition is implemented; the "
       + "per-incident report is the authoritative artifact" },
  { k: "Compliance packs", state: "NOT EVALUATED",
    why: "no compliance framework mapping is declared for this estate" },
];

const ts = (iso) => (iso ? String(iso).slice(0, 16).replace("T", " ") : null);

export default function XdrReportsPage() {
  const navigate = useNavigate();
  const [rows, setRows] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(null);

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const res = await listIncidents({ sort: "updated_at", order: "desc",
                                        limit: 200 });
      setRows(res.incidents || []);
    } catch (e) {
      setError(apiErrorText(e, "Failed to load."));
      setRows([]);
    } finally { setLoading(false); }
  }, []);
  useEffect(() => { load(); }, [load]);

  const visible = useMemo(() => {
    if (!rows) return [];
    const n = q.trim().toLowerCase();
    if (!n) return rows;
    return rows.filter((r) => `${r.number} ${r.name} ${r.customer}`
      .toLowerCase().includes(n));
  }, [rows, q]);

  return (
    <XdrShell>
      <div className="inv" data-testid="xdr-reports-page"
           style={{ padding: "12px 16px 24px" }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: 12,
                      flexWrap: "wrap" }}>
          <h1 style={{ margin: 0, fontSize: 19, fontWeight: 700 }}
              data-testid="xdr-reports-title">
            Reports
          </h1>
          <span style={{ fontSize: 11, color: "var(--nx-muted, var(--muted))",
                         maxWidth: 760, lineHeight: 1.6 }}>
            One deterministic investigation report per incident — system
            composition plus the persisted analyst overlay. The PDF is a
            projection of the same contract, never a second report engine.
          </span>
          <div style={{ marginLeft: "auto", display: "flex", gap: 8 }}>
            <input value={q} onChange={(e) => setQ(e.target.value)}
                   data-testid="xdr-reports-filter"
                   placeholder="Filter incident, tenant…"
                   style={{ fontSize: 11.5, padding: "5px 9px",
                            background: "var(--nx-surf, var(--panel))",
                            border: "1px solid var(--nx-bd-quiet, var(--border))",
                            borderRadius: 4,
                            color: "var(--nx-text, var(--text))" }} />
            <button className="inv-chip" onClick={load} disabled={loading}
                    data-testid="xdr-reports-refresh">
              <RefreshCw size={11} /> Refresh
            </button>
          </div>
        </div>

        <NxInvSection title="Investigation reports"
          subtitle={loading ? "reading the incident authority…"
            : `${visible.length} incident report(s) in your authorized scope`}
          testid="xdr-reports-library">
          {error && (
            <NxInvEmpty testid="xdr-reports-error"
              title={`${ABSENCE.NOT_AVAILABLE} — the report library could not be read`}
              body={String(typeof error === "object"
                ? JSON.stringify(error) : error)} />
          )}

          <div className="inv-split" data-testid="xdr-reports-wk"
               data-pane={sel ? "open" : "closed"}>
            <div className="inv-split__t">
              <NxInvTable testid="xdr-reports-table"
                          rows={visible.slice(0, 60)} rowKey={(r) => r.id}
                          onRowClick={(r) => setSel(r)}
                          columns={[
                            { key: "number", label: "Incident",
                              render: (r) => (
                                <span data-testid={`xdr-reports-row-${r.id}`}>
                                  <b>{r.number || r.id}</b> {r.name}
                                </span>) },
                            { key: "customer", label: "Customer", width: 150,
                              render: (r) => <NxInvValue value={r.customer} mono
                                absent={ABSENCE.NOT_ATTRIBUTED} /> },
                            { key: "verdict", label: "Verdict", width: 130,
                              render: (r) => <NxInvValue
                                value={r?.verdict?.stage2_label} mono
                                absent="NOT ISSUED" /> },
                            { key: "state", label: "State", width: 120,
                              render: (r) => <NxInvValue
                                value={String(r.state || "").replace("_", " ")
                                  || null}
                                mono absent={ABSENCE.NOT_RECORDED} /> },
                            { key: "last_activity", label: "Updated", width: 150,
                              render: (r) => <NxInvValue value={ts(r.last_activity)}
                                mono absent={ABSENCE.NOT_RECORDED} /> },
                            { key: "report", label: "Report", width: 168,
                              render: (r) => (
                                <span style={{ display: "inline-flex", gap: 4 }}>
                                  <button className="inv-chip"
                                          style={{ padding: "1px 6px",
                                                   fontSize: 9.4 }}
                                          data-testid={`xdr-reports-open-${r.id}`}
                                          onClick={(e) => { e.stopPropagation();
                                            navigate(`/xdr/incidents/${r.id}?tab=report`); }}>
                                    <FileText size={10} /> Open
                                  </button>
                                  <a className="inv-chip"
                                     style={{ padding: "1px 6px", fontSize: 9.4,
                                              textDecoration: "none" }}
                                     data-testid={`xdr-reports-pdf-${r.id}`}
                                     href={`${API_BASE}/incidents/${r.id}/report/pdf`}
                                     target="_blank" rel="noreferrer"
                                     onClick={(e) => e.stopPropagation()}>
                                    <Download size={10} /> PDF
                                  </a>
                                </span>) },
                          ]}
                          empty={<NxInvEmpty testid="xdr-reports-empty"
                            title={loading ? "Reading the incident authority…"
                              : "NO INCIDENT IN SCOPE"}
                            body={loading ? ""
                              : "A report exists only where an incident exists. This is an authorization and data statement, not a missing feature."} />} />
            </div>

            {sel && (
              <div className="inv-split__p" data-testid="xdr-reports-pane">
                <div className="inv-pane__h">
                  <span style={{ minWidth: 0 }}>
                    <div className="inv-pane__k">INVESTIGATION REPORT</div>
                    <div className="inv-pane__t" data-testid="xdr-reports-pane-title">
                      {sel.number || sel.id}
                    </div>
                  </span>
                  <button className="inv-chip" style={{ marginLeft: "auto" }}
                          onClick={() => setSel(null)}
                          data-testid="xdr-reports-pane-close">Close</button>
                </div>
                <div className="inv-pane__b">
                  <dl className="inv-kv">
                    <dt>Incident</dt>
                    <dd><NxInvValue value={sel.name}
                          absent={ABSENCE.NOT_RECORDED} /></dd>
                    <dt>Customer</dt>
                    <dd className="mono"><NxInvValue value={sel.customer}
                          absent={ABSENCE.NOT_ATTRIBUTED} /></dd>
                    <dt>Verdict</dt>
                    <dd className="mono"><NxInvValue
                          value={sel?.verdict?.stage2_label}
                          absent="NOT ISSUED" /></dd>
                    <dt>Lifecycle state</dt>
                    <dd className="mono"><NxInvValue value={sel.state}
                          absent={ABSENCE.NOT_RECORDED} /></dd>
                    <dt>Last activity</dt>
                    <dd className="mono"><NxInvValue value={ts(sel.last_activity)}
                          absent={ABSENCE.NOT_RECORDED} /></dd>
                  </dl>
                  <div style={{ display: "flex", gap: 6, marginTop: 10 }}>
                    <button className="inv-chip"
                            onClick={() => navigate(`/xdr/incidents/${sel.id}?tab=report`)}
                            data-testid="xdr-reports-pane-open">
                      <FileText size={11} /> Open the report
                    </button>
                    <a className="inv-chip" style={{ textDecoration: "none" }}
                       href={`${API_BASE}/incidents/${sel.id}/report/pdf`}
                       target="_blank" rel="noreferrer"
                       data-testid="xdr-reports-pane-pdf">
                      <Download size={11} /> PDF projection
                    </a>
                  </div>
                  <div className="inv-sec__s" style={{ marginTop: 10 }}>
                    The PDF is a projection of the same report contract — never a
                    second report engine.
                  </div>
                </div>
              </div>
            )}
          </div>
        </NxInvSection>

        <NxInvTech label="Report types this build does not produce"
                   testid="xdr-reports-unsupported">
          <NxInvTable testid="xdr-reports-unsupported-table" rows={UNSUPPORTED}
                      rowKey={(u) => u.k}
                      columns={[
                        { key: "k", label: "Report type", width: 230,
                          render: (u) => <b data-testid={`xdr-reports-unsupported-${
                            u.k.toLowerCase().replace(/\W+/g, "-")}`}>{u.k}</b> },
                        { key: "state", label: "State", width: 150,
                          render: (u) => <span className="inv-tb__na">{u.state}</span> },
                        { key: "why", label: "Why" },
                      ]} />
        </NxInvTech>
      </div>
    </XdrShell>
  );
}
