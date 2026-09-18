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
      <div className="cc" data-testid="xdr-reports-page"
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
            <button className="cx-pill" onClick={load} disabled={loading}
                    data-testid="xdr-reports-refresh">
              <RefreshCw size={11} /> Refresh
            </button>
          </div>
        </div>

        <div className="cc-card" data-testid="xdr-reports-library">
          <div className="cc-card__h">
            <span className="cc-card__t">Investigation reports</span>
            <span className="cc-card__s">
              {loading ? "reading the incident authority…"
                : `${visible.length} incident report(s) in your authorized scope`}
            </span>
          </div>
          <div className="cc-card__b">
            {error && (
              <div className="cc-empty" data-testid="xdr-reports-error">
                <b>NOT AVAILABLE</b> — {String(
                  typeof error === "object" ? JSON.stringify(error) : error)}
              </div>
            )}
            {!error && !loading && visible.length === 0 && (
              <div className="cc-empty" data-testid="xdr-reports-empty">
                <b>NO INCIDENT IN SCOPE</b> — a report exists only where an
                incident exists. This is an authorization and data statement,
                not a missing feature.
              </div>
            )}
            {visible.length > 0 && (
              <table className="cc-tb" data-testid="xdr-reports-table">
                <thead>
                  <tr>
                    <th>Incident</th><th>Tenant</th><th>Verdict</th>
                    <th>State</th><th>Updated</th><th>Report</th>
                  </tr>
                </thead>
                <tbody>
                  {visible.slice(0, 60).map((r) => (
                    <tr key={r.id} data-testid={`xdr-reports-row-${r.id}`}>
                      <td onClick={() => navigate(`/xdr/incidents/${r.id}?tab=report`)}>
                        <b>{r.number || r.id}</b> {r.name}
                      </td>
                      <td className="mono">
                        {r.customer || <span className="cc-tb__na">
                          NOT ATTRIBUTED</span>}
                      </td>
                      <td className="mono">
                        {r?.verdict?.stage2_label || <span className="cc-tb__na">
                          NOT ISSUED</span>}
                      </td>
                      <td className="mono">
                        {String(r.state || "").replace("_", " ")}
                      </td>
                      <td className="mono">
                        {ts(r.last_activity) || <span className="cc-tb__na">
                          NOT RECORDED</span>}
                      </td>
                      <td>
                        <button className="cx-pill"
                                data-testid={`xdr-reports-open-${r.id}`}
                                onClick={(e) => { e.stopPropagation();
                                  navigate(`/xdr/incidents/${r.id}?tab=report`); }}>
                          <FileText size={11} /> Open
                        </button>{" "}
                        <a className="cx-pill"
                           data-testid={`xdr-reports-pdf-${r.id}`}
                           href={`${API_BASE}/incidents/${r.id}/report/pdf`}
                           target="_blank" rel="noreferrer"
                           onClick={(e) => e.stopPropagation()}
                           style={{ textDecoration: "none" }}>
                          <Download size={11} /> PDF
                        </a>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        <div className="cc-card" data-testid="xdr-reports-unsupported">
          <div className="cc-card__h">
            <span className="cc-card__t">Report types this build does not produce</span>
          </div>
          <div className="cc-card__b">
            <table className="cc-tb">
              <tbody>
                {UNSUPPORTED.map((u) => (
                  <tr key={u.k} style={{ cursor: "default" }}
                      data-testid={`xdr-reports-unsupported-${
                        u.k.toLowerCase().replace(/\W+/g, "-")}`}>
                    <td style={{ width: 220 }}><b>{u.k}</b></td>
                    <td className="mono cc-tb__na" style={{ width: 140 }}>
                      {u.state}
                    </td>
                    <td>{u.why}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </XdrShell>
  );
}
