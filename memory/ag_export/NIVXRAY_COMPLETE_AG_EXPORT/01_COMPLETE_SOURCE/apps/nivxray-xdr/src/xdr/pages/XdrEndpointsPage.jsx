/**
 * XdrEndpointsPage · `/xdr/endpoints`
 *
 * Native XDR device inventory.  Read-only projection of
 * `/api/edr/endpoints` — every row is a real host extracted from an
 * existing case.  Row click / View Trajectory → the native Slice 6
 * canvas at `/xdr/endpoints/:device/trajectory`.
 */
import React, { useCallback, useEffect, useState, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { Loader2, HardDrive, Radar, Search } from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import { listEndpoints } from "@/nivxforge/edrApi";

const SEV_CLASS = {
  malicious:  "sev-critical",
  suspicious: "sev-medium",
  benign:     "sev-low",
  unknown:    "sev-info",
};
const SEV_LABEL = {
  malicious: "Malicious", suspicious: "Suspicious",
  benign: "Benign",       unknown:    "Unknown",
};

function fmtDate(iso) {
  if (!iso) return "—";
  try { return new Date(iso).toISOString().replace("T", " ").slice(0, 16) + "Z"; }
  catch { return iso; }
}

export default function XdrEndpointsPage() {
  const navigate = useNavigate();
  const [rows, setRows]         = useState(null);
  const [meta, setMeta]         = useState(null);
  const [loading, setLoading]   = useState(true);
  const [error, setError]       = useState(null);
  const [q, setQ]               = useState("");

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const data = await listEndpoints();
      setRows(data.endpoints || []);
      setMeta({ source: data.source, note: data.note });
    } catch (e) {
      setError(e?.response?.data?.detail || e?.message || "Failed to load endpoints.");
    } finally {
      setLoading(false);
    }
  }, []);
  useEffect(() => { load(); }, [load]);

  const filtered = useMemo(() => {
    const needle = (q || "").trim().toLowerCase();
    if (!needle) return rows || [];
    return (rows || []).filter((r) =>
      [r.host, r.tenant, r.engine, r.worst_label]
        .filter(Boolean).join(" ").toLowerCase().includes(needle),
    );
  }, [rows, q]);

  const openTrajectory = (host) =>
    navigate(`/xdr/endpoints/${encodeURIComponent(host)}/trajectory`);

  return (
    <XdrShell>
      <h1 className="page-h1" data-testid="xdr-endpoints-heading">Endpoints</h1>
      <div className="page-sub">
        Devices projected from saved cases.  Row → native Device Trajectory canvas.
      </div>

      {loading && (
        <div className="x-empty" data-testid="xdr-endpoints-loading">
          <Loader2 size={13} className="spin"
                    style={{ verticalAlign: "middle", marginRight: 6 }} />
          Loading endpoints …
        </div>
      )}
      {!loading && error && (
        <div className="x-empty" style={{ color: "#ff9494" }}
              data-testid="xdr-endpoints-error">{String(error)}</div>
      )}
      {!loading && !error && rows && rows.length === 0 && (
        <div className="x-empty" data-testid="xdr-endpoints-empty">
          <b>NO MATCHING EVIDENCE</b> — no endpoints projected from your saved cases yet.
        </div>
      )}
      {!loading && !error && rows && rows.length > 0 && (
        <section className="panel" style={{ overflow: "hidden" }}
                    data-testid="xdr-endpoints-panel">
          <div className="queue-toolbar">
            <Search size={13} style={{ color: "var(--muted)" }} />
            <input
              placeholder="Search host, tenant, verdict…"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              data-testid="xdr-endpoints-search"
            />
            <div style={{ flex: 1 }} />
            <div className="mono" style={{ color: "var(--faint)", fontSize: 10.5 }}>
              {filtered.length} of {rows.length}
            </div>
          </div>
          <table className="x-table" style={{ width: "100%" }}
                    data-testid="xdr-endpoints-table">
            <thead>
              <tr>
                <th>Host</th>
                <th>Worst Verdict</th>
                <th>Risk</th>
                <th>Incidents</th>
                <th>Detections</th>
                <th>Tenant</th>
                <th>Last Seen</th>
                <th style={{ textAlign: "right" }}>Action</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((r) => {
                const sev = SEV_CLASS[r.worst_label] || "sev-info";
                return (
                  <tr key={r.host}
                        className="rowlink"
                        onClick={() => openTrajectory(r.host)}
                        data-testid={`xdr-endpoints-row-${r.host}`}>
                    <td style={{ color: "var(--text)", fontWeight: 700 }}>
                      <HardDrive size={11}
                                    style={{ color: "var(--mint)",
                                              verticalAlign: "middle",
                                              marginRight: 6 }} />
                      {r.host}
                    </td>
                    <td>
                      <span className={`badge ${sev}`}>
                        {SEV_LABEL[r.worst_label] || r.worst_label}
                      </span>
                    </td>
                    <td className="mono" style={{
                        color: (r.worst_risk || 0) >= 80 ? "#ff9494"
                                : (r.worst_risk || 0) >= 50 ? "var(--amber)"
                                : "var(--text-dim)"
                      }}>
                      {r.worst_risk != null ? `${Math.round(r.worst_risk)}/100` : "—"}
                    </td>
                    <td className="mono">{r.incident_count}</td>
                    <td className="mono">{r.detection_count}</td>
                    <td className="mono">{r.tenant || "—"}</td>
                    <td className="mono" style={{ color: "var(--muted)" }}>
                      {fmtDate(r.last_seen)}
                    </td>
                    <td style={{ textAlign: "right" }}>
                      <button
                        className="btn primary"
                        style={{ padding: "3px 8px" }}
                        onClick={(e) => { e.stopPropagation(); openTrajectory(r.host); }}
                        data-testid={`xdr-endpoints-view-trajectory-${r.host}`}
                        title="Open native XDR trajectory canvas"
                      >
                        <Radar size={11} /> View Trajectory
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {meta?.source && (
            <div style={{
              padding: "8px 14px", fontSize: 9.8, letterSpacing: ".3px",
              color: "var(--faint)", textTransform: "uppercase", fontWeight: 800,
              borderTop: "1px solid var(--border)",
            }}>
              Source · <span style={{ color: "var(--cyan)" }}>{meta.source}</span>
            </div>
          )}
        </section>
      )}
    </XdrShell>
  );
}
