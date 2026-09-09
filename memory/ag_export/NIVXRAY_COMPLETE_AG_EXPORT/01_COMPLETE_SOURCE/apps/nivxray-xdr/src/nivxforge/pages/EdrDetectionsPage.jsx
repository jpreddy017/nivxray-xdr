/**
 * NivXForge EDR · Detections page.
 *
 * READ-ONLY projection from the Stage-2 Verdict Engine.  Every row
 * surfaces the rule that fired PLUS the analyst-facing "Detected By"
 * so provenance is always visible.  Clicking a row pivots into
 * Device Trajectory with the incident context preserved.
 */
import React, { useEffect, useState } from "react";
import { useSearchParams, Link } from "react-router-dom";
import { ExternalLink, ShieldAlert, Loader2 } from "lucide-react";

import NivXForgeConsole, { useIncidentContext } from "@/nivxforge/NivXForgeConsole";
import { listEdrDetections } from "@/nivxforge/edrApi";

const SEV_CLASS = {
  critical: "sev-critical",
  high:     "sev-high",
  medium:   "sev-medium",
  low:      "sev-low",
  info:     "sev-info",
};

function fmtTs(iso) {
  if (!iso) return "—";
  try { return new Date(iso).toISOString().replace("T", " ").slice(0, 16) + "Z"; }
  catch { return iso; }
}

export default function EdrDetectionsPage() {
  const ctx = useIncidentContext();
  const [params] = useSearchParams();
  const [rows, setRows]         = useState(null);
  const [meta, setMeta]         = useState(null);
  const [loading, setLoading]   = useState(false);
  const [error, setError]       = useState(null);

  useEffect(() => {
    if (!ctx.incident_id) { setRows([]); return; }
    let cancelled = false;
    (async () => {
      setLoading(true); setError(null);
      try {
        const data = await listEdrDetections(ctx.incident_id);
        if (!cancelled) {
          setRows(data.detections || []);
          setMeta({ source: data.source, note: data.note });
        }
      } catch (e) {
        if (!cancelled) setError(e?.response?.data?.detail || e?.message || "Failed to load detections.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [ctx.incident_id]);

  const trajLink = (r) => {
    const p = new URLSearchParams();
    if (ctx.incident_id) p.set("incident_id", ctx.incident_id);
    if (ctx.device)      p.set("device", ctx.device);
    if (ctx.tenant)      p.set("tenant", ctx.tenant);
    if (r.evidence_ref?.rule_id) p.set("rule_id", r.evidence_ref.rule_id);
    return `/edr/trajectory?${p.toString()}`;
  };

  return (
    <NivXForgeConsole activeTab="detections">
      <h1 className="page-h1" data-testid="edr-detections-heading">Detections</h1>
      <div className="page-sub">
        Read-only projection of the deterministic Stage-2 Verdict Engine.
        Row → Device Trajectory with incident context preserved.
      </div>

      {!ctx.incident_id && (
        <div className="x-empty" data-testid="edr-detections-noctx">
          Detections are scoped to an incident.
          Open this page from an incident's <b>NivXForge EDR</b> launcher.
        </div>
      )}
      {ctx.incident_id && loading && (
        <div className="x-empty" data-testid="edr-detections-loading">
          <Loader2 size={13} className="spin" style={{ verticalAlign: "middle", marginRight: 6 }} />
          Loading detections …
        </div>
      )}
      {ctx.incident_id && !loading && error && (
        <div className="x-empty" style={{ color: "#ff9494" }} data-testid="edr-detections-error">
          {String(error)}
        </div>
      )}
      {ctx.incident_id && !loading && !error && rows && rows.length === 0 && (
        <div className="x-empty" data-testid="edr-detections-empty">
          <b>NO MATCHING EVIDENCE</b> — Stage-2 has not fired any rules for this incident.
        </div>
      )}
      {ctx.incident_id && !loading && !error && rows && rows.length > 0 && (
        <>
          <div style={{
            marginBottom: 10, fontSize: 10.5, letterSpacing: ".3px",
            color: "var(--faint)", textTransform: "uppercase", fontWeight: 800,
          }}>
            Source · <span style={{ color: "var(--cyan)" }}>{meta?.source}</span>
          </div>
          <div className="panel" style={{ overflow: "hidden" }} data-testid="edr-detections-panel">
            <table className="x-table" style={{ width: "100%" }}>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Detection</th>
                  <th>Severity</th>
                  <th>Detected By</th>
                  <th>Source</th>
                  <th>Device</th>
                  <th>User</th>
                  <th>Process</th>
                  <th>Disposition</th>
                  <th style={{ textAlign: "right" }}>Pivot</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => {
                  const sev = SEV_CLASS[r.severity] || "sev-info";
                  return (
                    <tr key={r.detection_id}
                          data-testid={`edr-detection-row-${r.rule_id}`}>
                      <td className="mono" style={{ color: "var(--muted)" }}>{fmtTs(r.timestamp)}</td>
                      <td style={{ color: "var(--text)", fontWeight: 600 }}>
                        <ShieldAlert size={11} style={{
                          color: "var(--amber)", verticalAlign: "middle",
                          marginRight: 6,
                        }} />
                        {r.detection}
                      </td>
                      <td><span className={`badge ${sev}`}>{r.severity}</span></td>
                      <td className="mono" style={{ color: "var(--mint)" }} data-testid={`edr-detected-by-${r.rule_id}`}>
                        {r.detected_by}
                      </td>
                      <td className="mono" style={{ color: "var(--muted)" }}>
                        {r.rule_id}
                      </td>
                      <td className="mono">{r.device || "—"}</td>
                      <td className="mono">{r.user || "—"}</td>
                      <td className="mono">{r.process || "—"}</td>
                      <td className="mono" style={{ textTransform: "uppercase",
                                                          color: r.disposition === "malicious" ? "#ff9494" : "var(--text-dim)" }}>
                        {r.disposition}
                      </td>
                      <td style={{ textAlign: "right" }}>
                        <Link
                          to={trajLink(r)}
                          className="btn mint"
                          style={{ textDecoration: "none", padding: "3px 8px" }}
                          data-testid={`edr-pivot-trajectory-${r.rule_id}`}
                          title="Open Device Trajectory with this incident's context"
                        >
                          Trajectory <ExternalLink size={10} />
                        </Link>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </>
      )}
    </NivXForgeConsole>
  );
}
