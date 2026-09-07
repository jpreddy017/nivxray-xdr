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
import { listEdrDetections, listEndpointDetections } from "@/nivxforge/edrApi";
import { EndpointNotResolved,
         notResolved } from "@/nivxforge/components/EndpointNotResolved";

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

/**
 * P0-F · endpoint-scoped detections, straight from the authoritative
 * records the XDR detection fabric wrote onto the immutable raw endpoint
 * event. `events_not_evaluated` is shown deliberately: an endpoint event
 * that never reached detection is a DETECTION GAP, and a console that
 * hides it would be telling the analyst the endpoint is clean.
 */
const EndpointDetections = ({ endpointId, incidentId }) => {
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);

  useEffect(() => {
    let dead = false;
    listEndpointDetections(endpointId)
      .then((d) => { if (!dead) setData(d); })
      .catch((e) => { if (!dead) setErr(e?.message || String(e)); });
    return () => { dead = true; };
  }, [endpointId]);

  if (err) {
    return <div className="x-empty" style={{ color: "#ff9494" }}
                data-testid="edr-endpoint-detections-error">{err}</div>;
  }
  if (!data) {
    return <div className="x-empty"
                data-testid="edr-endpoint-detections-loading">
      <Loader2 size={13} className="spin"
               style={{ verticalAlign: "middle", marginRight: 6 }} />
      Reading endpoint detections …
    </div>;
  }
  if (notResolved(data)) {
    return <EndpointNotResolved supplied={endpointId} payload={data}
                                testid="edr-endpoint-detections-not-resolved" />;
  }
  return (
    <div data-testid="edr-endpoint-detections">
      <div style={{ marginBottom: 10, fontSize: 10.5, letterSpacing: ".3px",
                    color: "var(--faint)", textTransform: "uppercase",
                    fontWeight: 800 }}>
        Endpoint · <span style={{ color: "var(--cyan)" }}>{endpointId}</span>
        {"  ·  "}<span data-testid="edr-endpoint-detections-count">
          {data.count} detection{data.count === 1 ? "" : "s"}</span>
        {"  ·  "}{data.events_evaluated} events evaluated
        {data.events_not_evaluated > 0 && (
          <span style={{ color: "#ffb454" }}
                data-testid="edr-endpoint-detection-gap">
            {"  ·  "}{data.events_not_evaluated} NOT EVALUATED (detection gap)
          </span>)}
      </div>
      {data.count === 0 ? (
        <div className="x-empty" data-testid="edr-endpoint-detections-empty">
          <b>NO RULE FIRED</b> — {data.events_evaluated} endpoint events were
          evaluated by the detection fabric and none matched. This is not a
          statement that the endpoint is clean.
        </div>
      ) : (
        <div className="panel" style={{ overflow: "hidden" }}>
          <table className="x-table" style={{ width: "100%" }}>
            <thead>
              <tr>
                <th>Detected</th><th>Rules</th><th>Activity</th>
                <th>Command line</th><th>Verdict</th><th>Provenance</th>
                <th>Trajectory</th>
              </tr>
            </thead>
            <tbody>
              {data.detections.map((r) => (
                <tr key={r.raw_id}
                    data-testid={`edr-endpoint-detection-${r.raw_id}`}>
                  <td className="mono" style={{ color: "var(--muted)" }}>
                    {fmtTs(r.detected_at)}
                  </td>
                  <td className="mono" style={{ color: "var(--mint)" }}>
                    {(r.rule_ids || []).join(", ")}
                  </td>
                  <td className="mono">{r.activity}</td>
                  <td className="mono" style={{ color: "var(--text)",
                                                wordBreak: "break-all",
                                                maxWidth: 420 }}>
                    {r.command_line || r.image_path || "◇ not observed"}
                  </td>
                  <td className="mono" style={{ textTransform: "uppercase" }}>
                    {r.verdict || "—"}
                  </td>
                  <td className="mono" style={{ fontSize: 9,
                                                color: "var(--faint)" }}>
                    {r.raw_id} → {r.canonical_event_id}
                  </td>
                  <td>
                    {/* Hand off on the stable identifier, so the
                        trajectory opens on THIS observation. */}
                    <Link
                      to={`/xdr/edr/device-trajectory?device=`
                        + `${encodeURIComponent(endpointId)}`
                        + `&raw_event_id=${encodeURIComponent(r.raw_id)}`
                        + (r.canonical_event_id
                          ? `&canonical_event_id=`
                            + `${encodeURIComponent(r.canonical_event_id)}`
                          : "")
                        + (incidentId
                          ? `&incident_id=${encodeURIComponent(incidentId)}`
                          : "")}
                      data-testid={`edr-detection-trajectory-${r.raw_id}`}
                      style={{ color: "var(--cyan)", fontSize: 10.5,
                               textDecoration: "none", whiteSpace: "nowrap" }}
                    >
                      Trajectory <ExternalLink size={9} />
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default function EdrDetectionsPage() {
  const ctx = useIncidentContext();
  const [params] = useSearchParams();
  const endpointId = params.get("endpoint_id") || params.get("device");
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
        {endpointId
          ? "Authoritative endpoint detections produced by the NivXRay XDR "
            + "detection fabric from real sensor evidence. NivXForge EDR "
            + "runs no detection engine of its own."
          : "Read-only projection of the deterministic Stage-2 Verdict "
            + "Engine. Row → Device Trajectory with incident context "
            + "preserved."}
      </div>

      {endpointId && <EndpointDetections endpointId={endpointId}
                                         incidentId={ctx.incident_id} />}

      {!ctx.incident_id && !endpointId && (
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
