/**
 * TechnicalTab · Layer 3 · Analyst deep-technical view.
 *
 * Suspicious elements (rule · weight · engine · provenance) +
 * chain steps + IOC breakdown.  All fields provenance-linked.
 */
import React, { useEffect, useState } from "react";
import { Loader2 } from "lucide-react";

import { getIncidentSummary } from "@/lib/incidentsApi";
import { DomainTag } from "@/xdr/components/chips";

export default function TechnicalTab({ incident }) {
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);

  useEffect(() => {
    if (!incident?.id) return undefined;
    let cancelled = false;
    (async () => {
      setLoading(true); setError(null);
      try {
        const data = await getIncidentSummary(incident.id);
        if (!cancelled) setSummary(data);
      } catch (e) {
        if (!cancelled)
          setError(e?.response?.data?.detail || e?.message || "Failed to load technical summary.");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [incident?.id]);

  const suspicious = summary?.suspicious_elements || [];
  const iocs = incident.iocs || {};
  const chain = incident.chain_ids || [];

  if (loading) return (
    <div className="rl-loading">
      <Loader2 size={12} className="rl-spin" style={{ verticalAlign: "-2px", marginRight: 6 }} />
      LOADING TECHNICAL DETAIL…
    </div>
  );
  if (error) return <div className="rl-error">{String(error)}</div>;

  return (
    <div data-testid="xdr-record-technical">
      {/* Suspicious elements */}
      <div className="rl-section" data-testid="xdr-record-technical-suspicious">
        <div className="rl-section-title">Suspicious elements (rule-fired evidence)</div>
        {suspicious.length === 0
          ? <div className="rl-empty">NO MATCHING EVIDENCE — no rule-fired detections on this case yet.</div>
          : <table className="rl-table">
              <thead><tr>
                <th>Rule</th><th style={{ width: 70 }}>Weight</th>
                <th>Detected by</th><th>Provenance</th>
              </tr></thead>
              <tbody>
                {suspicious.map((r, i) => (
                  <tr key={i} data-testid={`xdr-record-technical-susp-${i}`}>
                    <td className="mono" style={{ color: "var(--rl-purple)" }}>
                      {r.rule_id || "—"}
                    </td>
                    <td className="mono" style={{
                      color: (r.weight || 0) >= 20 ? "var(--rl-amber)" : "var(--rl-text-dim)",
                      fontWeight: 700,
                    }}>
                      {r.weight != null ? `+${r.weight}` : "—"}
                    </td>
                    <td className="mono">{r.detected_by || <span className="rl-state na">NOT AVAILABLE</span>}</td>
                    <td className="mono" style={{ fontSize: 10.5, color: "var(--rl-faint)" }}>
                      {r.provenance || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>}
      </div>

      {/* Decoder chain */}
      <div className="rl-section" data-testid="xdr-record-technical-chain">
        <div className="rl-section-title">Decoder chain</div>
        {chain.length === 0
          ? <div className="rl-empty">NOT_RUN — no decoder chain recorded for this incident.</div>
          : <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {chain.map((c, i) => (
                <span key={i} className="rl-state ok"
                        style={{ padding: "3px 8px" }}
                        data-testid={`xdr-record-technical-chain-${i}`}>
                  {i + 1} · {c}
                </span>
              ))}
            </div>}
      </div>

      {/* IOC breakdown */}
      <div className="rl-section" data-testid="xdr-record-technical-iocs">
        <div className="rl-section-title">Indicators (from canonical IOC set)</div>
        {(() => {
          const kinds = ["url", "domain", "ip", "hash", "file", "email"];
          const rows = kinds.map(k => ({
            k,
            list: Array.isArray(iocs[k]) ? iocs[k] : [],
          })).filter(r => r.list.length > 0);
          if (rows.length === 0) {
            return <div className="rl-empty">
              NO EVIDENCE — no indicators projected onto this case.
            </div>;
          }
          return (
            <table className="rl-table">
              <thead><tr>
                <th style={{ width: 80 }}>Kind</th>
                <th style={{ width: 60 }}>Count</th>
                <th>Sample</th>
              </tr></thead>
              <tbody>
                {rows.map(r => (
                  <tr key={r.k} data-testid={`xdr-record-technical-ioc-${r.k}`}>
                    <td><DomainTag value={r.k.toUpperCase()} /></td>
                    <td className="mono">{r.list.length}</td>
                    <td className="mono" style={{ wordBreak: "break-all" }}>
                      {r.list.slice(0, 3).join("  ·  ")}
                      {r.list.length > 3 && `  +${r.list.length - 3} more`}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          );
        })()}
      </div>

      {/* Input preview */}
      {incident.input_preview && (
        <div className="rl-section" data-testid="xdr-record-technical-input">
          <div className="rl-section-title">Original input preview</div>
          <pre style={{
            margin: 0, padding: 10,
            background: "var(--rl-surface-2)",
            border: "1px solid var(--rl-border)",
            borderRadius: 4,
            fontFamily: "var(--rs-mono)", fontSize: 11,
            color: "var(--rl-text-dim)",
            maxHeight: 200, overflow: "auto",
            whiteSpace: "pre-wrap", wordBreak: "break-all",
          }}>{incident.input_preview}</pre>
        </div>
      )}
    </div>
  );
}
