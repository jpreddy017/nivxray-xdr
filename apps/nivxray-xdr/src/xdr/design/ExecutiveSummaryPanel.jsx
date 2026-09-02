/**
 * ExecutiveSummaryPanel · Round 38 / Phase 1 Cockpit Landing.
 * ---------------------------------------------------------------
 * Executive Summary panel powered by NivXRay XDR Narration Gateway.
 * (Deterministic today, LLM-upgradable later; provenance badges per paragraph).
 *
 * Fetches from: GET /api/narration/incident/{incident_id}/executive-summary
 */
import React, { useEffect, useState } from "react";
import { Sparkles, ShieldCheck, FileText, AlertTriangle, ExternalLink, RefreshCcw } from "lucide-react";
import api from "@/lib/api";
import EvidenceState from "@/xdr/design/EvidenceState";
import Action from "@/xdr/design/Action";
import "@/xdr/design/tokens.css";

export default function ExecutiveSummaryPanel({ incidentId, onSelectRef }) {
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState(null);

  const loadSummary = async () => {
    if (!incidentId) return;
    setLoading(true); setError(null);
    try {
      const res = await api.get(`/narration/incident/${incidentId}/executive-summary`);
      setData(res.data);
    } catch (e) {
      setError(e?.response?.data?.detail || e?.message || "Failed to load Narration Gateway executive summary.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSummary();
  }, [incidentId]);

  if (!incidentId) return null;

  return (
    <div className="evops-narration" data-testid="xdr-executive-summary-panel">
      <div className="evops-narration__head">
        <div className="evops-narration__title" data-testid="xdr-exec-summary-title">
          <Sparkles size={16} style={{ color: "var(--nx-purple)" }} />
          <span>Executive Summary · NivXRay XDR Narration Gateway</span>
        </div>
        <div className="evops-narration__meta">
          {data?.generation_mode && (
            <span className="evops-narration__badge evops-narration__badge--mode" data-testid="xdr-exec-summary-mode">
              {data.generation_mode}
            </span>
          )}
          {data?.provider && (
            <span className="evops-mono" style={{ fontSize: 10, color: "var(--nx-faint)" }} data-testid="xdr-exec-summary-provider">
              provider: {data.provider}
            </span>
          )}
          {data?.grounded !== undefined && (
            <span className="evops-narration__badge evops-narration__badge--grounded" data-testid="xdr-exec-summary-grounded">
              <ShieldCheck size={10} /> GROUNDED
            </span>
          )}
          <Action
            label="Refresh"
            icon={RefreshCcw}
            onRun={loadSummary}
            testid="xdr-exec-summary-refresh"
          />
        </div>
      </div>

      {loading && (
        <div className="evops-hint" data-testid="xdr-exec-summary-loading">
          Synthesizing governed executive narration …
        </div>
      )}

      {error && (
        <div className="evops-empty" data-testid="xdr-exec-summary-error">
          <div className="evops-empty__title">Narration Gateway unavailable</div>
          <div className="evops-empty__reason">{String(error)}</div>
        </div>
      )}

      {!loading && !error && data && (
        <div className="evops-narration__body" data-testid="xdr-exec-summary-body">
          {Array.isArray(data.paragraphs) && data.paragraphs.length > 0 ? (
            data.paragraphs.map((p, idx) => (
              <div key={idx} className="evops-narration__paragraph" data-testid={`xdr-exec-summary-para-${idx}`}>
                <div style={{ color: "var(--nx-text)", marginBottom: 4 }}>{p.text}</div>
                <div className="evops-narration__provenance-pills">
                  {(p.evidence_ids || []).map((eid) => (
                    <button
                      key={eid}
                      className="evops-narration__pill"
                      onClick={() => onSelectRef && onSelectRef("evidence", eid)}
                      data-testid={`xdr-exec-summary-pill-evd-${eid}`}
                      title="Inspect evidence in Shared Evidence Inspector"
                    >
                      <FileText size={9} />
                      <span>{eid}</span>
                    </button>
                  ))}
                  {(p.technique_ids || []).map((tid) => (
                    <button
                      key={tid}
                      className="evops-narration__pill"
                      onClick={() => onSelectRef && onSelectRef("technique", tid)}
                      data-testid={`xdr-exec-summary-pill-tech-${tid}`}
                      title="Inspect ATT&CK technique"
                    >
                      <ExternalLink size={9} />
                      <span>{tid}</span>
                    </button>
                  ))}
                </div>
              </div>
            ))
          ) : (
            <div style={{ color: "var(--nx-text)" }}>{data.text}</div>
          )}

          {Array.isArray(data.caveats) && data.caveats.length > 0 && (
            <div style={{ marginTop: 10, fontSize: 11, color: "var(--nx-muted)", display: "flex", alignItems: "center", gap: 6 }} data-testid="xdr-exec-summary-caveats">
              <AlertTriangle size={12} style={{ color: "var(--evops-cap-degraded-fg)" }} />
              <span>{data.caveats.join(" · ")}</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
