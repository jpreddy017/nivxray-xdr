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
import IntelligenceOverlayEditor from "@/xdr/components/IntelligenceOverlayEditor";
import "@/xdr/design/tokens.css";

export default function ExecutiveSummaryPanel({ incidentId, onSelectRef }) {
  const [data, setData]         = useState(null);
  const [loading, setLoading]   = useState(false);
  const [error, setError]       = useState(null);
  // R46 · Analyst overlay for the incident-level Executive Summary.
  // Machine truth = Gateway `text` at the moment we loaded it.  The
  // overlay layer edits *interpretation* only; verdict/severity/
  // confidence/evidence-ids/technique-ids stay strictly immutable.
  const [overlay, setOverlay]   = useState(null);

  const loadSummary = async () => {
    if (!incidentId) return;
    setLoading(true); setError(null);
    try {
      // Load Gateway narration and existing analyst overlay in parallel.
      const [narr, ov] = await Promise.all([
        api.get(`/narration/incident/${incidentId}/executive-summary`),
        api.get(
          `/intelligence-overlays/?incident_id=${encodeURIComponent(incidentId)}` +
          `&target_kind=exec_summary&target_id=${encodeURIComponent(incidentId)}` +
          `&field_key=content`,
        ).catch(() => ({ data: [] })),
      ]);
      setData(narr.data);
      const list = Array.isArray(ov.data) ? ov.data : (ov.data?.overlays || []);
      setOverlay(list && list[0] ? list[0] : null);
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

          {/* R46 · Analyst Interpretation overlay — edits narrative
                  only; verdict / severity / confidence / evidence_ids /
                  technique_ids remain strictly immutable. */}
          <div style={{ marginTop: 14 }} data-testid="xdr-exec-summary-overlay">
            <IntelligenceOverlayEditor
              incidentId   ={incidentId}
              targetKind   ="exec_summary"
              targetId     ={incidentId}
              fieldKey     ="content"
              machineValue ={data.text || ""}
              overlay      ={overlay}
              onChange     ={setOverlay}
              label        ="Analyst Interpretation"
            />
          </div>
        </div>
      )}
    </div>
  );
}
