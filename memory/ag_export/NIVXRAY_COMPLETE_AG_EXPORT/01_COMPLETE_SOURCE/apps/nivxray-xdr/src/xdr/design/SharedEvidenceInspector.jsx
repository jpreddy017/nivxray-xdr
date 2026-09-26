/**
 * SharedEvidenceInspector · Round 38.3 / Phase 1 Exemplar.
 * ---------------------------------------------------------------
 * ONE consistent detail surface opened by clicks in MITRE / Attack Story / Attack Graph.
 * Left  = Governed context (what/why/evidence ids, identity, verdict & confidence).
 * Right = Related entities, ATT&CK mapping, provenance chain, and investigation actions.
 */
import React, { useEffect, useState } from "react";
import { Loader2, ExternalLink, Play, X, ShieldAlert, FileText, Server, User, GitBranch } from "lucide-react";
import api from "@/lib/api";
import EvidenceState from "@/xdr/design/EvidenceState";
import Entity from "@/xdr/design/Entity";
import Provenance from "@/xdr/design/Provenance";
import Action, { ActionGroup } from "@/xdr/design/Action";
import "@/xdr/design/tokens.css";

const STATE_BADGE = {
  OBSERVED:     { state: "observed" },
  SUPPORTED:    { state: "supported" },
  HYPOTHESIZED: { state: "missing", reason: "HYPOTHESIZED" },
  SUPPRESSED:   { state: "suppressed" },
  NOT_OBSERVED: { state: "unavailable" },
};

export default function SharedEvidenceInspector({ incidentId, kind, refId, onClose, embedded = false }) {
  const [env, setEnv]         = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState(null);

  useEffect(() => {
    if (!incidentId || !kind || !refId) { setEnv(null); return; }
    let cancelled = false;
    setLoading(true); setError(null);
    api.get(`/incidents/${incidentId}/inspector/${kind}/${encodeURIComponent(refId)}`)
      .then(r => { if (!cancelled) setEnv(r.data); })
      .catch(e => { if (!cancelled) setError(e?.message || String(e)); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [incidentId, kind, refId]);

  if (!kind || !refId) {
    return (
      <div className="evops-empty" data-testid="xdr-shared-insp-empty">
        <div className="evops-empty__title">Evidence Inspector</div>
        <div className="evops-empty__reason">
          Select any technique, process, event, command, finding or entity in MITRE, Attack Story or Attack Graph to inspect canonical evidence.
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="evops-hint" data-testid="xdr-shared-insp-loading" style={{ padding: 16 }}>
        <Loader2 size={13} className="rl-spin" style={{ display: "inline", marginRight: 8 }} />
        Resolving canonical evidence for {kind}:{refId} …
      </div>
    );
  }

  if (error) {
    return (
      <div className="evops-empty" data-testid="xdr-shared-insp-error">
        <div className="evops-empty__title">Resolution failed</div>
        <div className="evops-empty__reason">{error}</div>
      </div>
    );
  }

  if (!env) return null;

  if (env.state === "MISSING") {
    return (
      <div className="evops-empty" data-testid="xdr-shared-insp-missing">
        <div className="evops-empty__title">NOT PRESENT</div>
        <div className="evops-empty__reason">{env.reason || `No governed record for ${kind}:${refId}.`}</div>
      </div>
    );
  }

  const id = env.identity || {};
  const rels = env.context?.relationships || [];
  const evs = env.evidence || [];
  const techs = env.attack?.techniques || [];
  const provs = env.provenance || [];
  const actions = env.actions || [];

  const provChainLayers = provs.map((p) => ({
    layer: p.layer || p.source || "canonical",
    value: p.note || p.value || p.source,
    present: true,
  }));

  return (
    <div className="evops-inspector" data-testid="xdr-shared-insp">
      {/* Left Column: Governed Context */}
      <div className="evops-inspector__left" data-testid="xdr-shared-insp-left">
        <div style={{ display: "flex", alignItems: "flex-start", justifyContext: "space-between" }}>
          <div>
            <div style={{ font: "var(--evops-t-eyebrow)", color: "var(--nx-muted)", textTransform: "uppercase", marginBottom: 2 }}>
              {id.subtitle || kind.toUpperCase()}
            </div>
            <div style={{ font: "var(--evops-t-title)", fontSize: 16, color: "var(--nx-text)", wordBreak: "break-all" }} data-testid="xdr-shared-insp-label">
              {id.label || refId}
            </div>
            <div style={{ display: "flex", gap: 6, marginTop: 6, flexWrap: "wrap" }}>
              {(id.badges || []).map((b, i) => (
                <EvidenceState key={i} state={STATE_BADGE[b.label]?.state || "observed"} label={b.label} testid={`xdr-shared-insp-badge-${b.label}`} />
              ))}
            </div>
          </div>
          {!embedded && onClose && (
            <button
              onClick={onClose}
              style={{ background: "transparent", border: 0, color: "var(--nx-muted)", cursor: "pointer", padding: 4 }}
              data-testid="xdr-shared-insp-close"
            >
              <X size={14} />
            </button>
          )}
        </div>

        {/* What / Why Governed Context */}
        <div style={{ marginTop: 12 }}>
          <div className="evops-section__eyebrow" style={{ marginBottom: 6 }}>Governed Context</div>
          <table style={{ width: "100%", fontSize: 12 }}>
            <tbody>
              {rels.map((r, i) => (
                <tr key={i} style={{ borderBottom: "1px solid var(--nx-divider)" }}>
                  <td style={{ color: "var(--nx-muted)", padding: "4px 8px 4px 0", width: "40%", verticalAlign: "top" }}>
                    {r.label}
                  </td>
                  <td className="evops-mono" style={{ color: "var(--nx-text)", wordBreak: "break-all", padding: "4px 0" }}>
                    {String(r.value)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Evidence Refs */}
        {evs.length > 0 && (
          <div style={{ marginTop: 12 }} data-testid="xdr-shared-insp-evidence">
            <div className="evops-section__eyebrow" style={{ marginBottom: 6 }}>Governed Evidence IDs</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
              {evs.map((e, i) => (
                <div key={i} className="evops-mono" style={{ fontSize: 11, background: "var(--nx-surf-inset)", padding: "4px 8px", borderRadius: 3, border: "1px solid var(--nx-divider)", color: "var(--nx-text-dim)", display: "flex", alignItems: "center", gap: 6 }}>
                  <FileText size={11} style={{ color: "var(--nx-purple)" }} />
                  <span>{e.label}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Right Column: Related Entities & Provenance Chain */}
      <div className="evops-inspector__right" data-testid="xdr-shared-insp-right">
        {/* ATT&CK Techniques */}
        {techs.length > 0 && (
          <div data-testid="xdr-shared-insp-attack">
            <div className="evops-section__eyebrow" style={{ marginBottom: 6 }}>ATT&amp;CK Technique Mapping</div>
            {techs.map((t, i) => (
              <div key={i} style={{ fontSize: 12, color: "var(--nx-text)", marginBottom: 4, display: "flex", alignItems: "center", gap: 8 }}>
                <span className="evops-mono" style={{ fontWeight: 700, color: "var(--nx-purple)" }}>{t.technique_id}</span>
                <span>{t.technique_name}</span>
                <span style={{ color: "var(--nx-faint)", fontSize: 11 }}>({t.tactic_name})</span>
              </div>
            ))}
          </div>
        )}

        {/* Provenance Chain */}
        {provs.length > 0 && (
          <div data-testid="xdr-shared-insp-provenance">
            <div className="evops-section__eyebrow" style={{ marginBottom: 6 }}>Provenance Derivation Chain</div>
            <Provenance chain={provChainLayers} testid="xdr-shared-insp-prov-chain" />
          </div>
        )}

        {/* Actions */}
        {actions.length > 0 && (
          <div data-testid="xdr-shared-insp-actions" style={{ borderTop: "1px solid var(--nx-divider)", paddingTop: 12, marginTop: "auto" }}>
            <div className="evops-section__eyebrow" style={{ marginBottom: 8 }}>Investigative Actions</div>
            <ActionGroup>
              {actions.map((a) => (
                <Action
                  key={a.id}
                  label={a.label}
                  icon={Play}
                  capability="cap-full"
                  onRun={() => console.log(`Executing ${a.id}`)}
                  testid={`xdr-shared-insp-action-${a.id}`}
                />
              ))}
            </ActionGroup>
          </div>
        )}
      </div>
    </div>
  );
}
