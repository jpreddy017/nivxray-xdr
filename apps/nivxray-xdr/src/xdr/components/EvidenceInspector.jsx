/**
 * Round 38.3 · Shared Evidence Inspector.
 *
 * ONE component consumed by MITRE, Attack Story, and Attack Graph.
 * Callers pass canonical (kind, ref_id) — never arbitrary display
 * data.  The backend resolver is the single source of truth.
 *
 *   <EvidenceInspector incidentId="…" kind="technique" refId="T1059.001" />
 *
 * If (kind, ref_id) is null → empty placeholder.
 * If backend returns MISSING → honest "not present" state (owner rule §11).
 */
import React, { useEffect, useState } from "react";
import { Loader2, Lock, Sparkles, Play, ExternalLink,
           ChevronRight, X } from "lucide-react";
import api from "@/lib/api";

const STATE_BADGE = {
  OBSERVED:     { bg: "var(--nx-benign)", fg: "var(--nx-benign-bg)" },
  SUPPORTED:    { bg: "var(--nx-info)", fg: "var(--nx-info-bg)" },
  HYPOTHESIZED: { bg: "var(--nx-medium)", fg: "var(--nx-medium-bg)" },
  POSSIBLE:     { bg: "var(--nx-medium)", fg: "var(--nx-medium-bg)" },
  SUPPRESSED:   { bg: "var(--nx-bd-strong)", fg: "var(--nx-bd-quiet)" },
  NOT_OBSERVED: { bg: "var(--nx-bd-quiet)", fg: "var(--nx-muted)" },
  SUSPICIOUS:   { bg: "var(--nx-high)", fg: "var(--nx-critical-bg)" },
};

function Badge({ label, tone }) {
  const s = STATE_BADGE[label] || { bg: "var(--nx-bd-strong)", fg: "var(--nx-text)" };
  return (
    <span style={{
             background: s.bg, color: s.fg,
             fontSize: 10, fontWeight: 700, letterSpacing: 0.3,
             padding: "2px 8px", borderRadius: 2,
             textTransform: "uppercase",
           }}
           data-testid={`xdr-insp-badge-${label}`}>
      {label}
    </span>
  );
}

export default function EvidenceInspector({ incidentId, kind, refId,
                                                        onClose, embedded, onAction }) {
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
      <div style={{ padding: 12, color: "var(--nx-faint)", fontSize: 11 }}
            data-testid="xdr-insp-empty">
        Select any technique, process, event, command, finding or
        entity to inspect.
      </div>
    );
  }
  if (loading) {
    return (
      <div style={{ padding: 12, color: "var(--nx-muted)", fontSize: 11 }}
            data-testid="xdr-insp-loading">
        <Loader2 size={11} className="rl-spin" style={{ verticalAlign: "-2px",
                                                                    marginRight: 6 }} />
        Resolving …
      </div>
    );
  }
  if (error) {
    return <div style={{ padding: 12, color: "var(--nx-critical)", fontSize: 11 }}>{error}</div>;
  }
  if (!env) return null;
  if (env.state === "MISSING") {
    return (
      <div style={{ padding: 12, color: "var(--nx-muted)", fontSize: 11 }}
            data-testid="xdr-insp-missing">
        <div style={{ fontWeight: 700, color: "var(--nx-text-dim)", marginBottom: 4 }}>
          NOT PRESENT
        </div>
        <div>{env.reason || `No governed record for ${kind}:${refId}.`}</div>
      </div>
    );
  }

  const id = env.identity || {};
  return (
    <div style={{ padding: 12, background: "var(--nx-surf-primary)", color: "var(--nx-text)",
                       fontSize: 12, borderRadius: 4, minWidth: 320 }}
          data-testid="xdr-insp">
      {/* Header */}
      <div style={{ display: "flex", alignItems: "flex-start", gap: 8,
                          borderBottom: "1px solid var(--nx-bd-quiet)", paddingBottom: 8,
                          marginBottom: 8 }}>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 10, color: "var(--nx-muted)", letterSpacing: 0.5,
                            textTransform: "uppercase", marginBottom: 2 }}>
            {id.subtitle || kind.toUpperCase()}
          </div>
          <div style={{ fontSize: 14, fontWeight: 700, color: "var(--nx-text)",
                            wordBreak: "break-all" }}
                data-testid="xdr-insp-label">
            {id.label || refId}
          </div>
          <div style={{ display: "flex", gap: 4, marginTop: 4, flexWrap: "wrap" }}>
            {(id.badges || []).map((b, i) => <Badge key={i} label={b.label} />)}
          </div>
        </div>
        {!embedded && onClose && (
          <button onClick={onClose}
                   style={{ background: "transparent", border: 0,
                               color: "var(--nx-muted)", cursor: "pointer", padding: 0 }}
                   data-testid="xdr-insp-close">
            <X size={14} />
          </button>
        )}
      </div>

      {/* Context relationships */}
      {(env.context?.relationships || []).length > 0 && (
        <div style={{ marginBottom: 10 }} data-testid="xdr-insp-context">
          <div style={{ fontSize: 10, color: "var(--nx-muted)", letterSpacing: 0.5,
                            marginBottom: 4, textTransform: "uppercase" }}>
            Context
          </div>
          <table style={{ width: "100%", fontSize: 11 }}>
            <tbody>
              {env.context.relationships.map((r, i) => (
                <tr key={i}>
                  <td style={{ color: "var(--nx-muted)", padding: "2px 8px 2px 0",
                                    minWidth: 90, verticalAlign: "top" }}>
                    {r.label}
                  </td>
                  <td className="mono" style={{ color: "var(--nx-text)",
                                                              wordBreak: "break-all" }}>
                    {String(r.value)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Evidence refs */}
      {(env.evidence || []).length > 0 && (
        <div style={{ marginBottom: 10 }} data-testid="xdr-insp-evidence">
          <div style={{ fontSize: 10, color: "var(--nx-muted)", letterSpacing: 0.5,
                            marginBottom: 4, textTransform: "uppercase" }}>
            Evidence
          </div>
          {env.evidence.map((e, i) => (
            <div key={i} className="mono"
                  style={{ fontSize: 10, background: "var(--nx-surf-primary)",
                              padding: "2px 6px", borderRadius: 2,
                              marginBottom: 2, color: "var(--nx-text-dim)",
                              display: "flex", alignItems: "center", gap: 4 }}>
              <ExternalLink size={9} style={{ color: "var(--nx-purple)" }} />
              {e.label}
            </div>
          ))}
        </div>
      )}

      {/* ATT&CK */}
      {(env.attack?.techniques || []).length > 0 && (
        <div style={{ marginBottom: 10 }} data-testid="xdr-insp-attack">
          <div style={{ fontSize: 10, color: "var(--nx-muted)", letterSpacing: 0.5,
                            marginBottom: 4, textTransform: "uppercase" }}>
            ATT&amp;CK
          </div>
          {env.attack.techniques.map((t, i) => (
            <div key={i} style={{ fontSize: 11, color: "var(--nx-purple-soft)" }}>
              <b>{t.technique_id}</b> · {t.technique_name} ·{" "}
              <span style={{ color: "var(--nx-muted)" }}>
                {t.tactic_id} · {t.tactic_name}
              </span>
            </div>
          ))}
        </div>
      )}

      {/* Provenance */}
      {(env.provenance || []).length > 0 && (
        <div style={{ marginBottom: 10 }} data-testid="xdr-insp-provenance">
          <div style={{ fontSize: 10, color: "var(--nx-muted)", letterSpacing: 0.5,
                            marginBottom: 4, textTransform: "uppercase" }}>
            Provenance
          </div>
          {env.provenance.map((p, i) => (
            <div key={i} style={{ fontSize: 10, color: "var(--nx-text-dim)",
                                          marginBottom: 2 }}>
              <span style={{ color: "var(--nx-purple)", fontWeight: 600 }}>
                {p.source}
              </span>
              {p.note && <span> · {p.note}</span>}
            </div>
          ))}
        </div>
      )}

      {/* INVESTIGATE actions */}
      {(env.actions || []).length > 0 && (
        <div data-testid="xdr-insp-actions"
              style={{ borderTop: "1px solid var(--nx-bd-quiet)", paddingTop: 8 }}>
          <div style={{ fontSize: 10, color: "var(--nx-muted)", letterSpacing: 0.5,
                            marginBottom: 4, textTransform: "uppercase" }}>
            Investigate
          </div>
          {/* Owner review 2026-09-05 · these controls used to be
                clickable with no handler at all.  An INVESTIGATE action
                is now interactive ONLY when the backend declares a real
                destination (`available: true`).  Anything else renders
                with the locked ⊘ CAPABILITY UNAVAILABLE state and is
                genuinely non-interactive — no stale buttons. */}
          {env.actions.map(a => {
            const live = Boolean(a.available) && typeof onAction === "function";
            return (
              <button key={a.id}
                       type="button"
                       disabled={!live}
                       aria-disabled={!live}
                       onClick={live ? () => onAction(a) : undefined}
                       title={live
                         ? (a.pivot?.note || a.description)
                         : (a.unavailable_reason
                             || "Not wired to any engine yet — NivXRay will not offer a control it cannot honour.")}
                       style={{ display: "flex", alignItems: "center", gap: 6,
                                   width: "100%", background: "transparent",
                                   border: `1px solid ${live ? "var(--nx-bd-strong)" : "var(--nx-bd-quiet)"}`,
                                   borderStyle: live ? "solid" : "dashed",
                                   borderRadius: 3,
                                   color: live ? "var(--nx-text-dim)" : "var(--nx-faint)",
                                   padding: "5px 8px",
                                   marginBottom: 4, fontSize: 11,
                                   cursor: live ? "pointer" : "not-allowed",
                                   textAlign: "left" }}
                       data-testid={`xdr-insp-action-${a.id}`}
                       data-action-available={live ? "true" : "false"}>
                {live
                  ? <Play size={10} style={{ color: "var(--nx-purple)" }} />
                  : <span style={{ color: "var(--nx-ep-nocap)", fontSize: 11,
                                       lineHeight: 1, width: 10 }}>⊘</span>}
                <span style={{ flex: 1 }}>{a.label}</span>
                {live
                  ? <ChevronRight size={10} style={{ color: "var(--nx-faint)" }} />
                  : <span className="mono"
                            style={{ fontSize: 8, letterSpacing: 0.4,
                                        color: "var(--nx-ep-nocap)" }}>
                      CAPABILITY UNAVAILABLE
                    </span>}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
