/**
 * Incident Overview · intelligence CONTEXT for this investigation.
 *
 * Deliberately smaller than the dashboard status: an investigation needs
 * to know what analysis was permitted here and where that came from. It
 * carries NO global-policy editing controls — policy is an administrative
 * authority, not an investigation step.
 *
 * The incident-only capability that genuinely existed before (a per-incident
 * override that may only NARROW the tenant ceiling) is preserved, but as a
 * disclosed control rather than a configuration panel.
 */
import React, { useState } from "react";
import { Lock } from "lucide-react";
import useIntelligencePolicy from "./useIntelligencePolicy";
import { MODES, summarize } from "./intelligenceModel";
import "./intel.css";

export default function IncidentIntelligenceContext({ incidentId }) {
  const {
    values, health, ceiling, inherited, loading, saving, error,
    save, clearOverride,
  } = useIntelligencePolicy({ scope: "incident", incidentId });
  const [open, setOpen] = useState(false);

  if (loading || !values) {
    return (
      <div className="nx-intel-ctx" data-testid="xdr-incident-intel-context"
           data-state={loading ? "LOADING" : "NOT_AVAILABLE"}>
        <span className="nx-intel-ctx__item">
          <span className="nx-intel-ctx__k">Intelligence</span>
          <span className="nx-intel-ctx__v">
            {loading ? "Loading…" : (error || "Not available")}
          </span>
        </span>
      </div>
    );
  }

  const s = summarize({ values, health });

  return (
    <div data-testid="xdr-incident-intel-context"
         data-mode={s.mode?.id || "unresolved"}>
      <div className="nx-intel-ctx">
        <span className="nx-intel-ctx__item">
          <span className="nx-intel-ctx__k">Intelligence</span>
          <span className="nx-intel-ctx__v"
                data-testid="xdr-incident-intel-mode">{s.modeLabel}</span>
        </span>
        <span className="nx-intel-ctx__item">
          <span className="nx-intel-ctx__k">Narration</span>
          <span className="nx-intel-ctx__v">{s.narration}</span>
        </span>
        <span className="nx-intel-ctx__item">
          <span className="nx-intel-ctx__k">Source</span>
          <span className="nx-intel-ctx__v"
                data-testid="xdr-incident-intel-source">
            {inherited ? "Tenant policy" : "Narrowed for this incident"}
          </span>
        </span>
        <button className="nx-intel-btn"
                style={{ padding: "3px 10px", fontSize: 11 }}
                data-testid="xdr-incident-intel-toggle"
                onClick={() => setOpen((v) => !v)}>
          {open ? "Hide" : "Restrict for this incident"}
        </button>
      </div>

      {open && (
        <div className="nx-intel-adv" data-testid="xdr-incident-intel-restrict">
          {error && <div className="nx-intel-err">{error}</div>}
          <div style={{ marginBottom: 10 }}>
            An investigation may only <strong>narrow</strong> the tenant
            policy. Widening it is an administrative decision and is refused
            by the server.
          </div>
          <div className="nx-intel-modes">
            {MODES.map((m) => {
              const widens = (m.values.online_ai === "on" && !ceiling.online_ai)
                || (m.values.online_llm === "on" && !ceiling.online_llm);
              return (
                <button key={m.id}
                        className="nx-intel-mode"
                        data-testid={`xdr-incident-intel-mode-${m.id}`}
                        data-selected={s.mode?.id === m.id ? "true" : "false"}
                        disabled={widens || saving}
                        title={widens
                          ? "Restricted by the tenant policy ceiling"
                          : m.hint}
                        onClick={() => save(m.values,
                          "narrowed for this incident")}>
                  {widens && <Lock size={11}
                    style={{ marginRight: 6, verticalAlign: -1 }} />}
                  {m.label}
                </button>
              );
            })}
          </div>
          {!inherited && (
            <div className="nx-intel-actions">
              <button className="nx-intel-btn"
                      data-testid="xdr-incident-intel-clear"
                      disabled={saving}
                      onClick={() => clearOverride("cleared")}>
                Revert to tenant policy
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
