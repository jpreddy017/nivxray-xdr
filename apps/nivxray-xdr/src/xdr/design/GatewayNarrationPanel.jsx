/**
 * GatewayNarrationPanel — provider-agnostic narration surface.
 *
 * Fetches a Gateway-backed narration endpoint and renders the
 * governed prose alongside the machine-truth badges (verdict,
 * severity, confidence, provider, generation_mode, grounded).
 *
 * Consumers pass an endpoint path (e.g.
 * `/narration/incident/{id}/attack-story`) — this component
 * knows nothing about the specific kind.  All governed truth is
 * inherited from the Gateway response verbatim; the LLM never
 * gets to invent it.
 */
import React, { useEffect, useState } from "react";
import { RefreshCcw, ShieldCheck, AlertTriangle } from "lucide-react";
import api from "@/lib/api";
import { neutralGatewayBadges } from "@/xdr/design/providerLabels";

export default function GatewayNarrationPanel({
  incidentId,
  endpoint,                 // e.g. "/narration/incident/{id}/attack-story"
  title,
  eyebrow,
  testidPrefix,
}) {
  const [data, setData]       = useState(null);
  const [error, setError]     = useState(null);
  const [loading, setLoading] = useState(false);
  const url = incidentId
    ? endpoint.replace("{id}", encodeURIComponent(incidentId))
    : null;

  const load = async () => {
    if (!url) return;
    setLoading(true); setError(null);
    try {
      const r = await api.get(url);
      setData(r.data);
    } catch (e) {
      setError(e?.response?.data?.detail || e?.message || "Failed to load");
      setData(null);
    } finally { setLoading(false); }
  };
  useEffect(() => { load(); /* eslint-disable-next-line */ }, [url]);

  return (
    <section className="rl-ai-status observed"
                  data-testid={`${testidPrefix}-panel`}>
      <div className="badge">
        <span>{eyebrow || "NIVXRAY XDR NARRATION GATEWAY"}</span>
      </div>
      <div className="txt" style={{ flex: 1 }}>
        <h5 style={{ display: "flex", alignItems: "center", gap: 10,
                            justifyContent: "space-between" }}>
          <span>{title || "Narration"}</span>
          <button
            type="button"
            onClick={load}
            data-testid={`${testidPrefix}-refresh`}
            title="Refresh narration"
            style={{
              display: "inline-flex", alignItems: "center", gap: 4,
              padding: "2px 8px", fontSize: 11,
              background: "transparent",
              border: "1px solid var(--nx-bd-quiet)",
              borderRadius: 4, cursor: "pointer",
              color: "var(--nx-muted)",
            }}>
            <RefreshCcw size={11}
              style={{ animation: loading ? "xdr-spin 900ms linear infinite" : "none" }} />
            {loading ? "…" : "Refresh"}
          </button>
        </h5>

        {loading && !data && (
          <p data-testid={`${testidPrefix}-loading`}
              style={{ color: "var(--nx-muted)" }}>
            Loading governed narration…
          </p>
        )}
        {error && (
          <p data-testid={`${testidPrefix}-error`}
              style={{ color: "var(--nx-high)", display: "inline-flex",
                          gap: 6, alignItems: "center" }}>
            <AlertTriangle size={12} /> {String(error)}
          </p>
        )}

        {data && (
          <>
            {(() => {
              const badges = neutralGatewayBadges(data);
              return (
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap",
                              margin: "4px 0 10px" }}>
              <span className="nx-pill nx-pill-purple"
                        data-testid={`${testidPrefix}-mode`}
                        data-mode-raw={data.generation_mode || ""}
                        title={`raw: ${data.generation_mode || "—"}`}>
                [ {badges.mode} ]
              </span>
              <span className="nx-pill nx-pill-faint"
                        data-testid={`${testidPrefix}-provider`}
                        data-provider-raw={badges.providerRaw}
                        title={`raw: ${badges.providerRaw || "—"}`}>
                provider: {badges.providerDisplay}
              </span>
              {data.grounded && (
                <span className="nx-pill nx-pill-benign"
                          data-testid={`${testidPrefix}-grounded`}>
                  <ShieldCheck size={9} style={{ marginRight: 3, verticalAlign: -1 }} />
                  GROUNDED
                </span>
              )}
              {data.verdict && (
                <span className="nx-pill nx-pill-amber"
                          data-testid={`${testidPrefix}-verdict`}>
                  {data.verdict}
                </span>
              )}
              {data.severity && (
                <span className="nx-pill nx-pill-critical"
                          data-testid={`${testidPrefix}-severity`}>
                  {data.severity}
                </span>
              )}
              {typeof data.confidence === "number" && (
                <span className="nx-pill nx-pill-info"
                          data-testid={`${testidPrefix}-confidence`}>
                  conf {data.confidence.toFixed(2)}
                </span>
              )}
            </div>
              );
            })()}

            <div data-testid={`${testidPrefix}-body`}
                    style={{ display: "flex", flexDirection: "column",
                                gap: 8 }}>
              {(data.paragraphs || []).map((p, i) => (
                <p key={i} style={{ margin: 0, lineHeight: 1.55 }}>
                  {p.text}
                  {(p.technique_ids?.length || p.evidence_ids?.length) ? (
                    <span style={{ marginLeft: 6, display: "inline-flex",
                                        gap: 4, flexWrap: "wrap" }}>
                      {(p.technique_ids || []).map((t) => (
                        <span key={`t-${i}-${t}`} className="nx-pill nx-pill-purple"
                                  style={{ fontFamily: "var(--mono)", fontSize: 10 }}
                                  data-testid={`${testidPrefix}-tech-${t}`}>
                          {t}
                        </span>
                      ))}
                      {(p.evidence_ids || []).slice(0, 3).map((e) => (
                        <span key={`e-${i}-${e}`} className="nx-pill nx-pill-faint"
                                  style={{ fontFamily: "var(--mono)", fontSize: 10 }}
                                  data-testid={`${testidPrefix}-evid-${e}`}>
                          {e}
                        </span>
                      ))}
                    </span>
                  ) : null}
                </p>
              ))}
            </div>

            {(data.caveats && data.caveats.length > 0) && (
              <div data-testid={`${testidPrefix}-caveats`}
                      style={{ marginTop: 8, fontSize: 11,
                                  color: "var(--nx-muted)",
                                  fontFamily: "var(--mono)" }}>
                {data.caveats.map((c, i) =>
                  <div key={i} title={c}>· {c.length > 140 ? c.slice(0, 140) + "…" : c}</div>)}
              </div>
            )}
          </>
        )}
      </div>
    </section>
  );
}
