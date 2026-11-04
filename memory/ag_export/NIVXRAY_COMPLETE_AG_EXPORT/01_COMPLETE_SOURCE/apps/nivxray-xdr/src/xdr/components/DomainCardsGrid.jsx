/**
 * DomainCardsGrid · Slice 7.
 *
 * "Incident Evidence Across Domains" — renders on the Incident
 * Overview.  Each of the six domain cards surfaces ONE of three
 * distinct, honest states (§4 of the implementation prompt):
 *
 *   RELATED       — real evidence in this incident's window
 *   SEARCHED      — connected, no hits (never claim absence == safe)
 *   NOT CONNECTED — integration not wired · links to Administration
 *
 * Quality bar (locked): more precise than Defender's "0 alerts" chip
 * and Falcon's flat "no data" pane — every state names WHAT was
 * searched, WHERE the data would live, and how to enable it.
 */
import React from "react";
import { useNavigate } from "react-router-dom";
import { ChevronRight, Settings } from "lucide-react";

import { DOMAIN_KEYS, DOMAIN_META, deriveDomainState } from "@/xdr/domains/domainMeta";

const STATE_META = {
  related: {
    label: "RELATED",
    color: "var(--mint)",
    cta:   "Open",
  },
  searched: {
    label: "SEARCHED",
    color: "var(--muted)",
    cta:   "Search Related",
  },
  not_connected: {
    label: "NOT CONNECTED",
    color: "var(--faint)",
    cta:   "Configure Integration",
  },
};

export default function DomainCardsGrid({ incident, evidenceCounts }) {
  const navigate = useNavigate();
  if (!incident) return null;

  const openDomain = (key, state) => {
    // Every card — regardless of state — opens the domain-detail
    // page for this incident.  The domain page renders the honest
    // NOT CONNECTED / SEARCHED / RELATED body itself.  From there,
    // the analyst can jump to Admin → Integrations if needed.
    navigate(`/xdr/incidents/${encodeURIComponent(incident.id)}/domain/${key}`);
  };

  return (
    <section className="panel2" style={{ padding: "12px 14px" }}
              data-testid="xdr-domain-cards-grid">
      <div className="section-title" style={{ marginBottom: 10 }}>
        Incident Evidence Across Domains
      </div>
      <div style={{
        display: "grid",
        gridTemplateColumns: "repeat(auto-fit, minmax(230px, 1fr))",
        gap: 10,
      }}>
        {DOMAIN_KEYS.map((key) => {
          const meta = DOMAIN_META[key];
          const count = evidenceCounts?.[key] ?? 0;
          const state = deriveDomainState(key, { detectionCount: count });
          const stateMeta = STATE_META[state];
          const Icon = meta.icon;
          const isConnected = state !== "not_connected";
          return (
            <button
              key={key}
              type="button"
              className="btn"
              style={{
                display: "flex", flexDirection: "column",
                alignItems: "stretch", textAlign: "left",
                padding: "12px 14px", gap: 8,
                borderLeft: `3px solid ${stateMeta.color}`,
                background: "var(--panel)",
                opacity: state === "searched" ? 0.88 :
                            state === "not_connected" ? 0.75 : 1,
                borderStyle: state === "not_connected" ? "dashed" : "solid",
              }}
              onClick={() => openDomain(key, state)}
              data-testid={`xdr-domain-card-${key}`}
              data-state={state}
              title={meta.subtitle}
            >
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <Icon size={14} style={{ color: stateMeta.color }} />
                <span style={{ color: "var(--text)", fontWeight: 800,
                                  fontSize: 12.5 }}>{meta.label}</span>
                <span style={{ flex: 1 }} />
                <span
                  data-testid={`xdr-domain-card-state-${key}`}
                  style={{
                    fontFamily: "var(--xmono)", fontSize: 9,
                    letterSpacing: ".4px", fontWeight: 800,
                    color: stateMeta.color,
                    border: `1px solid ${stateMeta.color}`,
                    padding: "1px 6px", borderRadius: 3,
                  }}
                >
                  {stateMeta.label}
                </span>
              </div>
              <div style={{ color: "var(--muted)", fontSize: 10.5 }}>
                {meta.subtitle}
              </div>
              <div style={{
                display: "flex", alignItems: "center",
                justifyContent: "space-between", marginTop: 4,
              }}>
                <span className="mono" style={{
                  fontSize: 10.5, color: "var(--text-dim)",
                }}>
                  {isConnected
                    ? (count > 0
                        ? `${count} detection${count === 1 ? "" : "s"} in window`
                        : "0 hits in incident window · scope tightly bounded")
                    : `Integration required · ${meta.integration}`}
                </span>
                <span style={{
                  color: stateMeta.color, fontSize: 10.5, fontWeight: 700,
                }}>
                  {!isConnected && <Settings size={10}
                                                  style={{ marginRight: 3,
                                                              verticalAlign: "middle" }} />}
                  {stateMeta.cta} <ChevronRight size={11}
                                                    style={{ verticalAlign: "middle" }} />
                </span>
              </div>
            </button>
          );
        })}
      </div>
      <div style={{
        marginTop: 10, fontSize: 9.5, color: "var(--faint)",
        letterSpacing: ".3px", textTransform: "uppercase", fontWeight: 800,
      }}>
        Evidence counts sourced from authoritative NivXRay APIs · never fabricated.
      </div>
    </section>
  );
}
