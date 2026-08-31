/**
 * AttackStoryTab · Layer 3 v2 · light-first investigation timeline.
 *
 * Renders every observed attack-progression stage as a timeline
 * event with tactic colour coding.  Stages come from
 * `incident.attack_progression` which is a backend-derived, honest
 * projection over `incident.mitre`.  If nothing was observed, we
 * render the honest empty state.
 */
import React from "react";
import { KILL_CHAIN } from "@/xdr/mitre/mitreTactics";

const CLASS_FOR = (key) => (
    key === "reconnaissance"       ? "reconn"
  : key === "resource-development" ? "reconn"
  : key === "initial-access"       ? "reconn"
  : key === "execution"            ? "exec"
  : key === "persistence"          ? "persist"
  : key === "privilege-escalation" ? "persist"
  : key === "defense-evasion"      ? "persist"
  : key === "credential-access"    ? "persist"
  : key === "discovery"            ? "reconn"
  : key === "lateral-movement"     ? "persist"
  : key === "collection"           ? "exec"
  : key === "command-and-control"  ? "exec"
  : key === "exfiltration"         ? "impact"
  : key === "impact"               ? "impact"
                                     : ""
);
const TACTIC_LABEL = Object.fromEntries(KILL_CHAIN.map(t => [t.key, t.label]));

export default function AttackStoryTab({ incident }) {
  const stages = incident.attack_progression || [];
  const created = incident.created_at;

  if (stages.length === 0) {
    return (
      <div data-testid="xdr-record-attack-story" className="rl-empty">
        NO EVIDENCE — no attack-progression stages have been derived
        for this incident yet.
        <span className="kbd">
          Stages appear when MITRE techniques are projected onto
          the case.
        </span>
      </div>
    );
  }

  return (
    <div data-testid="xdr-record-attack-story">
      <div className="rl-section" style={{ padding: "12px 14px" }}>
        <div className="rl-section-title">Investigation timeline</div>
        <div className="rl-timeline">
          {stages.map((s, i) => {
            const key = String(s.tactic || s.key || s.id || "").toLowerCase();
            const cls = CLASS_FOR(key) || "";
            const label = s.label || TACTIC_LABEL[key] || (key || `Stage ${i + 1}`);
            return (
              <div key={i} className={`rl-timeline-event ${cls}`}
                    data-testid={`xdr-record-story-event-${i}`}>
                <div className="rl-timeline-head">
                  <span className="rl-timeline-time">
                    Stage {i + 1}
                    {created && ` · ${String(created).slice(0, 16).replace("T", " ")}`}
                  </span>
                  <span className="rl-timeline-title">{label}</span>
                  {key && (
                    <span className="rl-state" style={{ padding: "1px 6px",
                                                            fontSize: 9.5,
                                                            marginLeft: 4 }}>
                      {key.toUpperCase().replace(/-/g, " ")}
                    </span>
                  )}
                </div>
                <div className="rl-timeline-body">
                  {s.description
                    || s.summary
                    || (s.techniques?.length
                        ? `Techniques: ${s.techniques.join(", ")}`
                        : "Stage observed from projected MITRE evidence.")}
                </div>
                {s.techniques?.length > 0 && (
                  <div style={{ marginTop: 6, display: "flex",
                                  flexWrap: "wrap", gap: 4 }}>
                    {s.techniques.map(t => (
                      <span key={t}
                              style={{ padding: "1px 7px", borderRadius: 3,
                                       background: "var(--rl-purple-dim)",
                                       color: "var(--rl-purple)",
                                       fontFamily: "var(--rs-mono)",
                                       fontSize: 10.5, fontWeight: 700 }}
                              data-testid={`xdr-record-story-tech-${t}`}>
                        {t}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
      <div style={{ marginTop: 10, fontSize: 10.5, color: "var(--rl-faint)",
                      fontFamily: "var(--rs-mono)", letterSpacing: 0.2 }}>
        Stages derived deterministically from projected MITRE
        techniques · never fabricated.
      </div>
    </div>
  );
}
