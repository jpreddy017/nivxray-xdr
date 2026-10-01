/**
 * Analyst Narrative Panel — deterministic Executive Summary, Analyst
 * Summary, Recommended Actions, Sigma / YARA hunt ideas, Threat-actor
 * context and MITRE ATT&CK matrix.  Data from /api/die/narrate.
 *
 * NO LLM.  All content is template-driven from the preprocessor stages.
 */
import { FileText, ShieldAlert, Fingerprint, Users, Layers,
         AlertOctagon, Zap } from "lucide-react";

export default function AnalystNarrativePanel({ narrative }) {
  if (!narrative) return null;
  const {
    executive_summary, analyst_summary, recommended_actions,
    sigma_hunts, yara_ideas, threat_actor_context, mitre_matrix,
    attack_progression, kill_chain_coverage, overall_assessment,
    behavior_summary,
  } = narrative;

  const hasContent =
    executive_summary || analyst_summary
    || (recommended_actions && recommended_actions.length)
    || (sigma_hunts && sigma_hunts.length)
    || (yara_ideas && yara_ideas.length)
    || (attack_progression && attack_progression.length)
    || (mitre_matrix && mitre_matrix.length)
    || (kill_chain_coverage && kill_chain_coverage.length)
    || overall_assessment
    || (behavior_summary && behavior_summary.length);
  if (!hasContent) return null;

  // ── Normalise mitre_matrix into tactic-grouped shape ──────────
  // Backend variants:
  //   A. [{tactic, techniques: [ids]}]  ← legacy stage-based generator
  //   B. [{id, name, tactic}]           ← canonical bridge (flat)
  // The panel renders shape A; if we detect shape B we regroup.
  const normalisedMitreMatrix = (() => {
    const raw = mitre_matrix || [];
    if (!raw.length) return raw;
    const looksFlat = raw.every(r => r && (r.id || r.name) && !r.techniques);
    if (!looksFlat) return raw;
    const byTactic = new Map();
    for (const r of raw) {
      const tac = r.tactic || "unknown";
      if (!byTactic.has(tac)) byTactic.set(tac, []);
      const ids = byTactic.get(tac);
      if (r.id && !ids.includes(r.id)) ids.push(r.id);
    }
    return Array.from(byTactic, ([tactic, techniques]) => ({ tactic, techniques }));
  })();

  return (
    <section data-testid="analyst-narrative" style={panel}>
      <div style={{ marginBottom: 12 }}>
        <div style={tagline}>ANALYST NARRATIVE</div>
        <div style={{ fontSize: 18, fontWeight: 700, color: "#e2e8f0",
                      marginTop: 2 }}>
          Deterministic summary · no LLM
        </div>
      </div>

      {/* ── Executive Summary ────────────────────────────────── */}
      {executive_summary && (
        <Block title="Executive Summary" icon={FileText}
               testid="narrative-exec">
          <p style={paragraph}>{executive_summary}</p>
        </Block>
      )}

      {/* ── Overall Assessment (Risk, Objective, Progress) ─── */}
      {narrative.overall_assessment && (
        <Block title="Overall Assessment" icon={AlertOctagon}
               testid="narrative-assessment">
          <div style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))",
            gap: 8,
          }}>
            <AssessmentCard label="Risk" value={narrative.overall_assessment.risk}
              tone={_toneFor(narrative.overall_assessment.risk)} />
            <AssessmentCard label="Primary Objective"
              value={narrative.overall_assessment.primary_objective} tone="cyan" />
            <AssessmentCard label="Attack Progress"
              value={`${narrative.overall_assessment.attack_progress_pct}%`}
              tone={narrative.overall_assessment.attack_progress_pct >= 75 ? "red"
                    : narrative.overall_assessment.attack_progress_pct >= 40 ? "amber" : "cyan"} />
            <AssessmentCard label="Confidence"
              value={narrative.overall_assessment.confidence}
              tone={narrative.overall_assessment.confidence === "High" ? "green"
                    : narrative.overall_assessment.confidence === "Medium" ? "amber" : "muted"} />
          </div>
          {narrative.kill_chain_coverage && narrative.kill_chain_coverage.length > 0 && (
            <div style={{ marginTop: 10 }}>
              <div style={{ ...sectionHeader, marginBottom: 4 }}>
                <Layers size={11} /> CYBER KILL CHAIN COVERAGE
              </div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                {narrative.kill_chain_coverage.map((p) => (
                  <span key={p} style={killChainBadge}>{p}</span>
                ))}
              </div>
            </div>
          )}
        </Block>
      )}

      {/* ── Analyst Summary ──────────────────────────────────── */}
      {analyst_summary && (
        <Block title="Analyst Summary" icon={ShieldAlert}
               testid="narrative-analyst">
          <p style={paragraph}>{analyst_summary}</p>
        </Block>
      )}

      {/* ── Behavior Summary Table ───────────────────────────── */}
      {narrative.behavior_summary && narrative.behavior_summary.length > 0 && (
        <Block title="Behavior Summary" icon={ShieldAlert}
               testid="narrative-behavior">
          <table style={{ width: "100%", borderCollapse: "collapse",
                          fontSize: 12.5, color: "#e2e8f0" }}>
            <thead>
              <tr style={{ borderBottom: "1px solid #1f2b3f" }}>
                <th style={thStyle}>Phase</th>
                <th style={thStyle}>Kill Chain</th>
                <th style={thStyle}>Observed Activity</th>
              </tr>
            </thead>
            <tbody>
              {narrative.behavior_summary.map((row, i) => (
                <tr key={i} style={{ borderBottom: "1px solid #131b2d" }}>
                  <td style={tdStyle}>
                    <span style={phaseBadge}>{row.phase}</span>
                  </td>
                  <td style={{ ...tdStyle, color: "#94a3b8", fontFamily: "JetBrains Mono, monospace", fontSize: 11 }}>
                    {row.kill_chain}
                  </td>
                  <td style={{ ...tdStyle, color: "#cbd5e1", lineHeight: 1.5 }}>
                    {row.activity}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Block>
      )}

      {/* ── Attack Progression (per-stage narrative paragraphs) ── */}
      {narrative.attack_progression && narrative.attack_progression.length > 0 && (
        <Block title="Attack Progression" icon={ShieldAlert}
               testid="narrative-progression">
          <div style={{ display: "grid", gap: 8 }}>
            {narrative.attack_progression.map((p, pi) => (
              <div key={p.index ?? p.tactic ?? pi}
                   data-testid={`narrative-progression-${p.index ?? pi}`}
                   style={{ background: "rgba(2,6,23,0.55)",
                            border: "1px solid #1f2b3f", borderRadius: 8,
                            padding: "8px 12px" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8,
                              marginBottom: 4 }}>
                  <div style={{ fontSize: 13, fontWeight: 700, color: "#e2e8f0" }}>
                    {p.title}
                  </div>
                  {p.tactic && <span style={phaseBadge}>{p.tactic}</span>}
                  {p.kill_chain && <span style={killChainBadge}>{p.kill_chain}</span>}
                  {(p.mitre || []).map((m, mi) => {
                    const id = (m && typeof m === "object") ? (m.id || m.name || "") : m;
                    return id ? (
                      <span key={`${id}-${mi}`} style={techBadge}>{id}</span>
                    ) : null;
                  })}
                </div>
                <p style={{ ...paragraph, fontSize: 12.5 }}>{p.narrative}</p>
              </div>
            ))}
          </div>
        </Block>
      )}

      {/* ── Likely Objective ─────────────────────────────────── */}
      {narrative.likely_objective && narrative.likely_objective.length > 0 && (
        <Block title="Likely Objective" icon={AlertOctagon}
               testid="narrative-objective">
          <ul style={list}>
            {narrative.likely_objective.map((o, i) => (
              <li key={i} style={listItem}>
                <span style={{ color: "#fbbf24" }}>▸</span>
                <span style={{ color: "#e2e8f0", fontSize: 12.5,
                               lineHeight: 1.55 }}>{o}</span>
              </li>
            ))}
          </ul>
        </Block>
      )}

      {/* ── Recommended Actions ──────────────────────────────── */}
      {recommended_actions && recommended_actions.length > 0 && (
        <Block title="Recommended Actions" icon={AlertOctagon}
               testid="narrative-actions">
          <ul style={list}>
            {recommended_actions.map((a, i) => (
              <li key={i} data-testid={`narrative-action-${i}`}
                  style={listItem}>
                <span style={{ color: "#f87171" }}>•</span>
                <span style={{ color: "#e2e8f0", fontSize: 12.5,
                               lineHeight: 1.55 }}>{a}</span>
              </li>
            ))}
          </ul>
        </Block>
      )}

      {/* ── Two-column: Sigma + YARA ─────────────────────────── */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr",
                    gap: 14 }}>
        {sigma_hunts && sigma_hunts.length > 0 && (
          <Block title="Sigma Hunt Opportunities" icon={Zap}
                 testid="narrative-sigma">
            <ul style={list}>
              {sigma_hunts.map((h, i) => (
                <li key={i} style={listItem}>
                  <span style={{ color: "#67e8f9" }}>›</span>
                  <span style={mono}>{h}</span>
                </li>
              ))}
            </ul>
          </Block>
        )}
        {yara_ideas && yara_ideas.length > 0 && (
          <Block title="YARA String Ideas" icon={Fingerprint}
                 testid="narrative-yara">
            <ul style={list}>
              {yara_ideas.map((h, i) => (
                <li key={i} style={listItem}>
                  <span style={{ color: "#a78bfa" }}>›</span>
                  <span style={mono}>{h}</span>
                </li>
              ))}
            </ul>
          </Block>
        )}
      </div>

      {/* ── MITRE Matrix ─────────────────────────────────────── */}
      {normalisedMitreMatrix && normalisedMitreMatrix.length > 0 && (
        <Block title="MITRE ATT&CK Coverage" icon={Layers}
               testid="narrative-mitre">
          <div style={{ display: "grid",
                        gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
                        gap: 8 }}>
            {normalisedMitreMatrix.map((row) => (
              <div key={row.tactic} data-testid={`narrative-mitre-${row.tactic}`}
                   style={{
                     background: "rgba(2,6,23,0.55)",
                     border: "1px solid #1f2b3f",
                     borderRadius: 8, padding: "8px 10px",
                   }}>
                <div style={{ fontSize: 10, letterSpacing: "0.14em",
                              textTransform: "uppercase", color: "#67e8f9" }}>
                  {row.tactic}
                </div>
                {row.techniques && row.techniques.length > 0 ? (
                  <div style={{ marginTop: 5, display: "flex",
                                flexWrap: "wrap", gap: 4 }}>
                    {row.techniques.map((t) => (
                      <span key={t} style={techBadge}>{t}</span>
                    ))}
                  </div>
                ) : (
                  <div style={{ marginTop: 5, fontSize: 11, color: "#64748b" }}>
                    (no explicit technique)
                  </div>
                )}
              </div>
            ))}
          </div>
        </Block>
      )}

      {/* ── Threat-actor context ─────────────────────────────── */}
      {threat_actor_context && (
        <Block title="Threat-actor Context" icon={Users}
               testid="narrative-actor">
          <p style={paragraph}>{threat_actor_context}</p>
        </Block>
      )}
    </section>
  );
}

function Block({ title, icon: Icon, children, testid }) {
  return (
    <div data-testid={testid} style={{ marginBottom: 14 }}>
      <div style={sectionHeader}>
        {Icon ? <Icon size={11} /> : null}{title}
      </div>
      <div style={{ marginTop: 6 }}>{children}</div>
    </div>
  );
}

function AssessmentCard({ label, value, tone }) {
  const map = {
    red:   { fg: "#f87171", bd: "rgba(248,113,113,0.35)", bg: "rgba(248,113,113,0.10)" },
    amber: { fg: "#fbbf24", bd: "rgba(251,191,36,0.35)",  bg: "rgba(251,191,36,0.10)" },
    green: { fg: "#86efac", bd: "rgba(134,239,172,0.35)", bg: "rgba(134,239,172,0.08)" },
    cyan:  { fg: "#67e8f9", bd: "rgba(103,232,249,0.35)", bg: "rgba(103,232,249,0.08)" },
    muted: { fg: "#94a3b8", bd: "rgba(148,163,184,0.30)", bg: "rgba(148,163,184,0.06)" },
  };
  const t = map[tone] || map.cyan;
  return (
    <div style={{ background: t.bg, border: `1px solid ${t.bd}`,
                  borderRadius: 8, padding: "8px 12px" }}>
      <div style={{ fontSize: 9, letterSpacing: "0.16em",
                    textTransform: "uppercase", color: "#94a3b8" }}>
        {label}
      </div>
      <div style={{ marginTop: 3, fontSize: 15, fontWeight: 700, color: t.fg,
                    fontFamily: "JetBrains Mono, monospace" }}>
        {value}
      </div>
    </div>
  );
}

function _toneFor(risk) {
  return {
    "Critical": "red", "High": "red",
    "Medium": "amber", "Low": "cyan",
  }[risk] || "muted";
}

const phaseBadge = {
  padding: "1px 6px", fontSize: 10, fontWeight: 700,
  color: "#c084fc", background: "rgba(192,132,252,0.10)",
  border: "1px solid rgba(192,132,252,0.35)",
  borderRadius: 4, fontFamily: "JetBrains Mono, monospace",
};
const killChainBadge = {
  padding: "1px 6px", fontSize: 10, fontWeight: 700,
  color: "#fbbf24", background: "rgba(251,191,36,0.10)",
  border: "1px solid rgba(251,191,36,0.35)",
  borderRadius: 4, fontFamily: "JetBrains Mono, monospace",
};
const thStyle = { textAlign: "left", padding: "6px 8px",
                  fontSize: 10, letterSpacing: "0.14em",
                  textTransform: "uppercase", color: "#94a3b8" };
const tdStyle = { padding: "6px 8px", verticalAlign: "top" };

const panel = {
  background: "linear-gradient(180deg, rgba(15,23,42,0.9), rgba(2,6,23,0.9))",
  border: "1px solid #1f2b3f",
  borderRadius: 12,
  padding: "16px 18px",
  marginBottom: 14,
};

const tagline = {
  fontSize: 9, letterSpacing: "0.22em", textTransform: "uppercase",
  color: "#67e8f9", fontFamily: "JetBrains Mono, monospace",
};

const sectionHeader = {
  display: "inline-flex", alignItems: "center", gap: 6,
  fontSize: 10, letterSpacing: "0.18em", textTransform: "uppercase",
  color: "#94a3b8", fontFamily: "JetBrains Mono, monospace",
};

const paragraph = { color: "#cbd5e1", fontSize: 13, lineHeight: 1.6,
                    margin: 0 };
const list      = { margin: 0, padding: 0, listStyle: "none",
                    display: "grid", gap: 5 };
const listItem  = { display: "flex", gap: 6, alignItems: "flex-start" };
const mono      = { fontFamily: "JetBrains Mono, monospace", fontSize: 11.5,
                    color: "#cbd5e1", lineHeight: 1.55 };
const techBadge = { padding: "1px 6px", fontSize: 10, fontWeight: 700,
                    color: "#67e8f9", background: "rgba(103,232,249,0.10)",
                    border: "1px solid rgba(103,232,249,0.35)",
                    borderRadius: 4, fontFamily: "JetBrains Mono, monospace" };
