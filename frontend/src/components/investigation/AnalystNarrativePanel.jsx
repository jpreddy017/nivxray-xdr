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
  } = narrative;

  const hasContent =
    executive_summary || analyst_summary
    || (recommended_actions && recommended_actions.length)
    || (sigma_hunts && sigma_hunts.length)
    || (yara_ideas && yara_ideas.length);
  if (!hasContent) return null;

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

      {/* ── Analyst Summary ──────────────────────────────────── */}
      {analyst_summary && (
        <Block title="Analyst Summary" icon={ShieldAlert}
               testid="narrative-analyst">
          <p style={paragraph}>{analyst_summary}</p>
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
      {mitre_matrix && mitre_matrix.length > 0 && (
        <Block title="MITRE ATT&CK Coverage" icon={Layers}
               testid="narrative-mitre">
          <div style={{ display: "grid",
                        gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
                        gap: 8 }}>
            {mitre_matrix.map((row) => (
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
