/**
 * P0.2 · Executive Dashboard
 *
 * Renders the Executive lens as an MDR-analyst investigation dashboard,
 * not a wall of prose. Stacked cards in analyst-priority order:
 *
 *   1. Verdict card (label + confidence + reason + contributor audit)
 *   2. Report Validator badge (PASS/FAIL + which checks passed)
 *   3. Recovered Command / Payload (fenced code block)
 *   4. Primary IOCs (URLs · IPs · Domains · Hashes)
 *   5. MITRE ATT&CK grid (technique tiles by tactic)
 *   6. LOLBAS (living-off-the-land binaries invoked)
 *   7. Executive Summary (RENDERED markdown from the customer report)
 *   8. Recommendations
 *   9. Confidence audit — collapsible detail (P0.4)
 *
 * P0.1 · The Executive Summary body is passed through `react-markdown`
 * so headings, bullets and emphasis render as real markup instead of
 * raw `#` / `##` / `**` characters.
 */
import React, { useState } from "react";
import ReactMarkdown from "react-markdown";

// ─── Small primitives ─────────────────────────────────────────────
const cardStyle = {
  background: "rgba(255,255,255,0.02)",
  border: "1px solid rgba(255,255,255,0.08)",
  borderRadius: 6,
  padding: "18px 20px",
  marginBottom: 18,
};

const lblStyle = {
  fontSize: 11,
  letterSpacing: "0.08em",
  textTransform: "uppercase",
  color: "var(--fg3, #7a8698)",
  marginBottom: 8,
  fontWeight: 600,
};

function Card({ testId, title, children, sub }) {
  return (
    <section data-testid={testId} style={cardStyle}>
      {title && (
        <div style={lblStyle}>
          {title}
          {sub && (
            <span style={{ marginLeft: 8, opacity: 0.7, fontWeight: 400 }}>
              {sub}
            </span>
          )}
        </div>
      )}
      {children}
    </section>
  );
}

// ─── 0 · Analyst Narrative (MDR-style Executive Investigation Summary) ─
function AnalystNarrativeCard({ narrative }) {
  if (!narrative || !narrative.trim()) return null;
  const paragraphs = narrative.split(/\n\n+/).filter(Boolean);
  return (
    <Card testId="exec-analyst-narrative">
      <div style={{
        fontSize: 11, letterSpacing: "0.08em", textTransform: "uppercase",
        color: "var(--fg3, #7a8698)", fontWeight: 600, marginBottom: 12,
      }}>
        Executive Investigation Summary
      </div>
      {paragraphs.map((p, i) => (
        <p key={i} data-testid={`exec-analyst-narrative-p${i + 1}`} style={{
          fontSize: 14.5, lineHeight: 1.75, marginTop: i === 0 ? 0 : 12,
          marginBottom: 0, color: "var(--fg1, #e2e8f0)",
          letterSpacing: "0.005em",
        }}>
          {p}
        </p>
      ))}
    </Card>
  );
}


// ─── 1 · Verdict Card ─────────────────────────────────────────────
function VerdictCard({ verdict, inputType, elapsed }) {
  const glyph = { MALICIOUS: "▲", SUSPICIOUS: "◆", "RUNTIME DEPENDENT": "●",
                  INFORMATIONAL: "○", UNDETERMINED: "○" }[verdict.label] || "▲";
  const color = { MALICIOUS: "#f87171", SUSPICIOUS: "#fbbf24",
                  "RUNTIME DEPENDENT": "#a3a3a3", INFORMATIONAL: "#22c55e",
                  UNDETERMINED: "#94a3b8" }[verdict.label] || "#f87171";
  return (
    <Card testId="exec-verdict-card">
      <div style={{ display: "flex", gap: 24, flexWrap: "wrap", alignItems: "flex-start" }}>
        <div style={{ flex: "0 0 auto" }}>
          <div style={lblStyle}>Verdict</div>
          <div data-testid="exec-verdict-label" style={{
            fontSize: 22, fontWeight: 700, letterSpacing: "0.04em",
            color, display: "flex", alignItems: "center", gap: 8,
          }}>
            <span>{glyph}</span>
            <span>{verdict.label}</span>
          </div>
        </div>
        <div style={{ flex: "0 0 auto" }}>
          <div style={lblStyle}>Confidence</div>
          <div data-testid="exec-verdict-confidence" style={{
            fontSize: 22, fontWeight: 700, fontFamily: "ui-monospace, Menlo, monospace",
          }}>
            {verdict.pct}%
            <span style={{
              marginLeft: 8, fontSize: 12, letterSpacing: "0.06em",
              opacity: 0.65, textTransform: "uppercase", fontWeight: 500,
            }}>{verdict.bucket}</span>
          </div>
        </div>
        <div style={{ flex: "0 0 auto" }}>
          <div style={lblStyle}>Input type</div>
          <div style={{ fontSize: 15, fontWeight: 600 }}>{inputType}</div>
        </div>
        <div style={{ flex: "0 0 auto" }}>
          <div style={lblStyle}>Elapsed</div>
          <div style={{ fontSize: 15, fontFamily: "ui-monospace, Menlo, monospace" }}>
            {elapsed}
          </div>
        </div>
      </div>
      {verdict.reason && (
        <div data-testid="exec-verdict-reason" style={{
          marginTop: 14, fontSize: 13, color: "var(--fg2, #9aa4b2)",
          lineHeight: 1.55, borderTop: "1px solid rgba(255,255,255,0.06)",
          paddingTop: 12,
        }}>
          {verdict.reason}
        </div>
      )}
    </Card>
  );
}

// ─── 2 · Report Validator badge ───────────────────────────────────
function ReportValidatorBadge({ validator }) {
  if (!validator) return null;
  const ok = validator.status === "pass";
  const barColor = ok ? "#22c55e" : "#f87171";
  return (
    <Card testId="exec-report-validator">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div>
          <div style={lblStyle}>Report Quality Gate</div>
          <div style={{ fontSize: 15, fontWeight: 600 }}>
            <span data-testid="exec-report-validator-status" style={{
              color: barColor, marginRight: 8,
            }}>
              {ok ? "PASS" : "FAIL"}
            </span>
            <span style={{ opacity: 0.7, fontSize: 13, fontWeight: 500 }}>
              {validator.summary || `score ${validator.score}/100`}
            </span>
          </div>
        </div>
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          {Object.entries(validator.checks || {}).map(([name, passed]) => (
            <span key={name} title={name} style={{
              fontSize: 10, letterSpacing: "0.04em", padding: "3px 8px",
              borderRadius: 3, textTransform: "uppercase",
              background: passed ? "rgba(34,197,94,0.12)" : "rgba(248,113,113,0.14)",
              color: passed ? "#4ade80" : "#f87171",
              border: `1px solid ${passed ? "rgba(34,197,94,0.35)" : "rgba(248,113,113,0.4)"}`,
              fontWeight: 600,
            }}>
              {passed ? "✓" : "✗"} {name.replace(/_/g, " ")}
            </span>
          ))}
        </div>
      </div>
      {(validator.blockers || []).length > 0 && (
        <div style={{
          marginTop: 12, padding: 10, borderRadius: 4,
          background: "rgba(248,113,113,0.06)",
          border: "1px solid rgba(248,113,113,0.28)",
        }}>
          <div style={{ fontSize: 11, color: "#f87171", letterSpacing: "0.06em",
                        textTransform: "uppercase", fontWeight: 600, marginBottom: 6 }}>
            Blockers
          </div>
          <ul style={{ margin: 0, paddingLeft: 18, fontSize: 12, color: "var(--fg2, #9aa4b2)" }}>
            {validator.blockers.map((b, i) => <li key={i}>{b}</li>)}
          </ul>
        </div>
      )}
    </Card>
  );
}

// ─── 3 · Recovered Command ────────────────────────────────────────
function RecoveredCommandCard({ payload, stages }) {
  if (!payload) return null;
  return (
    <Card testId="exec-recovered-command"
          title="Recovered Command"
          sub={stages && stages.length > 1 ? `${stages.length} stages` : null}>
      <pre data-testid="exec-recovered-command-body" style={{
        margin: 0, padding: "12px 14px",
        background: "#0b0d10", border: "1px solid rgba(255,255,255,0.08)",
        borderRadius: 4, color: "#e2e8f0",
        fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
        fontSize: 12.5, lineHeight: 1.55,
        overflowX: "auto", whiteSpace: "pre-wrap", wordBreak: "break-word",
      }}>
        {payload}
      </pre>
      {stages && stages.length > 1 && (
        <details style={{ marginTop: 10 }}>
          <summary style={{
            fontSize: 11, letterSpacing: "0.06em", textTransform: "uppercase",
            color: "var(--fg3, #7a8698)", cursor: "pointer", fontWeight: 600,
          }}>
            View all recovered stages
          </summary>
          <ol style={{ marginTop: 8, paddingLeft: 20 }}>
            {stages.slice(0, 6).map((s, i) => (
              <li key={i} style={{
                marginBottom: 6, fontFamily: "ui-monospace, Menlo, monospace",
                fontSize: 11.5, color: "var(--fg2, #9aa4b2)",
              }}>
                {s.length > 200 ? `${s.slice(0, 197)}…` : s}
              </li>
            ))}
          </ol>
        </details>
      )}
    </Card>
  );
}

// ─── 4 · Primary IOCs ─────────────────────────────────────────────
function PrimaryIocsCard({ iocs }) {
  const total = (iocs.urls?.length || 0) + (iocs.ips?.length || 0)
              + (iocs.domains?.length || 0) + (iocs.hashes?.length || 0);
  if (total === 0) return null;

  const Row = ({ label, values }) => {
    if (!values || values.length === 0) return null;
    return (
      <div style={{ marginBottom: 10 }}>
        <div style={{
          fontSize: 10, letterSpacing: "0.08em", textTransform: "uppercase",
          color: "var(--fg3, #7a8698)", fontWeight: 600, marginBottom: 5,
        }}>
          {label} ({values.length})
        </div>
        {values.slice(0, 6).map((v, i) => (
          <div key={i} data-testid={`exec-ioc-${label.toLowerCase()}`} style={{
            fontFamily: "ui-monospace, Menlo, monospace",
            fontSize: 12.5, padding: "5px 10px", margin: "3px 0",
            background: "rgba(255,255,255,0.03)",
            border: "1px solid rgba(255,255,255,0.06)",
            borderRadius: 3, color: "#fbbf24",
            wordBreak: "break-all",
          }}>
            {v}
          </div>
        ))}
      </div>
    );
  };
  return (
    <Card testId="exec-primary-iocs" title="Primary IOCs" sub={`${total} indicator${total === 1 ? "" : "s"}`}>
      <Row label="URLs" values={iocs.urls} />
      <Row label="IPs" values={iocs.ips} />
      <Row label="Domains" values={iocs.domains} />
      <Row label="Hashes" values={iocs.hashes} />
    </Card>
  );
}

// ─── 5 · MITRE ATT&CK grid ────────────────────────────────────────
function MitreCard({ techniques }) {
  if (!techniques || techniques.length === 0) return null;
  const byTactic = {};
  for (const t of techniques) {
    const tac = t.tactic || "Unspecified";
    (byTactic[tac] = byTactic[tac] || []).push(t);
  }
  return (
    <Card testId="exec-mitre" title="MITRE ATT&CK" sub={`${techniques.length} technique${techniques.length === 1 ? "" : "s"}`}>
      <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
        {Object.entries(byTactic).map(([tactic, techs]) => (
          <div key={tactic}>
            <div style={{
              fontSize: 10, letterSpacing: "0.08em", textTransform: "uppercase",
              color: "var(--fg3, #7a8698)", fontWeight: 600, marginBottom: 5,
            }}>{tactic}</div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
              {techs.map((t) => (
                <div key={t.id} data-testid="exec-mitre-tile" style={{
                  padding: "6px 10px", borderRadius: 3,
                  background: "rgba(15,158,122,0.08)",
                  border: "1px solid rgba(15,158,122,0.35)",
                  fontSize: 12, color: "#a7f3d0",
                  fontFamily: "ui-monospace, Menlo, monospace",
                }}>
                  <span style={{ fontWeight: 700, marginRight: 6 }}>{t.id}</span>
                  <span style={{ opacity: 0.85, fontFamily: "inherit" }}>{t.name}</span>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </Card>
  );
}

// ─── 6 · LOLBAS ───────────────────────────────────────────────────
function LolbasCard({ lolbins }) {
  if (!lolbins || lolbins.length === 0) return null;
  return (
    <Card testId="exec-lolbas" title="Living-Off-The-Land Binaries"
          sub={`${lolbins.length} binar${lolbins.length === 1 ? "y" : "ies"}`}>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
        {lolbins.map((l, i) => (
          <div key={i} data-testid="exec-lolbin-tile" style={{
            padding: "6px 12px", borderRadius: 3,
            background: "rgba(251,191,36,0.08)",
            border: "1px solid rgba(251,191,36,0.35)",
            fontSize: 12.5, color: "#fbbf24",
            fontFamily: "ui-monospace, Menlo, monospace", fontWeight: 600,
          }}>{l.binary}</div>
        ))}
      </div>
    </Card>
  );
}

// ─── 7 · Executive Summary (RENDERED markdown) ────────────────────
function ExecutiveSummaryCard({ markdown }) {
  if (!markdown) return null;
  return (
    <Card testId="exec-summary-markdown">
      <div className="xlab-md" data-testid="exec-summary-markdown-body">
        <ReactMarkdown
          components={{
            h1: ({ node, ...props }) => (
              <h1 style={{
                fontSize: 18, fontWeight: 700, marginTop: 0, marginBottom: 14,
                letterSpacing: "-0.01em",
              }} {...props} />
            ),
            h2: ({ node, ...props }) => (
              <h2 style={{
                fontSize: 15, fontWeight: 700, marginTop: 22, marginBottom: 8,
                letterSpacing: "0.01em", color: "#c9d1d9",
                borderBottom: "1px solid rgba(255,255,255,0.08)", paddingBottom: 4,
              }} {...props} />
            ),
            h3: ({ node, ...props }) => (
              <h3 style={{ fontSize: 13.5, fontWeight: 700, marginTop: 14, marginBottom: 6 }} {...props} />
            ),
            p: ({ node, ...props }) => (
              <p style={{
                fontSize: 13.5, lineHeight: 1.65, marginTop: 8, marginBottom: 8,
                color: "var(--fg2, #c9d1d9)",
              }} {...props} />
            ),
            ul: ({ node, ...props }) => (
              <ul style={{ marginTop: 6, marginBottom: 10, paddingLeft: 22,
                            fontSize: 13, lineHeight: 1.6 }} {...props} />
            ),
            li: ({ node, ...props }) => (
              <li style={{ marginBottom: 4 }} {...props} />
            ),
            strong: ({ node, ...props }) => (
              <strong style={{ color: "#e2e8f0", fontWeight: 700 }} {...props} />
            ),
            em: ({ node, ...props }) => (
              <em style={{
                fontStyle: "italic", color: "var(--fg3, #7a8698)",
                fontSize: 11.5, letterSpacing: "0.02em",
              }} {...props} />
            ),
            code: ({ node, inline, ...props }) =>
              inline ? (
                <code style={{
                  background: "rgba(255,255,255,0.06)", padding: "1px 5px",
                  borderRadius: 3, fontSize: 12, color: "#fbbf24",
                  fontFamily: "ui-monospace, Menlo, monospace",
                }} {...props} />
              ) : (
                <code style={{
                  display: "block", padding: 10, borderRadius: 4,
                  background: "#0b0d10", color: "#e2e8f0",
                  fontFamily: "ui-monospace, Menlo, monospace",
                  fontSize: 12, whiteSpace: "pre-wrap", wordBreak: "break-word",
                  border: "1px solid rgba(255,255,255,0.08)",
                }} {...props} />
              ),
          }}
        >
          {markdown}
        </ReactMarkdown>
      </div>
    </Card>
  );
}

// ─── 8 · Confidence Audit (P0.4) ──────────────────────────────────
function ConfidenceAuditCard({ explain }) {
  const [open, setOpen] = useState(false);
  if (!explain) return null;
  const calc = explain.confidence_calculation || {};
  const fired = explain.fired || [];
  const skipped = (explain.escalations || []).filter((e) => e.status === "skipped");
  const applied = explain.escalation_applied;
  return (
    <Card testId="exec-confidence-audit" title="Confidence Audit"
          sub={`raw ${calc.raw_noisy_or_pct}% → final ${calc.final_confidence_pct}%`}>
      <div style={{ fontSize: 12.5, color: "var(--fg2, #9aa4b2)", lineHeight: 1.6 }}>
        <div><b>Formula.</b> {calc.formula}</div>
        <div><b>Cap.</b> {calc.cap_reason} ({calc.confidence_cap_pct}%)</div>
        {calc.mitigators_present > 0 && (
          <div style={{ color: "#f87171" }}>
            <b>Mitigator dampening.</b> {calc.mitigators_present} mitigating signal(s) reduced the score
            by up to {calc.mitigator_dampening_max_pct}% — this is why the final number is lower than the
            raw Noisy-OR aggregate.
          </div>
        )}
        {applied ? (
          <div style={{ color: "#4ade80" }}>
            <b>Escalation applied:</b> <code>{applied}</code>
          </div>
        ) : (
          <div>
            <b>No escalation rule fired.</b> The verdict comes from the class distribution, not a rule.
          </div>
        )}
      </div>
      <details onToggle={(e) => setOpen(e.target.open)} style={{ marginTop: 12 }}>
        <summary style={{
          fontSize: 11, letterSpacing: "0.06em", textTransform: "uppercase",
          color: "var(--fg3, #7a8698)", cursor: "pointer", fontWeight: 600,
        }}>
          {open ? "Hide" : "Show"} contributor breakdown ({fired.reduce((a, f) => a + (f.count || 0), 0)} fired · {skipped.length} rules skipped)
        </summary>
        <div style={{ marginTop: 10 }}>
          {fired.map((f, i) => (
            <div key={i} style={{ marginBottom: 10 }}>
              <div style={{
                fontSize: 11, letterSpacing: "0.08em", textTransform: "uppercase",
                color: "var(--fg3, #7a8698)", fontWeight: 600,
              }}>
                {f.class} · {f.count} contributor{f.count === 1 ? "" : "s"}
              </div>
              {(f.contributors || []).slice(0, 6).map((c, ci) => (
                <div key={ci} style={{
                  fontSize: 12, padding: "4px 8px", margin: "3px 0",
                  background: "rgba(255,255,255,0.02)", borderRadius: 3,
                  fontFamily: "ui-monospace, Menlo, monospace",
                }}>
                  <span style={{ color: "#e2e8f0" }}>{c.label || c.kind}</span>
                  <span style={{ color: "var(--fg3, #7a8698)", marginLeft: 8 }}>
                    · w={c.weight} · conf={Math.round((c.confidence || 0) * 100)}%
                  </span>
                </div>
              ))}
            </div>
          ))}
          {skipped.length > 0 && (
            <details style={{ marginTop: 8 }}>
              <summary style={{
                fontSize: 11, letterSpacing: "0.06em", textTransform: "uppercase",
                color: "var(--fg3, #7a8698)", cursor: "pointer", fontWeight: 600,
              }}>
                {skipped.length} escalation rules considered but skipped
              </summary>
              <ul style={{ marginTop: 6, paddingLeft: 20, fontSize: 11.5, color: "var(--fg2, #9aa4b2)" }}>
                {skipped.slice(0, 6).map((r, i) => (
                  <li key={i} style={{ marginBottom: 4 }}>
                    <b>{r.rule}</b> — missing kinds: <code>{(r.missing_kinds || []).join(", ") || "—"}</code>
                  </li>
                ))}
              </ul>
            </details>
          )}
        </div>
      </details>
    </Card>
  );
}

// ─── Main ─────────────────────────────────────────────────────────
export default function ExecutiveDashboard({ view }) {
  const {
    verdict = {}, inputType = "TEXT", stats = {},
    recoveredPayload = "", recoveredStages = [],
    primaryIocs = {}, mitreTechniques = [], lolbins = [],
    customerReportMarkdown = "",
    analystNarrative = "",
    reportValidator = null,
  } = view || {};

  const elapsed = stats.elapsed || "—";
  return (
    <div data-testid="exec-dashboard" style={{ padding: "0 4px" }}>
      {/* 2026-08-01 · Lead block: MDR-analyst-style Executive
          Investigation Summary — a flowing 2-paragraph narrative
          composed from the CIO. Renders above the verdict card so
          analysts get the story BEFORE the metrics. */}
      <AnalystNarrativeCard narrative={analystNarrative} />
      <VerdictCard verdict={verdict} inputType={inputType} elapsed={elapsed} />
      <ReportValidatorBadge validator={reportValidator} />
      <RecoveredCommandCard payload={recoveredPayload} stages={recoveredStages} />
      <PrimaryIocsCard iocs={primaryIocs} />
      <MitreCard techniques={mitreTechniques} />
      <LolbasCard lolbins={lolbins} />
      <ExecutiveSummaryCard markdown={customerReportMarkdown} />
      <ConfidenceAuditCard explain={verdict.explain} />
    </div>
  );
}
