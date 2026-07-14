import { Download, Copy } from "lucide-react";
import PlaybookFeedback from "@/components/PlaybookFeedback";

/**
 * FinalSummary — executive briefing card rendered below the Attack Graph.
 * Consolidates malware family, summary, attack chain, behavior, IOC narrative,
 * attribution hints, and recommended actions from the AI description payload,
 * plus the final risk verdict.
 *
 * Includes a one-click TXT download of the whole briefing.
 */
export default function FinalSummary({ description = {}, verdict = null, risk = null, jobId = null, playbooksUsed = [] }) {
  const family = description.malware_family || {};
  const chain = description.attack_chain || [];
  const behavior = description.behavior || [];
  const actions = description.recommended_actions || verdict?.recommended_actions || [];
  const ioc = description.ioc_narrative || "";
  const attribution = description.attribution_hints || "";
  const summary = description.summary || verdict?.summary || "";

  const toText = () => {
    const lines = [];
    lines.push("NIVXRAY — FINAL INVESTIGATION SUMMARY");
    lines.push("=".repeat(50));
    lines.push(`Generated: ${new Date().toISOString()}`);
    lines.push("");

    if (risk) {
      lines.push(`RISK VERDICT: ${risk.verdict}  (score ${risk.score}/100 · ${risk.level})`);
    }
    if (verdict?.verdict) {
      lines.push(`AI VERDICT:   ${verdict.verdict}  (confidence ${verdict.confidence}%)`);
    }
    lines.push("");

    if (summary) {
      lines.push("EXECUTIVE SUMMARY");
      lines.push("-".repeat(50));
      lines.push(summary);
      lines.push("");
    }

    if (family?.name) {
      lines.push("MALWARE FAMILY");
      lines.push("-".repeat(50));
      lines.push(`Name:       ${family.name}`);
      lines.push(`Confidence: ${family.confidence || "unknown"}`);
      if (family.rationale) {
        lines.push(`Rationale:  ${family.rationale}`);
      }
      lines.push("");
    }

    if (chain.length) {
      lines.push(`ATTACK CHAIN (${chain.length} stages)`);
      lines.push("-".repeat(50));
      chain.forEach((c, i) => {
        const step = String(c.step ?? i + 1).padStart(2, "0");
        const kind = c.kind ? ` [${c.kind}]` : "";
        lines.push(`${step}. ${c.title || "(untitled)"}${kind}`);
        if (c.summary) lines.push(`    ${c.summary}`);
        if (c.technical_detail) lines.push(`    artifact: ${c.technical_detail}`);
        lines.push("");
      });
    }

    if (behavior.length) {
      lines.push("OBSERVED BEHAVIOR");
      lines.push("-".repeat(50));
      behavior.forEach((b) => lines.push(`- ${b}`));
      lines.push("");
    }

    if (ioc) {
      lines.push("IOC NARRATIVE");
      lines.push("-".repeat(50));
      lines.push(ioc);
      lines.push("");
    }

    if (attribution) {
      lines.push("ATTRIBUTION HINTS");
      lines.push("-".repeat(50));
      lines.push(attribution);
      lines.push("");
    }

    if (actions.length) {
      lines.push("RECOMMENDED ACTIONS");
      lines.push("-".repeat(50));
      actions.forEach((a) => lines.push(`- ${a}`));
      lines.push("");
    }

    return lines.join("\n");
  };

  const downloadTxt = () => {
    const blob = new Blob([toText()], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `nivxray_final_summary_${new Date().toISOString().replace(/[:.]/g, "-")}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const copyTxt = () => navigator.clipboard.writeText(toText());

  const familyColor = family.confidence === "high" ? "var(--high)" :
                      family.confidence === "medium" ? "var(--warn)" : "var(--accent)";

  return (
    <div className="nvx-card" data-testid="final-summary-card">
      <div className="nvx-card-head">
        <div className="nvx-card-title">
          <span className="dot" style={{ background: "var(--accent)" }} />
          FINAL SUMMARY
          <span className="count">
            {chain.length} stages · {behavior.length} behaviors · {actions.length} actions
          </span>
        </div>
        <div className="nvx-card-actions">
          <button className="nvx-btn sm ghost" onClick={copyTxt} data-testid="btn-final-summary-copy">
            <Copy size={11} /> COPY
          </button>
          <button className="nvx-btn primary sm" onClick={downloadTxt} data-testid="btn-final-summary-download">
            <Download size={11} /> DOWNLOAD TXT
          </button>
        </div>
      </div>
      <div className="nvx-card-body" style={{ padding: 16, display: "grid", gap: 14 }}>
        {/* Verdict strip */}
        {(risk || verdict) && (
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center" }}>
            {risk && (
              <span className={`badge ${risk.level}`} data-testid="fs-risk-badge">
                {risk.verdict} · {risk.score}/100
              </span>
            )}
            {verdict?.verdict && (
              <span className="badge warn" data-testid="fs-ai-verdict">
                AI · {verdict.verdict} · {verdict.confidence}%
              </span>
            )}
            {family?.name && (
              <span className="badge" style={{ borderColor: familyColor, color: familyColor }} data-testid="fs-family">
                FAMILY · {family.name}{family.confidence ? ` (${family.confidence})` : ""}
              </span>
            )}
          </div>
        )}

        {/* Executive summary */}
        {summary && (
          <SummaryBlock label="Executive Summary" testid="fs-summary">
            <p className="mono" style={{ margin: 0, fontSize: 12.5, color: "var(--text)", lineHeight: 1.65 }}>
              {summary}
            </p>
          </SummaryBlock>
        )}

        {/* Malware family rationale */}
        {family?.name && family?.rationale && (
          <SummaryBlock label={`Malware Family · ${family.name}`} testid="fs-family-block" accent={familyColor}>
            <div className="mono" style={{ fontSize: 11.5, color: "var(--text-dim)", lineHeight: 1.6 }}>
              <span style={{ color: familyColor, marginRight: 6 }}>▸</span>{family.rationale}
            </div>
          </SummaryBlock>
        )}

        {/* Attack chain — compact list */}
        {chain.length > 0 && (
          <SummaryBlock label={`Attack Chain · ${chain.length} stages`} testid="fs-chain-block">
            <ol style={{ margin: 0, padding: 0, listStyle: "none", display: "grid", gap: 6 }}>
              {chain.map((c, i) => (
                <li key={i} className="mono" style={{ fontSize: 11.5, color: "var(--text-dim)", display: "flex", gap: 8 }}
                    data-testid={`fs-chain-step-${i + 1}`}>
                  <span style={{ color: "var(--accent)", fontWeight: 700, minWidth: 24 }}>
                    {String(c.step ?? i + 1).padStart(2, "0")}
                  </span>
                  <div style={{ flex: 1 }}>
                    <div style={{ color: "var(--text)", fontWeight: 700, letterSpacing: "0.08em" }}>
                      {c.title || "(untitled)"}
                      {c.kind && <span className="badge" style={{ marginLeft: 8, fontSize: 9 }}>{c.kind}</span>}
                    </div>
                    {c.summary && (
                      <div style={{ color: "var(--text-dim)", marginTop: 3, lineHeight: 1.55 }}>{c.summary}</div>
                    )}
                  </div>
                </li>
              ))}
            </ol>
          </SummaryBlock>
        )}

        {/* Behavior */}
        {behavior.length > 0 && (
          <SummaryBlock label={`Observed Behavior · ${behavior.length}`} testid="fs-behavior-block">
            <ul style={{ margin: 0, padding: 0, listStyle: "none", display: "grid", gap: 4 }}>
              {behavior.map((b, i) => (
                <li key={i} className="mono" style={{ fontSize: 11.5, color: "var(--text-dim)", lineHeight: 1.55 }}>
                  <span style={{ color: "var(--warn)", marginRight: 8 }}>▪</span>{b}
                </li>
              ))}
            </ul>
          </SummaryBlock>
        )}

        {/* IOC narrative */}
        {ioc && (
          <SummaryBlock label="IOC Narrative" testid="fs-ioc-block">
            <p className="mono" style={{ margin: 0, fontSize: 11.5, color: "var(--text-dim)", lineHeight: 1.6 }}>{ioc}</p>
          </SummaryBlock>
        )}

        {/* Attribution */}
        {attribution && (
          <SummaryBlock label="Attribution Hints" testid="fs-attribution-block">
            <p className="mono" style={{ margin: 0, fontSize: 11.5, color: "var(--text-dim)", lineHeight: 1.6 }}>{attribution}</p>
          </SummaryBlock>
        )}

        {/* Recommended actions */}
        {actions.length > 0 && (
          <SummaryBlock label={`Recommended Actions · ${actions.length}`} testid="fs-actions-block" accent="var(--high)">
            <ul style={{ margin: 0, padding: 0, listStyle: "none", display: "grid", gap: 4 }}>
              {actions.map((a, i) => (
                <li key={i} className="mono" style={{ fontSize: 11.5, color: "var(--text)", lineHeight: 1.55 }}
                    data-testid={`fs-action-${i}`}>
                  <span style={{ color: "var(--high)", marginRight: 8 }}>➤</span>{a}
                </li>
              ))}
            </ul>
          </SummaryBlock>
        )}

        {/* Playbook feedback loop */}
        {jobId && (playbooksUsed || []).length > 0 && (
          <SummaryBlock label="Playbook Feedback · train your AI" testid="fs-playbook-feedback-block" accent="var(--accent)">
            <PlaybookFeedback jobId={jobId} testidPrefix="fs-playbook-feedback" />
          </SummaryBlock>
        )}
      </div>
    </div>
  );
}

function SummaryBlock({ label, children, testid, accent = "var(--accent)" }) {
  return (
    <div data-testid={testid} style={{ borderLeft: `3px solid ${accent}`, paddingLeft: 12 }}>
      <div className="mono"
        style={{ fontSize: 10, color: accent, letterSpacing: "0.22em", marginBottom: 6, textTransform: "uppercase" }}>
        {label}
      </div>
      {children}
    </div>
  );
}
