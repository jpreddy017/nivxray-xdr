import { Copy, Check, ShieldAlert, ShieldCheck, ShieldQuestion, HelpCircle, FileWarning } from "lucide-react";
import { useState } from "react";

/**
 * VerdictCard — SOC-grade evidence-driven verdict panel.
 *
 * Props
 *   verdict:  { label, confidence, reason, indicators[], recommended_action }
 *
 * Design rules:
 *  • Every "indicator" is EVIDENCE — never a speculative label.
 *  • Confidence is a single number the analyst can trust.
 *  • Corrupted / Undecoded verdicts show confidence = 0 (not "N/A").
 *  • COPY VERDICT clipboards a SOC-ticket-ready block for pasting into
 *    ServiceNow / Jira / SIEM / ticket comments.
 */
const _VERDICT_STYLE = {
  Malicious:  { color: "#f87171", bg: "rgba(248, 113, 113, 0.08)", Icon: ShieldAlert },
  Suspicious: { color: "#f59e0b", bg: "rgba(245, 158, 11, 0.08)", Icon: FileWarning },
  Corrupted:  { color: "#e879f9", bg: "rgba(232, 121, 249, 0.08)", Icon: FileWarning },
  Undecoded:  { color: "#94a3b8", bg: "rgba(148, 163, 184, 0.08)", Icon: HelpCircle },
  Benign:     { color: "#7ee3c9", bg: "rgba(126, 227, 201, 0.08)", Icon: ShieldCheck },
};

export default function VerdictCard({ verdict, testidPrefix = "verdict" }) {
  const [copied, setCopied] = useState(false);
  if (!verdict) return null;
  const { label, confidence, reason, indicators = [], recommended_action } = verdict;
  const style = _VERDICT_STYLE[label] || _VERDICT_STYLE.Undecoded;
  const Icon = style.Icon;

  const positive = indicators.filter((i) => i.kind === "positive");
  const neutral = indicators.filter((i) => i.kind === "neutral");
  const negative = indicators.filter((i) => i.kind === "negative");

  const socTicket = [
    "═══ NIVX FORGE — SOC VERDICT ═══",
    "",
    `Verdict:              ${label}`,
    `Confidence:           ${confidence}%`,
    `Reason:               ${reason}`,
    "",
    "Evidence:",
    ...(indicators.length
      ? indicators.map((i) => `  [${i.kind.toUpperCase().padEnd(8)}]  ${i.label}`)
      : ["  (no additional indicators)"]),
    "",
    `Recommended Action:   ${recommended_action || "—"}`,
    "",
    "════════════════════════════════",
  ].join("\n");

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(socTicket);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch (_) {}
  };

  return (
    <section
      className="brut-border"
      data-testid={`${testidPrefix}-card`}
      style={{ background: style.bg, borderColor: style.color }}
    >
      {/* Header row */}
      <div
        style={{
          padding: "12px 16px",
          borderBottom: `1px solid ${style.color}33`,
          display: "flex",
          alignItems: "center",
          gap: 12,
          flexWrap: "wrap",
        }}
      >
        <Icon size={18} style={{ color: style.color }} />
        <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
          <div
            className="mono"
            style={{ fontSize: 10, letterSpacing: "0.24em", color: "var(--text-mute)" }}
          >
            ▸ SOC VERDICT
          </div>
          <div style={{ display: "flex", alignItems: "baseline", gap: 12 }}>
            <span
              className="mono"
              style={{ fontSize: 18, color: style.color, fontWeight: 600, letterSpacing: "0.05em" }}
              data-testid={`${testidPrefix}-label`}
            >
              {label.toUpperCase()}
            </span>
            <span
              className="mono"
              style={{ fontSize: 12, color: "var(--text-dim)" }}
              data-testid={`${testidPrefix}-confidence`}
            >
              CONFIDENCE {confidence}%
            </span>
          </div>
        </div>
        <div style={{ flex: 1 }} />
        <button
          className="nvx-btn sm primary"
          onClick={copy}
          data-testid={`${testidPrefix}-copy`}
        >
          {copied ? <Check size={12} /> : <Copy size={12} />}
          {copied ? "COPIED" : "COPY VERDICT"}
        </button>
      </div>

      {/* Reason */}
      <div
        style={{
          padding: "12px 16px",
          borderBottom: "1px solid var(--border)",
        }}
      >
        <div
          className="mono"
          style={{ fontSize: 10, color: "var(--text-mute)", letterSpacing: "0.16em", marginBottom: 6 }}
        >
          REASON
        </div>
        <div
          className="mono"
          style={{ fontSize: 12, color: "var(--text)", lineHeight: 1.6 }}
          data-testid={`${testidPrefix}-reason`}
        >
          {reason}
        </div>
      </div>

      {/* Indicators */}
      {indicators.length > 0 && (
        <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--border)" }}>
          <div
            className="mono"
            style={{
              fontSize: 10,
              color: "var(--text-mute)",
              letterSpacing: "0.16em",
              marginBottom: 8,
            }}
          >
            EVIDENCE · {indicators.length} INDICATOR
            {indicators.length === 1 ? "" : "S"}
          </div>
          <div style={{ display: "grid", gap: 4 }}>
            {[...positive, ...negative, ...neutral].map((i, k) => {
              const c =
                i.kind === "positive"
                  ? "#7ee3c9"
                  : i.kind === "negative"
                  ? "#f87171"
                  : "var(--text-mute)";
              return (
                <div
                  key={k}
                  className="mono"
                  style={{
                    fontSize: 11,
                    color: "var(--text)",
                    display: "flex",
                    alignItems: "flex-start",
                    gap: 8,
                  }}
                  data-testid={`${testidPrefix}-indicator-${k}`}
                >
                  <span
                    style={{
                      color: c,
                      minWidth: 66,
                      fontSize: 9,
                      letterSpacing: "0.08em",
                      textTransform: "uppercase",
                      lineHeight: 1.6,
                    }}
                  >
                    [{i.kind}]
                  </span>
                  <span style={{ lineHeight: 1.6 }}>{i.label}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Recommended action */}
      {recommended_action && (
        <div style={{ padding: "12px 16px" }}>
          <div
            className="mono"
            style={{ fontSize: 10, color: "var(--text-mute)", letterSpacing: "0.16em", marginBottom: 6 }}
          >
            RECOMMENDED ACTION
          </div>
          <div
            className="mono"
            style={{ fontSize: 12, color: "var(--text)", lineHeight: 1.6 }}
            data-testid={`${testidPrefix}-action`}
          >
            {recommended_action}
          </div>
        </div>
      )}
    </section>
  );
}


/**
 * LayerEvidenceRow — inline per-layer metadata row for the decoding trace.
 *
 * Props
 *   evidence: { encoding, op, length, ascii, entropy, hex_preview, integrity }
 */
export function LayerEvidenceRow({ evidence, testid }) {
  if (!evidence) return null;
  const ok = evidence.integrity?.ok !== false;
  return (
    <div
      className="mono"
      style={{
        fontSize: 10,
        color: "var(--text-mute)",
        display: "grid",
        gridTemplateColumns: "repeat(auto-fit, minmax(120px, 1fr))",
        gap: 8,
        marginTop: 6,
        padding: "6px 8px",
        background: "var(--inset)",
        borderRadius: 2,
      }}
      data-testid={testid || "layer-evidence"}
    >
      <span>
        <b style={{ color: "var(--text-dim)" }}>Encoding:</b> {evidence.encoding}
      </span>
      <span>
        <b style={{ color: "var(--text-dim)" }}>Length:</b> {evidence.length}B
      </span>
      <span>
        <b style={{ color: "var(--text-dim)" }}>ASCII:</b>{" "}
        <span style={{ color: evidence.ascii ? "#7ee3c9" : "#f59e0b" }}>
          {evidence.ascii ? "Yes" : "No"}
        </span>
      </span>
      <span>
        <b style={{ color: "var(--text-dim)" }}>Entropy:</b> {evidence.entropy}
      </span>
      <span style={{ gridColumn: "1 / -1", wordBreak: "break-all" }}>
        <b style={{ color: "var(--text-dim)" }}>Hex:</b> {evidence.hex_preview}
      </span>
      <span style={{ gridColumn: "1 / -1" }}>
        <b style={{ color: "var(--text-dim)" }}>Integrity:</b>{" "}
        <span style={{ color: ok ? "#7ee3c9" : "#f87171" }}>
          {ok ? "OK" : `FAILED · ${evidence.integrity?.reason || ""}`}
        </span>
      </span>
    </div>
  );
}
