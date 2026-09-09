/**
 * CorrelationSuggestionCard — Phase 4 · P1.
 *
 * A single auto-correlation suggestion in the side panel. Shows the
 * candidate case + shared evidence + confidence, with confirm/dismiss
 * actions.
 */
import { Check, X, Fingerprint } from "lucide-react";

const CONFIDENCE_TONE = {
  high:   { fg: "#f87171", bg: "rgba(248,113,113,0.10)", bd: "rgba(248,113,113,0.35)" },
  medium: { fg: "#fbbf24", bg: "rgba(251,191,36,0.10)", bd: "rgba(251,191,36,0.35)" },
  low:    { fg: "#67e8f9", bg: "rgba(103,232,249,0.10)", bd: "rgba(103,232,249,0.35)" },
  weak:   { fg: "#94a3b8", bg: "rgba(148,163,184,0.10)", bd: "rgba(148,163,184,0.30)" },
};

export default function CorrelationSuggestionCard({ suggestion, onConfirm, onDismiss }) {
  const tone = CONFIDENCE_TONE[suggestion.confidence] || CONFIDENCE_TONE.low;
  const p = suggestion.case_preview || {};
  const sharedKeys = Object.keys(suggestion.shared || {});
  return (
    <div data-testid={`suggestion-${suggestion.case_id}`}
         style={{ background: "rgba(15,23,42,0.6)",
                  border: `1px solid ${tone.bd}`,
                  borderRadius: 8, padding: 10 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6 }}>
        <span style={{ padding: "1px 6px", fontSize: 9,
                       fontFamily: "JetBrains Mono, monospace",
                       background: tone.bg, color: tone.fg,
                       border: `1px solid ${tone.bd}`, borderRadius: 3,
                       letterSpacing: "0.08em", textTransform: "uppercase" }}>
          {suggestion.confidence} · {suggestion.score}
        </span>
        {p.artifact_type && (
          <span style={{ fontSize: 9, padding: "1px 5px",
                         background: "rgba(103,232,249,0.10)", color: "#67e8f9",
                         borderRadius: 3,
                         fontFamily: "JetBrains Mono, monospace",
                         textTransform: "uppercase" }}>
            {p.artifact_type}
          </span>
        )}
      </div>
      <div style={{ fontSize: 11, color: "#e2e8f0",
                    fontFamily: "JetBrains Mono, monospace",
                    overflow: "hidden", textOverflow: "ellipsis",
                    whiteSpace: "nowrap" }}
           title={p.case_name || p.input_preview}>
        {p.case_name || p.input_preview || suggestion.case_id.slice(0, 12)}
      </div>
      {sharedKeys.length > 0 && (
        <div style={{ marginTop: 6 }}>
          <div style={{ fontSize: 9, color: "#94a3b8",
                        fontFamily: "JetBrains Mono, monospace",
                        letterSpacing: "0.08em", textTransform: "uppercase",
                        display: "inline-flex", alignItems: "center", gap: 4 }}>
            <Fingerprint size={9} /> Shared evidence
          </div>
          <div style={{ marginTop: 3, display: "flex", flexWrap: "wrap", gap: 3 }}>
            {sharedKeys.slice(0, 5).map(k => (
              <span key={k}
                    title={fmtValue(suggestion.shared[k])}
                    style={{ fontSize: 9, padding: "1px 5px",
                             background: "rgba(139,92,246,0.10)",
                             color: "#c4b5fd", borderRadius: 3,
                             fontFamily: "JetBrains Mono, monospace" }}>
                {k} × {Array.isArray(suggestion.shared[k]) ? suggestion.shared[k].length : 1}
              </span>
            ))}
          </div>
        </div>
      )}
      <div style={{ marginTop: 8, display: "flex", gap: 6 }}>
        <button data-testid={`suggestion-confirm-${suggestion.case_id}`}
                onClick={onConfirm}
                style={{ flex: 1, padding: "5px 8px", fontSize: 10,
                         background: "rgba(34,197,94,0.14)",
                         color: "#86efac",
                         border: "1px solid rgba(34,197,94,0.35)",
                         borderRadius: 4, cursor: "pointer",
                         fontFamily: "JetBrains Mono, monospace",
                         letterSpacing: "0.08em", textTransform: "uppercase",
                         display: "inline-flex", alignItems: "center",
                         justifyContent: "center", gap: 4 }}>
          <Check size={11} /> Confirm
        </button>
        <button data-testid={`suggestion-dismiss-${suggestion.case_id}`}
                onClick={onDismiss}
                style={{ padding: "5px 8px", fontSize: 10,
                         background: "rgba(148,163,184,0.06)",
                         color: "#94a3b8",
                         border: "1px solid rgba(148,163,184,0.20)",
                         borderRadius: 4, cursor: "pointer",
                         fontFamily: "JetBrains Mono, monospace",
                         letterSpacing: "0.08em", textTransform: "uppercase",
                         display: "inline-flex", alignItems: "center",
                         gap: 4 }}>
          <X size={11} />
        </button>
      </div>
    </div>
  );
}

function fmtValue(v) {
  if (Array.isArray(v)) return v.slice(0, 3).join(", ") + (v.length > 3 ? ` (+${v.length-3})` : "");
  return String(v);
}
