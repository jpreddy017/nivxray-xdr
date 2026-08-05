/**
 * AttackChainView — Phase 4 · P1.
 *
 * Linear top-to-bottom attack chain visualization. Each node is a case
 * or an inline artifact. Indentation reflects tree depth.
 *
 * Owner directive: Chain view is the default because analysts want the
 * attack progression first. Graph is a deep-dive.
 */
import { Link } from "react-router-dom";
import { FileText, Binary, FileType2, FileCode2, Terminal,
         ArrowDown, X, ExternalLink } from "lucide-react";

const ARTIFACT_ICON = {
  pe:              Binary,
  elf:             Binary,
  pdf:             FileType2,
  office:          FileText,
  vba_macro:       FileCode2,
  powershell:      Terminal,
  pdf_javascript:  FileCode2,
  dde:             FileCode2,
  ole:             FileText,
  embedded_file:   FileText,
};

const VERDICT_COLOR = {
  Malicious: "#f87171", Suspicious: "#fbbf24", Partial: "#fbbf24",
  Benign: "#86efac", Unknown: "#94a3b8",
};

export default function AttackChainView({ chain, onUnlink, onOpenEvidence }) {
  if (!chain || !chain.steps || chain.steps.length === 0) {
    return (
      <div data-testid="chain-empty"
           style={{ padding: 40, textAlign: "center", color: "#64748b",
                    background: "rgba(2,6,23,0.5)",
                    border: "1px dashed rgba(148,163,184,0.14)",
                    borderRadius: 10, fontSize: 12 }}>
        Attack chain is empty.
      </div>
    );
  }
  return (
    <div data-testid="attack-chain"
         style={{ display: "grid", gap: 8, minWidth: 0, overflow: "hidden" }}>
      {chain.steps.map((step, idx) => (
        <div key={step.node_id}
             style={{ paddingLeft: (step.depth || 0) * 22, minWidth: 0 }}>
          <ChainNode step={step} idx={idx} onUnlink={onUnlink}
                     onOpenEvidence={onOpenEvidence} />
          {idx < chain.steps.length - 1 && (
            <div style={{ paddingLeft: 16, opacity: 0.5, margin: "2px 0",
                          color: "#475569" }}>
              <ArrowDown size={12} />
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function ChainNode({ step, idx, onUnlink, onOpenEvidence }) {
  const isCase = step.kind === "case";
  const isRoot = step.source === "root";
  const artifact = step.artifact_type || (isCase ? "case" : "artifact");
  const IconEl = ARTIFACT_ICON[artifact] || FileText;
  const vcol = VERDICT_COLOR[step.verdict] || "#94a3b8";
  const inline = step.source === "inline_recursive";

  return (
    <div
      data-testid={`chain-node-${idx}`}
      style={{
        display: "flex", alignItems: "start", gap: 12,
        padding: "10px 14px",
        background: isRoot
          ? "rgba(103,232,249,0.06)"
          : (inline ? "rgba(139,92,246,0.05)" : "rgba(15,23,42,0.7)"),
        border: `1px solid ${isRoot
          ? "rgba(103,232,249,0.30)"
          : (inline ? "rgba(139,92,246,0.24)" : "rgba(148,163,184,0.16)")}`,
        borderRadius: 8,
      }}
    >
      <div style={{ width: 30, height: 30, borderRadius: 6,
                    background: "rgba(2,6,23,0.7)",
                    border: "1px solid rgba(148,163,184,0.20)",
                    display: "flex", alignItems: "center", justifyContent: "center",
                    color: vcol, flexShrink: 0 }}>
        <IconEl size={15} strokeWidth={1.6} />
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8,
                      flexWrap: "wrap" }}>
          <span aria-hidden style={{ width: 6, height: 6, borderRadius: "50%",
                                     background: vcol }} />
          <div style={{ fontSize: 13, fontWeight: 600, color: "#e2e8f0",
                        fontFamily: "JetBrains Mono, monospace",
                        overflow: "hidden", textOverflow: "ellipsis",
                        whiteSpace: "nowrap", maxWidth: 480 }}>
            {step.case_name || step.label || step.input_preview || step.node_id}
          </div>
          <SourceChip source={step.source} />
          {step.artifact_type && (
            <span style={{ padding: "1px 6px", fontSize: 10,
                           background: "rgba(103,232,249,0.10)",
                           color: "#67e8f9",
                           border: "1px solid rgba(103,232,249,0.28)",
                           borderRadius: 3,
                           fontFamily: "JetBrains Mono, monospace",
                           textTransform: "uppercase" }}>
              {step.artifact_type}
            </span>
          )}
        </div>
        {step.input_preview && step.input_preview !== step.case_name && (
          <div style={{ marginTop: 4, fontSize: 11, color: "#94a3b8",
                        fontFamily: "JetBrains Mono, monospace",
                        overflow: "hidden", textOverflow: "ellipsis",
                        whiteSpace: "nowrap", maxWidth: "100%",
                        minWidth: 0 }}>
            {step.input_preview}
          </div>
        )}
        {step.snippet && (
          <pre style={{ marginTop: 6, fontSize: 10.5, color: "#cbd5e1",
                        background: "rgba(2,6,23,0.6)",
                        padding: "6px 8px", borderRadius: 4,
                        maxHeight: 80, overflow: "auto",
                        fontFamily: "JetBrains Mono, monospace" }}>
            {step.snippet}
          </pre>
        )}
        {step.techniques && step.techniques.length > 0 && (
          <div style={{ marginTop: 6, display: "flex", gap: 4, flexWrap: "wrap" }}>
            {step.techniques.slice(0, 6).map(t => (
              <span key={t}
                    style={{ fontSize: 9, padding: "1px 5px",
                             background: "rgba(245,158,11,0.10)",
                             color: "#fcd34d", borderRadius: 3,
                             fontFamily: "JetBrains Mono, monospace" }}>
                {t}
              </span>
            ))}
          </div>
        )}
      </div>
      <div style={{ display: "flex", gap: 6, alignItems: "center", flexShrink: 0 }}>
        {onOpenEvidence && (
          <button data-testid={`chain-node-evidence-${idx}`}
                  onClick={() => onOpenEvidence(step)}
                  title="Open evidence drill-down"
                  style={{ padding: "3px 8px", fontSize: 10,
                           background: "rgba(56,189,248,0.10)",
                           color: "#7dd3fc",
                           border: "1px solid rgba(56,189,248,0.30)",
                           borderRadius: 4, cursor: "pointer",
                           fontFamily: "JetBrains Mono, monospace",
                           letterSpacing: "0.08em" }}>
            EVIDENCE
          </button>
        )}
        {isCase && step.case_id && (
          <Link to={`/history?id=${step.case_id}`}
                data-testid={`chain-node-open-${idx}`}
                title="Open case in workspace"
                style={{ color: "#94a3b8", padding: "3px 6px",
                         borderRadius: 4, display: "inline-flex",
                         alignItems: "center", textDecoration: "none" }}
                onMouseEnter={(e) => e.currentTarget.style.color = "#67e8f9"}
                onMouseLeave={(e) => e.currentTarget.style.color = "#94a3b8"}>
            <ExternalLink size={13} />
          </Link>
        )}
        {isCase && !isRoot && onUnlink && (
          <button data-testid={`chain-node-unlink-${idx}`}
                  onClick={() => onUnlink(step.case_id)}
                  title="Unlink from investigation"
                  style={{ color: "#94a3b8", padding: "3px 6px",
                           borderRadius: 4, background: "transparent",
                           border: "none", cursor: "pointer" }}
                  onMouseEnter={(e) => e.currentTarget.style.color = "#f87171"}
                  onMouseLeave={(e) => e.currentTarget.style.color = "#94a3b8"}>
            <X size={13} />
          </button>
        )}
      </div>
    </div>
  );
}

function SourceChip({ source }) {
  if (!source) return null;
  const map = {
    root:             { label: "ROOT",     bg: "rgba(103,232,249,0.14)", fg: "#67e8f9" },
    manual:           { label: "MANUAL",   bg: "rgba(34,197,94,0.14)",   fg: "#86efac" },
    auto_correlated:  { label: "AUTO",     bg: "rgba(139,92,246,0.14)",  fg: "#c4b5fd" },
    inline_recursive: { label: "INLINE",   bg: "rgba(139,92,246,0.14)",  fg: "#c4b5fd" },
  };
  const c = map[source];
  if (!c) return null;
  return (
    <span style={{ padding: "1px 5px", fontSize: 9,
                   background: c.bg, color: c.fg, borderRadius: 3,
                   fontFamily: "JetBrains Mono, monospace",
                   letterSpacing: "0.08em" }}>
      {c.label}
    </span>
  );
}
