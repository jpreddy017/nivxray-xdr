import { useMemo, useState } from "react";
import { Eye, Binary, Hash, GitCompareArrows, Zap, Cpu, CheckCircle2, XCircle } from "lucide-react";
import { computeDiff, formatDelta, toHexDump, toBase64 } from "@/lib/diff";

/**
 * OutputView
 * ----------
 * Enhanced Output panel with:
 *  1. Live client-side preview status pill (JS vs BACKEND vs ERROR)
 *  2. View toggles — TEXT / HEX / BASE64
 *  3. Byte-level diff highlight when DIFF toggle is on
 *  4. Output size + delta from input (green if smaller, red if larger)
 *
 * Falls back to a plain read-only textarea when there's no output yet.
 */
export default function OutputView({
  input,
  output,
  livePreview,      // { output, ranSteps, unsupported, needsBackend, error, latencyMs }
  actions,          // React node — buttons rendered in the card header
}) {
  const [view, setView] = useState("text");  // text | hex | base64
  const [showDiff, setShowDiff] = useState(false);

  const diff = useMemo(() => computeDiff(input || "", output || ""), [input, output]);
  const renderedBody = useMemo(() => {
    if (view === "hex") return toHexDump(output || "");
    if (view === "base64") return toBase64(output || "");
    return output || "";
  }, [output, view]);

  return (
    <div className="nvx-card" data-testid="output-card">
      {/* Header — title + preview status + view toggles + actions */}
      <div className="nvx-card-head" style={{ flexWrap: "wrap", gap: 8 }}>
        <div className="nvx-card-title">
          <span className="dot" />
          OUTPUT
        </div>

        {/* Preview status pill */}
        {livePreview && <LivePreviewPill lp={livePreview} />}

        {/* Size + delta */}
        <SizeDeltaPill diff={diff} />

        {/* View toggles */}
        <div style={{ display: "flex", gap: 4, marginLeft: "auto" }} data-testid="output-view-toggles">
          <ViewToggle icon={Eye}     label="TEXT"   active={view === "text"}   onClick={() => setView("text")}   testId="output-view-text" />
          <ViewToggle icon={Binary}  label="HEX"    active={view === "hex"}    onClick={() => setView("hex")}    testId="output-view-hex" />
          <ViewToggle icon={Hash}    label="B64"    active={view === "base64"} onClick={() => setView("base64")} testId="output-view-b64" />
          <ViewToggle
            icon={GitCompareArrows}
            label="DIFF"
            active={showDiff}
            onClick={() => setShowDiff((s) => !s)}
            testId="output-view-diff"
            disabled={view !== "text"}
            title={view === "text" ? "Toggle byte-level diff vs input" : "Diff only available in TEXT view"}
          />
        </div>

        {/* Card actions (Copy, AI Describe, Analyze+OSINT) */}
        <div className="nvx-card-actions" style={{ flexShrink: 0 }}>{actions}</div>
      </div>

      {/* Body */}
      <div className="nvx-card-body">
        {showDiff && view === "text" ? (
          <DiffView segments={diff.segments} identical={diff.identical} />
        ) : (
          <textarea
            className="nvx-textarea nvx-output-textarea"
            data-testid="output-textarea"
            value={renderedBody}
            readOnly
            placeholder="Run a recipe or click AUTO INVESTIGATE to see decoded output here…"
            style={view === "hex" ? { fontFamily: "JetBrains Mono, monospace", fontSize: 11 } : undefined}
          />
        )}
      </div>
    </div>
  );
}

// ---------- Sub-components ----------
function ViewToggle({ icon: Icon, label, active, onClick, disabled, title, testId }) {
  return (
    <button
      className={`nvx-btn sm ${active ? "primary" : "ghost"}`}
      onClick={onClick}
      disabled={disabled}
      title={title}
      data-testid={testId}
      style={{ opacity: disabled ? 0.5 : 1 }}
    >
      <Icon size={11} /> {label}
    </button>
  );
}

function LivePreviewPill({ lp }) {
  if (!lp) return null;
  const { needsBackend, unsupported, error, latencyMs, ranSteps } = lp;
  const kind = error ? "error" : needsBackend ? "hybrid" : "js";
  const color = error ? "var(--high)" : needsBackend ? "var(--warn)" : "var(--accent)";
  const Icon = error ? XCircle : needsBackend ? Cpu : Zap;
  const label = error
    ? "PREVIEW ERR"
    : needsBackend
    ? `HYBRID · ${ranSteps.length} JS + ${unsupported.length} BE`
    : `JS · ${ranSteps.length} STEP${ranSteps.length === 1 ? "" : "S"}`;
  return (
    <span
      className="mono"
      title={
        error
          ? `Preview error: ${error}`
          : needsBackend
          ? `Ran ${ranSteps.length} step(s) in-browser. Server needed for: ${unsupported.join(", ")}`
          : `All ${ranSteps.length} step(s) ran in-browser (~${latencyMs ?? 0}ms)`
      }
      data-testid={`live-preview-pill-${kind}`}
      style={{
        display: "inline-flex", alignItems: "center", gap: 4,
        fontSize: 10, letterSpacing: "0.14em",
        padding: "2px 8px", border: `1px solid ${color}`, color,
        background: `${color}18`,
      }}
    >
      <Icon size={10} /> {label}
      {latencyMs != null && !error && (
        <span style={{ opacity: 0.7, marginLeft: 4 }}>· {latencyMs}ms</span>
      )}
    </span>
  );
}

function SizeDeltaPill({ diff }) {
  if (!diff) return null;
  const { outputBytes, deltaBytes, identical } = diff;
  const color = identical ? "var(--text-mute)"
              : deltaBytes < 0 ? "var(--accent)"
              : deltaBytes > 0 ? "var(--warn)"
              : "var(--text-mute)";
  return (
    <span
      className="mono"
      data-testid="output-size-delta"
      title={`${outputBytes} bytes  ·  ${deltaBytes >= 0 ? "grew" : "shrunk"} by ${Math.abs(deltaBytes)} vs input`}
      style={{
        display: "inline-flex", alignItems: "center", gap: 4,
        fontSize: 10, letterSpacing: "0.14em",
        padding: "2px 8px", border: `1px solid ${color}`, color,
      }}
    >
      {outputBytes}B
      {!identical && (
        <span style={{ opacity: 0.85 }}>· {formatDelta(deltaBytes)}</span>
      )}
      {identical && diff.inputBytes > 0 && (
        <CheckCircle2 size={10} style={{ marginLeft: 2 }} />
      )}
    </span>
  );
}

function DiffView({ segments, identical }) {
  if (identical && segments.length <= 1) {
    return (
      <div className="mono" style={{
        padding: 14, minHeight: 160,
        color: "var(--text-mute)", fontSize: 12, textAlign: "center",
        border: "1px solid var(--border)", background: "var(--bg)",
      }} data-testid="diff-identical">
        Input and output are identical.
      </div>
    );
  }
  return (
    <pre
      className="mono nvx-textarea"
      data-testid="diff-view"
      style={{
        margin: 0, padding: 12, fontSize: 12, whiteSpace: "pre-wrap",
        wordBreak: "break-all", lineHeight: 1.55,
        background: "var(--bg)",
        maxHeight: 420, minHeight: 180, overflow: "auto",
      }}
    >
      {segments.map((seg, idx) => {
        if (seg.type === "same") {
          return <span key={idx} style={{ color: "var(--text-mute)", opacity: 0.85 }}>{seg.value}</span>;
        }
        if (seg.type === "add") {
          return (
            <span
              key={idx}
              data-testid={`diff-add-${idx}`}
              style={{
                background: "rgba(126,227,201,0.22)",
                color: "var(--accent)",
                textDecoration: "underline",
                textDecorationColor: "rgba(126,227,201,0.6)",
              }}
            >
              {seg.value}
            </span>
          );
        }
        // deletion
        return (
          <span
            key={idx}
            data-testid={`diff-del-${idx}`}
            style={{
              background: "rgba(217,108,108,0.22)",
              color: "var(--high)",
              textDecoration: "line-through",
              textDecorationColor: "rgba(217,108,108,0.6)",
            }}
          >
            {seg.value}
          </span>
        );
      })}
    </pre>
  );
}
