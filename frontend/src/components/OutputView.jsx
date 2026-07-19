import { useEffect, useMemo, useState } from "react";
import { Eye, Binary, Hash, GitCompareArrows, Zap, Cpu, CheckCircle2, XCircle, Bug, ArrowDown, ShieldAlert } from "lucide-react";
import { computeDiff, formatDelta, toHexDump, toBase64 } from "@/lib/diff";
import { detectShellcode, extractShellcodeIocs } from "@/lib/shellcodeDetect";


/**
 * Detect a "terminal decode state" — the decoder recovered a clean readable
 * head followed by a run of binary / encrypted / unsupported bytes.
 *
 * Returns { clean, tailBytes, kind } when a terminal state is detected,
 * else null.
 *
 * Heuristic (mirrors backend engine._trim_tail_garbage but purely display-side):
 *   * Require ≥ 32 chars total
 *   * Sample last 40 chars: if printable ratio < 0.6, look for a garbage tail
 *   * Walk backwards to find where the binary run starts (min run = 8 bytes)
 *   * Require the head to be clean (printable ratio ≥ 0.85, non-empty)
 *   * Preserves valid Unicode (box-drawing, CJK) as printable
 */
function detectTerminalTail(text) {
  if (!text || text.length < 32) return null;

  const isPrintable = (c) => {
    const o = c.charCodeAt(0);
    if (o >= 32 && o < 127) return true;
    if (o === 9 || o === 10 || o === 13) return true;
    if (o >= 0x0100) return true;                          // real Unicode text
    return false;                                           // C0/C1 controls, Latin-1 supp
  };

  // Quick probe: last 40 chars
  const probe = text.slice(-40);
  let probeOk = 0;
  for (const c of probe) if (isPrintable(c)) probeOk++;
  if (probeOk / probe.length >= 0.6) return null;           // last 40 chars mostly clean → no tail garbage

  // Walk backwards to find where the binary run starts
  const n = text.length;
  let cut = n;
  let run = 0;
  for (let i = n - 1; i >= 0; i--) {
    if (!isPrintable(text[i])) {
      run++;
      if (run >= 8) cut = i - run + 1;
    } else {
      if (cut < n) break;
      run = 0;
    }
  }
  if (cut >= n) return null;

  const head = text.slice(0, cut);
  if (!head) return null;
  let headOk = 0;
  for (const c of head) if (isPrintable(c)) headOk++;
  if (headOk / head.length < 0.85) return null;             // head not clean → uniform garbage

  return {
    clean: head,
    tailBytes: n - cut,
    kind: "binary/encrypted/unsupported",
  };
}


/**
 * OutputView
 * ----------
 * Enhanced Output panel with:
 *  1. Live client-side preview status pill (JS vs BACKEND vs ERROR)
 *  2. View toggles — TEXT / HEX / BASE64
 *  3. Byte-level diff highlight when DIFF toggle is on
 *  4. Output size + delta from input (green if smaller, red if larger)
 *  5. Terminal-decode banner — clean head + suppressed binary tail (RC2.4)
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
  const [shellcodeBannerDismissed, setShellcodeBannerDismissed] = useState(false);

  const diff = useMemo(() => computeDiff(input || "", output || ""), [input, output]);
  const shellcode = useMemo(() => detectShellcode(output || ""), [output]);
  const shellcodeIocs = useMemo(() => shellcode ? extractShellcodeIocs(output || "") : null, [shellcode, output]);

  // RC2.4 — Terminal decode state: detect a clean head + binary tail.
  // Only surface this in TEXT view when NO shellcode was detected (shellcode
  // has its own dedicated banner + HEX auto-switch).
  const terminalTail = useMemo(
    () => (shellcode ? null : detectTerminalTail(output || "")),
    [output, shellcode],
  );

  // Auto-switch to HEX view when a decode terminates on known shellcode —
  // rendering raw binary in TEXT view looks like garbage. Runs once per
  // new detection (dismiss + change of output resets).
  useEffect(() => {
    if (shellcode) {
      setView("hex");
      setShowDiff(false);
      setShellcodeBannerDismissed(false);
    }
  }, [shellcode?.family]);
  const renderedBody = useMemo(() => {
    if (view === "hex") return toHexDump(output || "");
    if (view === "base64") return toBase64(output || "");
    // TEXT view — if a terminal-tail is detected, show the clean head only.
    // Raw bytes remain fully available in HEX / B64 views (evidence preserved).
    if (terminalTail) return terminalTail.clean;
    return output || "";
  }, [output, view, terminalTail]);

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

      {/* Shellcode banner — appears when the decoded output starts with a
          known executable prologue (MSFvenom stagers, PE, ELF, ARM64) */}
      {shellcode && !shellcodeBannerDismissed && (
        <div
          data-testid="shellcode-banner"
          style={{
            display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap",
            padding: "10px 14px",
            background: "rgba(126,227,201,0.10)",
            borderTop: "1px solid var(--border)",
            borderBottom: "1px solid rgba(126,227,201,0.35)",
          }}
        >
          <Bug size={14} style={{ color: "var(--accent)", flexShrink: 0 }} />
          <div style={{ flex: 1, minWidth: 240 }}>
            <div className="mono" style={{ fontSize: 11, letterSpacing: "0.2em", color: "var(--accent)", fontWeight: 600 }}>
              ⚡ SHELLCODE DECODED — {shellcode.family}
            </div>
            <div className="mono" style={{ fontSize: 10, color: "var(--text-mute)", marginTop: 3, lineHeight: 1.5 }}>
              Auto-switched to HEX view · arch: <b style={{ color: "var(--text)" }}>{shellcode.arch}</b>
              {shellcodeIocs?.ip && <> · C2 IP <b style={{ color: "var(--warn)" }}>{shellcodeIocs.ip}</b></>}
              {shellcodeIocs?.userAgent && <> · UA <b style={{ color: "var(--warn)" }}>{shellcodeIocs.userAgent.slice(0, 40)}…</b></>}
              {" · scroll ↓ for Capstone disassembly + IOC extraction"}
            </div>
          </div>
          <button
            className="nvx-btn sm ghost"
            onClick={() => {
              const view = document.querySelector('[data-testid="shellcode-view"]');
              if (view) view.scrollIntoView({ behavior: "smooth", block: "start" });
            }}
            data-testid="shellcode-banner-scroll"
            title="Scroll to Capstone disassembly + IOC extraction"
          >
            <ArrowDown size={11} /> DISASSEMBLY
          </button>
          <button
            className="nvx-btn sm ghost"
            onClick={() => setShellcodeBannerDismissed(true)}
            data-testid="shellcode-banner-dismiss"
            title="Dismiss banner"
          >
            <XCircle size={11} />
          </button>
        </div>
      )}

      {/* RC2.4 — Terminal decode state banner. Fires when the decoder
          recovered a clean head but the tail is binary/encrypted/unsupported.
          Explicitly does NOT fire when the shellcode banner is active. */}
      {terminalTail && view === "text" && (
        <div
          data-testid="terminal-decode-banner"
          style={{
            display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap",
            padding: "10px 14px",
            background: "rgba(230, 178, 79, 0.10)",
            borderTop: "1px solid var(--border)",
            borderBottom: "1px solid rgba(230, 178, 79, 0.35)",
          }}
        >
          <ShieldAlert size={14} style={{ color: "var(--warn)", flexShrink: 0 }} />
          <div style={{ flex: 1, minWidth: 240 }}>
            <div className="mono" style={{ fontSize: 11, letterSpacing: "0.2em", color: "var(--warn)", fontWeight: 600 }}>
              ⚠ TERMINAL DECODE STATE · Partial reconstruction complete
            </div>
            <div className="mono" style={{ fontSize: 10, color: "var(--text-mute)", marginTop: 3, lineHeight: 1.5 }}>
              Recovered the maximum readable content. Remaining <b style={{ color: "var(--text)" }}>{terminalTail.tailBytes} bytes</b>
              {" "}appear to be {terminalTail.kind} — no further supported decoder matched.
              {" "}Raw bytes preserved in <b style={{ color: "var(--text)" }}>HEX</b> / <b style={{ color: "var(--text)" }}>B64</b> views.
            </div>
          </div>
          <button
            className="nvx-btn sm ghost"
            onClick={() => setView("hex")}
            data-testid="terminal-decode-view-hex"
            title="Switch to HEX view to inspect raw remaining bytes"
          >
            <Binary size={11} /> INSPECT HEX
          </button>
        </div>
      )}

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
