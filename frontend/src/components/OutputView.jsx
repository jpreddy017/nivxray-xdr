import { useEffect, useMemo, useState } from "react";
import { Eye, Binary, Hash, GitCompareArrows, Zap, Cpu, CheckCircle2, XCircle, Bug, ArrowDown, ShieldAlert } from "lucide-react";
import NavTabs from "@/components/NavTabs";
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
 * detectBinaryPayload — Feb-2026 · Fix A (v2)
 *
 * Detect an ENTIRE binary/shellcode payload (as opposed to a clean-head +
 * binary-tail terminal state). Fires when the decoded output has high
 * Shannon entropy AND a low printable-character ratio in the payload
 * region between the "▼ DECODED OUTPUT" envelope header and the
 * "NIVXRAY INVESTIGATION SUMMARY" footer.
 *
 * Also EXTRACTS the actionable intel embedded inside the binary buffer:
 *   • C2 IPs (regex on the printable strings sub-strate)
 *   • URLs
 *   • User-Agent lines
 *   • Win32 API name hints (LoadLibrary, VirtualAlloc, wininet, …)
 *   • Full printable-string dump (≥ 5 chars, ASCII only)
 * These are surfaced BY the caller as a human-readable OUTPUT view, so
 * the DECODED OUTPUT panel shows actionable intelligence instead of
 * garble. Raw bytes remain one click away via [SHOW RAW BYTES ANYWAY].
 *
 * Returns { entropy, printableRatio, byteCount, extracted } when a
 * binary payload is detected, else null.
 *
 * `extracted` = { ips, urls, userAgents, apis, strings } — arrays.
 *
 * Threshold: entropy > 6.5  AND  printable < 50%  AND  payload len >= 64.
 * (Random bytes ~7.99, English text ~4.2.)
 */
function detectBinaryPayload(text) {
  if (!text || text.length < 64) return null;

  const isPrintable = (c) => {
    const o = c.charCodeAt(0);
    if (o >= 32 && o < 127) return true;
    if (o === 9 || o === 10 || o === 13) return true;
    if (o >= 0x0100) return true;
    return false;
  };

  // Envelope-aware slice: keep only the payload between the DECODED
  // OUTPUT header and the next section header. Falls back to the whole
  // string when no envelope is present.
  const HEADER_RE = /▼\s*DECODED\s*OUTPUT[^\n]*\n/i;
  const FOOTER_RE = /\n[^\n]*(?:NIVXRAY|INVESTIGATION\s*SUMMARY|RECOVERED\s*PAYLOAD)[^\n]*/i;
  let payload = text;
  const hm = text.match(HEADER_RE);
  if (hm) {
    let after = text.slice(hm.index + hm[0].length);
    after = after.replace(/^━+\s*\n/, "");
    const fm = after.match(FOOTER_RE);
    if (fm) after = after.slice(0, fm.index);
    after = after.replace(/\n━+\s*$/, "");
    payload = after;
  }
  payload = payload
    .split("\n")
    .filter((ln) => !/^[━─═\s]+$/.test(ln))
    .join("\n");

  if (!payload || payload.length < 64) return null;

  const sample = payload.length > 4096 ? payload.slice(0, 4096) : payload;
  const n = sample.length;

  let printable = 0;
  const freq = new Map();
  for (let i = 0; i < n; i++) {
    const c = sample[i];
    if (isPrintable(c)) printable++;
    freq.set(c, (freq.get(c) || 0) + 1);
  }
  const printableRatio = printable / n;
  if (printableRatio >= 0.5) return null;

  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / n;
    entropy -= p * Math.log2(p);
  }
  if (entropy <= 6.5) return null;

  // ── Intel extraction ──────────────────────────────────────────────
  // Regex-scan the full envelope-sliced payload (up to 32KB) for the
  // ASCII strings malware embeds inside the binary buffer.
  const scan = payload.length > 32768 ? payload.slice(0, 32768) : payload;
  const IPV4_RE   = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
  const URL_RE    = /\bhttps?:\/\/[^\s\x00-\x1f<>"'`]{4,200}/gi;
  const UA_RE     = /(?:User-Agent:\s*)?Mozilla\/[\d.]+\s*\([^)]{0,200}\)(?:\s*[^\s\x00-\x1f]{0,80})?/g;
  const API_RE    = /\b(?:LoadLibrary[AW]?|GetProcAddress|VirtualAlloc(?:Ex)?|VirtualProtect|CreateThread|CreateRemoteThread|WriteProcessMemory|ReadProcessMemory|OpenProcess|WinExec|ShellExecute[AW]?|CreateProcess[AW]?|CreateFile[AW]?|WriteFile|ReadFile|InternetOpen[AW]?|InternetOpenUrl[AW]?|InternetConnect[AW]?|InternetReadFile|HttpOpenRequest[AW]?|HttpSendRequest[AW]?|WSAStartup|WSASocket|connect|send|recv|closesocket|wininet|wsock32|ws2_32|kernel32|ntdll|advapi32|ThLw)\b/g;
  const STRING_RE = /[\x20-\x7e]{5,}/g;

  const uniq = (arr) => Array.from(new Set(arr));
  // Drop private/link-local/reserved IPs — reduce false positives from
  // parsed shellcode noise (0.0.0.0, 127.x, 10.x, 192.168.x, 169.254.x, 224.x+).
  const isRoutableIp = (ip) => {
    const [a, b] = ip.split(".").map(Number);
    if (a === 0 || a === 127 || a >= 224) return false;
    if (a === 10) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    return true;
  };

  const ips = uniq((scan.match(IPV4_RE) || []).filter(isRoutableIp));
  const urls = uniq(scan.match(URL_RE) || []);
  const userAgents = uniq(scan.match(UA_RE) || []).map((s) =>
    s.replace(/^User-Agent:\s*/i, "").trim(),
  );
  const apis = uniq(scan.match(API_RE) || []);
  // Printable strings — drop pure-punct / single-word noise
  const rawStrings = scan.match(STRING_RE) || [];
  const strings = uniq(
    rawStrings.filter((s) => /[A-Za-z0-9]/.test(s) && s.length >= 5),
  );

  const extracted = { ips, urls, userAgents, apis, strings };

  return {
    entropy: entropy,
    printableRatio: printableRatio,
    byteCount: payload.length,
    extracted: extracted,
  };
}


/**
 * formatExtractedIntel — render `detectBinaryPayload().extracted` as a
 * clean, meta-data-free block for the OUTPUT textarea. Pure intel only.
 */
function formatExtractedIntel(bp) {
  if (!bp?.extracted) return "";
  const { ips, urls, userAgents, apis, strings } = bp.extracted;
  const lines = [];
  const pad = (label) => label.padEnd(14);

  if (ips.length) lines.push(`${pad("C2 IPs:")}${ips.join(", ")}`);
  if (urls.length) {
    for (let i = 0; i < urls.length; i++) {
      lines.push(`${pad(i === 0 ? "URLs:" : "")}${urls[i]}`);
    }
  }
  if (userAgents.length) {
    for (let i = 0; i < userAgents.length; i++) {
      lines.push(`${pad(i === 0 ? "User-Agent:" : "")}${userAgents[i]}`);
    }
  }
  if (apis.length) lines.push(`${pad("API imports:")}${apis.join(", ")}`);

  if (strings.length) {
    if (lines.length) lines.push("");
    lines.push("Extracted strings:");
    for (const s of strings) lines.push(`  ${s}`);
  }

  return lines.join("\n");
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
  investigationMode = false,  // IUE v2.0 · true when the pane holds Investigation Results
}) {
  const [view, setView] = useState("text");  // text | hex | base64
  const [showDiff, setShowDiff] = useState(false);
  const [shellcodeBannerDismissed, setShellcodeBannerDismissed] = useState(false);
  // Fix A (Feb-2026) — analyst opt-in to view raw binary bytes as text
  // when the payload is high-entropy garble. Reset per new output.
  const [showRawBinary, setShowRawBinary] = useState(false);

  // 2026-02-15 · Permanent anti-hang guard
  // ────────────────────────────────────────
  // Every ``useMemo`` below scans the FULL output string.  For a
  // real-world 5–20 MB decoded blob, that's tens of milliseconds
  // per render × dozens of renders per second on a hot tab
  // (which Chrome then kills).  Solution: derive a bounded
  // ``renderOutput`` that never exceeds 128 KB for downstream memos
  // and DOM insertion.  The full ``output`` still lives in state for
  // API calls, HEX view (which paginates), and export.
  const DISPLAY_CAP = 128 * 1024;
  const _fullOutputLen = typeof output === "string" ? output.length : 0;
  const _outputTruncated = _fullOutputLen > DISPLAY_CAP;
  const renderOutput = useMemo(() => {
    if (typeof output !== "string") return output;
    if (output.length <= DISPLAY_CAP) return output;
    return output.slice(0, DISPLAY_CAP);
  }, [output]);

  const diff = useMemo(() => computeDiff(input || "", renderOutput || ""), [input, renderOutput]);
  const shellcode = useMemo(() => detectShellcode(renderOutput || ""), [renderOutput]);
  const shellcodeIocs = useMemo(() => shellcode ? extractShellcodeIocs(renderOutput || "") : null, [shellcode, renderOutput]);

  // RC2.4 — Terminal decode state: detect a clean head + binary tail.
  // Only surface this in TEXT view when NO shellcode was detected (shellcode
  // has its own dedicated banner + HEX auto-switch).
  const terminalTail = useMemo(
    () => (shellcode ? null : detectTerminalTail(renderOutput || "")),
    [renderOutput, shellcode],
  );

  // Fix A · Feb-2026 — Whole-payload binary garble detection. Fires when
  // the decoded output is high-entropy / low-printable AND no terminal-tail
  // case has claimed the render. We hide the raw bytes from the TEXT
  // textarea by default (opt-in via `[SHOW RAW BYTES ANYWAY]`) and surface
  // a banner directing the analyst to the HEX view + IOC panels.
  //
  // Feb-2026 SME-directive · v1.5.5 · The TERMINAL ARTIFACT for a
  // shellcode-terminating chain IS the extracted intel (C2 IPs, UA,
  // API imports, strings) — NOT the raw bytes. So we now compute
  // binaryPayload EVEN when a shellcode prologue was detected, so the
  // OUTPUT TEXT view surfaces `formatExtractedIntel(...)` (rather than
  // rendering the raw binary body). Raw bytes remain visible in HEX
  // (auto-selected when shellcode detected) and via [SHOW RAW BYTES].
  const binaryPayload = useMemo(
    () => (terminalTail ? null : detectBinaryPayload(renderOutput || "")),
    [renderOutput, terminalTail],
  );

  // Reset the raw-binary opt-in whenever the underlying output changes.
  useEffect(() => {
    setShowRawBinary(false);
  }, [output]);

  // Auto-switch to HEX view when a decode terminates on known shellcode —
  // rendering raw binary in TEXT view looks like garbage. Runs once per
  // new detection (dismiss + change of output resets).
  useEffect(() => {
    if (shellcode) {
      setView("hex");
      setShowDiff(false);
      setShellcodeBannerDismissed(false);
    }
  // only `shellcode?.family` matters here; a reference change to the outer
  // `shellcode` object without a family flip is intentional no-op.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [shellcode?.family]);
  const renderedBody = useMemo(() => {
    if (view === "hex") return toHexDump(output || "");
    if (view === "base64") return toBase64(output || "");
    // TEXT view — if a terminal-tail is detected, show the clean head only.
    // Raw bytes remain fully available in HEX / B64 views (evidence preserved).
    if (terminalTail) return terminalTail.clean;
    // Fix A · Feb-2026 — When the payload is high-entropy binary garble,
    // surface the EXTRACTED INTEL (C2 IPs, URLs, User-Agent, API imports,
    // ASCII strings) AS the decoded output. Raw bytes are one click away.
    if (binaryPayload && !showRawBinary) {
      return formatExtractedIntel(binaryPayload);
    }
    return output || "";
  }, [output, view, terminalTail, binaryPayload, showRawBinary]);

  return (
    <div className="nvx-card" data-testid="output-card">
      {/* Header — title + preview status + view toggles + actions */}
      <div className="nvx-card-head" style={{ flexWrap: "wrap", gap: 8 }}>
        <div className="nvx-card-title" data-testid="output-card-title">
          <span className="dot" />
          INVESTIGATION RESULTS
        </div>

        {/* IUE v2.0 · Investigation-mode pill — shown when the pane
            is holding deterministic findings.  Absent while a fresh
            decode is streaming, so analysts still see the decode
            pipeline status until the pane has been enriched. */}
        {investigationMode && (
          <span
            data-testid="investigation-mode-pill"
            className="mono"
            style={{
              display: "inline-flex", alignItems: "center", gap: 4,
              fontSize: 10, letterSpacing: "0.14em",
              padding: "2px 8px",
              border: "1px solid var(--accent)",
              color: "var(--accent)",
              background: "var(--accent, #10b981)18",
            }}
            title="This pane presents deterministic investigation findings produced by the Input Understanding Engine — never a duplicate of the input."
          >
            <CheckCircle2 size={10} /> IUE · INVESTIGATION READY
          </span>
        )}

        {/* Preview status pill — hidden in investigation mode */}
        {!investigationMode && livePreview && <LivePreviewPill lp={livePreview} />}

        {/* Size + delta — hidden in investigation mode (comparing input
            bytes to a findings-text pane is meaningless) */}
        {!investigationMode && <SizeDeltaPill diff={diff} />}

        {/* View toggles — unified NavTabs (DetectFlow). DIFF is
            state-driven and only enabled when TEXT view is active. */}
        <div style={{ marginLeft: "auto" }} data-testid="output-view-toggles">
          <NavTabs
            items={[
              { key: "text",   label: "TEXT", icon: Eye,    testId: "output-view-text" },
              { key: "hex",    label: "HEX",  icon: Binary, testId: "output-view-hex" },
              { key: "base64", label: "B64",  icon: Hash,   testId: "output-view-b64" },
              {
                key: "diff", label: "DIFF", icon: GitCompareArrows,
                testId: "output-view-diff",
                disabled: view !== "text",
                title: view === "text"
                  ? "Toggle byte-level diff vs input"
                  : "Diff only available in TEXT view",
              },
            ]}
            activeKey={view === "text" && showDiff ? "diff" : view}
            onSelect={(k) => {
              if (k === "diff") {
                if (view === "text") setShowDiff((s) => !s);
                return;
              }
              setView(k);
              setShowDiff(false);
            }}
            variant="strip"
            size="sm"
            tone="accent"
            testId="output-view-tabs"
            ariaLabel="Output view mode"
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

      {/* Fix A · Feb-2026 — Binary Shellcode Payload strip. When the
          decoded payload is high-entropy binary garble, we replace the
          raw-bytes render with an EXTRACTED INTEL block (C2 IPs, URLs,
          User-Agent, API imports, ASCII strings) so the OUTPUT panel
          shows actionable intelligence instead of noise. This strip is
          a minimal note + toggle — no meta-data decoration. */}
      {binaryPayload && view === "text" && (
        <div
          data-testid="binary-payload-banner"
          style={{
            display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap",
            padding: "8px 14px",
            background: "rgba(126,227,201,0.06)",
            borderTop: "1px solid var(--border)",
            borderBottom: "1px solid rgba(126,227,201,0.25)",
          }}
        >
          <div
            className="mono"
            style={{ fontSize: 10, letterSpacing: "0.18em", color: "var(--text-mute)", flex: 1, minWidth: 240 }}
          >
            {showRawBinary
              ? "▸ RAW BINARY BYTES"
              : `▸ EXTRACTED INTEL FROM ${binaryPayload.byteCount} BYTE SHELLCODE`}
          </div>
          <button
            className="nvx-btn sm ghost"
            onClick={() => setView("hex")}
            data-testid="binary-payload-view-hex"
            title="Switch to HEX view to inspect raw binary bytes"
          >
            <Binary size={11} /> HEX
          </button>
          <button
            className="nvx-btn sm ghost"
            onClick={() => setShowRawBinary((v) => !v)}
            data-testid="binary-payload-show-raw"
            title={showRawBinary ? "Show extracted intel view" : "Reveal raw binary bytes as text (may look garbled)"}
          >
            {showRawBinary ? "SHOW EXTRACTED INTEL" : "SHOW RAW BYTES"}
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
