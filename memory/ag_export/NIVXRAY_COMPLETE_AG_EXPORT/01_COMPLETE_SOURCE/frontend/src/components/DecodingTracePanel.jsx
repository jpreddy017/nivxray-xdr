import React, { useState } from "react";

/**
 * DecodingTracePanel — Shows every recursive step of a deterministic decode:
 *   Base64 → Gzip → Base64 → XOR → Shellcode
 * with the confidence of the overall chain, WHY each op was selected, and
 * expand/collapse per layer with the intermediate output for that layer.
 *
 * Props:
 *   trace       Array<{op, args, reason, output_preview, output_length, error?}>
 *   engine      "smart" | "magic" | "custom_recipe" | undefined
 *   confidence  0-100
 *   reachedShellcode  bool
 *   onJumpToLayer(index)  callback that pushes that layer's output to the Output panel
 */
export default function DecodingTracePanel({ trace, engine, confidence, reachedShellcode, onJumpToLayer, overallSuccess, stopReason }) {
  const [openIdx, setOpenIdx] = useState(0);
  if (!trace || trace.length === 0) return null;

  const OP_ICONS = {
    "extract-payload": "◇",
    "base64-decode": "B64",
    "base64-gzip": "GZ",
    "base64-zlib": "ZL",
    "gzip-decompress": "GZ",
    "zlib-decompress": "ZL",
    "lzma-decompress": "LZ",
    "bzip2-decompress": "BZ",
    "hex-decode": "HEX",
    "url-decode": "URL",
    "html-decode": "HTM",
    "powershell-encoded": "PS",
    "powershell-deobfuscate": "PS*",
    "cmd-deobfuscate": "CMD",
    "refang-iocs": "IOC",
    "js-charcode": "JS",
    "js-unescape": "JS\\",
    "unicode-escape": "\\u",
    "utf16le-decode": "U16",
    "xor": "XOR",
    "env-expand": "$",
    "extract-base64": "◈",
  };

  const engineBadge =
    engine === "magic" ? { label: "MAGIC · deep recursion", cls: "engine-magic" } :
    engine === "smart" ? { label: "SMART · greedy chain", cls: "engine-smart" } :
    engine === "custom_recipe" ? { label: "CUSTOM RECIPE", cls: "engine-custom" } :
    { label: "DETERMINISTIC", cls: "engine-det" };

  // Resolve stopReason from prop or first step metadata
  const effectiveStopReason = stopReason || trace[0]?.stop_reason || "";

  return (
    <div className="dtp" data-testid="decoding-trace-panel">
      <style>{`
        .dtp { border:1px solid var(--br); background:var(--sf); margin-top:12px; }
        .dtp-hdr {
          display:flex; align-items:center; gap:12px;
          padding:8px 12px; border-bottom:1px solid var(--br);
          background:var(--inset); font-family: 'JetBrains Mono', monospace;
          font-size:11px; letter-spacing:0.12em;
        }
        .dtp-title { color:var(--ac); font-weight:700; }
        .dtp-badge { padding:2px 8px; border:1px solid var(--br); font-size:10px; }
        .dtp-badge.engine-magic { color:var(--ac); border-color:var(--ac); background: rgba(74,168,144,0.08); }
        .dtp-badge.engine-smart { color:var(--dim); }
        .dtp-badge.engine-custom { color:var(--warn); border-color:var(--warn); }
        .dtp-badge.shellcode { color:var(--hi); border-color:var(--hi); background: rgba(217,108,108,0.12); }
        .dtp-badge.conf { color:var(--tx); }
        .dtp-count { margin-left:auto; color:var(--dim); }

        .dtp-chain {
          display:flex; align-items:center; gap:4px; padding:10px 12px;
          border-bottom:1px solid var(--br); overflow-x:auto;
          font-family: 'JetBrains Mono', monospace; font-size:10px;
        }
        .dtp-chip {
          padding:4px 10px; border:1px solid var(--br); background:var(--bg);
          color:var(--tx); cursor:pointer; transition: all .12s;
          white-space:nowrap; letter-spacing:0.06em;
        }
        .dtp-chip:hover { border-color: var(--ac); color: var(--ac); }
        .dtp-chip.active { border-color: var(--ac); background: rgba(74,168,144,0.10); color: var(--ac); }
        .dtp-chip.err { border-color: var(--hi); color: var(--hi); }
        .dtp-arrow { color: var(--dim); }
        .dtp-terminal { padding:4px 8px; color:var(--hi); border:1px dashed var(--hi); font-size:9px; }

        .dtp-body { padding:0; }
        .dtp-layer {
          border-bottom:1px solid var(--br);
          padding:0;
        }
        .dtp-layer:last-child { border-bottom:none; }
        .dtp-layer-hdr {
          display:flex; gap:12px; align-items:center; padding:8px 12px;
          cursor:pointer; user-select:none;
        }
        .dtp-layer-hdr:hover { background:rgba(74,168,144,0.04); }
        .dtp-index {
          width:20px; height:20px; display:flex; align-items:center; justify-content:center;
          border:1px solid var(--br); border-radius:999px;
          font-family:'JetBrains Mono',monospace; font-size:10px; color:var(--dim);
          flex-shrink:0;
        }
        .dtp-layer.open .dtp-index { border-color: var(--ac); color: var(--ac); }
        .dtp-op {
          font-family:'JetBrains Mono',monospace; font-size:12px; font-weight:700;
          color: var(--tx);
        }
        .dtp-op-icon {
          padding:2px 6px; border:1px solid var(--br); font-size:9px;
          color:var(--ac); margin-right:8px; letter-spacing:0.04em;
        }
        .dtp-reason { color:var(--dim); font-size:11px; flex:1; }
        .dtp-toggle { color: var(--dim); font-size:12px; margin-left:auto; }
        .dtp-details { padding:0 12px 12px 44px; }
        .dtp-args {
          font-family:'JetBrains Mono',monospace; font-size:10px; color:var(--warn);
          margin-bottom:6px;
        }
        .dtp-preview {
          background: var(--inset); border:1px solid var(--br); padding:8px;
          font-family:'JetBrains Mono',monospace; font-size:10px; color:var(--tx);
          white-space:pre-wrap; word-break:break-all; max-height:200px; overflow:auto;
        }
        .dtp-preview.err { color: var(--hi); border-color: var(--hi); }
        .dtp-length { color:var(--dim); font-size:10px; margin-top:4px; font-family:'JetBrains Mono',monospace; }
        .dtp-jump {
          margin-top:8px; padding:4px 10px; border:1px solid var(--ac);
          background:transparent; color:var(--ac); cursor:pointer;
          font-family:'JetBrains Mono',monospace; font-size:10px; letter-spacing:0.1em;
        }
        .dtp-jump:hover { background: rgba(74,168,144,0.1); }
      `}</style>

      <div className="dtp-hdr">
        <span className="dtp-title">▸ DECODING TRACE</span>
        <span className={`dtp-badge ${engineBadge.cls}`} data-testid="dtp-engine-badge">{engineBadge.label}</span>
        {(() => {
          const hasConf = Number.isFinite(confidence) && confidence > 0;
          const decodedOk = Array.isArray(trace) && trace.length > 0 && trace.some((t) => !t.error);
          if (hasConf) {
            return <span className="dtp-badge conf" data-testid="dtp-confidence">{confidence}% CONFIDENCE</span>;
          }
          if (decodedOk) {
            return <span className="dtp-badge conf" data-testid="dtp-confidence">CONF · N/A · DECODED</span>;
          }
          return null;
        })()}
        {reachedShellcode && (
          <span className="dtp-badge shellcode" data-testid="dtp-shellcode">▲ SHELLCODE TERMINAL</span>
        )}
        <span className="dtp-count">{trace.length} LAYER{trace.length === 1 ? "" : "S"} PEELED</span>
      </div>

      {effectiveStopReason && (
        <div className="dtp-stop-reason" data-testid="dtp-stop-reason" style={{
          padding: "6px 12px",
          background: "rgba(74, 168, 144, 0.08)",
          borderBottom: "1px solid var(--br)",
          fontSize: "11px",
          fontFamily: "'JetBrains Mono', monospace",
          display: "flex",
          alignItems: "center",
          gap: "8px",
        }}>
          <span style={{ color: "var(--ac)", fontWeight: 700, letterSpacing: "0.08em" }}>STOP REASON:</span>
          <span style={{ color: "var(--tx)", wordBreak: "break-all" }}>{effectiveStopReason}</span>
        </div>
      )}

      <div className="dtp-chain" data-testid="dtp-chain-strip">
        {trace.map((t, i) => {
          const opName = t.op || t.decoder || `layer-${i+1}`;
          const reasonText = t.reason || t.why || t.why_selected || opName;
          return (
            <React.Fragment key={i}>
              <button
                className={`dtp-chip ${i === openIdx ? "active" : ""} ${t.error ? "err" : ""}`}
                onClick={() => setOpenIdx(i)}
                data-testid={`dtp-chip-${i}`}
                title={reasonText}
              >
                {OP_ICONS[opName] ? `${OP_ICONS[opName]} ` : ""}{opName}
              </button>
              {i < trace.length - 1 && <span className="dtp-arrow">→</span>}
            </React.Fragment>
          );
        })}
        {reachedShellcode && (
          <>
            <span className="dtp-arrow">→</span>
            <span className="dtp-terminal">SHELLCODE</span>
          </>
        )}
      </div>

      <div className="dtp-body">
        {trace.map((t, i) => {
          const isOpen = i === openIdx;
          const health = _layerHealth(t, i, trace, overallSuccess);
          const opName = t.op || t.decoder || `layer-${i+1}`;
          const reasonText = t.reason || t.why || t.why_selected || "applied";
          const outPreview = t.output_preview || t.preview || t.output_payload || t.output || "";
          const outLen = t.output_length ?? t.out_len ?? (outPreview ? outPreview.length : null);
          const inLen = t.input_length ?? t.in_len;

          return (
            <div key={i} className={`dtp-layer ${isOpen ? "open" : ""}`} data-testid={`dtp-layer-${i}`}>
              <div className="dtp-layer-hdr" onClick={() => setOpenIdx(isOpen ? -1 : i)}>
                <span className="dtp-index">{i + 1}</span>
                {OP_ICONS[opName] && <span className="dtp-op-icon">{OP_ICONS[opName]}</span>}
                <span className="dtp-op" data-testid={`dtp-op-${i}`}>{opName}</span>
                {health.icon && (
                  <span
                    className="mono"
                    data-testid={`dtp-health-${i}`}
                    title={health.reason}
                    style={{
                      fontSize: 10, padding: "1px 6px", marginLeft: 6,
                      background: health.bg, color: health.fg,
                      border: `1px solid ${health.fg}`,
                      letterSpacing: "0.06em",
                    }}
                  >
                    {health.icon} {health.label}
                  </span>
                )}
                <span className="dtp-reason">— {reasonText}</span>
                <span className="dtp-toggle">{isOpen ? "▾" : "▸"}</span>
              </div>
              {isOpen && (
                <div className="dtp-details">
                  {t.why_selected && t.why_selected !== t.reason && (
                    <div style={{ fontSize: 10, color: "var(--ac)", marginBottom: 4, fontFamily: "'JetBrains Mono', monospace" }}>
                      <b>WHY SELECTED:</b> {t.why_selected}
                    </div>
                  )}
                  {t.args && Object.keys(t.args).length > 0 && (() => {
                    const meaningful = Object.entries(t.args).filter(([, v]) => {
                      if (v === false || v === null || v === undefined || v === "" || v === 0) return false;
                      if (Array.isArray(v) && v.length === 0) return false;
                      if (typeof v === "object" && !Array.isArray(v) && Object.keys(v).length === 0) return false;
                      return true;
                    });
                    if (meaningful.length === 0) return null;
                    return (
                      <div className="dtp-args" data-testid={`dtp-args-${i}`}>
                        args: {JSON.stringify(Object.fromEntries(meaningful))}
                      </div>
                    );
                  })()}
                  {health.detail && (
                    <div className="mono" data-testid={`dtp-health-detail-${i}`}
                      style={{
                        fontSize: 10, padding: "6px 8px", marginBottom: 6,
                        background: "rgba(0,0,0,0.2)", color: "var(--dim)",
                        border: "1px solid var(--br)", borderLeft: `3px solid ${health.fg}`,
                      }}>
                      <b style={{color:health.fg}}>X-RAY:</b> {health.detail}
                    </div>
                  )}
                  {t.input_hash && (
                    <div style={{ fontSize: 9, color: "var(--dim)", fontFamily: "'JetBrains Mono', monospace", marginBottom: 4 }}>
                      HASH: in={t.input_hash.slice(0, 12)}… | out={t.output_hash ? t.output_hash.slice(0, 12) + '…' : 'N/A'}
                    </div>
                  )}
                  {t.error ? (
                    <div className="dtp-preview err">ERROR: {t.error}</div>
                  ) : (
                    <>
                      <div className="dtp-preview" data-testid={`dtp-preview-${i}`}>
                        {outPreview || "(empty output)"}
                      </div>
                      {outLen != null && (
                        <div className="dtp-length">
                          {inLen != null ? `${inLen.toLocaleString()}B → ` : ""}{outLen.toLocaleString()} chars
                          {outLen > 400 ? " · showing first 400" : ""}
                        </div>
                      )}
                      {onJumpToLayer && (
                        <button
                          className="dtp-jump"
                          onClick={() => onJumpToLayer(i)}
                          data-testid={`dtp-jump-${i}`}
                        >
                          ▸ JUMP TO THIS LAYER
                        </button>
                      )}
                    </>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── X-RAY Layer Health Analyzer ─────────────────────────────────────────
// Runs cheap structural checks on a layer's output to give the analyst a
// per-node health verdict (✅ VALID / ✓ RECOVERED / 🔴 BROKEN) + the exact
// mathematical reason. Zero network cost — pure regex + length arithmetic.
//
// RC3.0 UX polish (Feb-2026): mid-chain BROKEN/MIXED steps are relabelled
// to ✓ RECOVERED (green) when a downstream layer successfully continued.
// RC3.1 (Feb-2026): terminal-layer BROKEN also downgrades to ✓ RECOVERED
// when the OVERALL investigation produced valid IOC / MITRE / LOLBAS signals
// (analysts previously saw a misleading red badge even when the pipeline
// extracted the payload cleanly). Hard red BROKEN is now reserved for
// pipeline dead-ends where NO intelligence was recovered.
function _layerHealth(step, idx, trace, overallSuccess) {
  const raw = _rawLayerHealth(step);
  const canDowngrade =
    trace &&
    idx != null &&
    (raw.label === "BROKEN" || raw.label === "MIXED") &&
    !step.error;
  if (!canDowngrade) return raw;

  const isTerminal = idx === trace.length - 1;

  // Mid-chain: downgrade when downstream layer recovered clean output
  if (!isTerminal) {
    const next = trace[idx + 1];
    const nextOk = next && !next.error && (next.output_length ?? String(next.output_preview || "").length) > 0;
    if (nextOk) {
      return {
        icon: "✓",
        label: "RECOVERED",
        fg: "#7ee3c9",
        bg: "rgba(126,227,201,0.12)",
        reason: `${raw.reason} — downstream layer recovered ${next.output_length || 0} clean chars`,
        detail: `${raw.detail}\n\n↪ Pipeline recovered cleanly: next op '${next.op}' produced ${next.output_length || 0} chars. Not a real issue — original label ${raw.label} downgraded to RECOVERED.`,
      };
    }
    return raw;
  }

  // Terminal: downgrade when the overall investigation succeeded
  // (IOCs / MITRE / LOLBAS / family / verdict extracted downstream).
  if (isTerminal && overallSuccess) {
    return {
      icon: "✓",
      label: "RECOVERED",
      fg: "#7ee3c9",
      bg: "rgba(126,227,201,0.12)",
      reason: `${raw.reason} — investigation extracted valid intelligence downstream`,
      detail: `${raw.detail}\n\n↪ Terminal layer looked non-textual but the OVERALL investigation surfaced valid IOC/MITRE/LOLBAS/family signals. Original label ${raw.label} downgraded to RECOVERED because the analyst outcome is a full report.`,
    };
  }
  return raw;
}

function _rawLayerHealth(step) {
  const out = String(step.output_preview || "");
  const len = step.output_length != null ? step.output_length : out.length;
  const op = String(step.op || "").toLowerCase();

  // Layer-specific structural checks
  if (op.includes("base64") || op.includes("b64")) {
    const stripped = out.replace(/[\s=]/g, "");
    const mod = stripped.length % 4;
    if (mod === 1) return {
      icon: "🔴", label: "BROKEN", fg: "#ff5c5c", bg: "rgba(255,92,92,0.1)",
      reason: `Base64 length ${stripped.length} ≡ 4k+1 (invalid — cannot pad)`,
      detail: `Length ${stripped.length} chars — base64 lengths must be 4k, 4k+2, or 4k+3. Salvage: drop last char → ${stripped.length - 1}.`,
    };
    if (/[^A-Za-z0-9+/=_\-]/.test(stripped.slice(0, 200))) return {
      icon: "⚠️", label: "MIXED", fg: "#ffb454", bg: "rgba(255,180,84,0.1)",
      reason: "Contains non-base64 chars — may need pre-strip",
      detail: "Non-base64 characters detected. Consider running strip-junk or extract-base64 first.",
    };
    return {
      icon: "✅", label: "VALID", fg: "#7ee3c9", bg: "rgba(126,227,201,0.1)",
      reason: `Base64 length ${stripped.length} (4k+${mod}) — well-formed`,
      detail: `Base64 charset OK · length ${stripped.length} · padding ${mod === 0 ? "not needed" : `${4 - mod} '=' required`}`,
    };
  }
  if (op.includes("hex") && !op.includes("family")) {
    const clean = out.replace(/[\s\\x0]/g, "").toLowerCase();
    if (clean.length % 2 !== 0) return {
      icon: "🔴", label: "BROKEN", fg: "#ff5c5c", bg: "rgba(255,92,92,0.1)",
      reason: `Hex length ${clean.length} is odd — needs pairs`,
      detail: `Hex must be pairs of [0-9a-f]. Salvage: drop last char.`,
    };
    if (/[^0-9a-f]/.test(clean.slice(0, 200))) return {
      icon: "🔴", label: "BROKEN", fg: "#ff5c5c", bg: "rgba(255,92,92,0.1)",
      reason: "Non-hex characters present",
      detail: "Hex accepts only [0-9a-f]. Consider hex-family/xhex-unmap first.",
    };
    return {
      icon: "✅", label: "VALID", fg: "#7ee3c9", bg: "rgba(126,227,201,0.1)",
      reason: `Hex ${clean.length} chars → ${clean.length / 2} bytes`,
      detail: `Even length · all chars [0-9a-f] · decodes to ${clean.length / 2} bytes`,
    };
  }
  if (op.includes("url")) {
    const escapes = out.match(/%(.{0,2})/g) || [];
    const malformed = escapes.filter((e) => !/^%[0-9a-fA-F]{2}$/.test(e));
    if (malformed.length > 0) return {
      icon: "🔴", label: "BROKEN", fg: "#ff5c5c", bg: "rgba(255,92,92,0.1)",
      reason: `${malformed.length} malformed %-escapes`,
      detail: `Invalid: ${malformed.slice(0, 3).join(", ")}`,
    };
    return {
      icon: "✅", label: "VALID", fg: "#7ee3c9", bg: "rgba(126,227,201,0.1)",
      reason: `${escapes.length} valid %-escapes`,
      detail: `All %-escapes conform to %XX pattern`,
    };
  }
  if (op.includes("utf16") || op.includes("utf-16")) {
    const printable = (out.match(/[\x20-\x7e\n\r\t]/g) || []).length / Math.max(out.length, 1);
    if (printable < 0.80) return {
      icon: "⚠️", label: "LOW-PRINT", fg: "#ffb454", bg: "rgba(255,180,84,0.1)",
      reason: `Printable ratio ${(printable * 100).toFixed(0)}% — possibly binary`,
      detail: `Only ${(printable * 100).toFixed(0)}% printable ASCII — output may be binary/shellcode`,
    };
    return {
      icon: "✅", label: "VALID", fg: "#7ee3c9", bg: "rgba(126,227,201,0.1)",
      reason: `UTF-16 decoded · ${(printable * 100).toFixed(0)}% printable`,
      detail: `${(printable * 100).toFixed(0)}% printable — clean text decode`,
    };
  }
  if (step.error) return {
    icon: "🔴", label: "ERROR", fg: "#ff5c5c", bg: "rgba(255,92,92,0.1)",
    reason: step.error, detail: `Layer raised: ${step.error}`,
  };
  // Generic default — printable-ratio check
  const printable = (out.match(/[\x20-\x7e\n\r\t]/g) || []).length / Math.max(out.length, 1);
  if (printable >= 0.85) return {
    icon: "✅", label: "OK", fg: "#7ee3c9", bg: "rgba(126,227,201,0.1)",
    reason: `${(printable * 100).toFixed(0)}% printable`,
    detail: `Output looks clean · ${len.toLocaleString()} chars · ${(printable * 100).toFixed(0)}% printable ASCII`,
  };
  return {
    icon: "⚠️", label: "LOW-PRINT", fg: "#ffb454", bg: "rgba(255,180,84,0.1)",
    reason: `Only ${(printable * 100).toFixed(0)}% printable`,
    detail: `Possibly compressed/encrypted binary — try gzip/zlib/XOR next`,
  };
}
