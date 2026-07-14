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
export default function DecodingTracePanel({ trace, engine, confidence, reachedShellcode, onJumpToLayer }) {
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
        {typeof confidence === "number" && (
          <span className="dtp-badge conf" data-testid="dtp-confidence">{confidence}% CONFIDENCE</span>
        )}
        {reachedShellcode && (
          <span className="dtp-badge shellcode" data-testid="dtp-shellcode">▲ SHELLCODE TERMINAL</span>
        )}
        <span className="dtp-count">{trace.length} LAYER{trace.length === 1 ? "" : "S"} PEELED</span>
      </div>

      <div className="dtp-chain" data-testid="dtp-chain-strip">
        {trace.map((t, i) => (
          <React.Fragment key={i}>
            <button
              className={`dtp-chip ${i === openIdx ? "active" : ""} ${t.error ? "err" : ""}`}
              onClick={() => setOpenIdx(i)}
              data-testid={`dtp-chip-${i}`}
              title={t.reason || t.op}
            >
              {OP_ICONS[t.op] ? `${OP_ICONS[t.op]} ` : ""}{t.op}
            </button>
            {i < trace.length - 1 && <span className="dtp-arrow">→</span>}
          </React.Fragment>
        ))}
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
          return (
            <div key={i} className={`dtp-layer ${isOpen ? "open" : ""}`} data-testid={`dtp-layer-${i}`}>
              <div className="dtp-layer-hdr" onClick={() => setOpenIdx(isOpen ? -1 : i)}>
                <span className="dtp-index">{i + 1}</span>
                {OP_ICONS[t.op] && <span className="dtp-op-icon">{OP_ICONS[t.op]}</span>}
                <span className="dtp-op">{t.op}</span>
                <span className="dtp-reason">— {t.reason || "applied"}</span>
                <span className="dtp-toggle">{isOpen ? "▾" : "▸"}</span>
              </div>
              {isOpen && (
                <div className="dtp-details">
                  {t.args && Object.keys(t.args).length > 0 && (
                    <div className="dtp-args" data-testid={`dtp-args-${i}`}>
                      args: {JSON.stringify(t.args)}
                    </div>
                  )}
                  {t.error ? (
                    <div className="dtp-preview err">ERROR: {t.error}</div>
                  ) : (
                    <>
                      <div className="dtp-preview" data-testid={`dtp-preview-${i}`}>
                        {t.output_preview || "(empty output)"}
                      </div>
                      {t.output_length != null && (
                        <div className="dtp-length">
                          {t.output_length.toLocaleString()} chars
                          {t.output_length > 400 ? " · showing first 400" : ""}
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
