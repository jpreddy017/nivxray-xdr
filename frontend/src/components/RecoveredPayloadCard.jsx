/* Recovered Payload Card
 * -----------------------
 * Analyst-workspace panel dedicated to the final decoded payload. Split
 * out from the old "Investigation Summary" blob (P0.2, RC2.9) so the
 * analyst sees WHAT was recovered separately from WHY the pipeline
 * thinks it's malicious.
 *
 * Contract
 *   props.output        · string          · final decoded plaintext
 *   props.finalLayer    · string | null   · label of the terminal decoder
 *                                           (e.g. "js-reconstruct")
 *   props.layerCount    · number          · total layers peeled
 *   props.confidence    · number | null   · 0-100
 *   props.testid        · string          · data-testid prefix (optional)
 *   props.collapsible   · boolean         · default true
 */
import { useState } from "react";
import { Copy, ChevronDown, ChevronRight, Check } from "lucide-react";

export default function RecoveredPayloadCard({
  output,
  finalLayer = null,
  layerCount = 0,
  confidence = null,
  testid = "recovered-payload",
  collapsible = true,
}) {
  const [open, setOpen] = useState(true);
  const [copied, setCopied] = useState(false);

  const empty = !output || !String(output).trim();
  const displayed = String(output || "");
  const byteLen = new Blob([displayed]).size;

  const doCopy = async () => {
    try {
      await navigator.clipboard.writeText(displayed);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch (_err) {
      /* clipboard blocked — no-op */
    }
  };

  return (
    <section
      className="brut-border"
      data-testid={testid}
      style={{
        margin: "0 16px 12px",
        background: "var(--surface, #0b0f14)",
        borderColor: "var(--border, #1e293b)",
      }}
    >
      {/* Sticky header */}
      <header
        style={{
          position: "sticky",
          top: 0,
          zIndex: 2,
          background: "var(--surface, #0b0f14)",
          borderBottom: "1px solid var(--border, #1e293b)",
          padding: "10px 14px",
          display: "flex",
          alignItems: "center",
          gap: 10,
          fontFamily: "JetBrains Mono, monospace",
        }}
      >
        {collapsible && (
          <button
            className="nvx-btn sm ghost"
            data-testid={`${testid}-toggle`}
            aria-label={open ? "Collapse Recovered Payload" : "Expand Recovered Payload"}
            aria-expanded={open}
            onClick={() => setOpen((v) => !v)}
            style={{ padding: "2px 4px" }}
          >
            {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
          </button>
        )}
        <span
          style={{
            fontSize: 11,
            letterSpacing: "0.18em",
            color: "var(--accent, #7ee3c9)",
            fontWeight: 700,
          }}
        >
          ▼ RECOVERED PAYLOAD
        </span>
        <span
          data-testid={`${testid}-byte-count`}
          style={{ fontSize: 10, color: "var(--text-mute, #64748b)" }}
        >
          {byteLen.toLocaleString()} B
        </span>
        {finalLayer && (
          <span
            data-testid={`${testid}-final-layer`}
            style={{
              fontSize: 10,
              padding: "2px 8px",
              background: "rgba(126,227,201,0.12)",
              border: "1px solid var(--accent, #7ee3c9)",
              color: "var(--accent, #7ee3c9)",
              letterSpacing: "0.06em",
              borderRadius: 3,
            }}
            title={`Terminal decoder that produced this payload · ${layerCount} layer(s) peeled`}
          >
            FINAL LAYER · {finalLayer.toUpperCase()}
          </span>
        )}
        {layerCount > 0 && (
          <span
            data-testid={`${testid}-layer-count`}
            style={{ fontSize: 10, color: "var(--text-mute, #64748b)" }}
          >
            {layerCount} layer{layerCount === 1 ? "" : "s"} peeled
          </span>
        )}
        {confidence != null && Number(confidence) > 0 && (
          <span
            data-testid={`${testid}-confidence`}
            style={{
              marginLeft: "auto",
              fontSize: 10,
              padding: "2px 8px",
              background: "rgba(56,189,248,0.12)",
              border: "1px solid #38bdf8",
              color: "#38bdf8",
              letterSpacing: "0.06em",
              borderRadius: 3,
            }}
          >
            DECODE CONF · {Math.round(confidence)}%
          </span>
        )}
        <button
          className="nvx-btn sm"
          data-testid={`${testid}-copy`}
          onClick={doCopy}
          disabled={empty}
          style={{ marginLeft: confidence != null ? 8 : "auto" }}
          title="Copy decoded payload to clipboard"
        >
          {copied ? <Check size={11} /> : <Copy size={11} />}
          {copied ? " COPIED" : " COPY"}
        </button>
      </header>

      {/* Body */}
      {open && (
        <div style={{ padding: "12px 14px" }}>
          {empty ? (
            <div
              data-testid={`${testid}-empty`}
              style={{
                fontFamily: "JetBrains Mono, monospace",
                fontSize: 11,
                color: "var(--text-mute, #64748b)",
                padding: "8px 4px",
              }}
            >
              No decoded payload yet — run AUTO INVESTIGATE or paste input.
            </div>
          ) : (
            <pre
              data-testid={`${testid}-body`}
              style={{
                margin: 0,
                fontFamily: "JetBrains Mono, monospace",
                fontSize: 12,
                lineHeight: 1.5,
                color: "var(--text, #e2e8f0)",
                whiteSpace: "pre-wrap",
                wordBreak: "break-all",
                maxHeight: 360,
                overflow: "auto",
                background: "var(--surface-2, #0a0e13)",
                border: "1px solid var(--border, #1e293b)",
                padding: 10,
              }}
            >
              {displayed}
            </pre>
          )}
        </div>
      )}
    </section>
  );
}
