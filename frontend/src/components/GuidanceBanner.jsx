import { useMemo, useEffect, useState, useRef } from "react";
import { classifyInput } from "@/lib/inputClassifier";
import api from "@/lib/api";
import { Sparkles, ArrowRight, Info, Zap, Brain } from "lucide-react";

/**
 * GuidanceBanner
 * --------------
 * Real-time, non-blocking hint bar that appears just above the button
 * toolbar. Reads the current input, classifies it via `classifyInput`,
 * and renders:
 *
 *   ┌─ Cisco-XDR-style "guided response" strip ──────────────────────┐
 *   │  🧠  ENCODED · powershell -enc detected · b64 blob             │
 *   │  →  1. AUTO INVESTIGATE  →  2. SMART DECODE                    │
 *   │      Encoded payload + malicious signals — go with AUTO for   │
 *   │      recursive decode + enrichment.                            │
 *   └─────────────────────────────────────────────────────────────────┘
 *
 * The recommended button ids also glow green on the toolbar itself
 * (via `getButtonHighlight` below).
 */
export default function GuidanceBanner({ input, className = "" }) {
  // Instant deterministic baseline — zero latency, keeps the banner useful
  // while the LLM refinement is in-flight or unavailable.
  const baseline = useMemo(() => classifyInput(input), [input]);
  const [llmView, setLlmView] = useState(null);
  const [llmBusy, setLlmBusy] = useState(false);
  const debounceRef = useRef(null);
  const abortRef = useRef(null);

  // Debounced LLM refinement (~1.2s after typing stops).
  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    if (abortRef.current) { try { abortRef.current.abort(); } catch {} }
    setLlmView(null);
    if (!input || input.trim().length < 8) return;
    debounceRef.current = setTimeout(async () => {
      const controller = new AbortController();
      abortRef.current = controller;
      setLlmBusy(true);
      try {
        const r = await api.post("/decode/guidance", { input },
                                  { signal: controller.signal, timeout: 12000 });
        // Only apply if the LLM actually produced actionable output.
        if (r?.data?.recommended?.length || r?.data?.guidance_steps?.length) {
          setLlmView(r.data);
        }
      } catch (_e) {
        // Silent fallback — the deterministic baseline is already rendered.
      } finally {
        setLlmBusy(false);
      }
    }, 1200);
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
      if (abortRef.current) { try { abortRef.current.abort(); } catch {} }
    };
  }, [input]);

  // Merge — LLM view wins when available, deterministic baseline is the
  // safety net.
  const c = llmView && llmView.kind !== "empty" ? llmView : baseline;
  const source = llmView && llmView.kind !== "empty"
    ? (llmView.engine === "llm" ? "llm" : "fallback")
    : "deterministic";

  if (c.kind === "empty") return null;

  const KIND_COLOUR = {
    encoded:             "#38bdf8",   // sky
    plaintext_malicious: "#ef4444",   // red
    multi_line_chain:    "#f59e0b",   // amber
    unclear_cipher:      "#a855f7",   // violet
    clean_text:          "#22c55e",   // green
  };
  const KIND_LABEL = {
    encoded:             "ENCODED",
    plaintext_malicious: "PLAINTEXT · MALICIOUS",
    multi_line_chain:    "MULTI-STAGE CHAIN",
    unclear_cipher:      "OBFUSCATED / CIPHER",
    clean_text:          "CLEAN TEXT",
  };
  const colour = KIND_COLOUR[c.kind] || "#94a3b8";

  return (
    <div
      className={className}
      data-testid="input-guidance-banner"
      style={{
        border: `1px solid ${colour}`,
        borderLeft: `4px solid ${colour}`,
        background: `${colour}15`,
        padding: "10px 12px",
        borderRadius: 4,
        fontSize: 11,
        fontFamily: "JetBrains Mono, monospace",
        color: "var(--text)",
        lineHeight: 1.55,
      }}
    >
      {/* Top row — kind + signals */}
      <div style={{ display: "flex", alignItems: "center", gap: 8,
                    flexWrap: "wrap", marginBottom: 8 }}>
        <Sparkles size={13} style={{ color: colour }} />
        <span style={{ color: colour, fontWeight: 700, letterSpacing: "0.18em" }}>
          {KIND_LABEL[c.kind]}
        </span>
        {/* Engine badge — instant vs LLM-refined */}
        <span
          data-testid="guidance-engine-badge"
          title={source === "llm"
            ? "Refined by NivX Cognis (Claude Sonnet 4.5) — reads the actual bytes."
            : source === "fallback"
              ? "LLM unavailable — using instant deterministic classifier."
              : llmBusy
                ? "Instant deterministic view — LLM refinement is running…"
                : "Instant deterministic view."
          }
          style={{
            display: "inline-flex", alignItems: "center", gap: 3,
            fontSize: 9, letterSpacing: "0.14em",
            padding: "2px 6px", borderRadius: 3,
            color: source === "llm" ? "#7ee3c9" : "#94a3b8",
            border: `1px solid ${source === "llm" ? "#0d9488" : "#334155"}`,
            background: source === "llm" ? "rgba(126,227,201,0.08)" : "transparent",
          }}
        >
          {source === "llm"
            ? <><Brain size={9} /> LLM · CLAUDE</>
            : llmBusy
              ? <><Zap size={9} /> INSTANT · LLM REFINING…</>
              : <><Zap size={9} /> INSTANT</>}
        </span>
        {c.signals.length > 0 && (
          <span style={{ color: "var(--text-mute)", letterSpacing: "0.06em" }}>
            · {c.signals.join(" · ")}
          </span>
        )}
      </div>

      {/* Step chain — 1 → 2 → 3 */}
      {c.guidance_steps.length > 0 && (
        <div style={{ display: "flex", alignItems: "center", flexWrap: "wrap",
                      gap: 6, marginBottom: 6 }}>
          {c.guidance_steps.map((step, i) => (
            <span key={i} style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
              <span
                data-testid={`guidance-step-${i}`}
                style={{
                  display: "inline-block",
                  padding: "3px 9px",
                  background: colour,
                  color: "#0b1220",
                  fontWeight: 700,
                  letterSpacing: "0.12em",
                  borderRadius: 3,
                }}
              >
                {i + 1}. {step.label}
              </span>
              {i < c.guidance_steps.length - 1 && (
                <ArrowRight size={12} style={{ color: colour, opacity: 0.7 }} />
              )}
            </span>
          ))}
        </div>
      )}

      {/* "Why" line for the primary (step 1) recommendation */}
      {c.guidance_steps[0]?.why && (
        <div style={{ display: "flex", alignItems: "flex-start", gap: 6,
                      color: "var(--text-mute)", fontSize: 10.5 }}>
          <Info size={11} style={{ marginTop: 2, flexShrink: 0 }} />
          <span>{c.guidance_steps[0].why}</span>
        </div>
      )}
    </div>
  );
}

/**
 * Compute inline style overrides for a button given the current input.
 * Returns `{ glow: bool, styleOverride: {...} }`.
 *
 * Usage:
 *   const { glow, styleOverride } = useButtonGuidance(input, "btn-auto-investigate");
 *   <button style={{ ...base, ...styleOverride }}>...</button>
 */
export function getRecommendedButtons(input) {
  return classifyInput(input).recommended || [];
}

export function isRecommended(input, buttonId) {
  const rec = getRecommendedButtons(input);
  return rec.includes(buttonId);
}

export function getGuidanceGlowStyle(input, buttonId) {
  const rec = getRecommendedButtons(input);
  const idx = rec.indexOf(buttonId);
  if (idx < 0) return null;
  // Primary recommendation gets a stronger glow.
  const strong = idx === 0;
  return {
    boxShadow: strong
      ? "0 0 0 2px #22c55e, 0 0 14px rgba(34,197,94,0.55)"
      : "0 0 0 1px #22c55e, 0 0 8px rgba(34,197,94,0.35)",
    borderColor: "#22c55e",
    animation: strong ? "nvx-recommend-pulse 1.6s ease-in-out infinite" : undefined,
  };
}
