/**
 * EscalationLadder  (v1.5.1 · Zero-Miss Architecture)
 * ─────────────────────────────────────────────────────
 * Renders the L1 → L2 → L3 escalation trace so the analyst can see
 * EXACTLY which layer decoded the payload, which layers gave up, and
 * with what confidence.
 *
 * Props:
 *   trace       — array of { layer, engine, chain_len, score, verdict }
 *   winner      — string engine name (e.g. "smart", "magic", "llm-l3")
 *   confidence  — 0-1 float
 */
export default function EscalationLadder({ trace, winner, confidence }) {
  if (!Array.isArray(trace) || trace.length === 0) return null;

  const engineToLayer = { smart: "L1", magic: "L2", "llm-l3": "L3" };
  // Archetype fast-path returns `engine: "archetype:<name>"` — collapse
  // any such value to the L0 card.
  let winnerLayer = engineToLayer[winner];
  if (!winnerLayer && typeof winner === "string" && winner.startsWith("archetype")) {
    winnerLayer = "L0";
  }
  winnerLayer = winnerLayer || winner;

  return (
    <div
      className="nvx-card"
      data-testid="escalation-ladder"
      style={{ marginTop: 10, marginBottom: 10 }}
    >
      <div className="nvx-card-head">
        <div className="nvx-card-title">
          <span className="dot" style={{ background: "#f59e0b" }} />
          ZERO-MISS ESCALATION TRACE
          <span className="count">
            winner: <b style={{ color: "#22c55e" }}>{winnerLayer}</b>
            {confidence != null && (
              <span style={{ marginLeft: 8, color: "#94a3b8" }}>
                · confidence <b style={{ color: "#22c55e" }}>{Math.round((confidence || 0) * 100)}%</b>
              </span>
            )}
          </span>
        </div>
      </div>
      <div className="nvx-card-body" style={{ display: "flex", gap: 12, alignItems: "stretch", flexWrap: "wrap" }}>
        {trace.map((step, i) => {
          const isWinner = step.layer === winnerLayer;
          const verdict = step.verdict || "unknown";
          const color =
            verdict === "reached-shellcode" ? "#22c55e"
            : verdict === "matched" ? "#22c55e"
            : verdict === "decoded" ? "#22c55e"
            : verdict === "zero-chain" ? "#94a3b8"
            : verdict === "skipped" ? "#475569"
            : verdict === "gave-up" ? "#ef4444" : "#94a3b8";
          const bg = isWinner ? "#052e16" : "#0f172a";
          const border = isWinner ? "#166534" : "#334155";
          return (
            <div
              key={i}
              data-testid={`escalation-step-${step.layer}`}
              style={{
                background: bg, border: `1px solid ${border}`,
                padding: "10px 14px", borderRadius: 8, minWidth: 140, flex: "1 1 140px",
                position: "relative",
              }}
            >
              <div style={{ fontSize: 10, letterSpacing: 2, color: "#94a3b8", marginBottom: 4 }}>
                {step.layer} · {step.engine.toUpperCase()}
              </div>
              <div style={{ fontSize: 13, fontWeight: 600, color, marginBottom: 3 }}>
                {verdict === "reached-shellcode" ? "SHELLCODE" :
                 verdict === "matched" ? "MATCHED" :
                 verdict === "decoded" ? "DECODED" :
                 verdict === "zero-chain" ? "ZERO-CHAIN" :
                 verdict === "skipped" ? "SKIPPED" :
                 verdict === "gave-up" ? "GAVE UP" : verdict.toUpperCase()}
              </div>
              <div style={{ fontSize: 10, color: "#64748b" }}>
                {step.chain_len || 0} ops · score {typeof step.score === "number" ? step.score.toFixed(2) : "—"}
              </div>
              {isWinner && (
                <div
                  style={{
                    position: "absolute", top: 6, right: 8,
                    background: "#166534", color: "#dcfce7",
                    padding: "1px 6px", borderRadius: 3,
                    fontSize: 9, letterSpacing: 1, fontWeight: 700,
                  }}
                >
                  WINNER
                </div>
              )}
            </div>
          );
        })}
      </div>
      <div style={{ padding: "0 16px 12px", fontSize: 10, color: "#64748b" }}>
        L1 heuristic → L2 magic branch-search → L3 Claude LLM fallback →
        L4 sandbox detonation (roadmap) → L5 behavior verdict (roadmap).
        Every payload MUST land on a verdict from at least one layer.
      </div>
    </div>
  );
}
