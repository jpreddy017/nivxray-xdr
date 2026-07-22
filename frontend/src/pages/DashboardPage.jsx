/**
 * DashboardPage — NivXRay Detection Pipeline (SOC Prime · DetectFlow-inspired).
 *
 * Layout: source topics → hex counters → glowing pipeline & MITRE
 * rings → destination topics, with a #RULES → STAGING → RULES DEPLOYED
 * lower lane. Beneath: a summary strip with corpus health, decode
 * latency, shadow run, and Evidence Graph observability.
 *
 * Data hooks: `/rc5/golden/summary`, `/rc5/shadow/status`,
 * `/rc5/shadow/gate`, `/rc5/evidence-graph/metrics`. If any endpoint
 * is unavailable the corresponding counter renders "—".
 *
 * Behavioural neutrality: zero verdict / scoring / analyst-visible
 * data changes. Pure visual layer.
 */
import React, { useEffect, useState, useCallback, useMemo } from "react";
import Header from "@/components/Header";
import PageHeader from "@/components/PageHeader";
import api from "@/lib/api";

// ═══════════════════════════════════════════════════════════════════
// Primitives
// ═══════════════════════════════════════════════════════════════════

// Hexagonal counter tile — sits at each end of the flow pipes.
const Hex = ({ label, value, sub, tone = "green", testId, size = 96 }) => {
  const tones = {
    green:  { fg: "#86efac", ring: "#22c55e", glow: "rgba(34,197,94,0.28)"  },
    violet: { fg: "#c4b5fd", ring: "#8b5cf6", glow: "rgba(139,92,246,0.28)" },
    cyan:   { fg: "#67e8f9", ring: "#06b6d4", glow: "rgba(6,182,212,0.28)"  },
    amber:  { fg: "#fcd34d", ring: "#f59e0b", glow: "rgba(245,158,11,0.28)" },
  };
  const t = tones[tone] || tones.green;
  const w = size, h = size * 1.15;
  return (
    <div data-testid={testId} style={{
      position: "relative", width: w, height: h,
      display: "flex", flexDirection: "column",
      alignItems: "center", justifyContent: "center",
      textAlign: "center",
    }}>
      <svg width={w} height={h} viewBox="0 0 100 115"
           style={{ position: "absolute", inset: 0, filter: `drop-shadow(0 0 12px ${t.glow})` }}>
        <polygon points="50,4 96,28 96,86 50,110 4,86 4,28"
                 fill="rgba(2,6,23,0.85)" stroke={t.ring} strokeWidth="1.5" />
        <polygon points="50,10 90,32 90,82 50,104 10,82 10,32"
                 fill="none" stroke={t.ring} strokeWidth="0.6" strokeOpacity="0.35" />
      </svg>
      <div style={{ position: "relative", zIndex: 2 }}>
        <div style={{
          fontFamily: "JetBrains Mono, ui-monospace, monospace",
          fontSize: 9, color: "rgba(148,163,184,0.75)",
          letterSpacing: "0.14em", textTransform: "uppercase",
        }}>{label}</div>
        <div style={{
          fontSize: 22, fontWeight: 700, color: t.fg,
          fontFamily: "JetBrains Mono, ui-monospace, monospace",
          lineHeight: 1.05, marginTop: 2,
        }}>{value ?? "—"}</div>
        {sub != null && sub !== "" && (
          <div style={{
            fontSize: 8, color: "rgba(148,163,184,0.55)",
            fontFamily: "JetBrains Mono, ui-monospace, monospace",
            letterSpacing: "0.06em", marginTop: 2,
          }}>{sub}</div>
        )}
      </div>
    </div>
  );
};

// Glowing circular ring — the two "pipeline" and "MITRE tie" central nodes.
const Ring = ({ label, value, sub, tone = "green", testId, size = 128 }) => {
  const tones = {
    green:  { fg: "#86efac", ring: "#22c55e" },
    violet: { fg: "#c4b5fd", ring: "#8b5cf6" },
    cyan:   { fg: "#67e8f9", ring: "#06b6d4" },
    amber:  { fg: "#fcd34d", ring: "#f59e0b" },
  };
  const t = tones[tone] || tones.green;
  return (
    <div data-testid={testId} style={{
      position: "relative", width: size, height: size,
      display: "flex", flexDirection: "column",
      alignItems: "center", justifyContent: "center",
    }}>
      <svg width={size} height={size} viewBox="0 0 100 100"
           style={{ position: "absolute", inset: 0,
                    filter: `drop-shadow(0 0 14px ${t.ring}55)` }}>
        <circle cx="50" cy="50" r="46" fill="rgba(2,6,23,0.75)"
                stroke={t.ring} strokeWidth="1.4" strokeOpacity="0.9" />
        <circle cx="50" cy="50" r="41" fill="none"
                stroke={t.ring} strokeWidth="0.6" strokeOpacity="0.4"
                strokeDasharray="1.5 3.5" />
      </svg>
      <div style={{ position: "relative", zIndex: 2, textAlign: "center" }}>
        <div style={{
          fontSize: 26, fontWeight: 700, color: t.fg,
          fontFamily: "JetBrains Mono, ui-monospace, monospace",
          lineHeight: 1,
        }}>{value ?? "—"}</div>
        <div style={{
          fontFamily: "JetBrains Mono, ui-monospace, monospace",
          fontSize: 9, color: "rgba(148,163,184,0.85)",
          letterSpacing: "0.14em", textTransform: "uppercase",
          marginTop: 6, maxWidth: size * 0.7,
        }}>{label}</div>
        {sub && (
          <div style={{
            fontSize: 8, color: "rgba(148,163,184,0.55)",
            fontFamily: "JetBrains Mono, ui-monospace, monospace",
            marginTop: 3,
          }}>{sub}</div>
        )}
      </div>
    </div>
  );
};

// Topic-list column.
const TopicList = ({ title, items, tone = "cyan", side = "left", testId }) => {
  const dot = { cyan: "#67e8f9", green: "#86efac", violet: "#c4b5fd", amber: "#fcd34d" }[tone] || "#67e8f9";
  return (
    <div data-testid={testId} style={{
      display: "flex", flexDirection: "column",
      alignItems: side === "left" ? "flex-start" : "flex-end",
      gap: 6,
    }}>
      <div style={{
        fontFamily: "JetBrains Mono, ui-monospace, monospace",
        fontSize: 9, color: dot,
        letterSpacing: "0.18em", textTransform: "uppercase",
        marginBottom: 4, opacity: 0.9,
      }}>{title}</div>
      {items.map((it, i) => (
        <div key={i} data-testid={`${testId}-item-${i}`} style={{
          display: "flex", alignItems: "center",
          flexDirection: side === "left" ? "row" : "row-reverse",
          gap: 8,
          fontFamily: "JetBrains Mono, ui-monospace, monospace",
          fontSize: 11, color: "rgba(203,213,225,0.85)",
          padding: "3px 10px", borderRadius: 3,
          background: "rgba(15,23,42,0.55)",
          border: "1px solid rgba(148,163,184,0.10)",
          minWidth: 150, justifyContent: "space-between",
        }}>
          <span style={{
            width: 5, height: 5, borderRadius: "50%",
            background: dot, flexShrink: 0,
            boxShadow: `0 0 8px ${dot}`,
          }} />
          <span style={{ whiteSpace: "nowrap", textAlign: side === "left" ? "left" : "right" }}>
            {it.label}{it.count != null ? ` · ${it.count}` : ""}
          </span>
        </div>
      ))}
    </div>
  );
};

// Animated bezier flow line with glowing dots travelling along it.
const FlowLine = ({ d, color = "#22c55e", speed = 2.4, dotCount = 3 }) => {
  const dots = Array.from({ length: dotCount });
  return (
    <>
      <path d={d} fill="none" stroke={color} strokeOpacity="0.35" strokeWidth="1.2" />
      {dots.map((_, i) => (
        <circle key={i} r="2.4" fill={color}
                style={{ filter: `drop-shadow(0 0 4px ${color})` }}>
          <animateMotion
            dur={`${speed}s`}
            repeatCount="indefinite"
            begin={`${(i * speed) / (dotCount || 1)}s`}
            path={d}
          />
        </circle>
      ))}
    </>
  );
};

// Summary KPI cell for the row beneath the pipeline.
const KpiCell = ({ label, value, sub, tone = "green", testId }) => {
  const tones = { green: "#86efac", violet: "#c4b5fd", cyan: "#67e8f9", amber: "#fcd34d", red: "#fca5a5" };
  return (
    <div data-testid={testId} style={{
      background: "linear-gradient(160deg, rgba(15,23,42,0.75), rgba(2,6,23,0.9))",
      border: "1px solid rgba(148,163,184,0.14)",
      borderRadius: 10, padding: "12px 16px",
      backdropFilter: "blur(12px)",
      minWidth: 180, flex: 1,
    }}>
      <div style={{
        fontFamily: "JetBrains Mono, ui-monospace, monospace",
        fontSize: 9, color: "rgba(148,163,184,0.65)",
        letterSpacing: "0.16em", textTransform: "uppercase",
      }}>{label}</div>
      <div style={{
        fontSize: 22, fontWeight: 700, color: tones[tone] || tones.green,
        fontFamily: "JetBrains Mono, ui-monospace, monospace",
        marginTop: 4, lineHeight: 1.05,
      }}>{value ?? "—"}</div>
      {sub && (
        <div style={{
          fontSize: 10, color: "rgba(148,163,184,0.55)",
          fontFamily: "JetBrains Mono, ui-monospace, monospace",
          marginTop: 3,
        }}>{sub}</div>
      )}
    </div>
  );
};

// ═══════════════════════════════════════════════════════════════════
// LatencyTrendChart — DetectFlow-style stacked-area trend chart.
//
// Renders REAL data returned by /api/rc5/golden/history:
//   • Stacked area 1 (accent green) — p50 latency (ms)
//   • Stacked area 2 (violet)       — p95 latency headroom (p95 - p50)
//   • Overlay line (cyan)           — MITRE technique count on 2nd axis
// Hover tooltip pins a vertical guide + reveals per-run metrics.
//
// All rendering is pure SVG (no chart library) to match the deterministic-
// first / bundle-size posture and the existing DetectFlow glass aesthetic.
// ═══════════════════════════════════════════════════════════════════
const LatencyTrendChart = ({ history, testId = "latency-trend-chart" }) => {
  const [hoverIdx, setHoverIdx] = useState(null);
  const svgRef = React.useRef(null);

  const pts = useMemo(
    () => (Array.isArray(history) ? history : []),
    [history],
  );
  const n = pts.length;

  // Chart geometry
  const W = 800;
  const H = 220;
  const PAD_L = 44;
  const PAD_R = 40;
  const PAD_T = 18;
  const PAD_B = 30;
  const innerW = W - PAD_L - PAD_R;
  const innerH = H - PAD_T - PAD_B;

  const { p95Max, mitreMax, path50, path95, mitrePath, xs, y50s, y95s, mitreYs } = useMemo(() => {
    if (n === 0) {
      return { p95Max: 1, mitreMax: 1, path50: "", path95: "",
               mitrePath: "", xs: [], y50s: [], y95s: [], mitreYs: [] };
    }
    // Latency axis — pad max to give the top some breathing room.
    const p95Values = pts.map(p => p.p95_ms || 0);
    let p95Peak = Math.max(...p95Values, 0.001);
    // Nudge the axis up 20 % so the top curve does not touch the ceiling.
    p95Peak = p95Peak * 1.2;

    const mitreValues = pts.map(p => p.mitre_technique_count || 0);
    let mitrePeak = Math.max(...mitreValues, 1);
    mitrePeak = Math.max(mitrePeak * 1.15, 1);

    const xs_ = pts.map((_, i) =>
      n === 1 ? PAD_L + innerW / 2 : PAD_L + (i * innerW) / (n - 1),
    );
    const y50s_ = pts.map(p => PAD_T + innerH - ((p.p50_ms || 0) / p95Peak) * innerH);
    const y95s_ = pts.map(p => PAD_T + innerH - ((p.p95_ms || 0) / p95Peak) * innerH);
    const mitreYs_ = pts.map(p =>
      PAD_T + innerH - ((p.mitre_technique_count || 0) / mitrePeak) * innerH,
    );

    // Build area paths. p50 area: baseline (bottom) → curve → back down.
    const linePath = (ys) =>
      ys.map((y, i) => `${i === 0 ? "M" : "L"}${xs_[i].toFixed(2)},${y.toFixed(2)}`).join(" ");

    const areaPath = (ys, baselineY) => {
      if (!ys.length) return "";
      const top = linePath(ys);
      const bl = `L${xs_[xs_.length - 1].toFixed(2)},${baselineY} L${xs_[0].toFixed(2)},${baselineY} Z`;
      return `${top} ${bl}`;
    };

    // The p50 area sits on the bottom axis; the p95 "headroom" area sits
    // between the p50 curve and the p95 curve (rendered second so it's
    // painted on top for a stacked look).
    const baseline = PAD_T + innerH;
    const p50Area = areaPath(y50s_, baseline);
    // p95 headroom: top curve = y95, bottom curve = y50
    const p95Top = linePath(y95s_);
    const p95Bot = y50s_.slice().reverse().map((y, i) => {
      const revIdx = y50s_.length - 1 - i;
      return `L${xs_[revIdx].toFixed(2)},${y.toFixed(2)}`;
    }).join(" ");
    const p95Area = `${p95Top} ${p95Bot} Z`;

    return {
      p95Max: p95Peak,
      mitreMax: mitrePeak,
      path50: p50Area,
      path95: p95Area,
      mitrePath: linePath(mitreYs_),
      xs: xs_,
      y50s: y50s_,
      y95s: y95s_,
      mitreYs: mitreYs_,
    };
  }, [pts, n, innerH, innerW]);

  const onMove = (e) => {
    if (!svgRef.current || n === 0) return;
    const rect = svgRef.current.getBoundingClientRect();
    const px = ((e.clientX - rect.left) / rect.width) * W;
    let bestIdx = 0;
    let bestDist = Infinity;
    for (let i = 0; i < xs.length; i++) {
      const d = Math.abs(xs[i] - px);
      if (d < bestDist) { bestDist = d; bestIdx = i; }
    }
    setHoverIdx(bestIdx);
  };
  const onLeave = () => setHoverIdx(null);

  const active = hoverIdx != null ? pts[hoverIdx] : null;
  const activeTs = active?.ts ? active.ts.slice(0, 19).replace("T", " ") : null;

  // Y-axis ticks (5 divisions)
  const yTicks = useMemo(() => {
    const div = 4;
    return Array.from({ length: div + 1 }, (_, i) => {
      const frac = i / div;
      const y = PAD_T + innerH - frac * innerH;
      const value = frac * p95Max;
      return { y, value };
    });
  }, [p95Max, innerH]);

  return (
    <div data-testid={testId} style={{
      marginTop: 22,
      background: "linear-gradient(160deg, rgba(15,23,42,0.72), rgba(2,6,23,0.88))",
      backdropFilter: "blur(18px) saturate(160%)",
      border: "1px solid rgba(148,163,184,0.14)",
      borderRadius: 12,
      padding: "16px 20px",
      position: "relative",
      overflow: "hidden",
      boxShadow: "0 6px 24px rgba(34,197,94,0.08), inset 0 1px 0 rgba(255,255,255,0.04)",
    }}>
      {/* Subtle grid backdrop — matches the DetectFlow panel style. */}
      <div style={{
        position: "absolute", inset: 0, pointerEvents: "none",
        backgroundImage: "linear-gradient(rgba(148,163,184,0.04) 1px, transparent 1px), "
                       + "linear-gradient(90deg, rgba(148,163,184,0.04) 1px, transparent 1px)",
        backgroundSize: "40px 40px",
        maskImage: "radial-gradient(circle at center, black 60%, transparent 95%)",
        WebkitMaskImage: "radial-gradient(circle at center, black 60%, transparent 95%)",
      }} />

      {/* Header row */}
      <div style={{
        display: "flex", alignItems: "center", justifyContent: "space-between",
        marginBottom: 8, position: "relative", zIndex: 2,
      }}>
        <div style={{
          fontFamily: "JetBrains Mono, ui-monospace, monospace",
          fontSize: 10, color: "rgba(148,163,184,0.75)",
          letterSpacing: "0.18em", textTransform: "uppercase",
        }}>
          Latency &amp; MITRE Trend · Golden Corpus
        </div>
        <div style={{
          display: "flex", gap: 14,
          fontFamily: "JetBrains Mono, ui-monospace, monospace",
          fontSize: 9, color: "rgba(148,163,184,0.7)",
          letterSpacing: "0.12em", textTransform: "uppercase",
        }}>
          <LegendDot color="#22c55e" label="p50 ms" />
          <LegendDot color="#8b5cf6" label="p95 headroom" />
          <LegendDot color="#67e8f9" label="MITRE tech" dashed />
          <span style={{ color: "rgba(148,163,184,0.5)" }}>
            {n} run{n === 1 ? "" : "s"}
          </span>
        </div>
      </div>

      {n === 0 ? (
        <div data-testid="latency-trend-empty" style={{
          padding: "38px 12px",
          textAlign: "center",
          fontFamily: "JetBrains Mono, ui-monospace, monospace",
          fontSize: 11, color: "rgba(148,163,184,0.55)",
          fontStyle: "italic",
        }}>
          No historical runs yet · execute the Golden Corpus benchmark to populate
        </div>
      ) : (
        <div style={{ position: "relative", zIndex: 2 }}>
          <svg
            ref={svgRef}
            viewBox={`0 0 ${W} ${H}`}
            preserveAspectRatio="none"
            width="100%" height={H}
            data-testid="latency-trend-svg"
            onMouseMove={onMove}
            onMouseLeave={onLeave}
            style={{ display: "block", cursor: n > 1 ? "crosshair" : "default" }}
          >
            <defs>
              <linearGradient id="grad-p50" x1="0" x2="0" y1="0" y2="1">
                <stop offset="0%"  stopColor="#22c55e" stopOpacity="0.55" />
                <stop offset="100%" stopColor="#22c55e" stopOpacity="0.02" />
              </linearGradient>
              <linearGradient id="grad-p95" x1="0" x2="0" y1="0" y2="1">
                <stop offset="0%"  stopColor="#8b5cf6" stopOpacity="0.42" />
                <stop offset="100%" stopColor="#8b5cf6" stopOpacity="0.03" />
              </linearGradient>
            </defs>

            {/* Y-grid + tick labels */}
            {yTicks.map((t, i) => (
              <g key={i}>
                <line x1={PAD_L} x2={W - PAD_R} y1={t.y} y2={t.y}
                      stroke="rgba(148,163,184,0.08)" strokeDasharray="2 4" />
                <text x={PAD_L - 6} y={t.y + 3} textAnchor="end"
                      style={{
                        fontFamily: "JetBrains Mono, ui-monospace, monospace",
                        fontSize: 9, fill: "rgba(148,163,184,0.5)",
                      }}>
                  {t.value < 1
                    ? t.value.toFixed(2)
                    : t.value < 10
                    ? t.value.toFixed(1)
                    : Math.round(t.value)}
                </text>
              </g>
            ))}
            {/* Axis label (left, ms) */}
            <text x={PAD_L - 32} y={PAD_T + innerH / 2}
                  transform={`rotate(-90 ${PAD_L - 32} ${PAD_T + innerH / 2})`}
                  textAnchor="middle"
                  style={{
                    fontFamily: "JetBrains Mono, ui-monospace, monospace",
                    fontSize: 9, fill: "rgba(148,163,184,0.6)",
                    letterSpacing: "0.14em", textTransform: "uppercase",
                  }}>
              latency ms
            </text>
            {/* Axis label (right, MITRE) */}
            <text x={W - PAD_R + 30} y={PAD_T + innerH / 2}
                  transform={`rotate(90 ${W - PAD_R + 30} ${PAD_T + innerH / 2})`}
                  textAnchor="middle"
                  style={{
                    fontFamily: "JetBrains Mono, ui-monospace, monospace",
                    fontSize: 9, fill: "rgba(103,232,249,0.7)",
                    letterSpacing: "0.14em", textTransform: "uppercase",
                  }}>
              mitre count · max {Math.round(mitreMax)}
            </text>

            {/* Areas — p95 headroom drawn first (violet, wider), then
                p50 area over the top (green fill). */}
            <path d={path95} fill="url(#grad-p95)" stroke="#8b5cf6"
                  strokeOpacity="0.55" strokeWidth="1.1" />
            <path d={path50} fill="url(#grad-p50)" stroke="#22c55e"
                  strokeOpacity="0.85" strokeWidth="1.3"
                  style={{ filter: "drop-shadow(0 0 4px rgba(34,197,94,0.35))" }} />

            {/* MITRE overlay line (secondary axis · cyan · dashed) */}
            <path d={mitrePath} fill="none" stroke="#67e8f9"
                  strokeWidth="1.4" strokeDasharray="4 3"
                  style={{ filter: "drop-shadow(0 0 4px rgba(103,232,249,0.4))" }} />

            {/* Data-point dots */}
            {xs.map((x, i) => (
              <g key={i}>
                <circle cx={x} cy={y95s[i]} r="2.8" fill="#8b5cf6"
                        stroke="#0f172a" strokeWidth="1"
                        style={{ filter: "drop-shadow(0 0 3px #8b5cf6)" }} />
                <circle cx={x} cy={y50s[i]} r="2.6" fill="#22c55e"
                        stroke="#0f172a" strokeWidth="1"
                        style={{ filter: "drop-shadow(0 0 3px #22c55e)" }} />
                <circle cx={x} cy={mitreYs[i]} r="2.2" fill="#67e8f9"
                        stroke="#0f172a" strokeWidth="1" />
              </g>
            ))}

            {/* Hover guide */}
            {active && hoverIdx != null && (
              <g pointerEvents="none">
                <line x1={xs[hoverIdx]} x2={xs[hoverIdx]}
                      y1={PAD_T} y2={PAD_T + innerH}
                      stroke="rgba(103,232,249,0.55)" strokeWidth="1"
                      strokeDasharray="3 3" />
                <circle cx={xs[hoverIdx]} cy={y95s[hoverIdx]} r="4.2"
                        fill="none" stroke="#8b5cf6" strokeWidth="1.4"
                        style={{ filter: "drop-shadow(0 0 6px #8b5cf6)" }} />
                <circle cx={xs[hoverIdx]} cy={y50s[hoverIdx]} r="4"
                        fill="none" stroke="#22c55e" strokeWidth="1.4"
                        style={{ filter: "drop-shadow(0 0 6px #22c55e)" }} />
              </g>
            )}

            {/* X-axis min / max tick labels */}
            {n > 0 && (
              <>
                <text x={xs[0]} y={PAD_T + innerH + 16}
                      textAnchor="start"
                      style={{
                        fontFamily: "JetBrains Mono, ui-monospace, monospace",
                        fontSize: 9, fill: "rgba(148,163,184,0.5)",
                      }}>
                  {pts[0]?.ts ? pts[0].ts.slice(0, 10) : ""}
                </text>
                <text x={xs[xs.length - 1]} y={PAD_T + innerH + 16}
                      textAnchor="end"
                      style={{
                        fontFamily: "JetBrains Mono, ui-monospace, monospace",
                        fontSize: 9, fill: "rgba(148,163,184,0.5)",
                      }}>
                  {pts[pts.length - 1]?.ts ? pts[pts.length - 1].ts.slice(0, 10) : ""}
                </text>
              </>
            )}
          </svg>

          {/* Hover tooltip (rendered as HTML to inherit theme fonts) */}
          {active && (
            <div data-testid="latency-trend-tooltip" style={{
              position: "absolute", top: 6, right: 8,
              padding: "8px 12px",
              background: "rgba(2,6,23,0.92)",
              border: "1px solid rgba(103,232,249,0.35)",
              borderRadius: 6,
              fontFamily: "JetBrains Mono, ui-monospace, monospace",
              fontSize: 10, lineHeight: 1.5,
              color: "rgba(203,213,225,0.92)",
              boxShadow: "0 4px 18px rgba(2,6,23,0.6)",
              pointerEvents: "none",
              minWidth: 200,
            }}>
              <div style={{ color: "rgba(103,232,249,0.85)",
                            letterSpacing: "0.12em", textTransform: "uppercase",
                            fontSize: 9, marginBottom: 4 }}>
                {activeTs}
              </div>
              <TooltipRow color="#22c55e" label="p50" value={`${(active.p50_ms || 0).toFixed(2)} ms`} />
              <TooltipRow color="#8b5cf6" label="p95" value={`${(active.p95_ms || 0).toFixed(2)} ms`} />
              <TooltipRow color="#67e8f9" label="MITRE" value={active.mitre_technique_count ?? 0} />
              <TooltipRow color="#86efac" label="pass" value={`${active.passed}/${active.total}`} />
              {active.regression_count > 0 && (
                <TooltipRow color="#fca5a5" label="regress"
                            value={active.regression_count} />
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

const LegendDot = ({ color, label, dashed }) => (
  <span style={{ display: "inline-flex", alignItems: "center", gap: 6 }}>
    <span style={{
      display: "inline-block",
      width: dashed ? 14 : 8, height: dashed ? 2 : 8,
      borderRadius: dashed ? 0 : "50%",
      background: dashed
        ? `repeating-linear-gradient(90deg, ${color} 0 4px, transparent 4px 7px)`
        : color,
      boxShadow: dashed ? "none" : `0 0 6px ${color}`,
    }} />
    <span style={{ color: "rgba(203,213,225,0.75)" }}>{label}</span>
  </span>
);

const TooltipRow = ({ color, label, value }) => (
  <div style={{ display: "flex", justifyContent: "space-between", gap: 12 }}>
    <span style={{ color, letterSpacing: "0.08em" }}>{label}</span>
    <span style={{ color: "rgba(226,232,240,0.95)" }}>{value}</span>
  </div>
);

// ═══════════════════════════════════════════════════════════════════
// Main page
// ═══════════════════════════════════════════════════════════════════
export default function DashboardPage() {
  const [golden, setGolden] = useState(null);
  const [shadow, setShadow] = useState(null);
  const [gate, setGate] = useState(null);
  const [egMetrics, setEgMetrics] = useState(null);
  const [history, setHistory] = useState([]);

  const load = useCallback(async () => {
    const [g, s, gt, eg, h] = await Promise.all([
      api.get("/rc5/golden/summary").catch(() => ({ data: null })),
      api.get("/rc5/shadow/status").catch(() => ({ data: null })),
      api.get("/rc5/shadow/gate").catch(() => ({ data: null })),
      api.get("/rc5/evidence-graph/metrics").catch(() => ({ data: null })),
      api.get("/rc5/golden/history?limit=60").catch(() => ({ data: [] })),
    ]);
    setGolden(g.data); setShadow(s.data); setGate(gt.data); setEgMetrics(eg.data);
    setHistory(Array.isArray(h.data) ? h.data : []);
  }, []);
  useEffect(() => { load(); const t = setInterval(load, 60000); return () => clearInterval(t); }, [load]);

  // ---- derived counters --------------------------------------------
  // NOTE: backend returns `pass_rate` on a 0-100 scale — do NOT multiply.
  const totalSamples   = golden?.total ?? null;
  const passed         = golden?.passed ?? null;
  const passRate       = golden?.pass_rate != null ? Math.round(golden.pass_rate) : null;
  const p50            = golden?.latency?.p50_ms ?? null;
  const p95            = golden?.latency?.p95_ms ?? null;
  const mitreHits      = golden?.mitre_technique_count ?? golden?.mitre_hits ?? null;
  const shadowDays     = shadow?.days_running ?? shadow?.days_elapsed ?? null;
  const gateCriteria   = gate?.criteria || [];
  const gatePassed     = gateCriteria.filter(c => c.ok).length;
  const gateTotal      = gateCriteria.length;
  const readyForCutover = !!gate?.ready_for_cutover;

  const egMode         = egMetrics?.mode ?? "off";
  const egP95          = egMetrics?.build_ms_p95 ?? null;
  const egSuccess      = egMetrics?.success_rate != null ? Math.round(egMetrics.success_rate * 100) : null;
  const egSampleCount  = egMetrics?.sample_count ?? 0;
  const egIntegErr     = egMetrics?.integrity_error_total ?? 0;

  // Feb-2026 · Data-integrity sprint: honest empty-state signal from
  // the backend (`has_data`). When false the Dashboard renders "No Data
  // Available" tiles instead of "—" placeholders.
  const hasData        = golden?.has_data ?? (totalSamples != null && totalSamples > 0);
  const categoryEntries = useMemo(
    () => {
      // Feb-2026 · initialisation moved inside the memo so the identity
      // of `categoryCoverage` is derived from `golden` alone (the only
      // real dependency). Prevents a per-render new-object identity
      // from busting the memo.
      const coverage = golden?.category_coverage || {};
      return Object.entries(coverage).sort((a, b) => a[0].localeCompare(b[0]));
    },
    [golden],
  );

  // ---- topic lists -------------------------------------------------
  const sources = useMemo(() => [
    { label: "analyst-inbox",   count: null },
    { label: "corpus-runner",   count: totalSamples },
    { label: "shadow-replay",   count: shadowDays != null ? `d${shadowDays}` : null },
    { label: "rss-crawler",     count: null },
    { label: "learner-feedback",count: null },
  ], [totalSamples, shadowDays]);
  const destinations = useMemo(() => [
    { label: "sigma-rules",     count: null },
    { label: "yara-rules",      count: null },
    { label: "mitre-heatmap",   count: mitreHits },
    { label: "threat-intel-tag",count: null },
    { label: "training-inbox",  count: null },
  ], [mitreHits]);

  return (
    <div data-testid="dashboard-page" style={{
      minHeight: "100vh",
      background: "radial-gradient(1200px 800px at 15% 0%, rgba(34,197,94,0.08) 0%, transparent 50%),"
                 + "radial-gradient(900px 700px at 85% 100%, rgba(139,92,246,0.09) 0%, transparent 45%),"
                 + "linear-gradient(180deg, #020617 0%, #030b1c 100%)",
      color: "#e2e8f0",
    }}>
      <Header />

      <main style={{ padding: "24px 28px 60px", maxWidth: 1500, margin: "0 auto" }}>

        {/* Page header — unified corporate hero. */}
        <PageHeader
          testId="dashboard-hero"
          eyebrow={`Deterministic-First · RC5 Semantic Engine · Evidence-Graph mode: ${egMode}`}
          title="NivXRay · Detection Pipeline"
          subtitle="Live visualisation of the RC5 corpus, latency envelope, MITRE tie-ins and the observational Evidence-Graph side-car. All figures update every 60 s."
        />

        {/* DetectFlow pipeline panel */}
        <div data-testid="detectflow-panel" style={{
          background: "linear-gradient(160deg, rgba(15,23,42,0.72), rgba(2,6,23,0.88))",
          backdropFilter: "blur(18px) saturate(160%)",
          border: "1px solid rgba(148,163,184,0.14)",
          borderRadius: 16,
          padding: "28px 24px 32px",
          position: "relative",
          overflow: "hidden",
          boxShadow: "0 8px 32px rgba(34,197,94,0.10), inset 0 1px 0 rgba(255,255,255,0.04)",
        }}>
          <div style={{
            position: "absolute", inset: 0, pointerEvents: "none",
            backgroundImage: "linear-gradient(rgba(148,163,184,0.04) 1px, transparent 1px), "
                           + "linear-gradient(90deg, rgba(148,163,184,0.04) 1px, transparent 1px)",
            backgroundSize: "40px 40px",
            maskImage: "radial-gradient(circle at center, black 50%, transparent 90%)",
            WebkitMaskImage: "radial-gradient(circle at center, black 50%, transparent 90%)",
          }} />

          <div style={{
            display: "grid",
            gridTemplateColumns: "170px 1fr 170px",
            gap: 20, alignItems: "center",
            position: "relative", zIndex: 2,
          }}>
            <TopicList title="Source Topics" items={sources}
                       tone="cyan" side="left" testId="source-topics" />

            <div style={{
              position: "relative", minHeight: 340,
              display: "flex", flexDirection: "column",
              justifyContent: "center", alignItems: "center",
            }}>
              <svg viewBox="0 0 800 340" preserveAspectRatio="none"
                   style={{ position: "absolute", inset: 0, width: "100%", height: "100%" }}>
                <FlowLine d="M0,80 C120,80 180,80 260,90"       color="#22c55e" speed={2.2} />
                <FlowLine d="M340,90 C400,90 440,130 480,140"   color="#22c55e" speed={2.0} />
                <FlowLine d="M580,140 C640,140 680,110 720,90"  color="#8b5cf6" speed={2.4} />
                <FlowLine d="M0,260 C120,260 190,260 260,250"   color="#67e8f9" speed={2.6} />
                <FlowLine d="M340,250 C400,250 440,220 480,210" color="#67e8f9" speed={2.4} />
                <FlowLine d="M580,210 C640,210 680,240 720,260" color="#67e8f9" speed={2.4} />
              </svg>

              <div style={{
                display: "flex", alignItems: "center",
                justifyContent: "space-between", width: "100%",
                marginBottom: 34, position: "relative", zIndex: 2,
              }}>
                <Hex label="Samples" tone="green" size={88}
                     value={totalSamples ?? "—"}
                     sub={passRate != null ? `${passRate}% pass` : ""}
                     testId="hex-samples" />
                <Ring label="RC5 Pipeline" tone="green" size={120}
                      value={passed ?? "—"}
                      sub={p95 != null ? `p95 ${p95}ms` : ""}
                      testId="ring-pipeline" />
                <Ring label="MITRE Tie" tone="violet" size={120}
                      value={mitreHits ?? "—"}
                      sub="techniques"
                      testId="ring-mitre" />
                <Hex label="Tagged" tone="violet" size={88}
                     value={mitreHits ?? "—"}
                     sub="/ sample"
                     testId="hex-tagged" />
              </div>

              <div style={{
                display: "flex", alignItems: "center",
                justifyContent: "space-between", width: "100%",
                position: "relative", zIndex: 2,
              }}>
                <Hex label="# Rules" tone="cyan" size={80}
                     value={gateTotal || "—"}
                     sub="gate criteria"
                     testId="hex-rules" />
                <Ring label="Staging" tone="cyan" size={104}
                      value={gatePassed}
                      sub={`${gatePassed}/${gateTotal || 0}`}
                      testId="ring-staging" />
                <Ring label={readyForCutover ? "Ready" : "Locked"}
                      tone={readyForCutover ? "green" : "amber"}
                      size={104}
                      value={readyForCutover ? "✓" : "◌"}
                      sub="cutover gate"
                      testId="ring-cutover" />
                <Hex label="Deployed" tone="green" size={80}
                     value={egSampleCount}
                     sub="builds seen"
                     testId="hex-deployed" />
              </div>
            </div>

            <TopicList title="Destination Topics" items={destinations}
                       tone="violet" side="right" testId="destination-topics" />
          </div>
        </div>

        {/* Summary KPI strip */}
        <div style={{ display: "flex", gap: 12, marginTop: 22, flexWrap: "wrap" }}>
          <KpiCell testId="kpi-corpus" tone="green"
                   label="Corpus Health"
                   value={passRate != null ? `${passRate}%` : "—"}
                   sub={`${passed ?? 0}/${totalSamples ?? 0} samples`} />
          <KpiCell testId="kpi-latency" tone="cyan"
                   label="Decode Latency"
                   value={p95 != null ? `${p95} ms` : "—"}
                   sub={p50 != null ? `p50 ${p50} ms` : ""} />
          <KpiCell testId="kpi-shadow" tone="amber"
                   label="Shadow Run"
                   value={shadowDays != null ? `${shadowDays}d` : "—"}
                   sub="quality-gated" />
          <KpiCell testId="kpi-eg-p95" tone="violet"
                   label="Evidence Graph · p95"
                   value={egP95 != null ? `${egP95} ms` : "—"}
                   sub={egMode === "sidecar" ? `${egSampleCount} builds` : "sidecar off"} />
          <KpiCell testId="kpi-eg-health" tone={egSuccess === 100 && egIntegErr === 0 ? "green" : "amber"}
                   label="Evidence Graph · Health"
                   value={egSuccess != null ? `${egSuccess}%` : "—"}
                   sub={`${egIntegErr} integrity err`} />
        </div>

        {/* Latency & MITRE trend — Feb-2026 P1 · REAL data from /golden/history. */}
        <LatencyTrendChart history={history} testId="latency-trend-chart" />

        {/* Category Coverage — populated in Feb-2026 data-integrity sprint. */}
        <div data-testid="category-coverage-panel" style={{
          marginTop: 22,
          background: "linear-gradient(160deg, rgba(15,23,42,0.72), rgba(2,6,23,0.88))",
          border: "1px solid rgba(148,163,184,0.14)",
          borderRadius: 12, padding: "16px 20px",
          backdropFilter: "blur(12px)",
        }}>
          <div style={{
            display: "flex", alignItems: "center", justifyContent: "space-between",
            marginBottom: 12,
          }}>
            <div style={{
              fontFamily: "JetBrains Mono, ui-monospace, monospace",
              fontSize: 10, color: "rgba(148,163,184,0.75)",
              letterSpacing: "0.18em", textTransform: "uppercase",
            }}>Category Coverage</div>
            <div style={{
              fontFamily: "JetBrains Mono, ui-monospace, monospace",
              fontSize: 10, color: "rgba(148,163,184,0.6)",
            }}>
              {categoryEntries.length} categories · {mitreHits ?? 0} MITRE techniques
            </div>
          </div>
          {hasData && categoryEntries.length > 0 ? (
            <div style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fill, minmax(240px, 1fr))",
              gap: 8,
            }}>
              {categoryEntries.map(([cat, m]) => {
                const rate = m.pass_rate || 0;
                const color = rate >= 95 ? "#86efac" : rate >= 75 ? "#fcd34d" : "#fca5a5";
                return (
                  <div key={cat} data-testid={`category-${cat}`} style={{
                    background: "rgba(15,23,42,0.55)",
                    border: "1px solid rgba(148,163,184,0.10)",
                    borderRadius: 8, padding: "10px 12px",
                    fontFamily: "JetBrains Mono, ui-monospace, monospace",
                  }}>
                    <div style={{
                      display: "flex", justifyContent: "space-between",
                      alignItems: "baseline", gap: 8,
                    }}>
                      <span style={{
                        color: "rgba(203,213,225,0.88)", fontSize: 11,
                        overflow: "hidden", textOverflow: "ellipsis",
                        whiteSpace: "nowrap",
                      }}>{cat}</span>
                      <span style={{ color, fontWeight: 700, fontSize: 12 }}>
                        {Math.round(rate)}%
                      </span>
                    </div>
                    <div style={{
                      marginTop: 5, height: 4, borderRadius: 2,
                      background: "rgba(148,163,184,0.10)", overflow: "hidden",
                    }}>
                      <div style={{
                        width: `${Math.max(0, Math.min(100, rate))}%`, height: "100%",
                        background: color,
                        boxShadow: `0 0 6px ${color}`,
                      }} />
                    </div>
                    <div style={{
                      marginTop: 4, fontSize: 9,
                      color: "rgba(148,163,184,0.55)",
                    }}>
                      {m.passed}/{m.total} passing
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div data-testid="category-coverage-empty" style={{
              padding: "24px 12px",
              textAlign: "center",
              fontFamily: "JetBrains Mono, ui-monospace, monospace",
              fontSize: 11, color: "rgba(148,163,184,0.55)",
              fontStyle: "italic",
            }}>
              No Data Available · run a Golden Corpus execution to populate
            </div>
          )}
        </div>

      </main>
    </div>
  );
}
