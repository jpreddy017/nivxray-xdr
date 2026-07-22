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
import { useEffect, useState, useCallback, useMemo } from "react";
import Header from "@/components/Header";
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
// Main page
// ═══════════════════════════════════════════════════════════════════
export default function DashboardPage() {
  const [golden, setGolden] = useState(null);
  const [shadow, setShadow] = useState(null);
  const [gate, setGate] = useState(null);
  const [egMetrics, setEgMetrics] = useState(null);

  const load = useCallback(async () => {
    const [g, s, gt, eg] = await Promise.all([
      api.get("/rc5/golden/summary").catch(() => ({ data: null })),
      api.get("/rc5/shadow/status").catch(() => ({ data: null })),
      api.get("/rc5/shadow/gate").catch(() => ({ data: null })),
      api.get("/rc5/evidence-graph/metrics").catch(() => ({ data: null })),
    ]);
    setGolden(g.data); setShadow(s.data); setGate(gt.data); setEgMetrics(eg.data);
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
  const categoryCoverage = golden?.category_coverage || {};
  const categoryEntries = useMemo(
    () => Object.entries(categoryCoverage).sort((a, b) => a[0].localeCompare(b[0])),
    [categoryCoverage],
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

        {/* Hero */}
        <div style={{ marginBottom: 20 }}>
          <h1 data-testid="dashboard-title" style={{
            fontSize: 28, fontWeight: 700, margin: 0, letterSpacing: "-0.02em",
            background: "linear-gradient(90deg, #86efac, #a7f3d0, #c4b5fd)",
            WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent",
          }}>NivXRay · Detection Pipeline</h1>
          <p style={{
            margin: "6px 0 0", fontSize: 11,
            color: "rgba(148,163,184,0.7)",
            fontFamily: "JetBrains Mono, ui-monospace, monospace",
            letterSpacing: "0.10em", textTransform: "uppercase",
          }}>
            deterministic-first · rc5 semantic engine · evidence-graph mode: {egMode}
          </p>
        </div>

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
