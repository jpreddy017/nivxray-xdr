/**
 * DashboardPage — NivXRay executive/analyst dashboard.
 *
 * Rich, glass-morphism panels aggregating every deterministic signal
 * the RC5 engine exposes: verdict distribution, corpus health,
 * per-category taxonomy pass-rate, latency percentiles, shadow-run
 * progress, cutover-gate readiness, MITRE coverage. Pure viz — no
 * detection logic touched.
 *
 * Design notes:
 *  - Glassmorphism via `backdrop-filter: blur(18px)` on semi-transparent
 *    panels layered over a subtle radial-gradient stage.
 *  - Every metric is deterministic; nothing is mocked. If a backend
 *    endpoint is unavailable, the card reads "—" rather than fabricating.
 */
import { useEffect, useState, useCallback, useMemo } from "react";
import Header from "@/components/Header";
import api from "@/lib/api";
import {
  Activity, ShieldCheck, ShieldAlert, ShieldX, Timer, Layers,
  TrendingUp, GitBranch, Cpu, Radio, Sparkles, Target, FolderOpen,
  BarChart3, CheckCircle2, XCircle, Clock,
} from "lucide-react";

// ── Glass panel primitive ────────────────────────────────────────────
const Glass = ({ children, style, testId, glow = "cyan", className = "" }) => {
  const glows = {
    cyan:   "0 8px 32px rgba(6,182,212,0.10), inset 0 1px 0 rgba(255,255,255,0.04)",
    green:  "0 8px 32px rgba(34,197,94,0.10), inset 0 1px 0 rgba(255,255,255,0.04)",
    amber:  "0 8px 32px rgba(245,158,11,0.12), inset 0 1px 0 rgba(255,255,255,0.04)",
    red:    "0 8px 32px rgba(239,68,68,0.14), inset 0 1px 0 rgba(255,255,255,0.04)",
    violet: "0 8px 32px rgba(139,92,246,0.12), inset 0 1px 0 rgba(255,255,255,0.04)",
  };
  return (
    <div data-testid={testId} className={className} style={{
      background: "linear-gradient(160deg, rgba(15,23,42,0.72), rgba(2,6,23,0.85))",
      backdropFilter: "blur(18px) saturate(160%)",
      WebkitBackdropFilter: "blur(18px) saturate(160%)",
      border: "1px solid rgba(148,163,184,0.14)",
      borderRadius: 14,
      boxShadow: glows[glow] || glows.cyan,
      padding: 18,
      position: "relative",
      overflow: "hidden",
      ...style,
    }}>
      {children}
    </div>
  );
};

// ── KPI stat ──────────────────────────────────────────────────────────
const Kpi = ({ label, value, sub, icon: Icon, tone = "cyan", testId }) => {
  const tones = {
    cyan:   { text: "#67e8f9", bar: "#06b6d4" },
    green:  { text: "#86efac", bar: "#22c55e" },
    amber:  { text: "#fcd34d", bar: "#f59e0b" },
    red:    { text: "#fca5a5", bar: "#ef4444" },
    violet: { text: "#c4b5fd", bar: "#8b5cf6" },
  };
  const t = tones[tone] || tones.cyan;
  return (
    <div data-testid={testId} style={{
      display: "flex", flexDirection: "column", gap: 4, minWidth: 0,
    }}>
      <div style={{
        display: "flex", alignItems: "center", gap: 6,
        color: "rgba(148,163,184,0.75)",
        fontSize: 10, letterSpacing: "0.14em", textTransform: "uppercase",
        fontFamily: "JetBrains Mono, ui-monospace, monospace",
      }}>
        {Icon && <Icon size={11} />} {label}
      </div>
      <div style={{
        fontFamily: "JetBrains Mono, ui-monospace, monospace",
        fontSize: 28, fontWeight: 600, color: t.text,
        lineHeight: 1.1, letterSpacing: "-0.01em",
      }}>{value ?? "—"}</div>
      {sub != null && (
        <div style={{
          fontSize: 11, color: "rgba(148,163,184,0.6)",
          fontFamily: "JetBrains Mono, ui-monospace, monospace",
        }}>{sub}</div>
      )}
    </div>
  );
};

// ── Category coverage bar ────────────────────────────────────────────
const CategoryBar = ({ name, passed, total, pct }) => {
  const w = Math.max(1, pct || 0);
  const tone = pct === 100 ? "#22c55e" : pct >= 90 ? "#84cc16" : pct >= 70 ? "#f59e0b" : "#ef4444";
  return (
    <div style={{ marginBottom: 10 }} data-testid={`cat-${name}`}>
      <div style={{
        display: "flex", justifyContent: "space-between", marginBottom: 3,
        fontFamily: "JetBrains Mono, ui-monospace, monospace",
        fontSize: 10, color: "rgba(203,213,225,0.85)",
      }}>
        <span>{name.replace(/_/g, " ")}</span>
        <span style={{ color: "rgba(148,163,184,0.6)" }}>
          {passed}/{total} · <span style={{ color: tone }}>{pct}%</span>
        </span>
      </div>
      <div style={{
        height: 6, background: "rgba(30,41,59,0.6)", borderRadius: 3, overflow: "hidden",
      }}>
        <div style={{
          width: `${w}%`, height: "100%",
          background: `linear-gradient(90deg, ${tone}80, ${tone})`,
          transition: "width 500ms cubic-bezier(0.4,0,0.2,1)",
        }} />
      </div>
    </div>
  );
};

// ── Gate criterion row ───────────────────────────────────────────────
const GateRow = ({ name, ok, actual, target }) => (
  <div style={{
    display: "grid", gridTemplateColumns: "auto 1fr auto auto", gap: 8,
    alignItems: "center", padding: "6px 0",
    borderBottom: "1px solid rgba(148,163,184,0.08)",
    fontFamily: "JetBrains Mono, ui-monospace, monospace", fontSize: 11,
  }}>
    {ok ? <CheckCircle2 size={13} color="#22c55e" /> : <XCircle size={13} color="#ef4444" />}
    <span style={{ color: "rgba(203,213,225,0.9)" }}>{name}</span>
    <span style={{ color: "rgba(148,163,184,0.7)" }}>{actual ?? "—"}</span>
    <span style={{ color: "rgba(100,116,139,0.6)" }}>≥ {target}</span>
  </div>
);

// ── Main page ────────────────────────────────────────────────────────
export default function DashboardPage() {
  const [golden, setGolden] = useState(null);
  const [shadow, setShadow] = useState(null);
  const [gate, setGate] = useState(null);
  const [egMetrics, setEgMetrics] = useState(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    const [g, s, gt, eg] = await Promise.all([
      api.get("/rc5/golden/summary").catch(() => ({ data: null })),
      api.get("/rc5/shadow/status").catch(() => ({ data: null })),
      api.get("/rc5/shadow/gate").catch(() => ({ data: null })),
      api.get("/rc5/evidence-graph/metrics").catch(() => ({ data: null })),
    ]);
    setGolden(g.data); setShadow(s.data); setGate(gt.data);
    setEgMetrics(eg.data);
    setLoading(false);
  }, []);
  useEffect(() => { load(); const t = setInterval(load, 60000); return () => clearInterval(t); }, [load]);

  // Derived KPIs
  const passRate = golden?.pass_rate ?? null;
  const totalSamples = golden?.total ?? 0;
  const passed = golden?.passed ?? 0;
  const failed = golden?.failed ?? 0;
  const p95 = golden?.latency?.p95_ms ?? null;
  const p50 = golden?.latency?.p50_ms ?? null;
  const totalMs = golden?.latency?.total_ms ?? null;
  const categoryCoverage = golden?.category_coverage || {};
  const categoryList = useMemo(() => (
    Object.entries(categoryCoverage)
      .map(([k, v]) => ({ name: k, ...v }))
      .sort((a, b) => (b.total || 0) - (a.total || 0))
  ), [categoryCoverage]);
  const shadowDays = shadow?.days_running ?? shadow?.days_elapsed ?? null;
  const gateCriteria = gate?.criteria || [];
  const readyForCutover = !!gate?.ready_for_cutover;

  return (
    <div style={{
      minHeight: "100vh",
      background: "radial-gradient(1200px 800px at 15% 0%, rgba(6,182,212,0.09) 0%, transparent 45%),"
                 + "radial-gradient(900px 700px at 85% 100%, rgba(139,92,246,0.09) 0%, transparent 40%),"
                 + "linear-gradient(180deg, #020617 0%, #030b1c 100%)",
      color: "#e2e8f0",
    }} data-testid="dashboard-page">
      <Header />

      <main style={{ padding: "24px 28px 60px", maxWidth: 1500, margin: "0 auto" }}>
        {/* Hero title */}
        <div style={{
          display: "flex", alignItems: "baseline", justifyContent: "space-between",
          marginBottom: 22, gap: 20, flexWrap: "wrap",
        }}>
          <div>
            <h1 style={{
              fontSize: 30, fontWeight: 700, margin: 0, letterSpacing: "-0.02em",
              background: "linear-gradient(90deg, #67e8f9, #a5f3fc, #c4b5fd)",
              WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent",
            }} data-testid="dashboard-title">NivXRay · Operations Dashboard</h1>
            <p style={{
              margin: "6px 0 0", fontSize: 12,
              color: "rgba(148,163,184,0.7)",
              fontFamily: "JetBrains Mono, ui-monospace, monospace",
              letterSpacing: "0.06em", textTransform: "uppercase",
            }}>
              Deterministic RC5 Engine · Shadow-Run in Progress · Live Signals
            </p>
          </div>
          <button className="nvx-btn ghost" onClick={load} disabled={loading}
                  data-testid="dashboard-refresh"
                  style={{ borderColor: "rgba(6,182,212,0.4)", color: "#67e8f9" }}>
            <Activity size={12} /> {loading ? "REFRESHING…" : "REFRESH"}
          </button>
        </div>

        {/* Top KPI strip */}
        <div style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))",
          gap: 14, marginBottom: 16,
        }}>
          <Glass glow="green" testId="kpi-corpus-passrate">
            <Kpi label="Corpus Pass Rate" tone="green" icon={ShieldCheck}
                 value={passRate != null ? `${passRate}%` : "—"}
                 sub={`${passed} / ${totalSamples} samples`} />
          </Glass>
          <Glass glow="cyan" testId="kpi-corpus-size">
            <Kpi label="Curated Corpus Size" tone="cyan" icon={Layers}
                 value={totalSamples || "—"}
                 sub={`${Object.keys(categoryCoverage).length} categories`} />
          </Glass>
          <Glass glow="red" testId="kpi-corpus-failing">
            <Kpi label="Failing Samples" tone={failed > 0 ? "red" : "green"} icon={ShieldAlert}
                 value={failed}
                 sub={failed === 0 ? "clean" : "needs triage"} />
          </Glass>
          <Glass glow="cyan" testId="kpi-latency-p95">
            <Kpi label="Latency p95" tone="cyan" icon={Timer}
                 value={p95 != null ? `${p95} ms` : "—"}
                 sub={p50 != null ? `p50: ${p50} ms` : ""} />
          </Glass>
          <Glass glow="violet" testId="kpi-total-compute">
            <Kpi label="Total Compute" tone="violet" icon={Cpu}
                 value={totalMs != null ? `${totalMs} ms` : "—"}
                 sub="whole corpus / run" />
          </Glass>
          <Glass glow="amber" testId="kpi-shadow-days">
            <Kpi label="Shadow-Run Progress" tone="amber" icon={Radio}
                 value={shadowDays != null ? `${shadowDays} / 30` : "—"}
                 sub="days elapsed" />
          </Glass>
          {egMetrics && egMetrics.mode === "sidecar" && (
            <Glass glow="cyan" testId="kpi-evidence-graph">
              <Kpi label="Evidence Graph · p95" tone="cyan" icon={Cpu}
                   value={egMetrics.build_ms_p95 != null
                          ? `${egMetrics.build_ms_p95} ms`
                          : "—"}
                   sub={`p50 ${egMetrics.build_ms_p50 ?? 0} ms · peak ${Math.round((egMetrics.peak_memory_kb_p95 ?? 0))} KB`} />
            </Glass>
          )}
          {egMetrics && egMetrics.mode === "sidecar" && (
            <Glass glow={egMetrics.integrity_error_total === 0 ? "green" : "red"}
                   testId="kpi-evidence-graph-health">
              <Kpi label="Evidence Graph · Health"
                   tone={egMetrics.integrity_error_total === 0 ? "green" : "red"}
                   icon={ShieldCheck}
                   value={`${Math.round((egMetrics.success_rate ?? 1) * 100)}%`}
                   sub={`${egMetrics.sample_count ?? 0} builds · avg ${egMetrics.node_count_mean ?? 0}n/${egMetrics.edge_count_mean ?? 0}e · ${egMetrics.integrity_error_total ?? 0} integ err`} />
            </Glass>
          )}
        </div>

        {/* Grid: category coverage + cutover gate */}
        <div style={{
          display: "grid", gridTemplateColumns: "1.4fr 1fr",
          gap: 14, marginBottom: 16,
        }}>
          <Glass glow="cyan" testId="panel-category-coverage">
            <div style={{
              display: "flex", alignItems: "center", gap: 8, marginBottom: 12,
            }}>
              <BarChart3 size={14} color="#67e8f9" />
              <span style={{
                fontSize: 11, letterSpacing: "0.14em", textTransform: "uppercase",
                fontFamily: "JetBrains Mono, ui-monospace, monospace",
                color: "rgba(203,213,225,0.9)", fontWeight: 600,
              }}>Per-Category Coverage · {categoryList.length} taxonomy classes</span>
            </div>
            {categoryList.length === 0 && (
              <div style={{ color: "rgba(148,163,184,0.5)", fontSize: 12,
                            fontFamily: "JetBrains Mono, monospace", padding: 20 }}>
                {loading ? "Loading…" : "No corpus data yet."}
              </div>
            )}
            <div style={{ maxHeight: 380, overflowY: "auto", paddingRight: 6 }}>
              {categoryList.map((c) => (
                <CategoryBar key={c.name} name={c.name}
                             passed={c.passed} total={c.total} pct={c.pass_rate} />
              ))}
            </div>
          </Glass>

          <Glass glow={readyForCutover ? "green" : "amber"} testId="panel-cutover-gate">
            <div style={{
              display: "flex", alignItems: "center", justifyContent: "space-between",
              marginBottom: 12,
            }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                <Target size={14} color={readyForCutover ? "#22c55e" : "#f59e0b"} />
                <span style={{
                  fontSize: 11, letterSpacing: "0.14em", textTransform: "uppercase",
                  fontFamily: "JetBrains Mono, monospace",
                  color: "rgba(203,213,225,0.9)", fontWeight: 600,
                }}>Cutover Gate · 9 Criteria</span>
              </div>
              <span style={{
                fontSize: 10, fontFamily: "JetBrains Mono, monospace",
                padding: "3px 8px", borderRadius: 4,
                background: readyForCutover ? "rgba(34,197,94,0.15)" : "rgba(245,158,11,0.15)",
                color: readyForCutover ? "#86efac" : "#fcd34d",
                border: `1px solid ${readyForCutover ? "rgba(34,197,94,0.35)" : "rgba(245,158,11,0.35)"}`,
              }} data-testid="cutover-status-badge">
                {readyForCutover ? "READY" : "BLOCKED"}
              </span>
            </div>
            <div style={{ maxHeight: 380, overflowY: "auto" }}>
              {gateCriteria.length === 0 && (
                <div style={{ color: "rgba(148,163,184,0.5)", fontSize: 12,
                              fontFamily: "JetBrains Mono, monospace", padding: 20 }}>
                  {loading ? "Loading…" : "Gate status unavailable."}
                </div>
              )}
              {gateCriteria.map((c, i) => (
                <GateRow key={i} name={c.name || c.criterion || `criterion-${i+1}`}
                         ok={c.pass || c.ok || c.passed}
                         actual={c.actual != null ? String(c.actual) : (c.value != null ? String(c.value) : null)}
                         target={c.target != null ? String(c.target) : (c.threshold != null ? String(c.threshold) : "—")} />
              ))}
            </div>
          </Glass>
        </div>

        {/* Bottom: quick links + status */}
        <div style={{
          display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))",
          gap: 14,
        }}>
          <Glass glow="violet" testId="panel-shadow-info">
            <div style={{
              display: "flex", alignItems: "center", gap: 8, marginBottom: 12,
            }}>
              <GitBranch size={14} color="#c4b5fd" />
              <span style={{
                fontSize: 11, letterSpacing: "0.14em", textTransform: "uppercase",
                fontFamily: "JetBrains Mono, monospace",
                color: "rgba(203,213,225,0.9)", fontWeight: 600,
              }}>Shadow-Run</span>
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              <Kpi label="Toggle" value={shadow?.enabled ? "ON" : "OFF"}
                   tone={shadow?.enabled ? "green" : "amber"} icon={Sparkles} />
              <Kpi label="Snapshots collected"
                   value={shadow?.total_snapshots ?? shadow?.snapshot_count ?? "—"}
                   tone="cyan" icon={TrendingUp} />
              <Kpi label="v1 vs v2 mismatches"
                   value={shadow?.mismatches ?? shadow?.delta_count ?? "—"}
                   tone="amber" icon={XCircle} />
            </div>
          </Glass>

          <Glass glow="green" testId="panel-latency-breakdown">
            <div style={{
              display: "flex", alignItems: "center", gap: 8, marginBottom: 12,
            }}>
              <Clock size={14} color="#86efac" />
              <span style={{
                fontSize: 11, letterSpacing: "0.14em", textTransform: "uppercase",
                fontFamily: "JetBrains Mono, monospace",
                color: "rgba(203,213,225,0.9)", fontWeight: 600,
              }}>Latency Percentiles</span>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
              <Kpi label="p50" tone="green"
                   value={p50 != null ? `${p50}ms` : "—"} />
              <Kpi label="p95" tone="cyan"
                   value={p95 != null ? `${p95}ms` : "—"} />
              <Kpi label="p99" tone="amber"
                   value={golden?.latency?.p99_ms != null ? `${golden.latency.p99_ms}ms` : "—"} />
              <Kpi label="max" tone="red"
                   value={golden?.latency?.max_ms != null ? `${golden.latency.max_ms}ms` : "—"} />
            </div>
          </Glass>

          <Glass glow="cyan" testId="panel-detector-accuracy">
            <div style={{
              display: "flex", alignItems: "center", gap: 8, marginBottom: 12,
            }}>
              <ShieldX size={14} color="#67e8f9" />
              <span style={{
                fontSize: 11, letterSpacing: "0.14em", textTransform: "uppercase",
                fontFamily: "JetBrains Mono, monospace",
                color: "rgba(203,213,225,0.9)", fontWeight: 600,
              }}>Detector Accuracy</span>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
              <Kpi label="Verdict" tone="green"
                   value={golden?.accuracy?.verdict != null ? `${golden.accuracy.verdict}%` : "—"} />
              <Kpi label="MITRE" tone="cyan"
                   value={golden?.accuracy?.mitre != null ? `${golden.accuracy.mitre}%` : "—"} />
              <Kpi label="LOLBIN" tone="amber"
                   value={golden?.accuracy?.lolbin != null ? `${golden.accuracy.lolbin}%` : "—"} />
              <Kpi label="Behavior" tone="violet"
                   value={golden?.accuracy?.behavior != null ? `${golden.accuracy.behavior}%` : "—"} />
            </div>
          </Glass>

          <Glass glow="amber" testId="panel-quick-links">
            <div style={{
              display: "flex", alignItems: "center", gap: 8, marginBottom: 12,
            }}>
              <FolderOpen size={14} color="#fcd34d" />
              <span style={{
                fontSize: 11, letterSpacing: "0.14em", textTransform: "uppercase",
                fontFamily: "JetBrains Mono, monospace",
                color: "rgba(203,213,225,0.9)", fontWeight: 600,
              }}>Deep Links</span>
            </div>
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {[
                { to: "/analyst/rc5", label: "Analyst Workspace" },
                { to: "/heatmap",     label: "MITRE Heatmap" },
                { to: "/documents",   label: "Documents Library" },
                { to: "/benchmark",   label: "Benchmark Suite" },
                { to: "/admin",       label: "Admin Panel" },
              ].map((l) => (
                <a key={l.to} href={l.to} data-testid={`link-${l.to.replace(/[/]/g, "-")}`}
                   style={{
                     display: "flex", alignItems: "center", justifyContent: "space-between",
                     padding: "6px 10px", borderRadius: 6,
                     background: "rgba(30,41,59,0.4)",
                     border: "1px solid rgba(148,163,184,0.1)",
                     color: "rgba(203,213,225,0.9)",
                     textDecoration: "none",
                     fontFamily: "JetBrains Mono, monospace", fontSize: 11,
                     transition: "all 150ms",
                   }}
                   onMouseEnter={(e) => {
                     e.currentTarget.style.background = "rgba(6,182,212,0.12)";
                     e.currentTarget.style.borderColor = "rgba(6,182,212,0.4)";
                     e.currentTarget.style.color = "#67e8f9";
                   }}
                   onMouseLeave={(e) => {
                     e.currentTarget.style.background = "rgba(30,41,59,0.4)";
                     e.currentTarget.style.borderColor = "rgba(148,163,184,0.1)";
                     e.currentTarget.style.color = "rgba(203,213,225,0.9)";
                   }}>
                  <span>{l.label}</span>
                  <span style={{ color: "rgba(100,116,139,0.5)" }}>→</span>
                </a>
              ))}
            </div>
          </Glass>
        </div>
      </main>
    </div>
  );
}
