/**
 * BenchmarkPage — NivXRay Public Benchmark (SOC Prime Management-Dashboard style).
 *
 * Same visual language as `DashboardPage`: donut KPIs, delta cards,
 * area charts. Data is fetched from the identical endpoints as before
 * (`/api/benchmark/real-world` + `/api/benchmark/refresh`). Zero
 * behavioural changes — pure visual refresh.
 */
import { useEffect, useState } from "react";
import axios from "axios";
import Header from "@/components/Header";
import PageHeader from "@/components/PageHeader";
import { CheckCircle2, XCircle, TrendingUp, TrendingDown, Download, FileText, RefreshCw, Gauge } from "lucide-react";

const API = process.env.REACT_APP_BACKEND_URL + "/api";

// ═══════════════════════════════════════════════════════════════════
// Primitives (mirror DashboardPage's design language)
// ═══════════════════════════════════════════════════════════════════

const DonutKpi = ({ label, value, pct, tone = "green", testId, sub }) => {
  const tones = {
    green:  { fg: "#86efac", ring: "#22c55e", track: "rgba(34,197,94,0.15)" },
    violet: { fg: "#c4b5fd", ring: "#8b5cf6", track: "rgba(139,92,246,0.15)" },
    cyan:   { fg: "#67e8f9", ring: "#06b6d4", track: "rgba(6,182,212,0.15)"  },
    amber:  { fg: "#fcd34d", ring: "#f59e0b", track: "rgba(245,158,11,0.15)" },
    red:    { fg: "#fca5a5", ring: "#ef4444", track: "rgba(239,68,68,0.15)"  },
  };
  const t = tones[tone] || tones.green;
  const p = Math.max(0, Math.min(100, pct ?? 0));
  const C = 2 * Math.PI * 26;
  const dash = (p / 100) * C;
  return (
    <div data-testid={testId} style={{
      display: "flex", alignItems: "center", gap: 14,
      background: "linear-gradient(160deg, rgba(15,23,42,0.75), rgba(2,6,23,0.90))",
      border: "1px solid rgba(148,163,184,0.14)",
      borderRadius: 12, padding: "14px 16px",
      backdropFilter: "blur(12px)",
      minWidth: 200, flex: 1,
    }}>
      <div style={{ position: "relative", width: 62, height: 62, flexShrink: 0 }}>
        <svg width="62" height="62" viewBox="0 0 62 62"
             style={{ filter: `drop-shadow(0 0 8px ${t.ring}55)` }}>
          <circle cx="31" cy="31" r="26" fill="none" stroke={t.track} strokeWidth="6" />
          <circle cx="31" cy="31" r="26" fill="none"
                  stroke={t.ring} strokeWidth="6" strokeLinecap="round"
                  strokeDasharray={`${dash} ${C - dash}`}
                  transform="rotate(-90 31 31)" />
        </svg>
        <div style={{
          position: "absolute", inset: 0,
          display: "flex", alignItems: "center", justifyContent: "center",
          fontFamily: "JetBrains Mono, ui-monospace, monospace",
          fontSize: 11, fontWeight: 700, color: t.fg,
        }}>{pct != null ? `${Math.round(p)}%` : "—"}</div>
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{
          fontFamily: "JetBrains Mono, ui-monospace, monospace",
          fontSize: 9, color: "rgba(148,163,184,0.7)",
          letterSpacing: "0.14em", textTransform: "uppercase",
          marginBottom: 3,
        }}>{label}</div>
        <div style={{
          fontSize: 18, fontWeight: 700, color: "#e2e8f0",
          fontFamily: "JetBrains Mono, ui-monospace, monospace",
          lineHeight: 1.1,
        }}>{value ?? "—"}</div>
        {sub && (
          <div style={{
            fontSize: 10, color: "rgba(148,163,184,0.55)",
            fontFamily: "JetBrains Mono, ui-monospace, monospace",
            marginTop: 2,
          }}>{sub}</div>
        )}
      </div>
    </div>
  );
};

const DeltaKpi = ({ label, value, delta, target, tone = "green", testId, unit = "" }) => {
  const tones = { green: "#86efac", violet: "#c4b5fd", cyan: "#67e8f9", amber: "#fcd34d", red: "#fca5a5" };
  const up = delta != null && delta >= 0;
  const dColor = up ? "#22c55e" : "#ef4444";
  const DIcon = up ? TrendingUp : TrendingDown;
  return (
    <div data-testid={testId} style={{
      background: "linear-gradient(160deg, rgba(15,23,42,0.75), rgba(2,6,23,0.90))",
      border: "1px solid rgba(148,163,184,0.14)",
      borderRadius: 12, padding: "14px 16px",
      backdropFilter: "blur(12px)",
      minWidth: 200, flex: 1,
    }}>
      <div style={{
        fontFamily: "JetBrains Mono, ui-monospace, monospace",
        fontSize: 9, color: "rgba(148,163,184,0.7)",
        letterSpacing: "0.14em", textTransform: "uppercase",
        marginBottom: 6,
      }}>{label}</div>
      <div style={{ display: "flex", alignItems: "baseline", gap: 10, flexWrap: "wrap" }}>
        <div style={{
          fontSize: 24, fontWeight: 700, color: tones[tone] || tones.green,
          fontFamily: "JetBrains Mono, ui-monospace, monospace",
          lineHeight: 1,
        }}>{value ?? "—"}{value != null && unit}</div>
        {delta != null && (
          <div style={{
            display: "inline-flex", alignItems: "center", gap: 3,
            fontSize: 11, color: dColor,
            fontFamily: "JetBrains Mono, ui-monospace, monospace",
          }}>
            <DIcon size={11} />
            <span>{up ? "+" : ""}{delta}%</span>
          </div>
        )}
        {target && (
          <span style={{
            fontSize: 11, color: "rgba(148,163,184,0.5)",
            fontFamily: "JetBrains Mono, ui-monospace, monospace",
          }}>| {target}</span>
        )}
      </div>
    </div>
  );
};

const Pill = ({ children, tone = "cyan" }) => {
  const tones = {
    cyan:   { bg: "rgba(6,182,212,0.10)",   fg: "#67e8f9", bd: "rgba(6,182,212,0.28)"   },
    violet: { bg: "rgba(139,92,246,0.10)",  fg: "#c4b5fd", bd: "rgba(139,92,246,0.28)"  },
    green:  { bg: "rgba(34,197,94,0.10)",   fg: "#86efac", bd: "rgba(34,197,94,0.28)"   },
  };
  const t = tones[tone] || tones.cyan;
  return (
    <span style={{
      display: "inline-block",
      padding: "4px 10px",
      background: t.bg,
      color: t.fg,
      border: `1px solid ${t.bd}`,
      borderRadius: 999,
      fontFamily: "JetBrains Mono, ui-monospace, monospace",
      fontSize: 11,
      letterSpacing: "0.04em",
    }}>{children}</span>
  );
};

// ═══════════════════════════════════════════════════════════════════
// Main page
// ═══════════════════════════════════════════════════════════════════

export default function BenchmarkPage() {
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);
  const [refreshing, setRefreshing] = useState(false);

  const load = async () => {
    try {
      const r = await axios.get(`${API}/benchmark/real-world`);
      setData(r.data);
      setErr(null);
    } catch (e) {
      setErr(e?.message || "failed to fetch");
    }
  };

  useEffect(() => { load(); }, []);

  const runRefresh = async () => {
    setRefreshing(true);
    try {
      await axios.post(`${API}/benchmark/refresh`);
      await load();
    } catch (e) {
      setErr(e?.message || "refresh failed");
    } finally {
      setRefreshing(false);
    }
  };

  const pageWrap = {
    minHeight: "100vh",
    background: "radial-gradient(1200px 800px at 15% 0%, rgba(34,197,94,0.08) 0%, transparent 50%),"
               + "radial-gradient(900px 700px at 85% 100%, rgba(139,92,246,0.09) 0%, transparent 45%),"
               + "linear-gradient(180deg, #020617 0%, #030b1c 100%)",
    color: "#e2e8f0",
  };

  if (err) return (
    <div data-testid="benchmark-page-wrap" style={pageWrap}>
      <Header />
      <div style={{ padding: "24px 28px", maxWidth: 1500, margin: "0 auto" }}>
        <div style={{
          background: "rgba(239,68,68,0.10)", border: "1px solid rgba(239,68,68,0.28)",
          borderRadius: 12, padding: "16px 20px", color: "#fca5a5",
          fontFamily: "JetBrains Mono, ui-monospace, monospace", fontSize: 12,
        }}>
          <strong>error</strong> · {err}
        </div>
      </div>
    </div>
  );

  if (!data) return (
    <div data-testid="benchmark-page-wrap" style={pageWrap}>
      <Header />
      <div style={{
        padding: "80px 28px", textAlign: "center",
        fontFamily: "JetBrains Mono, ui-monospace, monospace",
        color: "rgba(148,163,184,0.6)", fontSize: 12,
      }}>loading real-world benchmark …</div>
    </div>
  );

  const m = data.metrics || {};
  const gateOk = data.gate?.ok;
  const gateTone = gateOk ? "green" : "red";
  const iocOk = (m.ioc_recall || 0) >= 0.70;

  // Deterministic deltas: current vs threshold.
  const delta = (v, target, invert = false) => {
    if (v == null || target == null) return null;
    const d = invert ? target - v : v - target;
    return +(d * 100).toFixed(1);
  };

  return (
    <div data-testid="benchmark-page-wrap" style={pageWrap}>
      <Header />
      <main data-testid="benchmark-page" style={{ padding: "24px 28px 60px", maxWidth: 1500, margin: "0 auto" }}>

        {/* Hero — unified corporate PageHeader. */}
        <PageHeader
          testId="benchmark-hero"
          eyebrow={`Real-World Stress Suite · ${data.corpus_size} curated payloads · ≥5 obfuscation layers`}
          title={`Real-World Stress · ${gateOk ? "PASSING" : "FAILING"}`}
          subtitle={`Public benchmark that stress-tests NivXRay against payload chains derived from real-world tradecraft. Last computed ${data.generated_at ? new Date(data.generated_at).toLocaleString() : "—"}.`}
          icon={Gauge}
          tone={gateOk ? "accent" : "amber"}
        />

        {/* Row 1 — 4 donut KPIs (thresholded metrics) */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: 12, marginBottom: 12 }}>
          <DonutKpi testId="kpi-mitre" tone={(m.mitre_hit_rate || 0) >= 0.75 ? "green" : "amber"}
                    label="MITRE Hit-Rate"
                    value={`${((m.mitre_hit_rate || 0) * 100).toFixed(1)}%`}
                    pct={(m.mitre_hit_rate || 0) * 100}
                    sub="target ≥ 75%" />
          <DonutKpi testId="kpi-undecoded" tone={(m.undecoded_rate || 0) <= 0.10 ? "green" : "red"}
                    label="Undecoded Rate"
                    value={`${((m.undecoded_rate || 0) * 100).toFixed(1)}%`}
                    pct={100 - Math.min(100, (m.undecoded_rate || 0) * 100 * 10)}
                    sub="target ≤ 10%" />
          <DonutKpi testId="kpi-ioc" tone={iocOk ? "green" : "red"}
                    label="IOC Recall"
                    value={`${((m.ioc_recall || 0) * 100).toFixed(1)}%`}
                    pct={(m.ioc_recall || 0) * 100}
                    sub="target ≥ 70% · reported" />
          <DonutKpi testId="kpi-marker" tone="violet"
                    label="Marker Hit-Rate"
                    value={`${((m.marker_hit_rate || 0) * 100).toFixed(1)}%`}
                    pct={(m.marker_hit_rate || 0) * 100}
                    sub="informational" />
        </div>

        {/* Row 2 — 4 delta KPIs (raw counts + latency) */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: 12, marginBottom: 20 }}>
          <DeltaKpi testId="kpi-layers" tone="cyan"
                    label="Avg Layers / Entry"
                    value={m.avg_layers != null ? m.avg_layers.toFixed(2) : null}
                    delta={m.avg_layers != null ? +((m.avg_layers - 5) * 20).toFixed(1) : null}
                    target="target ≥ 5" />
          <DeltaKpi testId="kpi-latency" tone="violet"
                    label="Avg Latency"
                    value={m.avg_latency_ms ?? null}
                    unit=" ms"
                    delta={null}
                    target="p50 pipeline" />
          <DeltaKpi testId="kpi-corpus" tone="green"
                    label="Corpus Size"
                    value={data.corpus_size}
                    delta={null}
                    target="curated payloads" />
          <DeltaKpi testId="kpi-gate" tone={gateTone}
                    label="Gate Status"
                    value={gateOk ? "PASS" : "FAIL"}
                    delta={null}
                    target={`${(data.gate?.failures || []).length} failures`} />
        </div>

        {/* Action bar */}
        <div style={{ display: "flex", gap: 10, marginBottom: 22, flexWrap: "wrap" }}>
          <a data-testid="btn-download-corpus"
             href={`${API}/benchmark/real-world/download`}
             style={{
               display: "inline-flex", alignItems: "center", gap: 8,
               padding: "10px 16px", borderRadius: 8,
               background: "rgba(34,197,94,0.10)",
               border: "1px solid rgba(34,197,94,0.35)",
               color: "#86efac", textDecoration: "none",
               fontFamily: "JetBrains Mono, ui-monospace, monospace",
               fontSize: 11, letterSpacing: "0.08em", textTransform: "uppercase",
             }}>
            <Download size={13} /> Download Full Corpus (JSON)
          </a>
          <a data-testid="btn-view-html-report"
             href="/downloads/real_world_stress.html"
             target="_blank" rel="noopener noreferrer"
             style={{
               display: "inline-flex", alignItems: "center", gap: 8,
               padding: "10px 16px", borderRadius: 8,
               background: "rgba(139,92,246,0.10)",
               border: "1px solid rgba(139,92,246,0.35)",
               color: "#c4b5fd", textDecoration: "none",
               fontFamily: "JetBrains Mono, ui-monospace, monospace",
               fontSize: 11, letterSpacing: "0.08em", textTransform: "uppercase",
             }}>
            <FileText size={13} /> View Per-Payload HTML Report
          </a>
          <button data-testid="btn-refresh-benchmark"
                  onClick={runRefresh}
                  disabled={refreshing}
                  style={{
                    display: "inline-flex", alignItems: "center", gap: 8,
                    padding: "10px 16px", borderRadius: 8,
                    background: "rgba(6,182,212,0.10)",
                    border: "1px solid rgba(6,182,212,0.35)",
                    color: "#67e8f9",
                    cursor: refreshing ? "wait" : "pointer",
                    fontFamily: "JetBrains Mono, ui-monospace, monospace",
                    fontSize: 11, letterSpacing: "0.08em", textTransform: "uppercase",
                    opacity: refreshing ? 0.55 : 1,
                  }}>
            <RefreshCw size={13} className={refreshing ? "spin" : ""} />
            {refreshing ? "Refreshing …" : "Refresh Corpus + Re-Run"}
          </button>
        </div>

        {/* Ground-truth sources */}
        <div style={{ marginBottom: 22 }}>
          <div style={{
            fontFamily: "JetBrains Mono, ui-monospace, monospace",
            fontSize: 9, color: "rgba(148,163,184,0.7)",
            letterSpacing: "0.14em", textTransform: "uppercase",
            marginBottom: 8,
          }}>Ground-Truth Sources</div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            {(data.sources || []).map((s) => (
              <Pill key={s} tone="cyan">{s}</Pill>
            ))}
          </div>
        </div>

        {/* Per-family breakdown */}
        <div data-testid="family-table" style={{
          background: "linear-gradient(160deg, rgba(15,23,42,0.75), rgba(2,6,23,0.90))",
          border: "1px solid rgba(148,163,184,0.14)",
          borderRadius: 12, overflow: "hidden",
          backdropFilter: "blur(12px)",
        }}>
          <div style={{
            padding: "14px 18px",
            fontFamily: "JetBrains Mono, ui-monospace, monospace",
            fontSize: 9, color: "rgba(148,163,184,0.7)",
            letterSpacing: "0.14em", textTransform: "uppercase",
            borderBottom: "1px solid rgba(148,163,184,0.10)",
          }}>Per-Family Breakdown</div>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
            <thead>
              <tr style={{ background: "rgba(15,23,42,0.55)" }}>
                {["Family", "Payloads", "MITRE Hits", "Undecoded", "Hit-Rate"].map((h) => (
                  <th key={h} style={{
                    textAlign: "left", padding: "10px 16px",
                    fontFamily: "JetBrains Mono, ui-monospace, monospace",
                    fontSize: 10, letterSpacing: "0.10em", textTransform: "uppercase",
                    color: "rgba(148,163,184,0.75)", fontWeight: 500,
                  }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {Object.entries(data.per_family || {})
                .sort((a, b) => a[0].localeCompare(b[0]))
                .map(([fam, f]) => {
                  const rate = f.total ? f.mitre_hits / f.total : 0;
                  const rateColor = rate >= 0.75 ? "#86efac" : rate >= 0.5 ? "#fcd34d" : "#fca5a5";
                  return (
                    <tr key={fam} style={{ borderTop: "1px solid rgba(148,163,184,0.08)" }}>
                      <td style={cellStyle}>{fam}</td>
                      <td style={cellStyle}>{f.total}</td>
                      <td style={cellStyle}>{f.mitre_hits}</td>
                      <td style={cellStyle}>{f.undecoded}</td>
                      <td style={{ ...cellStyle, color: rateColor, fontWeight: 700 }}>
                        {(rate * 100).toFixed(0)}%
                      </td>
                    </tr>
                  );
                })}
            </tbody>
          </table>
        </div>

        <footer style={{
          marginTop: 24,
          color: "rgba(148,163,184,0.55)", fontSize: 11, lineHeight: 1.6,
          fontFamily: "JetBrains Mono, ui-monospace, monospace",
        }}>
          Every payload is reconstructed from a documented public incident write-up so
          ground truth is verifiable. Corpus refreshes weekly via MalwareBazaar + Atomic
          Red Team. CI gate: MITRE hit-rate ≥ 75% + Undecoded ≤ 10%.
        </footer>
      </main>

      <style>{`
        .spin { animation: spin 1s linear infinite; }
        @keyframes spin { to { transform: rotate(360deg); } }
      `}</style>
    </div>
  );
}

const cellStyle = {
  padding: "10px 16px",
  fontFamily: "JetBrains Mono, ui-monospace, monospace",
  color: "rgba(203,213,225,0.88)",
};
