/**
 * MitreHeatmapPage — /heatmap
 *
 * Visual MITRE ATT&CK coverage matrix. Shows every tactic column with
 * technique cards colored by heuristic count (severity). Analysts see
 * at-a-glance where NivXRay has strong coverage vs sparse tactics that
 * need more signatures.
 *
 * Backend endpoints:
 *   GET  /api/mitre/heatmap                — full coverage matrix
 *   POST /api/mitre/heatmap/probe          — probe a payload
 */
import { useEffect, useMemo, useState } from "react";
import Header from "@/components/Header";
import api from "@/lib/api";
import { Grid, Search, RefreshCw, Target, AlertCircle, TrendingUp } from "lucide-react";

const SEVERITY_COLOR = {
  high:   { bg: "rgba(239,68,68,0.18)",  border: "#ef4444", text: "#fecaca" },
  medium: { bg: "rgba(245,158,11,0.18)", border: "#f59e0b", text: "#fde68a" },
  low:    { bg: "rgba(107,114,128,0.20)", border: "#6b7280", text: "#d1d5db" },
};

// Heat scale for cell background based on hit-count (0..N)
function heatColor(count, max) {
  if (!count) return { bg: "rgba(255,255,255,0.02)", border: "var(--border)", text: "var(--text-mute)" };
  const t = Math.min(1, count / Math.max(1, max));
  // Green → Amber → Red gradient
  if (t < 0.33) return { bg: "rgba(126,227,201,0.15)", border: "#7ee3c9", text: "#a7f3d0" };
  if (t < 0.66) return { bg: "rgba(245,158,11,0.20)", border: "#f59e0b", text: "#fde68a" };
  return { bg: "rgba(239,68,68,0.20)", border: "#ef4444", text: "#fecaca" };
}

export default function MitreHeatmapPage() {
  const [data,    setData]    = useState(null);
  const [busy,    setBusy]    = useState(false);
  const [err,     setErr]     = useState(null);
  const [filter,  setFilter]  = useState("");
  const [probe,   setProbe]   = useState("");
  const [probeR,  setProbeR]  = useState(null);

  const load = async () => {
    setBusy(true); setErr(null);
    try {
      const r = await api.get("/mitre/heatmap");
      setData(r.data);
    } catch (e) {
      setErr(e.response?.data?.detail || e.message);
    } finally { setBusy(false); }
  };
  useEffect(() => { load(); }, []);

  const runProbe = async () => {
    if (!probe.trim()) return;
    setBusy(true); setErr(null);
    try {
      const r = await api.post("/mitre/heatmap/probe", { text: probe });
      setProbeR(r.data);
    } catch (e) {
      setErr(e.response?.data?.detail || e.message);
    } finally { setBusy(false); }
  };

  const maxCount = useMemo(() => {
    if (!data?.matrix) return 1;
    let m = 1;
    Object.values(data.matrix).forEach(techs => techs.forEach(t => { if (t.count > m) m = t.count; }));
    return m;
  }, [data]);

  const lit = useMemo(() => {
    const s = new Set();
    (probeR?.cells || []).forEach(c => s.add(c.id));
    return s;
  }, [probeR]);

  const matches = (t) => !filter || t.id.toLowerCase().includes(filter.toLowerCase()) ||
                         (t.name || "").toLowerCase().includes(filter.toLowerCase());

  return (
    <div data-testid="mitre-heatmap-page">
      <Header />
      <main style={{ maxWidth: 1600, margin: "0 auto", padding: "16px 24px" }}>
        <div style={{ marginBottom: 14, display: "flex", alignItems: "flex-end", justifyContent: "space-between", flexWrap: "wrap", gap: 12 }}>
          <div>
            <h1 style={{ fontSize: 22, margin: 0, color: "var(--text)", display: "flex", alignItems: "center", gap: 8 }}>
              <Grid size={20} /> MITRE ATT&CK Detection Heatmap
            </h1>
            <p style={{ margin: "4px 0 0", fontSize: 12, color: "var(--text-dim)" }}>
              Visual coverage matrix — {data?.total_heuristics || "…"} heuristics ·{" "}
              {data?.unique_techniques || "…"} unique techniques across{" "}
              {data?.tactics?.length || "…"} tactics.
            </p>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <div style={{ position: "relative" }}>
              <Search size={12} style={{ position: "absolute", left: 8, top: 8, color: "var(--text-mute)" }} />
              <input
                data-testid="heatmap-filter-input"
                value={filter} onChange={e => setFilter(e.target.value)}
                placeholder="Filter T-ID or name…"
                style={{ padding: "4px 8px 4px 24px", background: "var(--bg-mute)",
                          border: "1px solid var(--border)", color: "var(--text)",
                          borderRadius: 4, fontFamily: "JetBrains Mono", fontSize: 11,
                          width: 220 }} />
            </div>
            <button onClick={load} disabled={busy} className="nvx-btn sm ghost" data-testid="heatmap-refresh">
              <RefreshCw size={12} /> REFRESH
            </button>
          </div>
        </div>

        {err && (
          <div className="nvx-card" style={{ marginBottom: 12, borderColor: "#ef4444" }}>
            <div className="nvx-card-body" style={{ color: "#fecaca", fontSize: 12 }}
                 data-testid="heatmap-error">
              <AlertCircle size={12} style={{ display: "inline", marginRight: 6 }} />
              {err}
            </div>
          </div>
        )}

        {/* Probe input */}
        <div className="nvx-card" style={{ marginBottom: 12 }}>
          <div className="nvx-card-head">
            <div className="nvx-card-title" style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <Target size={14} /> Probe a payload → light up matching cells
            </div>
            {probeR && (
              <div style={{ fontSize: 11, color: "var(--text-dim)" }} data-testid="heatmap-probe-summary">
                Lit {probeR.unique_techniques} technique{probeR.unique_techniques === 1 ? "" : "s"} across{" "}
                {Object.keys(probeR.by_tactic || {}).length} tactic{Object.keys(probeR.by_tactic || {}).length === 1 ? "" : "s"}
              </div>
            )}
          </div>
          <div className="nvx-card-body" style={{ display: "flex", gap: 8, alignItems: "flex-start", flexWrap: "wrap" }}>
            <textarea
              data-testid="heatmap-probe-input"
              value={probe} onChange={e => setProbe(e.target.value)}
              rows={2} spellCheck={false}
              placeholder="Paste any suspicious command / payload…"
              style={{ flex: 1, minWidth: 400, fontFamily: "JetBrains Mono", fontSize: 12,
                       background: "var(--bg-deep)", color: "var(--text)",
                       border: "1px solid var(--border)", borderRadius: 6, padding: 8 }} />
            <div style={{ display: "flex", gap: 6, flexDirection: "column" }}>
              <button onClick={runProbe} disabled={busy || !probe.trim()}
                      data-testid="heatmap-probe-btn" className="nvx-btn sm primary">
                <Target size={12} /> LIGHT UP
              </button>
              {probeR && (
                <button onClick={() => { setProbeR(null); setProbe(""); }}
                        data-testid="heatmap-probe-clear" className="nvx-btn sm ghost">
                  CLEAR
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Top hottest techniques */}
        {data?.top_techniques?.length > 0 && (
          <div className="nvx-card" style={{ marginBottom: 12 }} data-testid="heatmap-top">
            <div className="nvx-card-head">
              <div className="nvx-card-title" style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <TrendingUp size={14} /> Top-covered techniques
              </div>
            </div>
            <div className="nvx-card-body" style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {data.top_techniques.slice(0, 15).map(t => {
                const c = heatColor(t.count, maxCount);
                return (
                  <div key={t.id} data-testid={`heatmap-top-${t.id}`}
                       title={`${t.tactic} · ${t.name}`}
                       style={{ padding: "4px 8px", background: c.bg, border: `1px solid ${c.border}`,
                                 color: c.text, fontFamily: "JetBrains Mono", fontSize: 11,
                                 borderRadius: 3, whiteSpace: "nowrap" }}>
                    {t.id} · <span style={{ opacity: 0.75 }}>{t.count}</span>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Sparse tactics warning */}
        {data?.sparse_tactics?.length > 0 && (
          <div className="nvx-card" style={{ marginBottom: 12, borderColor: "rgba(245,158,11,0.4)" }}
               data-testid="heatmap-sparse">
            <div className="nvx-card-body" style={{ fontSize: 11, color: "#fde68a" }}>
              <AlertCircle size={12} style={{ display: "inline", marginRight: 6 }} />
              <strong>Sparse coverage</strong> (&lt;5 techniques) in:{" "}
              {data.sparse_tactics.join(" · ")} — candidates for new signatures.
            </div>
          </div>
        )}

        {/* Full matrix */}
        {data?.matrix && (
          <div className="nvx-card" data-testid="heatmap-matrix">
            <div className="nvx-card-head">
              <div className="nvx-card-title">Coverage Matrix (Kill-Chain Order)</div>
              <div style={{ fontSize: 11, color: "var(--text-dim)" }}>
                {probeR ? `${lit.size} cells lit` : "click a cell to focus"}
              </div>
            </div>
            <div className="nvx-card-body" style={{ overflowX: "auto", padding: 0 }}>
              <div style={{ display: "flex", gap: 6, padding: 10, minWidth: "100%" }}>
                {data.tactics.map(tactic => {
                  const techs = (data.matrix[tactic] || []).filter(matches);
                  return (
                    <div key={tactic} data-testid={`heatmap-column-${tactic.replace(/\s+/g, "-").toLowerCase()}`}
                         style={{ flex: "0 0 190px", minWidth: 190, display: "flex", flexDirection: "column", gap: 4 }}>
                      <div style={{ fontFamily: "Chivo", fontWeight: 700, fontSize: 11,
                                     color: "var(--text)", letterSpacing: "0.06em",
                                     textTransform: "uppercase", padding: "6px 4px",
                                     borderBottom: "1px solid var(--border)",
                                     background: "var(--bg-deep)" }}>
                        {tactic}
                        <div style={{ fontSize: 9, color: "var(--text-mute)", fontWeight: 400,
                                      letterSpacing: 0, marginTop: 2 }}>
                          {data.matrix[tactic].length} technique{data.matrix[tactic].length === 1 ? "" : "s"}
                        </div>
                      </div>
                      {techs.map(t => {
                        const c = heatColor(t.count, maxCount);
                        const isLit = lit.has(t.id);
                        return (
                          <div key={t.id}
                               data-testid={`heatmap-cell-${t.id}`}
                               title={`${t.name} · sources: ${(t.sources || []).join(", ") || "—"}`}
                               style={{ padding: "5px 7px",
                                         background: isLit ? "#7ee3c9" : c.bg,
                                         border: `1px solid ${isLit ? "#7ee3c9" : c.border}`,
                                         color:  isLit ? "#0b1220" : c.text,
                                         fontFamily: "JetBrains Mono", fontSize: 10,
                                         borderRadius: 3, cursor: "pointer",
                                         boxShadow: isLit ? "0 0 12px rgba(126,227,201,0.6)" : "none",
                                         transition: "all 120ms" }}>
                            <div style={{ fontWeight: 700, letterSpacing: 0 }}>{t.id}</div>
                            <div style={{ fontSize: 9, marginTop: 1, opacity: 0.75,
                                           whiteSpace: "nowrap", overflow: "hidden",
                                           textOverflow: "ellipsis" }}>
                              {t.name}
                            </div>
                            <div style={{ fontSize: 9, marginTop: 2, opacity: 0.6 }}>
                              n={t.count}
                            </div>
                          </div>
                        );
                      })}
                      {techs.length === 0 && filter && (
                        <div style={{ padding: "8px 4px", color: "var(--text-mute)", fontSize: 10, fontStyle: "italic" }}>
                          no match
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}

        {/* Probe results list */}
        {probeR && probeR.cells?.length > 0 && (
          <div className="nvx-card" style={{ marginTop: 12 }} data-testid="heatmap-probe-results">
            <div className="nvx-card-head">
              <div className="nvx-card-title">Probe Results</div>
            </div>
            <div className="nvx-card-body" style={{ fontSize: 11 }}>
              {Object.entries(probeR.by_tactic || {}).map(([tactic, cells]) => (
                <div key={tactic} style={{ marginBottom: 8 }}>
                  <div style={{ color: "var(--accent)", fontFamily: "Chivo", fontWeight: 700,
                                 letterSpacing: "0.08em", textTransform: "uppercase",
                                 fontSize: 10, marginBottom: 4 }}>
                    {tactic}
                  </div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                    {cells.map(c => (
                      <span key={c.id}
                            style={{ padding: "2px 6px", background: "rgba(126,227,201,0.15)",
                                      border: "1px solid #7ee3c9", color: "#a7f3d0",
                                      fontFamily: "JetBrains Mono", fontSize: 10, borderRadius: 3 }}>
                        {c.id} · {c.name}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
