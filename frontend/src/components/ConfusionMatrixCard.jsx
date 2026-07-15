import { useEffect, useState } from "react";
import api from "@/lib/api";
import {
  Target, RefreshCw, TrendingUp, TrendingDown, ChevronRight, X,
  CheckCircle2, XCircle, Activity,
} from "lucide-react";

/**
 * ConfusionMatrixCard
 * -------------------
 * Admin-page dashboard widget consuming `/api/training/confusion/summary`
 * for the fast-path overview + `/api/training/confusion?categories=<slug>`
 * to drill into the failing samples of a specific category.
 *
 * Design goals:
 *   • Zero clicks to answer "what's my decoder's baseline right now?"
 *   • One click to jump into the failing sample list of the WORST category.
 *   • Refresh button forces a full 245-sample recompute (~11s).
 *
 * All 5 worst-recall categories are clickable — clicking opens a slide-in
 * detail pane listing the actual `id / expected / got / engine / confidence`
 * for every FN, so the analyst can immediately grab a fixture and iterate.
 */
export default function ConfusionMatrixCard() {
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [expanded, setExpanded] = useState(null); // category slug
  const [detail, setDetail] = useState(null);     // { category, failures[] }
  const [detailLoading, setDetailLoading] = useState(false);

  const loadSummary = async () => {
    setLoading(true);
    setError("");
    try {
      const r = await api.get("/training/confusion/summary");
      setSummary(r.data);
    } catch (e) {
      setError(e?.response?.data?.detail || e.message);
    } finally {
      setLoading(false);
    }
  };

  const refresh = async () => {
    setRefreshing(true);
    setError("");
    try {
      await api.get("/training/confusion?refresh=true");
      await loadSummary();
    } catch (e) {
      setError(e?.response?.data?.detail || e.message);
    } finally {
      setRefreshing(false);
    }
  };

  const openDetail = async (slug) => {
    if (expanded === slug) {
      setExpanded(null);
      setDetail(null);
      return;
    }
    setExpanded(slug);
    setDetailLoading(true);
    try {
      const r = await api.get(
        `/training/confusion?categories=${encodeURIComponent(slug)}&include_negatives=false`,
      );
      const c = (r.data?.categories || []).find((x) => x.category === slug);
      setDetail(c || { category: slug, failures: [] });
    } catch (e) {
      setDetail({ category: slug, failures: [], _error: e?.message || "load failed" });
    } finally {
      setDetailLoading(false);
    }
  };

  useEffect(() => { loadSummary(); }, []);

  const ov = summary?.overall;
  const pct = (v) => (v === undefined || v === null ? "—" : `${(v * 100).toFixed(1)}%`);

  return (
    <section
      className="brut-border"
      style={{ background: "var(--surface)" }}
      data-testid="confusion-matrix-card"
    >
      {/* Header */}
      <div
        style={{
          padding: "12px 16px",
          borderBottom: "1px solid var(--border)",
          display: "flex",
          alignItems: "center",
          gap: 10,
          flexWrap: "wrap",
        }}
      >
        <Target size={16} style={{ color: "#f59e0b" }} />
        <div style={{ flex: 1 }}>
          <div
            className="mono"
            style={{ fontSize: 11, letterSpacing: "0.24em", color: "#f59e0b" }}
          >
            ▸ CORPUS CONFUSION MATRIX
          </div>
          <div
            className="mono"
            style={{
              fontSize: 11,
              color: "var(--text-mute)",
              marginTop: 4,
              lineHeight: 1.5,
            }}
          >
            Per-category decoder recall against the 245-sample supervised
            corpus + 10 negatives. Auto-cached for 10 min · click a category
            for the failing samples.
          </div>
        </div>
        <button
          className="nvx-btn primary sm"
          onClick={refresh}
          disabled={refreshing || loading}
          data-testid="confusion-refresh-btn"
        >
          <RefreshCw
            size={12}
            style={{ animation: refreshing ? "spin 0.8s linear infinite" : "none" }}
          />
          {refreshing ? "RECOMPUTING…" : "RECOMPUTE"}
        </button>
      </div>

      {loading ? (
        <div
          className="mono"
          style={{ padding: 16, fontSize: 11, color: "var(--text-mute)" }}
          data-testid="confusion-loading"
        >
          Loading matrix…
        </div>
      ) : error ? (
        <div
          className="mono"
          style={{ padding: 16, fontSize: 11, color: "var(--high)" }}
          data-testid="confusion-error"
        >
          ERROR: {error}
        </div>
      ) : !summary ? null : (
        <>
          {/* Overall metrics tiles */}
          <div
            style={{
              padding: 16,
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))",
              gap: 12,
              borderBottom: "1px solid var(--border)",
            }}
            data-testid="confusion-overall-tiles"
          >
            <MetricTile
              label="PRECISION"
              value={pct(ov?.precision)}
              hint={`${ov?.tp || 0} TP · ${ov?.fp || 0} FP`}
              tone="accent"
              testid="metric-precision"
            />
            <MetricTile
              label="RECALL"
              value={pct(ov?.recall)}
              hint={`${ov?.tp || 0} TP · ${ov?.fn || 0} FN`}
              tone={ov?.recall >= 0.95 ? "accent" : "warn"}
              testid="metric-recall"
            />
            <MetricTile
              label="F1"
              value={pct(ov?.f1)}
              hint="harmonic mean"
              tone="accent"
              testid="metric-f1"
            />
            <MetricTile
              label="ACCURACY"
              value={pct(ov?.accuracy)}
              hint={`${ov?.tp + ov?.tn} correct / ${
                (ov?.tp || 0) + (ov?.fn || 0) + (ov?.fp || 0) + (ov?.tn || 0)
              }`}
              tone="accent"
              testid="metric-accuracy"
            />
            <MetricTile
              label="AVG CONF"
              value={ov?.avg_confidence !== undefined ? `${ov.avg_confidence}` : "—"}
              hint="0-100 · decoder score"
              tone="mute"
              testid="metric-avg-confidence"
            />
            <MetricTile
              label="NEGATIVES"
              value={`${ov?.tn || 0} / ${(ov?.tn || 0) + (ov?.fp || 0)}`}
              hint={`${ov?.fp || 0} false positives`}
              tone={ov?.fp === 0 ? "accent" : "warn"}
              testid="metric-negatives"
            />
          </div>

          {/* Worst + best category lists */}
          <div
            style={{
              padding: 16,
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: 16,
            }}
          >
            <CategoryList
              title="WORST 5 · RECALL"
              icon={<TrendingDown size={12} style={{ color: "var(--high)" }} />}
              rows={summary.worst_5_recall || []}
              onClick={openDetail}
              expanded={expanded}
              testidPrefix="worst"
              badgeTone="warn"
            />
            <CategoryList
              title="BEST 5 · RECALL"
              icon={<TrendingUp size={12} style={{ color: "#7ee3c9" }} />}
              rows={summary.best_5_recall || []}
              onClick={openDetail}
              expanded={expanded}
              testidPrefix="best"
              badgeTone="accent"
            />
          </div>

          {/* Detail drawer */}
          {expanded && (
            <div
              style={{
                borderTop: "1px solid var(--border)",
                background: "var(--inset)",
              }}
              data-testid={`confusion-detail-${expanded}`}
            >
              <div
                style={{
                  padding: "10px 16px",
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  borderBottom: "1px solid var(--border)",
                }}
              >
                <div
                  className="mono"
                  style={{
                    fontSize: 11,
                    letterSpacing: "0.14em",
                    color: "var(--accent)",
                  }}
                >
                  <Activity
                    size={11}
                    style={{ verticalAlign: "middle", marginRight: 6 }}
                  />
                  {expanded.toUpperCase()} · FAILING SAMPLES
                </div>
                <button
                  className="nvx-btn ghost sm"
                  onClick={() => {
                    setExpanded(null);
                    setDetail(null);
                  }}
                  data-testid="confusion-detail-close"
                >
                  <X size={11} /> CLOSE
                </button>
              </div>
              {detailLoading ? (
                <div
                  className="mono"
                  style={{
                    padding: 16,
                    fontSize: 11,
                    color: "var(--text-mute)",
                  }}
                >
                  Loading failing samples…
                </div>
              ) : detail?._error ? (
                <div
                  className="mono"
                  style={{ padding: 16, fontSize: 11, color: "var(--high)" }}
                >
                  ERROR: {detail._error}
                </div>
              ) : (detail?.failures || []).length === 0 ? (
                <div
                  className="mono"
                  style={{
                    padding: 16,
                    fontSize: 11,
                    color: "var(--text-mute)",
                    display: "flex",
                    alignItems: "center",
                    gap: 8,
                  }}
                >
                  <CheckCircle2 size={12} style={{ color: "#7ee3c9" }} />
                  All {detail?.samples || 0} samples decoded correctly. Nothing
                  to fix in this category.
                </div>
              ) : (
                <div style={{ padding: 16, display: "grid", gap: 8 }}>
                  {detail.failures.map((f) => (
                    <div
                      key={f.id}
                      className="brut-border"
                      style={{ padding: 12, background: "var(--bg)" }}
                      data-testid={`confusion-failure-${f.id}`}
                    >
                      <div
                        style={{
                          display: "flex",
                          justifyContent: "space-between",
                          alignItems: "center",
                          marginBottom: 6,
                          gap: 8,
                          flexWrap: "wrap",
                        }}
                      >
                        <div
                          className="mono"
                          style={{
                            fontSize: 11,
                            color: "var(--text)",
                            fontWeight: 600,
                          }}
                        >
                          <XCircle
                            size={10}
                            style={{
                              color: "var(--high)",
                              verticalAlign: "middle",
                              marginRight: 6,
                            }}
                          />
                          {f.id}
                        </div>
                        <div
                          className="mono"
                          style={{ fontSize: 10, color: "var(--text-mute)" }}
                        >
                          engine={f.engine || "—"} · conf={f.confidence ?? "—"}
                        </div>
                      </div>
                      <div
                        className="mono"
                        style={{
                          fontSize: 10,
                          color: "var(--text-mute)",
                          lineHeight: 1.6,
                          wordBreak: "break-all",
                        }}
                      >
                        <div>
                          <span style={{ color: "#7ee3c9" }}>expected:</span>{" "}
                          {(f.expected || "").slice(0, 200)}
                        </div>
                        <div style={{ marginTop: 4 }}>
                          <span style={{ color: "var(--high)" }}>got:</span>{" "}
                          {(f.got || "").slice(0, 200)}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </>
      )}

      {/* Local keyframe for the refresh spinner */}
      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
      `}</style>
    </section>
  );
}


function MetricTile({ label, value, hint, tone, testid }) {
  const toneColor =
    tone === "accent"
      ? "#7ee3c9"
      : tone === "warn"
      ? "#f59e0b"
      : "var(--text-mute)";
  return (
    <div
      className="brut-border"
      style={{ padding: 12, background: "var(--inset)" }}
      data-testid={testid}
    >
      <div
        className="mono"
        style={{
          fontSize: 10,
          color: "var(--text-mute)",
          letterSpacing: "0.14em",
        }}
      >
        {label}
      </div>
      <div
        className="mono"
        style={{
          fontSize: 22,
          color: toneColor,
          marginTop: 6,
          fontWeight: 600,
        }}
      >
        {value}
      </div>
      <div
        className="mono"
        style={{ fontSize: 9, color: "var(--text-mute)", marginTop: 4 }}
      >
        {hint}
      </div>
    </div>
  );
}


function CategoryList({ title, icon, rows, onClick, expanded, testidPrefix, badgeTone }) {
  const badge =
    badgeTone === "warn"
      ? { border: "1px solid #f59e0b", color: "#f59e0b" }
      : { border: "1px solid #7ee3c9", color: "#7ee3c9" };
  return (
    <div data-testid={`confusion-${testidPrefix}-list`}>
      <div
        className="mono"
        style={{
          fontSize: 10,
          letterSpacing: "0.14em",
          color: "var(--text-mute)",
          marginBottom: 8,
          display: "flex",
          alignItems: "center",
          gap: 6,
        }}
      >
        {icon} {title}
      </div>
      <div style={{ display: "grid", gap: 6 }}>
        {rows.length === 0 ? (
          <div
            className="mono"
            style={{ fontSize: 11, color: "var(--text-mute)" }}
          >
            No data.
          </div>
        ) : (
          rows.map((c) => {
            const isOpen = expanded === c.category;
            return (
              <button
                key={c.category}
                className="brut-border"
                onClick={() => onClick(c.category)}
                data-testid={`${testidPrefix}-cat-${c.category}`}
                style={{
                  padding: "8px 12px",
                  background: isOpen ? "var(--inset)" : "var(--bg)",
                  border: isOpen
                    ? "1px solid var(--accent)"
                    : "1px solid var(--border)",
                  cursor: "pointer",
                  textAlign: "left",
                  display: "flex",
                  alignItems: "center",
                  gap: 10,
                  transition: "background 0.15s ease, border-color 0.15s ease",
                }}
              >
                <ChevronRight
                  size={11}
                  style={{
                    color: "var(--text-mute)",
                    transform: isOpen ? "rotate(90deg)" : "none",
                    transition: "transform 0.15s ease",
                  }}
                />
                <div style={{ flex: 1 }}>
                  <div
                    className="mono"
                    style={{ fontSize: 11, color: "var(--text)" }}
                  >
                    {c.category}
                  </div>
                  <div
                    className="mono"
                    style={{
                      fontSize: 9,
                      color: "var(--text-mute)",
                      marginTop: 2,
                    }}
                  >
                    {c.samples || 0} samples ·{" "}
                    {c.fn !== undefined ? `${c.fn} FN` : "—"} · F1{" "}
                    {c.f1 !== undefined ? c.f1.toFixed(3) : "—"}
                  </div>
                </div>
                <span
                  className="mono"
                  style={{
                    ...badge,
                    padding: "2px 8px",
                    fontSize: 10,
                    letterSpacing: "0.08em",
                    background: "transparent",
                  }}
                >
                  {(c.recall * 100).toFixed(1)}%
                </span>
              </button>
            );
          })
        )}
      </div>
    </div>
  );
}
