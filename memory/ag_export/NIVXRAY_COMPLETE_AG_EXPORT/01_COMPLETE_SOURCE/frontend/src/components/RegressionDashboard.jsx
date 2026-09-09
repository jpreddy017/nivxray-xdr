import { useState, useEffect } from "react";
import { Play, RefreshCw, TrendingUp, TrendingDown, AlertTriangle, CheckCircle2, Shield, ShieldAlert } from "lucide-react";
import api from "@/lib/api";

/**
 * RegressionDashboard — Feb-2026 #4 auto-benchmark UI.
 *
 * Shows:
 *   - Latest run summary (pass/fail counts, pass rate)
 *   - Gate status (permits or blocks decoder/library promotion)
 *   - New regressions (pass → fail flips) and resolved regressions (fail → pass)
 *   - Affected decoders
 *   - Run history strip
 */
function StatChip({ label, value, color, testid }) {
  return (
    <div
      style={{
        padding: "10px 14px",
        background: "rgba(15,23,42,0.5)",
        border: `1px solid ${color}33`,
        borderRadius: 4,
        minWidth: 110,
      }}
      data-testid={testid}
    >
      <div style={{ fontSize: 10, color: "#94a3b8", letterSpacing: 1 }}>{label}</div>
      <div style={{ fontSize: 22, color, fontWeight: 700, fontFamily: "monospace" }}>{value}</div>
    </div>
  );
}

function FlipRow({ flip, direction }) {
  const bad = direction === "regression";
  const color = bad ? "#f87171" : "#7ee3c9";
  const bg = bad ? "rgba(248,113,113,0.05)" : "rgba(126,227,201,0.05)";
  return (
    <div
      style={{
        display: "flex", alignItems: "flex-start", gap: 10,
        padding: "8px 10px", background: bg, borderRadius: 3, marginBottom: 4,
        fontSize: 11, color: "#c9d1d9",
      }}
      data-testid={`flip-${direction}-${flip.sample_id}`}
    >
      {bad ? <TrendingDown size={13} color={color} /> : <TrendingUp size={13} color={color} />}
      <div style={{ flex: 1 }}>
        <div style={{ color, fontFamily: "monospace", fontWeight: 600 }}>
          {flip.name || flip.sample_id?.slice(-8)}
        </div>
        <div style={{ opacity: 0.7 }}>
          {flip.from} → {flip.to} · diff: {flip.diff_type}
        </div>
        {bad && flip.expected && (
          <div style={{ fontFamily: "monospace", fontSize: 10, opacity: 0.55, marginTop: 3 }}>
            expected: {String(flip.expected).slice(0, 80)}
          </div>
        )}
        {bad && flip.actual && (
          <div style={{ fontFamily: "monospace", fontSize: 10, opacity: 0.55 }}>
            actual: {String(flip.actual).slice(0, 80)}
          </div>
        )}
      </div>
    </div>
  );
}

export default function RegressionDashboard() {
  const [latest, setLatest] = useState(null);
  const [gate, setGate] = useState(null);
  const [corpusSize, setCorpusSize] = useState(0);
  const [history, setHistory] = useState([]);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState(null);

  const refresh = async () => {
    setError(null);
    try {
      const [l, h] = await Promise.all([
        api.get("/regression/latest"),
        api.get("/regression/history?limit=15"),
      ]);
      setLatest(l.data.run);
      setGate(l.data.gate);
      setCorpusSize(l.data.corpus_size);
      setHistory(h.data.runs || []);
    } catch (e) {
      setError(e.response?.data?.detail || e.message);
    }
  };

  useEffect(() => {
    refresh();
  }, []);

  const runNow = async () => {
    setRunning(true);
    try {
      await api.post("/regression/run", {});
      await refresh();
    } catch (e) {
      setError(e.response?.data?.detail || e.message);
    } finally {
      setRunning(false);
    }
  };

  const passRate = latest?.pass_rate ?? gate?.last_pass_rate;
  const gatePermits =
    passRate == null ? null : passRate >= 1.0;
  const bandColor =
    passRate == null ? "#94a3b8"
      : passRate >= 1.0 ? "#7ee3c9"
        : passRate >= 0.9 ? "#f59e0b"
          : "#f87171";

  return (
    <div className="nvx-card" data-testid="regression-dashboard" style={{ marginBottom: 16 }}>
      <div className="nvx-card-head">
        <div className="nvx-card-title">
          <span className="dot" />
          REGRESSION DASHBOARD
        </div>
        <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{ fontSize: 11, color: "#94a3b8" }}>
            Corpus: <b style={{ color: "#c9d1d9" }}>{corpusSize}</b> samples
          </span>
          <button
            className="nvx-btn sm ghost"
            onClick={refresh}
            data-testid="regression-refresh"
          >
            <RefreshCw size={12} /> REFRESH
          </button>
          <button
            className="nvx-btn sm"
            onClick={runNow}
            disabled={running}
            data-testid="regression-run"
          >
            <Play size={12} /> {running ? "RUNNING…" : "RUN NOW"}
          </button>
        </div>
      </div>
      <div className="nvx-card-body">
        {/* Gate banner */}
        {gate && gate.last_run_id && (
          <div
            style={{
              padding: "10px 14px",
              background: gatePermits
                ? "rgba(126,227,201,0.06)" : "rgba(248,113,113,0.08)",
              border: `1px solid ${gatePermits ? "rgba(126,227,201,0.3)" : "rgba(248,113,113,0.3)"}`,
              borderRadius: 4,
              marginBottom: 14,
              display: "flex",
              alignItems: "center",
              gap: 10,
              fontSize: 12,
            }}
            data-testid="regression-gate-banner"
          >
            {gatePermits
              ? <Shield size={16} color="#7ee3c9" />
              : <ShieldAlert size={16} color="#f87171" />}
            <div>
              <span style={{ color: gatePermits ? "#7ee3c9" : "#f87171", fontWeight: 700 }}>
                {gatePermits ? "GATE PASSING" : "GATE BLOCKED"}
              </span>
              <span style={{ color: "#94a3b8", marginLeft: 8 }}>
                Last run: {gate.last_passed}/{gate.last_total} passed
                {" · "}
                {(passRate * 100).toFixed(1)}%
              </span>
              {!gatePermits && (
                <div style={{ fontSize: 11, color: "#f87171", marginTop: 4 }}>
                  Library promotion is BLOCKED until every sample passes.
                </div>
              )}
            </div>
          </div>
        )}

        {/* Summary stat chips */}
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap", marginBottom: 16 }}>
          <StatChip
            label="TOTAL"
            value={latest?.total ?? 0}
            color="#c9d1d9"
            testid="regression-stat-total"
          />
          <StatChip
            label="PASSED"
            value={latest?.passed ?? 0}
            color="#7ee3c9"
            testid="regression-stat-passed"
          />
          <StatChip
            label="FAILED"
            value={latest?.failed ?? 0}
            color="#f87171"
            testid="regression-stat-failed"
          />
          <StatChip
            label="PASS RATE"
            value={passRate == null ? "—" : `${(passRate * 100).toFixed(0)}%`}
            color={bandColor}
            testid="regression-stat-passrate"
          />
          <StatChip
            label="NEW REGRESSIONS"
            value={latest?.new_regressions?.length ?? 0}
            color={latest?.new_regressions?.length ? "#f87171" : "#94a3b8"}
            testid="regression-stat-newregs"
          />
          <StatChip
            label="RESOLVED"
            value={latest?.resolved_regressions?.length ?? 0}
            color={latest?.resolved_regressions?.length ? "#7ee3c9" : "#94a3b8"}
            testid="regression-stat-resolved"
          />
        </div>

        {/* Regressions + resolved */}
        {latest?.new_regressions?.length > 0 && (
          <div style={{ marginBottom: 14 }}>
            <div
              style={{
                fontSize: 11, color: "#f87171", fontWeight: 600, marginBottom: 6,
                display: "flex", gap: 6, alignItems: "center",
              }}
            >
              <AlertTriangle size={13} />
              NEW REGRESSIONS ({latest.new_regressions.length})
            </div>
            {latest.new_regressions.map((f, i) => (
              <FlipRow key={i} flip={f} direction="regression" />
            ))}
          </div>
        )}

        {latest?.resolved_regressions?.length > 0 && (
          <div style={{ marginBottom: 14 }}>
            <div
              style={{
                fontSize: 11, color: "#7ee3c9", fontWeight: 600, marginBottom: 6,
                display: "flex", gap: 6, alignItems: "center",
              }}
            >
              <CheckCircle2 size={13} />
              RESOLVED REGRESSIONS ({latest.resolved_regressions.length})
            </div>
            {latest.resolved_regressions.map((f, i) => (
              <FlipRow key={i} flip={f} direction="resolved" />
            ))}
          </div>
        )}

        {/* Affected decoders */}
        {latest?.affected_decoders?.length > 0 && (
          <div style={{ marginBottom: 14 }}>
            <div style={{ fontSize: 11, color: "#7ee3c9", fontWeight: 600, marginBottom: 6 }}>
              AFFECTED DECODERS ({latest.affected_decoders.length})
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
              {latest.affected_decoders.map((op) => (
                <span
                  key={op}
                  style={{
                    padding: "2px 8px",
                    background: "rgba(245,158,11,0.10)",
                    color: "#f59e0b",
                    borderRadius: 3,
                    fontSize: 11,
                    fontFamily: "monospace",
                  }}
                >
                  {op}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Run history strip */}
        {history.length > 0 && (
          <div>
            <div style={{ fontSize: 11, color: "#7ee3c9", fontWeight: 600, marginBottom: 6 }}>
              RECENT RUNS ({history.length})
            </div>
            <div style={{ display: "flex", gap: 4, alignItems: "flex-end", height: 40 }}>
              {history.slice().reverse().map((run, i) => {
                const pr = run.pass_rate ?? 0;
                const h = Math.max(4, pr * 40);
                const color = pr >= 1.0 ? "#7ee3c9" : pr >= 0.9 ? "#f59e0b" : "#f87171";
                return (
                  <div
                    key={i}
                    title={`${run.finished_at?.slice(0, 19)}\n${run.passed}/${run.total} passed\ntrigger: ${run.trigger}`}
                    style={{
                      width: 12,
                      height: h,
                      background: color,
                      borderRadius: 1,
                    }}
                  />
                );
              })}
            </div>
          </div>
        )}

        {!latest && !error && (
          <div style={{ fontSize: 12, color: "#94a3b8", padding: 20, textAlign: "center" }}>
            No regression runs recorded yet. Add samples to the corpus and click <b>RUN NOW</b>.
          </div>
        )}

        {error && (
          <div
            style={{
              padding: 10,
              background: "rgba(248,113,113,0.08)",
              color: "#f87171",
              fontSize: 11,
              borderRadius: 4,
            }}
            data-testid="regression-error"
          >
            {String(error)}
          </div>
        )}
      </div>
    </div>
  );
}
