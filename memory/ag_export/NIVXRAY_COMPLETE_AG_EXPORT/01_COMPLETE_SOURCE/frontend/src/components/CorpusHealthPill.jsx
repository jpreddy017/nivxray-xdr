/**
 * CorpusHealthPill — live-pulsing chip next to the NIVXRAY wordmark
 * that reflects the current Golden-Corpus benchmark gate.
 *
 * Polls `/api/rc5/golden/summary` every 60 s and colours the chip:
 *   • Green pulsing → gate PASSING     (all corpus samples ok, no regressions)
 *   • Amber pulsing → gate REGRESSED   (some failures or drift detected)
 *   • Grey static  → data unavailable (endpoint offline / not seeded)
 *
 * Custom hover tooltip surfaces:
 *   • pass rate / regression count numbers (the numbers a `title`
 *     attribute used to show), and
 *   • a 7-run rolling pass-rate SPARKLINE fetched from
 *     `/api/rc5/golden/history?limit=7` — no mocks, real historical
 *     data only. Gracefully hides itself when the endpoint has fewer
 *     than 2 samples to draw a line from.
 */
import { useEffect, useRef, useState } from "react";
import { CheckCircle2, AlertTriangle, Loader2 } from "lucide-react";
import { toast } from "sonner";
import api from "@/lib/api";

const POLL_MS = 60_000;

export default function CorpusHealthPill() {
  const [state, setState] = useState({ loading: true });
  const [history, setHistory] = useState([]);   // [{ ts, pass_rate }]
  const [hover, setHover] = useState(false);
  // Track previous gate so we only toast on the transition, not on
  // every poll. Persist across polls but scoped to the component.
  const prevGateRef = useRef(null);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        // Summary + history in parallel — history is best-effort and
        // must NEVER break the pill if it errors out.
        const [summaryRes, historyRes] = await Promise.all([
          api.get("/rc5/golden/summary"),
          api.get("/rc5/golden/history?limit=7").catch(() => null),
        ]);
        if (cancelled) return;

        const data = summaryRes?.data || {};
        const passed = data?.passed ?? 0;
        const total  = data?.total ?? 0;
        const failed = data?.failed ?? 0;
        const rate   = total > 0 ? (passed / total) * 100 : 0;
        const gateOk = failed === 0 && total > 0;

        // Regression detection: previous poll was PASS, this poll is
        // FAIL → surface a subtle toast so the analyst is warned even
        // if they aren't looking at the pill.
        if (prevGateRef.current === true && gateOk === false && total > 0) {
          toast.warning("Corpus regression detected", {
            description: `${failed} sample${failed === 1 ? "" : "s"} now failing (${passed}/${total} passing). Check /benchmark for the diff.`,
            duration: 10000,
            id: "corpus-regression-alert",
          });
        }
        // Recovery signal — pill was failing, is now green again.
        if (prevGateRef.current === false && gateOk === true) {
          toast.success("Corpus back to green", {
            description: `All ${total} samples passing again.`,
            duration: 6000,
            id: "corpus-recovery-alert",
          });
        }
        prevGateRef.current = total > 0 ? gateOk : null;

        setState({ loading: false, gateOk, passed, total, failed, rate,
                   hasData: total > 0 });

        // History for the sparkline. `pass_rate` in the API is a
        // 0.0-1.0 fraction — normalise to percent so the sparkline
        // axis is consistent with the summary label.
        const rows = Array.isArray(historyRes?.data) ? historyRes.data : [];
        const trend = rows
          .filter(r => Number.isFinite(r?.pass_rate) || (r?.total > 0))
          .map(r => ({
            ts: r?.ts || null,
            pct: Number.isFinite(r?.pass_rate)
              ? (r.pass_rate <= 1 ? r.pass_rate * 100 : r.pass_rate)
              : ((r?.passed || 0) / Math.max(1, r?.total || 1)) * 100,
            passed: r?.passed || 0,
            total:  r?.total  || 0,
          }));
        setHistory(trend);
      } catch {
        if (!cancelled) setState({ loading: false, hasData: false });
      }
    };
    load();
    const id = setInterval(load, POLL_MS);
    return () => { cancelled = true; clearInterval(id); };
  }, []);

  const { loading, gateOk, passed, total, failed, rate, hasData } = state;

  const tone = loading || !hasData
    ? { fg: "#94a3b8", ring: "rgba(148,163,184,0.35)", fill: "rgba(148,163,184,0.10)" }
    : gateOk
      ? { fg: "#86efac", ring: "rgba(34,197,94,0.55)", fill: "rgba(34,197,94,0.14)" }
      : { fg: "#fcd34d", ring: "rgba(245,158,11,0.55)", fill: "rgba(245,158,11,0.14)" };

  const Icon = loading ? Loader2 : (gateOk ? CheckCircle2 : AlertTriangle);
  const label = loading
    ? "CHECKING…"
    : !hasData
      ? "CORPUS · IDLE"
      : gateOk
        ? `CORPUS · ${passed}/${total}`
        : `CORPUS · ${failed} FAIL`;

  const headline = loading
    ? "Polling /api/rc5/golden/summary…"
    : !hasData
      ? "No corpus history yet — trigger a benchmark run to populate."
      : gateOk
        ? `Golden gate PASSING · ${passed}/${total} · ${rate.toFixed(1)}% pass`
        : `Golden gate REGRESSED · ${failed} fail · ${passed}/${total} passed`;

  return (
    <span
      data-testid="corpus-health-pill"
      data-gate={loading ? "loading" : hasData ? (gateOk ? "pass" : "fail") : "idle"}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      style={{
        position: "relative",
        display: "inline-flex", alignItems: "center", gap: 6,
        padding: "3px 9px",
        borderRadius: 999,
        background: tone.fill,
        border: `1px solid ${tone.ring}`,
        color: tone.fg,
        fontFamily: "JetBrains Mono, ui-monospace, monospace",
        fontSize: 9, letterSpacing: "0.14em", fontWeight: 700,
        whiteSpace: "nowrap",
        cursor: "default",
      }}
    >
      <span
        aria-hidden
        style={{
          width: 7, height: 7, borderRadius: "50%",
          background: tone.fg,
          boxShadow: `0 0 6px ${tone.fg}`,
          animation: loading ? "none"
                    : hasData ? "nvx-pulse 1.6s ease-in-out infinite"
                    : "none",
        }}
      />
      <Icon
        size={11}
        strokeWidth={2}
        style={{ animation: loading ? "spin 1s linear infinite" : "none" }}
      />
      <span>{label}</span>

      {hover && (
        <CorpusTooltip
          headline={headline}
          history={history}
          tone={tone}
          gateOk={gateOk}
          hasData={hasData}
        />
      )}

      {/* Local keyframes — scoped to this component via a data attribute
          so we don't pollute the global stylesheet. */}
      <style>{`
        @keyframes nvx-pulse {
          0%, 100% { opacity: 1;    box-shadow: 0 0 6px  ${tone.fg}; }
          50%      { opacity: 0.55; box-shadow: 0 0 14px ${tone.fg}; }
        }
      `}</style>
    </span>
  );
}

/* ────────────────────────────────────────────────────────────────
 * CorpusTooltip
 *   • Headline copy (numeric)
 *   • 7-run pass-rate sparkline (SVG, no third-party lib)
 *   • Hidden when history has < 2 samples
 * ─────────────────────────────────────────────────────────────── */
function CorpusTooltip({ headline, history, tone, gateOk, hasData }) {
  const W = 200, H = 42, PAD = 4;
  const canPlot = history.length >= 2;

  let pathD = "";
  let lastX = 0, lastY = 0;
  let minPct = 100, maxPct = 0;
  if (canPlot) {
    for (const h of history) {
      if (h.pct < minPct) minPct = h.pct;
      if (h.pct > maxPct) maxPct = h.pct;
    }
    // add a bit of head-room so a totally flat 100% line isn't stuck
    // to the top edge.
    const span = Math.max(1, maxPct - minPct);
    const yFor = (p) => H - PAD - ((p - minPct) / span) * (H - PAD * 2);
    const xFor = (i) => PAD + (i / (history.length - 1)) * (W - PAD * 2);
    pathD = history.map((h, i) => {
      const x = xFor(i), y = yFor(h.pct);
      if (i === 0) { lastX = x; lastY = y; return `M ${x.toFixed(1)} ${y.toFixed(1)}`; }
      lastX = x; lastY = y;
      return `L ${x.toFixed(1)} ${y.toFixed(1)}`;
    }).join(" ");
  }

  return (
    <div
      data-testid="corpus-health-tooltip"
      role="tooltip"
      style={{
        position: "absolute",
        top: "calc(100% + 8px)",
        left: 0,
        minWidth: 220,
        padding: "10px 12px",
        background: "linear-gradient(160deg, rgba(15,23,42,0.98), rgba(2,6,23,0.95))",
        border: "1px solid rgba(148,163,184,0.22)",
        borderLeft: `2px solid ${tone.fg}`,
        borderRadius: 8,
        boxShadow: "0 16px 32px rgba(2,6,23,0.65), inset 0 1px 0 rgba(255,255,255,0.04)",
        backdropFilter: "blur(18px) saturate(160%)",
        color: "#e2e8f0",
        fontFamily: "JetBrains Mono, ui-monospace, monospace",
        fontSize: 10,
        letterSpacing: "0.02em",
        zIndex: 60,
        pointerEvents: "none",
      }}
    >
      <div style={{
        fontSize: 9, letterSpacing: "0.18em", color: tone.fg,
        fontWeight: 700, marginBottom: 6,
      }}>
        {hasData ? (gateOk ? "CORPUS · PASS" : "CORPUS · REGRESSED") : "CORPUS · IDLE"}
      </div>
      <div style={{ color: "#cbd5e1", marginBottom: canPlot ? 8 : 0 }}>
        {headline}
      </div>
      {canPlot && (
        <div data-testid="corpus-health-sparkline">
          <div style={{
            fontSize: 8, letterSpacing: "0.20em", color: "rgba(148,163,184,0.7)",
            marginBottom: 3,
          }}>
            LAST {history.length} RUNS · PASS-RATE
          </div>
          <svg width={W} height={H} viewBox={`0 0 ${W} ${H}`} style={{ display: "block" }}>
            {/* baseline */}
            <line x1={PAD} y1={H - PAD} x2={W - PAD} y2={H - PAD}
                  stroke="rgba(148,163,184,0.18)" strokeWidth="0.5" />
            {/* filled area under the curve for visual weight */}
            <path
              d={`${pathD} L ${lastX.toFixed(1)} ${H - PAD} L ${PAD} ${H - PAD} Z`}
              fill={tone.fg}
              fillOpacity="0.10"
            />
            <path
              d={pathD}
              fill="none"
              stroke={tone.fg}
              strokeWidth="1.4"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
            {/* dot for the most recent point */}
            <circle cx={lastX} cy={lastY} r="2.2" fill={tone.fg}
                    stroke="rgba(2,6,23,0.85)" strokeWidth="0.8" />
          </svg>
          <div style={{
            display: "flex", justifyContent: "space-between",
            fontSize: 8, color: "rgba(148,163,184,0.7)", marginTop: 2,
          }}>
            <span>min {Math.round(minPct)}%</span>
            <span>now {Math.round(history[history.length - 1].pct)}%</span>
            <span>max {Math.round(maxPct)}%</span>
          </div>
        </div>
      )}
      {!canPlot && hasData && (
        <div style={{ fontSize: 9, color: "rgba(148,163,184,0.65)", marginTop: 4 }}>
          Sparkline appears once ≥ 2 runs are in history.
        </div>
      )}
    </div>
  );
}
