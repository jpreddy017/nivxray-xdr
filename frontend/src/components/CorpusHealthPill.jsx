/**
 * CorpusHealthPill — live-pulsing chip next to the NIVXRAY wordmark
 * that reflects the current Golden-Corpus benchmark gate.
 *
 * Polls `/api/rc5/golden/summary` every 60 s and colours the chip:
 *   • Green pulsing → gate PASSING     (all corpus samples ok, no regressions)
 *   • Amber pulsing → gate REGRESSED   (some failures or drift detected)
 *   • Grey static  → data unavailable (endpoint offline / not seeded)
 *
 * Tooltip surfaces pass-rate / regression count so analysts can hover
 * for the numbers without leaving the current page.
 */
import { useEffect, useRef, useState } from "react";
import { CheckCircle2, AlertTriangle, Loader2 } from "lucide-react";
import { toast } from "sonner";
import api from "@/lib/api";

const POLL_MS = 60_000;

export default function CorpusHealthPill() {
  const [state, setState] = useState({ loading: true });
  // Track previous gate so we only toast on the transition, not on
  // every poll. Persist across polls but scoped to the component.
  const prevGateRef = useRef(null);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const { data } = await api.get("/rc5/golden/summary");
        if (cancelled) return;
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

  const title = loading
    ? "Polling /api/rc5/golden/summary…"
    : !hasData
      ? "No corpus history yet — trigger a benchmark run to populate."
      : gateOk
        ? `Golden gate PASSING · ${passed}/${total} samples · ${rate.toFixed(1)}% pass rate`
        : `Golden gate REGRESSED · ${failed} failure${failed === 1 ? "" : "s"} · ${passed}/${total} passed`;

  return (
    <span
      data-testid="corpus-health-pill"
      data-gate={loading ? "loading" : hasData ? (gateOk ? "pass" : "fail") : "idle"}
      title={title}
      style={{
        display: "inline-flex", alignItems: "center", gap: 6,
        padding: "3px 9px",
        borderRadius: 999,
        background: tone.fill,
        border: `1px solid ${tone.ring}`,
        color: tone.fg,
        fontFamily: "JetBrains Mono, ui-monospace, monospace",
        fontSize: 9, letterSpacing: "0.14em", fontWeight: 700,
        whiteSpace: "nowrap",
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
