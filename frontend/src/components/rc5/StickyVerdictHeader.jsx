/**
 * RC5 · Sticky Verdict Header — always-visible summary that stays
 * pinned as the analyst scrolls the dashboard.
 *
 * Props:
 *   verdict: { verdict, risk, scores, top_reasons, cap_applied, floor_applied }
 *   xDecodeMs?: string | number
 *   runId?: string
 */
import React from "react";

const TIER_BG = {
  Benign:     { fill: "bg-emerald-500", text: "text-emerald-950" },
  Suspicious: { fill: "bg-amber-500",   text: "text-amber-950"   },
  Malicious:  { fill: "bg-red-500",     text: "text-red-50"      },
  Critical:   { fill: "bg-rose-600",    text: "text-rose-50"     },
};

const DIM_LABELS = {
  capability: "CAP",
  execution: "EXEC",
  persistence: "PERS",
  network: "NET",
  evasion: "EVA",
  impact: "IMP",
  intent: "INT",
};

export const StickyVerdictHeader = ({ verdict, xDecodeMs, runId }) => {
  const tier = verdict?.verdict?.value || verdict?.verdict || "—";
  const risk = verdict?.risk ?? verdict?.risk_score ?? 0;
  const scores = verdict?.scores || {};
  const style = TIER_BG[tier] || { fill: "bg-slate-700", text: "text-slate-200" };

  return (
    <div
      className="sticky top-0 z-40 w-full bg-slate-950/95 backdrop-blur-xl
                 border-b border-slate-800 px-4 py-2.5"
      data-testid="sticky-verdict-header"
    >
      <div className="max-w-7xl mx-auto flex items-center gap-4">
        {/* Verdict badge */}
        <div className="flex items-center gap-2">
          <div
            className={`px-3 py-1.5 rounded-sm text-[11px] font-mono uppercase
                       tracking-[0.15em] font-bold ${style.fill} ${style.text}`}
            data-testid="verdict-tier-badge"
          >
            {tier}
          </div>
          <div className="flex items-baseline gap-1">
            <span className="text-2xl font-mono font-semibold text-slate-100"
                  data-testid="verdict-risk-score">
              {risk}
            </span>
            <span className="text-[10px] font-mono uppercase tracking-wider text-slate-500">
              /100 risk
            </span>
          </div>
        </div>

        {/* 7-dimension mini bars */}
        <div className="hidden lg:flex items-center gap-2 flex-1 justify-center">
          {Object.entries(DIM_LABELS).map(([k, label]) => {
            const v = Math.max(0, Math.min(100, scores[k] ?? 0));
            return (
              <div key={k} className="flex flex-col items-center gap-0.5 min-w-[36px]">
                <div className="w-full h-1 bg-slate-800 rounded-sm overflow-hidden">
                  <div
                    className="h-full bg-sky-500"
                    style={{ width: `${v}%` }}
                    data-testid={`dim-bar-${k}`}
                  />
                </div>
                <span className="text-[9px] font-mono uppercase tracking-wider text-slate-500">
                  {label}
                </span>
                <span className="text-[9px] font-mono text-slate-400">{v}</span>
              </div>
            );
          })}
        </div>

        {/* Meta */}
        <div className="flex items-center gap-3 text-[10px] font-mono text-slate-500">
          {verdict?.cap_applied ? (
            <span className="border border-amber-800 text-amber-400 px-1.5 py-0.5 rounded-sm"
                  title="Cap applied — verdict was capped">CAP</span>
          ) : null}
          {verdict?.floor_applied ? (
            <span className="border border-emerald-800 text-emerald-400 px-1.5 py-0.5 rounded-sm"
                  title="Floor applied — verdict was floored">FLOOR</span>
          ) : null}
          {xDecodeMs != null ? (
            <span>· {xDecodeMs}ms decode</span>
          ) : null}
          {runId ? (
            <span className="truncate max-w-[120px]" title={runId}>· {runId}</span>
          ) : null}
        </div>
      </div>
    </div>
  );
};

export default StickyVerdictHeader;
