/**
 * Summary lens · Blueprint §9 · PR-4.
 *
 * Reads deterministic executive_summary output from the L2 service and
 * renders:
 *   - Verdict pill (malicious / suspicious / unknown)
 *   - Risk bucket + numeric score
 *   - Family / technique attribution
 *   - Canonical-state readiness
 *   - Top 3 IOCs
 *   - Top 3 recommended actions (evidence-anchored)
 *   - Evidence-anchored bullets
 *
 * Every visible chip/row carries a data-testid so tests can drive it.
 * Every anchored element (IOC / action / bullet) exposes its anchor on
 * click via `onAnchorClick` — the PR-5 Evidence lens will consume this.
 */
import React, { useCallback, useEffect, useState } from "react";
import api from "./investigationApi";
import {
  TID_SUMMARY_LENS,
  TID_SUMMARY_LOADING,
  TID_SUMMARY_ERROR,
  TID_SUMMARY_VERDICT,
  TID_SUMMARY_RISK,
  TID_SUMMARY_RISK_SCORE,
  TID_SUMMARY_FAMILY,
  TID_SUMMARY_TECHNIQUE,
  TID_SUMMARY_CANONICAL,
  TID_SUMMARY_TOP_IOCS,
  TID_SUMMARY_TOP_IOC,
  TID_SUMMARY_TOP_ACTIONS,
  TID_SUMMARY_ACTION,
  TID_SUMMARY_BULLETS,
  TID_SUMMARY_BULLET,
} from "./testIds";

const VERDICT_STYLE = {
  malicious:  "bg-rose-950 text-rose-200 border-rose-700",
  suspicious: "bg-amber-950 text-amber-200 border-amber-700",
  unknown:    "bg-slate-800 text-slate-200 border-slate-600",
};

const RISK_STYLE = {
  critical:      "bg-rose-900 text-rose-100 border-rose-600",
  high:          "bg-orange-900 text-orange-100 border-orange-600",
  medium:        "bg-amber-900 text-amber-100 border-amber-600",
  low:           "bg-sky-900 text-sky-100 border-sky-600",
  informational: "bg-slate-800 text-slate-300 border-slate-600",
};

export default function SummaryLens({ caseId, onAnchorClick }) {
  const [status, setStatus] = useState("loading"); // loading · ready · error
  const [data, setData]     = useState(null);
  const [error, setError]   = useState("");

  const load = useCallback(async () => {
    if (!caseId) return;
    setStatus("loading");
    setError("");
    try {
      const res = await api.getService(caseId, "summary");
      setData(res.body || {});
      setStatus("ready");
    } catch (e) {
      setError(e?.response?.data?.detail || e?.message || "load_failed");
      setStatus("error");
    }
  }, [caseId]);

  useEffect(() => { load(); }, [load]);

  if (status === "loading") {
    return (
      <div
        data-testid={TID_SUMMARY_LOADING}
        className="flex flex-1 items-center justify-center px-4 py-16 text-sm text-slate-400"
      >
        Loading executive summary…
      </div>
    );
  }
  if (status === "error") {
    return (
      <div
        data-testid={TID_SUMMARY_ERROR}
        className="flex flex-1 items-center justify-center px-4 py-16 text-sm text-rose-300"
      >
        Failed to load summary: {error}
      </div>
    );
  }

  const {
    verdict,
    risk,
    risk_score,
    family,
    technique,
    ready_for_behavioral_analysis,
    top_iocs = [],
    top_actions = [],
    bullets = [],
  } = data || {};

  const anchor = (a) => onAnchorClick?.(a);

  return (
    <section
      data-testid={TID_SUMMARY_LENS}
      className="flex flex-1 flex-col gap-6 px-6 py-6"
    >
      {/* Verdict + risk row */}
      <div className="flex flex-wrap items-center gap-3">
        <span
          data-testid={TID_SUMMARY_VERDICT}
          className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-medium uppercase tracking-wider ${VERDICT_STYLE[verdict] || VERDICT_STYLE.unknown}`}
        >
          Verdict · {verdict || "unknown"}
        </span>
        <span
          data-testid={TID_SUMMARY_RISK}
          className={`inline-flex items-center rounded-full border px-3 py-1 text-xs font-medium uppercase tracking-wider ${RISK_STYLE[risk] || RISK_STYLE.informational}`}
        >
          Risk · {risk || "informational"}
        </span>
        <span
          data-testid={TID_SUMMARY_RISK_SCORE}
          className="rounded-md border border-slate-700 bg-slate-900 px-3 py-1 font-mono text-xs text-slate-300"
        >
          {typeof risk_score === "number" ? `${risk_score}/100` : "—/100"}
        </span>
        {ready_for_behavioral_analysis ? (
          <span
            data-testid={TID_SUMMARY_CANONICAL}
            className="rounded-md border border-emerald-800 bg-emerald-950 px-3 py-1 text-xs text-emerald-200"
          >
            Canonical · ready for behavioural analysis
          </span>
        ) : (
          <span
            data-testid={TID_SUMMARY_CANONICAL}
            className="rounded-md border border-rose-800 bg-rose-950 px-3 py-1 text-xs text-rose-200"
          >
            Residual obfuscation remains
          </span>
        )}
      </div>

      {/* Attribution row */}
      {(family || technique) ? (
        <div className="flex flex-wrap gap-4 text-xs text-slate-400">
          {family ? (
            <span data-testid={TID_SUMMARY_FAMILY}>
              <span className="uppercase tracking-widest text-slate-500">Family: </span>
              <span className="font-mono text-slate-200">{family}</span>
            </span>
          ) : null}
          {technique ? (
            <span data-testid={TID_SUMMARY_TECHNIQUE}>
              <span className="uppercase tracking-widest text-slate-500">Technique: </span>
              <span className="font-mono text-slate-200">{technique}</span>
            </span>
          ) : null}
        </div>
      ) : null}

      {/* Bullets */}
      {bullets.length ? (
        <div>
          <p className="mb-2 text-xs uppercase tracking-widest text-slate-500">Executive bullets</p>
          <ul
            data-testid={TID_SUMMARY_BULLETS}
            className="space-y-2"
          >
            {bullets.map((b) => (
              <li
                key={b.bullet_id}
                data-testid={TID_SUMMARY_BULLET(b.bullet_id)}
                onClick={() => anchor(b.anchor)}
                className="cursor-pointer rounded-md border border-slate-800 bg-slate-900/40 px-3 py-2 text-sm text-slate-200 transition hover:border-indigo-700 hover:bg-slate-900"
                title={`Anchor · ${b.anchor?.kind || "n/a"}`}
              >
                {b.text}
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {/* Top IOCs */}
      {top_iocs.length ? (
        <div>
          <p className="mb-2 text-xs uppercase tracking-widest text-slate-500">Top IOCs</p>
          <ul
            data-testid={TID_SUMMARY_TOP_IOCS}
            className="space-y-2"
          >
            {top_iocs.map((ioc) => (
              <li
                key={ioc.ioc_id}
                data-testid={TID_SUMMARY_TOP_IOC(ioc.ioc_id)}
                onClick={() => anchor({ kind: "ioc", ioc_id: ioc.ioc_id, iteration: ioc.source_iteration })}
                className="flex cursor-pointer items-center gap-3 rounded-md border border-slate-800 bg-slate-900/40 px-3 py-2 text-sm transition hover:border-indigo-700 hover:bg-slate-900"
              >
                <span className="rounded-md bg-slate-800 px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-slate-300">
                  {ioc.ioc_type}
                </span>
                <span className="font-mono text-sm text-slate-100 break-all">{ioc.value}</span>
                <span className="ml-auto font-mono text-[10px] text-slate-500">
                  iter {ioc.source_iteration}
                </span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {/* Top Actions */}
      {top_actions.length ? (
        <div>
          <p className="mb-2 text-xs uppercase tracking-widest text-slate-500">Recommended actions</p>
          <ol
            data-testid={TID_SUMMARY_TOP_ACTIONS}
            className="space-y-2"
          >
            {top_actions.map((a) => (
              <li
                key={a.action_id}
                data-testid={TID_SUMMARY_ACTION(a.action_id)}
                onClick={() => anchor(a.anchor)}
                className="flex cursor-pointer items-start gap-3 rounded-md border border-slate-800 bg-slate-900/40 px-3 py-2 text-sm transition hover:border-indigo-700 hover:bg-slate-900"
              >
                <span className="mt-0.5 rounded-md border border-amber-800 bg-amber-950 px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-amber-200">
                  {a.priority}
                </span>
                <span className="text-slate-100">{a.text}</span>
              </li>
            ))}
          </ol>
        </div>
      ) : null}
    </section>
  );
}
