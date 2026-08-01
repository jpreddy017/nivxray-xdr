import React, { useEffect, useState } from "react";
import { Sparkles, ChevronDown, ChevronRight, Copy } from "lucide-react";
import api from "../../lib/api";

/**
 * LearningAppliedPanel — projects `cio.metadata.learning_applied` OR
 * fetches `/learning-engine/context` for the current CIO. Renders a
 * compact, honest strip that tells the analyst exactly what past
 * knowledge influenced this investigation.
 *
 * Design contract:
 *   • Never lies. If `applied=false`, the panel says so and explains why.
 *   • Only surfaces terminology + structure references. Never claims
 *     verdict/decision was learned — those stay deterministic.
 */
export function LearningAppliedPanel({ cio }) {
  const [ctx, setCtx] = useState(null);
  const [expanded, setExpanded] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!cio) return;
    let alive = true;
    setLoading(true);
    setError(null);
    api.post("/learning-engine/context", { cio, surface: "summary", limit: 5 })
      .then((r) => { if (alive) setCtx(r.data); })
      .catch((e) => { if (alive) setError(e?.response?.status ? `HTTP ${e.response.status}` : String(e?.message || e)); })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [cio?.snapshot_hash, cio?.verdict?.label]);

  if (loading) return (
    <div className="learning-applied learning-loading" data-testid="learning-applied-loading">
      <Sparkles size={12} /> Learning Engine · retrieving similar cases…
    </div>
  );

  if (error) return (
    <div className="learning-applied learning-error" data-testid="learning-applied-error">
      Learning Engine unavailable · {error}
    </div>
  );

  if (!ctx) return null;

  const applied = ctx.applied === true;
  const matches = ctx.matches || [];
  const conf = ctx.confidence || "none";
  const fp = ctx.fingerprint || {};

  return (
    <div className={`learning-applied learning-${conf}`} data-testid="learning-applied">
      <button
        type="button"
        className="learning-head"
        onClick={() => setExpanded((v) => !v)}
        data-testid="learning-applied-toggle"
      >
        {expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        <Sparkles size={12} />
        <span className="learning-title">
          {applied ? (
            <>Learning applied · <b>{matches.length}</b> similar case{matches.length === 1 ? "" : "s"} · top match <b>{Math.round(ctx.top_similarity * 100)}%</b></>
          ) : matches.length > 0 ? (
            <>Learning available · <b>{matches.length}</b> weak match{matches.length === 1 ? "" : "es"} below apply-threshold ({Math.round(ctx.apply_threshold * 100)}%)</>
          ) : (
            <>No past analyst summary matches this pattern yet · corpus is cold-start for this fingerprint</>
          )}
        </span>
        <span className={`learning-conf-chip conf-${conf}`}>{conf.toUpperCase()}</span>
      </button>

      {expanded ? (
        <div className="learning-body">
          <div className="learning-fp">
            <span className="quiet">Fingerprint · </span>
            <b>{fp.verdict_label || "?"}</b>
            {fp.mitre_ids && fp.mitre_ids.length > 0 ? <span> · MITRE {fp.mitre_ids.join(", ")}</span> : null}
            {fp.lolbins && fp.lolbins.length > 0 ? <span> · LOLBIN {fp.lolbins.join(", ")}</span> : null}
            {fp.ioc_kinds && fp.ioc_kinds.length > 0 ? <span> · IOC {fp.ioc_kinds.join(", ")}</span> : null}
            <span className="quiet mono"> · hash {fp.hash}</span>
          </div>

          {matches.length === 0 ? (
            <div className="learning-empty">
              No past analyst summaries share this fingerprint. Once you save a Manual Summary
              for this or a similar investigation, the Learning Engine will surface it here
              on the next matching case.
            </div>
          ) : (
            <ul className="learning-matches" data-testid="learning-matches">
              {matches.map((m, i) => (
                <li key={m.id} className="learning-match" data-testid={`learning-match-${i}`}>
                  <div className="learning-match-head">
                    <span className="learning-match-sim">{Math.round(m.similarity * 100)}%</span>
                    <span className="learning-match-verdict">{m.verdict_label}</span>
                    <span className="learning-match-author quiet">{m.author}</span>
                    <span className="learning-match-date quiet">{(m.created_at || "").slice(0, 10)}</span>
                    <button
                      className="learning-match-copy"
                      type="button"
                      title="Copy analyst text"
                      onClick={() => navigator.clipboard?.writeText(m.analyst_text || "")}
                    >
                      <Copy size={11} />
                    </button>
                  </div>
                  <div className="learning-match-text">
                    {(m.analyst_text || "").slice(0, 260)}{(m.analyst_text || "").length > 260 ? "…" : ""}
                  </div>
                </li>
              ))}
            </ul>
          )}

          <div className="learning-honesty quiet">
            The Learning Engine retrieves similar past analyst summaries and surfaces them here.
            It does <b>not</b> modify the deterministic verdict or evidence graph — only analyst-facing
            narrative (Executive Summary, Story) can be seeded from these matches.
          </div>
        </div>
      ) : null}
    </div>
  );
}
