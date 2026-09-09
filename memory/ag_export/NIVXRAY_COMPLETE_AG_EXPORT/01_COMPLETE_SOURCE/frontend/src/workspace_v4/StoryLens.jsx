/**
 * Story lens · Blueprint §9 · PR-4.
 *
 * Reads deterministic attack_story output from the L2 service and
 * renders:
 *   - Human-readable narrative (deterministic prose)
 *   - Ordered chapter list (Unwrap · Normalize · Decode · Interpret)
 *   - Event list, each event evidence-anchored to a transformation
 *     iteration (§8.4). Clicking an event surfaces its anchor via
 *     `onAnchorClick` — the PR-5 Evidence lens will consume this.
 */
import React, { useCallback, useEffect, useState } from "react";
import api from "./investigationApi";
import {
  TID_STORY_LENS,
  TID_STORY_LOADING,
  TID_STORY_ERROR,
  TID_STORY_NARRATIVE,
  TID_STORY_CHAPTERS,
  TID_STORY_CHAPTER,
  TID_STORY_EVENTS,
  TID_STORY_EVENT,
  TID_STORY_EVENT_ANCHOR,
  TID_STORY_EMPTY,
} from "./testIds";

const CHAPTER_STYLE = {
  Unwrap:    "border-indigo-700 bg-indigo-950 text-indigo-200",
  Normalize: "border-cyan-700 bg-cyan-950 text-cyan-200",
  Decode:    "border-emerald-700 bg-emerald-950 text-emerald-200",
  Interpret: "border-amber-700 bg-amber-950 text-amber-200",
};

export default function StoryLens({ caseId, onAnchorClick }) {
  const [status, setStatus] = useState("loading");
  const [data, setData]     = useState(null);
  const [error, setError]   = useState("");

  const load = useCallback(async () => {
    if (!caseId) return;
    setStatus("loading");
    setError("");
    try {
      const res = await api.getService(caseId, "story");
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
        data-testid={TID_STORY_LOADING}
        className="flex flex-1 items-center justify-center px-4 py-16 text-sm text-slate-400"
      >
        Loading attack story…
      </div>
    );
  }
  if (status === "error") {
    return (
      <div
        data-testid={TID_STORY_ERROR}
        className="flex flex-1 items-center justify-center px-4 py-16 text-sm text-rose-300"
      >
        Failed to load story: {error}
      </div>
    );
  }

  const { narrative = "", chapters = [], events = [] } = data || {};

  const anchor = (a) => onAnchorClick?.(a);

  return (
    <section
      data-testid={TID_STORY_LENS}
      className="flex flex-1 flex-col gap-6 px-6 py-6"
    >
      {/* Narrative */}
      <div>
        <p className="mb-2 text-xs uppercase tracking-widest text-slate-500">Attack narrative</p>
        <p
          data-testid={TID_STORY_NARRATIVE}
          className="rounded-md border border-slate-800 bg-slate-900/40 px-4 py-3 text-sm leading-relaxed text-slate-200"
        >
          {narrative || "No narrative available."}
        </p>
      </div>

      {/* Chapter chips */}
      {chapters.length ? (
        <div>
          <p className="mb-2 text-xs uppercase tracking-widest text-slate-500">Chapters</p>
          <div
            data-testid={TID_STORY_CHAPTERS}
            className="flex flex-wrap gap-2"
          >
            {chapters.map((c) => (
              <span
                key={c.chapter}
                data-testid={TID_STORY_CHAPTER(c.chapter)}
                className={`inline-flex items-center gap-2 rounded-md border px-3 py-1 text-xs ${CHAPTER_STYLE[c.chapter] || "border-slate-700 bg-slate-900 text-slate-200"}`}
              >
                <span className="uppercase tracking-wider">{c.chapter}</span>
                <span className="font-mono text-[10px] opacity-80">×{c.event_count}</span>
              </span>
            ))}
          </div>
        </div>
      ) : null}

      {/* Events */}
      {events.length ? (
        <div>
          <p className="mb-2 text-xs uppercase tracking-widest text-slate-500">Story events</p>
          <ol
            data-testid={TID_STORY_EVENTS}
            className="space-y-2"
          >
            {events.map((e) => (
              <li
                key={e.event_id}
                data-testid={TID_STORY_EVENT(e.event_id)}
                onClick={() => anchor(e.anchor)}
                className="cursor-pointer rounded-md border border-slate-800 bg-slate-900/40 px-3 py-2 text-sm transition hover:border-indigo-700 hover:bg-slate-900"
              >
                <div className="flex items-start gap-3">
                  <span className="mt-0.5 rounded-md border border-slate-700 bg-slate-800 px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-slate-300">
                    iter {e.iteration}
                  </span>
                  <span
                    className={`mt-0.5 rounded-md border px-2 py-0.5 text-[10px] uppercase tracking-wider ${CHAPTER_STYLE[e.chapter] || "border-slate-700 bg-slate-900 text-slate-300"}`}
                  >
                    {e.chapter}
                  </span>
                  <span className="flex-1 text-slate-100">{e.text}</span>
                  <button
                    type="button"
                    data-testid={TID_STORY_EVENT_ANCHOR(e.event_id)}
                    onClick={(ev) => { ev.stopPropagation(); anchor(e.anchor); }}
                    className="ml-2 rounded border border-slate-700 bg-slate-900 px-2 py-0.5 text-[10px] text-slate-300 hover:border-indigo-600 hover:text-indigo-200"
                    title="Open in Evidence lens (PR-5)"
                  >
                    view evidence →
                  </button>
                </div>
              </li>
            ))}
          </ol>
        </div>
      ) : (
        <p
          data-testid={TID_STORY_EMPTY}
          className="text-sm text-slate-400"
        >
          No story events available — the artefact converged with no observed transformations.
        </p>
      )}
    </section>
  );
}
