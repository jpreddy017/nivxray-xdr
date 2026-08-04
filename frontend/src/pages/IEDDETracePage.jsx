/**
 * Live IEDDE Trace Panel · consumes POST /api/iedde/analyze.
 *
 * Pure visualization — every field rendered here comes from the API.
 * The UI never re-runs decoders locally, never composes reasoning; it
 * only presents the deterministic engine's response.
 *
 * View layout (Rule 24 §4 · IEDDE §5 contract):
 *   1. INPUT
 *   2. Interpreter identification (with confidence + signals)
 *   3. Technique inventory (initial)
 *   4. Recipe execution — per-stage decision + reasoning
 *   5. Progress evaluation — canonicality deltas
 *   6. Final state — canonical output OR reasoned stability-gate message
 */
import React, { useState } from "react";
import api from "@/lib/api";

const TID = {
  page: "iedde-trace-page",
  input: "iedde-input",
  analyzeBtn: "iedde-analyze-btn",
  loading: "iedde-loading",
  error: "iedde-error",
  interpreter: "iedde-interpreter",
  techInventory: "iedde-tech-inventory",
  stages: "iedde-stages",
  stage: (i) => `iedde-stage-${i}`,
  decision: (i) => `iedde-decision-${i}`,
  canonical: "iedde-canonical-output",
  terminal: "iedde-terminal-state",
  stopReason: "iedde-stop-reason",
};

const PILL = "inline-flex items-center rounded-md border px-2 py-0.5 text-xs";
const OK = "border-emerald-700 bg-emerald-950 text-emerald-200";
const WARN = "border-amber-700 bg-amber-950 text-amber-200";
const HOT = "border-rose-700 bg-rose-950 text-rose-200";
const NEU = "border-slate-700 bg-slate-900 text-slate-300";

function ConfidenceBar({ value }) {
  const pct = Math.round((value || 0) * 100);
  return (
    <span className="ml-2 inline-flex items-center gap-1 font-mono text-[10px] text-slate-400">
      <span className="h-1.5 w-16 rounded-full bg-slate-800">
        <span
          className="block h-full rounded-full bg-indigo-500"
          style={{ width: `${pct}%` }}
        />
      </span>
      {pct}%
    </span>
  );
}

function InterpreterCard({ ident }) {
  if (!ident) return null;
  const { primary_interpreter, confidence, interpreters, stability_reason } = ident;
  return (
    <section
      data-testid={TID.interpreter}
      className="rounded-md border border-slate-800 bg-slate-900/40 p-4"
    >
      <div className="mb-3 flex items-baseline justify-between">
        <p className="text-xs uppercase tracking-widest text-slate-500">Interpreter identification</p>
        <p className="font-mono text-[10px] text-slate-500">{stability_reason}</p>
      </div>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <span className={`${PILL} ${primary_interpreter === "unknown" ? WARN : OK} uppercase tracking-widest`}>
          {primary_interpreter}
        </span>
        <ConfidenceBar value={confidence} />
      </div>
      {interpreters && interpreters.length > 1 ? (
        <div className="mt-2 flex flex-wrap gap-1">
          {interpreters.slice(1).map((m) => (
            <span
              key={m.interpreter}
              className={`${PILL} ${NEU}`}
              title={`${m.signals.length} signal(s)`}
            >
              {m.interpreter} · {Math.round(m.confidence * 100)}%
            </span>
          ))}
        </div>
      ) : null}
    </section>
  );
}

function TechniqueInventoryCard({ inv, title }) {
  if (!inv) return null;
  return (
    <section
      data-testid={TID.techInventory}
      className="rounded-md border border-slate-800 bg-slate-900/40 p-4"
    >
      <div className="mb-3 flex items-baseline justify-between">
        <p className="text-xs uppercase tracking-widest text-slate-500">{title}</p>
        <p className="font-mono text-[10px] text-slate-500">{inv.stability_reason}</p>
      </div>
      {inv.techniques && inv.techniques.length ? (
        <ul className="grid grid-cols-1 gap-1 sm:grid-cols-2">
          {inv.techniques.map((t) => (
            <li
              key={t.technique}
              className="flex items-center justify-between rounded border border-slate-800 bg-slate-950 px-2 py-1"
            >
              <span className="font-mono text-xs text-slate-200">✓ {t.technique}</span>
              <ConfidenceBar value={t.confidence} />
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-xs text-slate-500">None detected.</p>
      )}
    </section>
  );
}

function StageCard({ stage, idx }) {
  const dec = stage.decision || {};
  const delta = (stage.canonicality_delta || 0) * 100;
  const deltaColor = delta > 0 ? "text-emerald-400" : delta < 0 ? "text-rose-400" : "text-slate-500";
  return (
    <li
      data-testid={TID.stage(idx)}
      className="rounded-md border border-slate-800 bg-slate-900/40 p-3"
    >
      <div className="mb-2 flex flex-wrap items-baseline gap-3">
        <span className={`${PILL} ${NEU} font-mono`}>iter {stage.iteration}</span>
        {stage.chosen_pass ? (
          <span className={`${PILL} border-indigo-700 bg-indigo-950 text-indigo-200 uppercase tracking-widest`}>
            {stage.chosen_pass}
          </span>
        ) : (
          <span className={`${PILL} ${WARN} uppercase tracking-widest`}>stability gate</span>
        )}
        <span className="font-mono text-[10px] text-slate-500">
          {stage.content_len_before}c → {stage.content_len_after}c
        </span>
        <span className={`font-mono text-[10px] ${deltaColor}`}>
          canonicality {delta >= 0 ? "+" : ""}{delta.toFixed(1)}%
        </span>
      </div>

      {/* Decision */}
      <div data-testid={TID.decision(idx)} className="mb-2 rounded border border-slate-800 bg-slate-950/40 p-2 text-xs">
        <p className="mb-1 uppercase tracking-widest text-slate-500">Planner decision</p>
        <p className="text-slate-200">
          {dec.selected ? (
            <>
              Selected <span className="font-mono text-indigo-300">{dec.selected}</span>
              {dec.selected_pass ? (
                <> → <span className="font-mono text-emerald-300">{dec.selected_pass}</span></>
              ) : null}
              <ConfidenceBar value={dec.confidence} />
            </>
          ) : (
            <span className="text-amber-300">No deterministic transformation justified.</span>
          )}
        </p>
        <p className="mt-1 text-slate-400">{dec.reason}</p>
        {dec.remaining_candidates && dec.remaining_candidates.length ? (
          <p className="mt-1 text-[11px] text-slate-500">
            Remaining candidates: {dec.remaining_candidates.map((r) => (
              <span key={r} className="ml-1 font-mono">{r}</span>
            ))}
          </p>
        ) : null}
        {dec.key_required_deferred && dec.key_required_deferred.length ? (
          <p className="mt-1 text-[11px] text-rose-400">
            Deferred (key unavailable): {dec.key_required_deferred.join(", ")}
          </p>
        ) : null}
      </div>

      {/* Fired transformations */}
      {stage.fired_transformations && stage.fired_transformations.length ? (
        <div className="text-xs">
          <p className="mb-1 uppercase tracking-widest text-slate-500">Fired transformations</p>
          <ul className="space-y-0.5">
            {stage.fired_transformations.map((t) => (
              <li key={t} className="font-mono text-[11px] text-emerald-300">✓ {t}</li>
            ))}
          </ul>
        </div>
      ) : null}

      {stage.stop_reason ? (
        <p className="mt-2 rounded border border-amber-800 bg-amber-950/40 px-2 py-1 font-mono text-[10px] text-amber-200">
          {stage.stop_reason}
        </p>
      ) : null}
    </li>
  );
}

function FinalStateCard({ result }) {
  const canonical = result.terminal_state === "canonical";
  return (
    <section className="rounded-md border border-slate-800 bg-slate-900/40 p-4">
      <div className="mb-3 flex items-center gap-2">
        <span
          data-testid={TID.terminal}
          className={`${PILL} uppercase tracking-widest ${canonical ? OK : HOT}`}
        >
          {result.terminal_state}
        </span>
        <span className={`${PILL} ${NEU}`}>{result.iterations_executed} iteration(s)</span>
      </div>
      <p
        data-testid={TID.stopReason}
        className="mb-3 font-mono text-[11px] text-slate-400"
      >
        {result.stop_reason}
      </p>
      <p className="mb-1 text-xs uppercase tracking-widest text-slate-500">Canonical output</p>
      <pre
        data-testid={TID.canonical}
        className="whitespace-pre-wrap break-all rounded border border-slate-800 bg-black/60 p-3 font-mono text-sm text-slate-100"
      >
        {result.canonical_output || "(empty)"}
      </pre>
    </section>
  );
}

export default function IEDDETracePage() {
  const [input, setInput] = useState(
    'powershell.exe -NoProfile -Command "&((\'Get-\' + \'Process\') \'lsass\')"',
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);

  const analyze = async () => {
    if (!input.trim()) return;
    setBusy(true);
    setError("");
    setResult(null);
    try {
      const { data } = await api.post("/iedde/analyze", { input });
      setResult(data);
    } catch (e) {
      setError(e?.response?.data?.detail || e?.message || "analyze_failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      data-testid={TID.page}
      className="min-h-screen bg-slate-950 text-slate-100"
    >
      <header className="border-b border-slate-800 bg-slate-950/80 px-6 py-3">
        <div className="flex items-center gap-3">
          <a href="/" className="text-xs uppercase tracking-widest text-slate-500 hover:text-slate-200">
            NivXRay
          </a>
          <span className="text-slate-700">/</span>
          <span className="text-sm font-medium text-slate-200">IEDDE · Live Trace</span>
          <span className="ml-3 rounded border border-indigo-700 bg-indigo-950 px-2 py-0.5 text-[10px] uppercase tracking-widest text-indigo-200">
            Intelligent Evidence-Driven Decoding Engine
          </span>
        </div>
      </header>

      <div className="mx-auto max-w-6xl px-6 py-6">
        {/* INPUT */}
        <section className="mb-6">
          <p className="mb-2 text-xs uppercase tracking-widest text-slate-500">Input</p>
          <textarea
            data-testid={TID.input}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            spellCheck={false}
            rows={4}
            className="w-full resize-y rounded-md border border-slate-800 bg-slate-950 p-3 font-mono text-sm text-slate-100 outline-none focus:border-indigo-500"
            placeholder="Paste any command line — PowerShell, CMD, Bash, Python, JavaScript, VBScript, Perl, PHP, mshta, rundll32, regsvr32 …"
          />
          <div className="mt-2 flex items-center gap-3">
            <button
              data-testid={TID.analyzeBtn}
              onClick={analyze}
              disabled={busy || !input.trim()}
              className={`rounded-md px-4 py-2 text-sm font-medium transition ${
                busy || !input.trim()
                  ? "cursor-not-allowed border border-slate-800 bg-slate-900 text-slate-500"
                  : "border border-indigo-600 bg-indigo-600 text-white hover:bg-indigo-500"
              }`}
            >
              {busy ? "Analyzing…" : "Analyze"}
            </button>
            {error ? (
              <span data-testid={TID.error} className="font-mono text-xs text-rose-300">
                ✗ {error}
              </span>
            ) : null}
          </div>
        </section>

        {/* RESULTS */}
        {busy ? (
          <p data-testid={TID.loading} className="text-sm text-slate-400">
            Running IEDDE loop…
          </p>
        ) : null}

        {result ? (
          <div className="space-y-5">
            <InterpreterCard ident={result.initial_interpreter_identification} />
            <TechniqueInventoryCard
              inv={result.initial_technique_inventory}
              title="Initial technique inventory"
            />

            {/* Recipe = stages */}
            <section>
              <div className="mb-2 flex items-baseline justify-between">
                <p className="text-xs uppercase tracking-widest text-slate-500">Recipe · discovery-driven</p>
                <p className="font-mono text-[10px] text-slate-500">
                  {result.stages.length} stage(s) · Rule 26 (understand-first)
                </p>
              </div>
              <ol
                data-testid={TID.stages}
                className="space-y-2"
              >
                {result.stages.map((s, i) => (
                  <StageCard key={s.iteration} stage={s} idx={i} />
                ))}
              </ol>
            </section>

            <FinalStateCard result={result} />
          </div>
        ) : null}
      </div>
    </div>
  );
}
