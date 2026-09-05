/**
 * IEDDE Decision Trace Panel
 * ─────────────────────────────────────────────────────────────
 * Priority 2 · SSOT observability · owner-approved 2026-02
 *
 * Renders the Intelligent Evidence-Driven Decoding Engine reasoning
 * trace as a collapsible panel above the existing decoding surfaces.
 * Never replaces existing Workspace panels — additive only.
 *
 * Contract:
 *  • Input `iedde`: shape of `services.recipe_planner.PlanResult.to_dict()`
 *    delivered as `response.iedde` from /api/decode/smart and
 *    /api/analyze/async.
 *  • Renders four sub-surfaces (top → bottom):
 *      1. Interpreter Identification (with confidence)
 *      2. Detected Techniques (chips)
 *      3. Recipe (iteration-by-iteration planner decisions +
 *         canonicality delta + fired transformations)
 *      4. Terminal State + Stop Reason
 *  • Rule 24 (Understand-First) — every stage carries the reason the
 *    planner chose that technique.
 *  • Rule 23 (Stability Gate) — stop reason always human-readable.
 */
import { useState } from "react";
import { ChevronDown, ChevronRight, Cpu, Layers, GitBranch, Flag } from "lucide-react";

// -----------------------------------------------------------------------------
// Utility helpers
// -----------------------------------------------------------------------------
const _fmtPct = (n) => {
  if (n == null || Number.isNaN(n)) return "—";
  const v = typeof n === "number" ? n : Number(n);
  return `${(v * 100).toFixed(1)}%`;
};

const _stateColor = (state) => {
  switch (state) {
    case "canonical":
      return "bg-emerald-500/15 text-emerald-300 border-emerald-500/40";
    case "binary_artifact_recovered":
      return "bg-cyan-500/15 text-cyan-300 border-cyan-500/40";
    case "stability_gate":
      return "bg-amber-500/15 text-amber-300 border-amber-500/40";
    default:
      return "bg-neutral-500/15 text-neutral-300 border-neutral-500/40";
  }
};

const _stateLabel = (state) => {
  switch (state) {
    case "canonical":
      return "Canonical";
    case "binary_artifact_recovered":
      return "Binary Artifact Recovered";
    case "stability_gate":
      return "Stability Gate";
    default:
      return state || "Unknown";
  }
};

// -----------------------------------------------------------------------------
// Sub-components
// -----------------------------------------------------------------------------
function InterpreterRow({ interp, confidence }) {
  return (
    <div className="flex items-center gap-2 text-[13px]" data-testid="iedde-interpreter-row">
      <Cpu className="w-4 h-4 text-sky-400" />
      <span className="text-neutral-400">Interpreter</span>
      <span
        className="px-2 py-0.5 rounded font-mono text-sky-300 bg-sky-500/10 border border-sky-500/30"
        data-testid="iedde-interpreter-value"
      >
        {interp || "unknown"}
      </span>
      <span className="text-neutral-500 font-mono text-xs">
        ({_fmtPct(confidence)})
      </span>
    </div>
  );
}

function TechniqueChips({ techniques }) {
  if (!techniques || techniques.length === 0) {
    return (
      <div className="text-[13px] text-neutral-500 italic" data-testid="iedde-no-techniques">
        No deterministic techniques detected.
      </div>
    );
  }
  return (
    <div className="flex flex-wrap gap-1.5" data-testid="iedde-technique-chips">
      {techniques.map((t) => (
        <span
          key={t}
          className="px-2 py-0.5 rounded text-xs font-mono bg-violet-500/10 text-violet-300 border border-violet-500/30"
          data-testid={`iedde-technique-${t}`}
        >
          {t}
        </span>
      ))}
    </div>
  );
}

function PlannerStage({ stage, index, totalStages }) {
  const decision = stage.decision || {};
  const selected = decision.selected;
  const isTerminal = !stage.chosen_pass;

  return (
    <div className="relative pl-6" data-testid={`iedde-stage-${index}`}>
      {/* Vertical connector line */}
      {index < totalStages - 1 && (
        <div className="absolute left-[9px] top-6 bottom-0 w-px bg-neutral-700/60" />
      )}
      {/* Iteration dot */}
      <div
        className={`absolute left-1.5 top-1.5 w-3 h-3 rounded-full border-2 ${
          isTerminal
            ? "bg-neutral-900 border-amber-500"
            : "bg-neutral-900 border-emerald-500"
        }`}
      />
      <div className="pb-3">
        <div className="flex items-center gap-2 mb-1">
          <span className="text-xs text-neutral-500 font-mono">
            Iteration {stage.iteration}
          </span>
          {stage.chosen_pass && (
            <span className="px-1.5 py-0.5 rounded text-[10px] font-mono uppercase tracking-wider bg-emerald-500/10 text-emerald-300 border border-emerald-500/30">
              {stage.chosen_pass}
            </span>
          )}
          {isTerminal && (
            <span className="px-1.5 py-0.5 rounded text-[10px] font-mono uppercase tracking-wider bg-amber-500/10 text-amber-300 border border-amber-500/30">
              stability gate
            </span>
          )}
          {typeof stage.canonicality_delta === "number" &&
            stage.canonicality_delta > 0 && (
              <span className="text-[10px] font-mono text-neutral-500">
                Δ {_fmtPct(stage.canonicality_delta)}
              </span>
            )}
        </div>

        {selected && (
          <div className="text-[13px] font-mono text-neutral-200">
            <span className="text-neutral-500">Selected · </span>
            <span
              className="text-emerald-300"
              data-testid={`iedde-stage-${index}-selected`}
            >
              {selected}
            </span>
            {typeof decision.confidence === "number" && (
              <span className="text-neutral-500">
                {" "}(conf {_fmtPct(decision.confidence)})
              </span>
            )}
          </div>
        )}

        {decision.reason && (
          <div
            className="text-xs text-neutral-400 mt-0.5"
            data-testid={`iedde-stage-${index}-reason`}
          >
            {decision.reason}
          </div>
        )}

        {stage.fired_transformations && stage.fired_transformations.length > 0 && (
          <div className="mt-1 flex flex-wrap gap-1">
            {stage.fired_transformations.map((t) => (
              <span
                key={t}
                className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-sky-500/10 text-sky-300 border border-sky-500/30"
              >
                {t}
              </span>
            ))}
          </div>
        )}

        {isTerminal && stage.stop_reason && (
          <div
            className="text-xs text-amber-300/80 mt-1 font-mono"
            data-testid={`iedde-stage-${index}-stop-reason`}
          >
            ⏹ {stage.stop_reason}
          </div>
        )}
      </div>
    </div>
  );
}

// -----------------------------------------------------------------------------
// Main component
// -----------------------------------------------------------------------------
export default function IEDDEDecisionTrace({
  iedde,
  canonicalConfidence,
  canonicalConfidenceReason,
  diagnostics,
  defaultOpen = false,
}) {
  const [open, setOpen] = useState(defaultOpen);

  if (!iedde) return null;

  const stages = iedde.stages || [];
  const initialStage = stages[0] || {};
  const initialInterp = initialStage.interpreter || iedde.final_interpreter;
  const initialConf = initialStage.interpreter_confidence;
  const initialTechs = initialStage.techniques_present || [];
  const terminal = iedde.terminal_state;
  const stopReason = iedde.stop_reason;
  const iterations = iedde.iterations_executed || 0;
  // ▲ 2026-02 · Phase 2 · Broken Payload Diagnostics
  const diags =
    (diagnostics && diagnostics.length ? diagnostics : iedde.diagnostics) || [];

  return (
    <div
      className="border border-neutral-700/60 rounded-lg bg-neutral-900/60 mb-3"
      data-testid="iedde-decision-trace"
    >
      {/* Header ───────────────────────────────────────────────── */}
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center justify-between px-4 py-3 hover:bg-neutral-800/40 transition-colors rounded-lg"
        data-testid="iedde-decision-trace-toggle"
      >
        <div className="flex items-center gap-3">
          {open ? (
            <ChevronDown className="w-4 h-4 text-neutral-400" />
          ) : (
            <ChevronRight className="w-4 h-4 text-neutral-400" />
          )}
          <span className="text-sm font-semibold tracking-wide uppercase text-neutral-200">
            IEDDE Decision Trace
          </span>
          <span className="text-[11px] font-mono text-neutral-500">
            {iterations} iteration{iterations === 1 ? "" : "s"}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span
            className={`px-2 py-0.5 rounded text-xs border font-mono ${_stateColor(
              terminal
            )}`}
            data-testid="iedde-terminal-state-badge"
          >
            {_stateLabel(terminal)}
          </span>
          {typeof canonicalConfidence === "number" && (
            <span
              className="px-2 py-0.5 rounded text-xs font-mono bg-neutral-800 text-neutral-300 border border-neutral-700"
              data-testid="iedde-canonical-confidence"
            >
              Canonical {canonicalConfidence}%
            </span>
          )}
        </div>
      </button>

      {/* Body ─────────────────────────────────────────────────── */}
      {open && (
        <div
          className="px-4 pb-4 pt-1 space-y-4 border-t border-neutral-800/60"
          data-testid="iedde-decision-trace-body"
        >
          {/* Interpreter */}
          <div className="pt-3">
            <InterpreterRow interp={initialInterp} confidence={initialConf} />
          </div>

          {/* Detected techniques (initial state) */}
          <div className="space-y-1.5">
            <div className="flex items-center gap-2 text-[12px] uppercase tracking-wider text-neutral-500 font-semibold">
              <Layers className="w-3.5 h-3.5" />
              Detected Techniques
            </div>
            <TechniqueChips techniques={initialTechs} />
          </div>

          {/* Recipe · per-iteration reasoning */}
          <div className="space-y-1.5">
            <div className="flex items-center gap-2 text-[12px] uppercase tracking-wider text-neutral-500 font-semibold">
              <GitBranch className="w-3.5 h-3.5" />
              Recipe · Planner Reasoning
            </div>
            <div className="mt-2" data-testid="iedde-stages">
              {stages.length === 0 ? (
                <div className="text-[13px] text-neutral-500 italic pl-6">
                  No iterations executed.
                </div>
              ) : (
                stages.map((s, i) => (
                  <PlannerStage
                    key={i}
                    stage={s}
                    index={i}
                    totalStages={stages.length}
                  />
                ))
              )}
            </div>
          </div>

          {/* Terminal state + stop reason */}
          <div className="rounded border border-neutral-800 bg-neutral-950/40 px-3 py-2 space-y-1">
            <div className="flex items-center gap-2 text-[12px] uppercase tracking-wider text-neutral-500 font-semibold">
              <Flag className="w-3.5 h-3.5" />
              Terminal State
            </div>
            <div className="flex items-center gap-2">
              <span
                className={`px-2 py-0.5 rounded text-xs font-mono border ${_stateColor(
                  terminal
                )}`}
              >
                {_stateLabel(terminal)}
              </span>
              {iedde.binary_artifact && (
                <span className="text-xs font-mono text-cyan-300">
                  → {iedde.binary_artifact.kind} · {iedde.binary_artifact.subtype}
                </span>
              )}
            </div>
            {stopReason && (
              <div
                className="text-xs text-neutral-400 font-mono break-words"
                data-testid="iedde-stop-reason"
              >
                {stopReason}
              </div>
            )}
            {canonicalConfidenceReason && (
              <div
                className="text-[11px] text-neutral-500 font-mono break-words pt-1 border-t border-neutral-800"
                data-testid="iedde-canonical-confidence-reason"
              >
                Canonical Confidence · {canonicalConfidenceReason}
              </div>
            )}
          </div>

          {/* ▲ 2026-02 · Phase 2 · Broken Payload Diagnostics ─────
              When the deterministic recovery halts at a stability gate,
              surface structured analyst-facing explanations here.
              Each diagnostic cites layer + reason + recommendation. */}
          {diags && diags.length > 0 && (
            <div className="space-y-2" data-testid="iedde-broken-payload-diagnostics">
              <div className="flex items-center gap-2 text-[12px] uppercase tracking-wider text-amber-400 font-semibold">
                <Flag className="w-3.5 h-3.5" />
                Broken Payload Diagnostics
              </div>
              {diags.map((d, idx) => (
                <div
                  key={`${d.code}-${idx}`}
                  data-testid={`iedde-diagnostic-${d.code}`}
                  className="rounded border border-amber-500/40 bg-amber-500/5 px-3 py-2"
                >
                  <div className="flex items-center gap-2 mb-1">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase tracking-wider border ${
                        d.severity === "critical" || d.severity === "high"
                          ? "text-rose-300 bg-rose-500/10 border-rose-500/40"
                          : d.severity === "medium"
                          ? "text-amber-300 bg-amber-500/10 border-amber-500/40"
                          : "text-neutral-300 bg-neutral-500/10 border-neutral-500/40"
                      }`}
                    >
                      {d.severity}
                    </span>
                    <span className="text-xs font-mono text-neutral-200">
                      Layer · <span className="text-amber-200">{d.layer}</span>
                    </span>
                    {d.offset != null && (
                      <span className="text-[10px] font-mono text-neutral-500">
                        offset 0x{d.offset.toString(16)}
                      </span>
                    )}
                  </div>
                  <div
                    className="text-[13px] text-neutral-100 font-mono break-words"
                    data-testid={`iedde-diagnostic-reason-${idx}`}
                  >
                    {d.reason}
                  </div>
                  {d.recommendation && (
                    <div
                      className="text-xs text-emerald-300/90 font-mono break-words mt-1"
                      data-testid={`iedde-diagnostic-recommendation-${idx}`}
                    >
                      ↳ {d.recommendation}
                    </div>
                  )}
                  {d.hex_snippet && (
                    <div
                      className="text-[10px] text-neutral-500 font-mono break-all mt-1"
                      data-testid={`iedde-diagnostic-hex-${idx}`}
                    >
                      hex · {d.hex_snippet}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
