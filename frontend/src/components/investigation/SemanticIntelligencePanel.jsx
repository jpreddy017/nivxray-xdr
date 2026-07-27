/**
 * Phase 9.4 · PowerShell Semantic Intelligence panel
 *
 * Renders NivXRay-native behavior tags, Explainable Verdict breakdown,
 * Full Decode Timeline, Evidence Graph, and AST Tree Viewer.
 *
 * Consumes `chain.semantic.{behaviors_v2, verdict_breakdown, decode_timeline,
 * evidence_graph, ast_tree, resolved_variables}` from the backend semantic
 * result. Falls back gracefully if the new fields are absent (legacy cache).
 */
import React, { useMemo, useState } from "react";

const SEVERITY_STYLE = {
  critical: "border-red-600/70 text-red-100 bg-red-600/20",
  high:     "border-orange-500/70 text-orange-100 bg-orange-500/15",
  medium:   "border-amber-500/70 text-amber-100 bg-amber-500/15",
  low:      "border-sky-500/70 text-sky-100 bg-sky-500/15",
  info:     "border-emerald-500/70 text-emerald-100 bg-emerald-500/15",
};

const STATUS_STYLE = {
  applied: "border-emerald-500/60 text-emerald-200 bg-emerald-500/10",
  skipped: "border-slate-600/60 text-slate-300 bg-slate-500/10",
  failed:  "border-red-500/60 text-red-200 bg-red-500/10",
};

const CARD = "border border-cyan-500/20 bg-slate-950/60 rounded-md p-3";
const SECTION_HEADER = "text-[10px] tracking-[0.24em] font-bold text-cyan-300 uppercase";
const SUB_HEADER = "text-[10px] uppercase tracking-widest text-slate-400 mb-1.5";


function ScoreBar({ label, value, color = "cyan" }) {
  const pct = Math.max(0, Math.min(100, value || 0));
  const barColor = {
    red:     "bg-red-500",
    orange:  "bg-orange-500",
    amber:   "bg-amber-500",
    cyan:    "bg-cyan-500",
    emerald: "bg-emerald-500",
  }[color] || "bg-cyan-500";
  return (
    <div className="flex flex-col gap-1">
      <div className="flex items-baseline justify-between text-[10px] text-slate-400 uppercase tracking-widest">
        <span>{label}</span>
        <span className="font-mono text-slate-200 text-[11px] font-bold">{pct}</span>
      </div>
      <div className="h-1.5 rounded-full bg-slate-800 overflow-hidden">
        <div className={`h-full ${barColor} transition-all duration-500`}
             style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}


function ExplainableVerdict({ vb, chainIndex }) {
  if (!vb || !vb.verdict) return null;
  const verdictTone = {
    malicious:     "border-red-600/70 text-red-100 bg-red-600/20",
    suspicious:    "border-amber-500/70 text-amber-100 bg-amber-500/15",
    needs_review:  "border-sky-500/70 text-sky-100 bg-sky-500/15",
    informational: "border-slate-500/60 text-slate-200 bg-slate-500/10",
    benign:        "border-emerald-500/60 text-emerald-100 bg-emerald-500/15",
  }[vb.verdict] || "border-slate-600 text-slate-300";
  return (
    <div className={CARD} data-testid={`semantic-v2-verdict-${chainIndex}`}>
      <div className="flex items-center gap-2 mb-3">
        <span className={SECTION_HEADER}>Explainable Verdict</span>
        <span className={`ml-auto px-2 py-0.5 rounded-full border text-[10px] uppercase tracking-widest font-bold ${verdictTone}`}
              data-testid={`semantic-v2-verdict-label-${chainIndex}`}>
          {vb.verdict.replace(/_/g, " ")}
        </span>
        <span className="text-[10px] font-mono text-slate-400">conf {vb.confidence}%</span>
      </div>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-3">
        <ScoreBar label="Risk"        value={vb.risk_score}
                  color={vb.risk_score >= 75 ? "red" : vb.risk_score >= 40 ? "orange" : "cyan"} />
        <ScoreBar label="Behavior"    value={vb.behavior_score} color="orange" />
        <ScoreBar label="IOC"         value={vb.ioc_score} color="amber" />
        <ScoreBar label="Obfuscation" value={vb.obfuscation_score} color="cyan" />
      </div>
      {(vb.rationale || []).length > 0 && (
        <div className="space-y-1 border-t border-slate-800 pt-2">
          <div className={SUB_HEADER}>Analyst rationale</div>
          <ul className="text-[11px] text-slate-300 space-y-0.5"
              data-testid={`semantic-v2-rationale-${chainIndex}`}>
            {vb.rationale.map((r, i) => (
              <li key={i} className="flex gap-1.5">
                <span className="text-cyan-400 mt-0.5">▸</span>
                <span>{r}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
      {(vb.top_signals || []).length > 0 && (
        <div className="mt-2 border-t border-slate-800 pt-2">
          <div className={SUB_HEADER}>Top scoring signals</div>
          <div className="flex flex-wrap gap-1">
            {vb.top_signals.slice(0, 6).map((s, i) => (
              <span key={i}
                    className={`px-1.5 py-0.5 rounded text-[10px] font-mono border ${
                      SEVERITY_STYLE[s.severity] || "border-slate-700 text-slate-300"
                    }`}
                    title={`weight ${s.weight}`}>
                {s.name} · {s.weight}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}


function DecodeTimeline({ steps, chainIndex }) {
  if (!steps || steps.length === 0) return null;
  return (
    <div className={CARD} data-testid={`semantic-v2-timeline-${chainIndex}`}>
      <div className="flex items-center gap-2 mb-3">
        <span className={SECTION_HEADER}>Full Decode Timeline</span>
        <span className="text-[10px] font-mono text-slate-500 ml-auto">{steps.length} step(s)</span>
      </div>
      <ol className="relative border-l-2 border-cyan-500/20 pl-4 space-y-2.5">
        {steps.map((s, i) => (
          <li key={i} className="relative"
              data-testid={`semantic-v2-timeline-step-${chainIndex}-${i}`}>
            <span className={`absolute -left-[22px] top-1 w-3 h-3 rounded-full border-2 ${
              s.status === "applied" ? "bg-emerald-500 border-emerald-300"
              : s.status === "skipped" ? "bg-slate-600 border-slate-400"
              : "bg-red-500 border-red-300"
            }`} />
            <div className="flex flex-wrap items-baseline gap-2">
              <span className="text-[11px] font-mono font-bold text-cyan-200">
                {s.decoder}
              </span>
              <span className={`px-1.5 py-0 rounded text-[9px] uppercase tracking-widest font-bold border ${
                STATUS_STYLE[s.status] || "border-slate-700 text-slate-300"
              }`}>
                {s.status}
              </span>
              {s.duration_ms > 0 && (
                <span className="text-[10px] font-mono text-slate-500">
                  {s.duration_ms.toFixed(1)}ms
                </span>
              )}
              {(s.input_len > 0 || s.output_len > 0) && (
                <span className="text-[10px] font-mono text-slate-500">
                  {s.input_len}B → {s.output_len}B
                </span>
              )}
            </div>
            <div className="text-[11px] text-slate-300 mt-0.5 leading-snug">
              {s.reason}
            </div>
            {s.preview && (
              <pre className="mt-1 px-2 py-1 bg-slate-950/80 border border-slate-800 rounded text-[10px] font-mono text-emerald-200 whitespace-pre-wrap break-all leading-snug max-h-24 overflow-y-auto">
                {s.preview}
              </pre>
            )}
          </li>
        ))}
      </ol>
    </div>
  );
}


function BehaviorCards({ behaviors, chainIndex, onHighlight }) {
  if (!behaviors || behaviors.length === 0) return null;
  return (
    <div className={CARD} data-testid={`semantic-v2-behaviors-${chainIndex}`}>
      <div className="flex items-center gap-2 mb-3">
        <span className={SECTION_HEADER}>Behavior Intelligence</span>
        <span className="text-[10px] font-mono text-slate-500 ml-auto">{behaviors.length} tag(s)</span>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
        {behaviors.map((b, i) => (
          <button
            key={i}
            onClick={() => onHighlight && onHighlight(b.evidence?.[0])}
            className={`text-left p-2.5 rounded-md border transition ${
              SEVERITY_STYLE[b.severity] || "border-slate-700 text-slate-300"
            } hover:brightness-125`}
            data-testid={`semantic-v2-behavior-${chainIndex}-${i}`}>
            <div className="flex items-baseline gap-2 mb-1">
              <span className="font-bold text-[12px] leading-tight">{b.name}</span>
              <span className="ml-auto text-[9px] uppercase tracking-widest font-bold opacity-80">
                {b.severity}
              </span>
            </div>
            <div className="flex items-baseline gap-2 mb-1">
              <div className="flex-1 h-1 rounded-full bg-black/40 overflow-hidden">
                <div className="h-full bg-white/70"
                     style={{ width: `${Math.max(0, Math.min(100, b.confidence))}%` }} />
              </div>
              <span className="text-[9px] font-mono opacity-70">{b.confidence}%</span>
            </div>
            <div className="text-[10.5px] leading-snug opacity-90">
              {b.rationale}
            </div>
            <div className="flex flex-wrap gap-1 mt-1.5">
              {(b.mitre || []).map((m, mi) => (
                <span key={mi} className="text-[9px] font-mono px-1.5 py-0 rounded bg-black/25 border border-white/10">
                  {m}
                </span>
              ))}
              {(b.evidence || []).length > 0 && (
                <span className="text-[9px] font-mono px-1.5 py-0 rounded bg-black/25 border border-white/10 ml-auto">
                  {b.evidence.length} evidence
                </span>
              )}
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}


function EvidenceGraph({ graph, chainIndex }) {
  const groups = useMemo(() => {
    const by = { decoder_layer: [], script: [], behavior: [], ioc: [] };
    ((graph && graph.nodes) || []).forEach(n => {
      (by[n.kind] || (by[n.kind] = [])).push(n);
    });
    return by;
  }, [graph]);
  if (!graph || !graph.nodes || graph.nodes.length === 0) return null;
  return (
    <div className={CARD} data-testid={`semantic-v2-graph-${chainIndex}`}>
      <div className="flex items-center gap-2 mb-2">
        <span className={SECTION_HEADER}>Investigation Evidence Graph</span>
        <span className="text-[10px] font-mono text-slate-500 ml-auto">
          {graph?.stats?.node_count ?? 0} nodes · {graph?.stats?.edge_count ?? 0} edges
        </span>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-4 gap-2">
        <GraphColumn title="Decoder Chain" tone="cyan"
                     nodes={groups.decoder_layer || []} chainIndex={chainIndex} lane="decoders" />
        <GraphColumn title="Script" tone="violet"
                     nodes={groups.script || []} chainIndex={chainIndex} lane="script" />
        <GraphColumn title="Behaviors" tone="orange"
                     nodes={groups.behavior || []} chainIndex={chainIndex} lane="behaviors" />
        <GraphColumn title="IOCs" tone="amber"
                     nodes={groups.ioc || []} chainIndex={chainIndex} lane="iocs" />
      </div>
    </div>
  );
}


function GraphColumn({ title, tone, nodes, chainIndex, lane }) {
  const border = {
    cyan:    "border-cyan-500/40",
    violet:  "border-violet-500/40",
    orange:  "border-orange-500/40",
    amber:   "border-amber-500/40",
  }[tone] || "border-slate-600";
  return (
    <div className={`p-2 rounded border ${border} bg-slate-950/40`}
         data-testid={`semantic-v2-graph-lane-${lane}-${chainIndex}`}>
      <div className="text-[10px] uppercase tracking-widest text-slate-400 font-bold mb-1.5">
        {title}
      </div>
      {nodes.length === 0 ? (
        <div className="text-[10px] text-slate-600 italic">(none)</div>
      ) : (
        <div className="space-y-1">
          {nodes.slice(0, 12).map((n, i) => (
            <div key={n.id || i}
                 title={n.meta?.rationale || n.meta?.why || ""}
                 className="text-[10.5px] px-1.5 py-1 rounded bg-slate-900/60 border border-slate-800 truncate"
                 data-testid={`semantic-v2-graph-node-${lane}-${chainIndex}-${i}`}>
              <div className="font-mono text-slate-200 truncate">{n.label}</div>
              {n.meta?.severity && (
                <div className={`text-[9px] uppercase tracking-widest inline-block px-1 mt-0.5 rounded ${
                  SEVERITY_STYLE[n.meta.severity] || "text-slate-500"
                }`}>
                  {n.meta.severity} · conf {n.meta.confidence}
                </div>
              )}
              {n.meta?.confidence != null && n.kind === "decoder_layer" && (
                <div className="text-[9px] font-mono text-slate-500">
                  conf {Math.round((n.meta.confidence || 0) * 100)}%
                </div>
              )}
            </div>
          ))}
          {nodes.length > 12 && (
            <div className="text-[9px] text-slate-500 italic">
              + {nodes.length - 12} more…
            </div>
          )}
        </div>
      )}
    </div>
  );
}


function ASTViewer({ tree, resolvedVars, chainIndex }) {
  const [open, setOpen] = useState(false);
  if (!tree || !(tree.statements && tree.statements.length)) return null;
  return (
    <div className={CARD} data-testid={`semantic-v2-ast-${chainIndex}`}>
      <button
        onClick={() => setOpen(v => !v)}
        className="flex items-center gap-2 w-full text-left"
        data-testid={`semantic-v2-ast-toggle-${chainIndex}`}>
        <span className={SECTION_HEADER}>AST Tree</span>
        <span className="text-[10px] font-mono text-slate-500">
          {tree.statements.length} stmt(s) · {Object.keys(resolvedVars || {}).length} folded var(s)
        </span>
        <span className="ml-auto text-cyan-300 text-[11px]">{open ? "▾" : "▸"}</span>
      </button>
      {open && (
        <div className="mt-2 border-t border-slate-800 pt-2 space-y-2">
          {Object.keys(resolvedVars || {}).length > 0 && (
            <div>
              <div className={SUB_HEADER}>Resolved variables</div>
              <div className="space-y-0.5 font-mono text-[10.5px]"
                   data-testid={`semantic-v2-vars-${chainIndex}`}>
                {Object.entries(resolvedVars).slice(0, 12).map(([k, v]) => (
                  <div key={k} className="flex gap-2">
                    <span className="text-violet-300">{"$" + k}</span>
                    <span className="text-slate-500">=</span>
                    <span className="text-emerald-200 truncate">{JSON.stringify(v)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
          <div>
            <div className={SUB_HEADER}>Statements</div>
            <ASTStatements statements={tree.statements} />
          </div>
        </div>
      )}
    </div>
  );
}

function flattenAst(nodes, depth, out) {
  for (const n of nodes || []) {
    if (!n) continue;
    out.push({ node: n, depth });
    const kids = (n.children || []).slice(0, 8);
    flattenAst(kids, depth + 1, out);
    if ((n.children || []).length > 8) {
      out.push({ overflow: true, count: n.children.length - 8, depth: depth + 1 });
    }
  }
  return out;
}

function ASTStatements({ statements }) {
  const rows = flattenAst(statements || [], 0, []);
  return (
    <div className="space-y-0.5">
      {rows.map((r, i) => {
        if (r.overflow) {
          return (
            <div key={i} className="text-[9px] text-slate-500 italic"
                 style={{ paddingLeft: `${r.depth * 12}px` }}>
              + {r.count} more children…
            </div>
          );
        }
        const n = r.node;
        const label = n.kind + (n.meta?.cmdlet ? " · " + n.meta.cmdlet : "")
                    + (n.meta?.member ? "." + n.meta.member : "")
                    + (n.meta?.target ? " $" + n.meta.target : "");
        return (
          <div key={i} className="text-[10.5px] font-mono"
               style={{ paddingLeft: `${r.depth * 12}px` }}>
            <span className="text-cyan-300">{label}</span>
            {n.text && !n.meta?.cmdlet && !n.meta?.member && (
              <span className="text-slate-400"> {JSON.stringify(n.text).slice(0, 60)}</span>
            )}
          </div>
        );
      })}
    </div>
  );
}


function DecodeFailureCard({ err, chainIndex }) {
  if (!err || !err.status) return null;
  return (
    <div className="border border-red-500/60 bg-red-950/30 rounded-md p-3"
         data-testid={`semantic-v2-decode-error-${chainIndex}`}>
      <div className="flex items-baseline gap-2 mb-2">
        <span className="text-[10px] tracking-[0.24em] font-bold text-red-200 uppercase">
          Decode Failure · analysis halted
        </span>
        <span className="ml-auto px-2 py-0.5 rounded-full border border-red-500/70
                         bg-red-600/30 text-red-100 text-[10px] uppercase tracking-widest font-bold">
          decode_error
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-2 mb-2 text-[11px]">
        <div className="flex items-baseline gap-2">
          <span className={`w-4 text-[13px] font-bold ${
            err.b64_status === "succeeded" ? "text-emerald-400" : "text-red-400"
          }`}>{err.b64_status === "succeeded" ? "✓" : "✗"}</span>
          <span className="text-slate-200 font-bold">Base64 decoded</span>
          <span className="text-slate-500">·</span>
          <span className="text-slate-400 font-mono">{err.b64_reason}</span>
        </div>
        <div className="flex items-baseline gap-2">
          <span className="w-4 text-[13px] font-bold text-red-400">✗</span>
          <span className="text-slate-200 font-bold">UTF-16LE validation failed</span>
          {err.first_invalid_offset != null && (
            <span className="text-slate-400 font-mono">
              at byte {err.first_invalid_offset}
            </span>
          )}
        </div>
      </div>

      {err.invalid_reason && (
        <div className="text-[11px] text-slate-300 mb-2 pl-6">
          <span className="text-slate-500 uppercase text-[9px] tracking-widest mr-2">Reason</span>
          <span className="font-mono">{err.invalid_reason}</span>
        </div>
      )}

      {err.hex_preview && (
        <div className="mb-2">
          <div className="text-[9px] uppercase tracking-widest text-slate-500 mb-1">
            Hex preview (first {Math.min(64, (err.hex_preview.length || 0) / 2)} bytes)
          </div>
          <pre className="px-2 py-1 bg-slate-950/80 border border-slate-800 rounded text-[10px]
                          font-mono text-amber-200 whitespace-pre-wrap break-all leading-snug"
               data-testid={`semantic-v2-decode-error-hex-${chainIndex}`}>
            {err.hex_preview.replace(/(.{2})/g, "$1 ").trim()}
          </pre>
        </div>
      )}

      {(err.possible_causes || []).length > 0 && (
        <div className="mb-2">
          <div className="text-[9px] uppercase tracking-widest text-slate-500 mb-1">
            Possible causes
          </div>
          <ul className="text-[11px] text-slate-300 space-y-0.5"
              data-testid={`semantic-v2-decode-error-causes-${chainIndex}`}>
            {err.possible_causes.map((c, i) => (
              <li key={i} className="flex gap-1.5">
                <span className="text-red-400 mt-0.5">▸</span>
                <span>{c}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {(err.attempts || []).length > 0 && (
        <div>
          <div className="text-[9px] uppercase tracking-widest text-slate-500 mb-1">
            Recovery attempts ({err.attempts.length})
          </div>
          <div className="space-y-1"
               data-testid={`semantic-v2-decode-error-attempts-${chainIndex}`}>
            {err.attempts.map((a, i) => (
              <div key={i}
                   data-testid={`semantic-v2-decode-error-attempt-${chainIndex}-${i}`}
                   className={`flex flex-wrap items-baseline gap-2 text-[10.5px] px-2 py-1 rounded border ${
                     a.status === "succeeded" ? "border-emerald-500/50 bg-emerald-500/5"
                     : a.status === "skipped" ? "border-slate-700 bg-slate-800/30"
                     : "border-red-500/40 bg-red-500/5"
                   }`}>
                <span className="font-mono font-bold text-slate-200">{a.decoder}</span>
                <span className={`px-1.5 py-0 rounded text-[9px] uppercase tracking-widest font-bold border ${
                  a.status === "succeeded" ? "border-emerald-500/60 text-emerald-200"
                  : a.status === "skipped" ? "border-slate-600/60 text-slate-300"
                  : "border-red-500/60 text-red-200"
                }`}>{a.status}</span>
                <span className="text-slate-400 font-mono flex-1 min-w-0 break-words">
                  {a.reason}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="mt-2 pt-2 border-t border-red-500/20 text-[10.5px] text-slate-400 italic">
        Semantic analysis intentionally halted — no AST, no behavior extraction,
        and no verdict scoring is performed on unrecovered payloads. This card is
        the ONLY output for this chain.
      </div>
    </div>
  );
}


export default function SemanticIntelligencePanel({ semantic, chainIndex, onHighlight }) {
  if (!semantic || !semantic.detected) return null;

  // Decode-error path — render only the failure card, halt all other UI.
  const decodeError = semantic.decode_error;
  const hasDecodeError = semantic.decode_outcome === "decode_error"
                          || (decodeError && decodeError.status === "decode_error");

  const hasV2 = (semantic.behaviors_v2 && semantic.behaviors_v2.length) ||
                (semantic.decode_timeline && semantic.decode_timeline.length) ||
                (semantic.verdict_breakdown && semantic.verdict_breakdown.verdict);
  if (!hasV2 && !hasDecodeError) return null;

  return (
    <div className="border-t border-cyan-500/30 bg-slate-950/40 p-3 space-y-3"
         data-testid={`semantic-v2-panel-${chainIndex}`}>
      <div className="flex items-baseline gap-2">
        <span className="text-[10px] tracking-[0.24em] font-bold text-cyan-200 uppercase">
          PowerShell Semantic Intelligence · Phase 9.4
        </span>
        <span className="text-[9px] font-mono text-slate-500 ml-auto">
          NivXRay-native taxonomy · deterministic
        </span>
      </div>

      {hasDecodeError ? (
        <>
          <DecodeFailureCard err={decodeError} chainIndex={chainIndex} />
          {/* Even on failure, we still show the timeline so the analyst can
              audit every decoder decision. */}
          <DecodeTimeline steps={semantic.decode_timeline} chainIndex={chainIndex} />
        </>
      ) : (
        <>
          <ExplainableVerdict vb={semantic.verdict_breakdown} chainIndex={chainIndex} />
          <DeobfuscationChain deob={semantic.deobfuscation} chainIndex={chainIndex} />
          <BehaviorCards behaviors={semantic.behaviors_v2}
                         chainIndex={chainIndex}
                         onHighlight={onHighlight} />
          <DecodeTimeline steps={semantic.decode_timeline} chainIndex={chainIndex} />
          <EvidenceGraph graph={semantic.evidence_graph} chainIndex={chainIndex} />
          <ASTViewer tree={semantic.ast_tree}
                     resolvedVars={semantic.resolved_variables}
                     chainIndex={chainIndex} />
        </>
      )}
    </div>
  );
}
        </div>
      )}
    </div>
  );
}


export default function SemanticIntelligencePanel({ semantic, chainIndex, onHighlight }) {
  if (!semantic || !semantic.detected) return null;

  // Decode-error path — render only the failure card, halt all other UI.
  const decodeError = semantic.decode_error;
  const hasDecodeError = semantic.decode_outcome === "decode_error"
                          || (decodeError && decodeError.status === "decode_error");

  const hasV2 = (semantic.behaviors_v2 && semantic.behaviors_v2.length) ||
                (semantic.decode_timeline && semantic.decode_timeline.length) ||
                (semantic.verdict_breakdown && semantic.verdict_breakdown.verdict);
  if (!hasV2 && !hasDecodeError) return null;

  return (
    <div className="border-t border-cyan-500/30 bg-slate-950/40 p-3 space-y-3"
         data-testid={`semantic-v2-panel-${chainIndex}`}>
      <div className="flex items-baseline gap-2">
        <span className="text-[10px] tracking-[0.24em] font-bold text-cyan-200 uppercase">
          PowerShell Semantic Intelligence · Phase 9.4
        </span>
        <span className="text-[9px] font-mono text-slate-500 ml-auto">
          NivXRay-native taxonomy · deterministic
        </span>
      </div>

      {hasDecodeError ? (
        <>
          <DecodeFailureCard err={decodeError} chainIndex={chainIndex} />
          {/* Even on failure, we still show the timeline so the analyst can
              audit every decoder decision. */}
          <DecodeTimeline steps={semantic.decode_timeline} chainIndex={chainIndex} />
        </>
      ) : (
        <>
          <ExplainableVerdict vb={semantic.verdict_breakdown} chainIndex={chainIndex} />
          <BehaviorCards behaviors={semantic.behaviors_v2}
                         chainIndex={chainIndex}
                         onHighlight={onHighlight} />
          <DecodeTimeline steps={semantic.decode_timeline} chainIndex={chainIndex} />
          <EvidenceGraph graph={semantic.evidence_graph} chainIndex={chainIndex} />
          <ASTViewer tree={semantic.ast_tree}
                     resolvedVars={semantic.resolved_variables}
                     chainIndex={chainIndex} />
        </>
      )}
    </div>
  );
}
