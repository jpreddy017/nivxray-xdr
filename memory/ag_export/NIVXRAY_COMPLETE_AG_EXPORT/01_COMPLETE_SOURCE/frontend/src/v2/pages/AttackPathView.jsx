/**
 * AttackPathView — causality-first alternative to the chronological
 * DeviceTrajectoryV2 canvas. Renders the attack chain as a vertical
 * flow of nodes connected by labelled arrows (spawned · created ·
 * modified · contacted · loaded · executed).
 *
 * Deterministic: derives every node from the IKG. No LLM. Every step
 * is clickable and hydrates the global SelectionContext so the
 * Evidence Card and every other tab stays in sync.
 */
import { useMemo } from "react";
import { T } from "../theme";
import { useSelection } from "./SelectionContext";

const EDGE_LABELS = {
  spawned:    "spawned",
  created:    "created",
  modified:   "modified",
  loaded:     "loaded",
  contacted:  "contacted",
  executed_by:"executed by",
  maps_to:    "→ MITRE",
};

const NODE_TONE = {
  process:   { bg: "rgba(74,222,128,0.10)", br: "#4ADE80", fg: "#E5FFE5" },
  file:      { bg: "rgba(125,177,214,0.10)", br: "#7DB1D6", fg: "#E5F3FF" },
  registry:  { bg: "rgba(245,163,76,0.10)", br: "#F5A34C", fg: "#FFECD5" },
  network:   { bg: "rgba(248,113,113,0.10)", br: "#F87171", fg: "#FEE" },
  technique: { bg: "rgba(196,181,253,0.10)", br: "#C4B5FD", fg: "#F5F3FF" },
};

function typeIcon(t) {
  switch (t) {
    case "process":   return "◈";
    case "file":      return "▤";
    case "registry":  return "⧉";
    case "network":   return "◉";
    case "technique": return "★";
    default:          return "○";
  }
}

/**
 * Build a causality chain by walking spawn + touch edges from the
 * earliest root process. This is intentionally simple — Phase 5 will
 * replace it with the full Evidence Graph.
 */
function buildChain(inv) {
  const nodes = inv?.ikg?.nodes || [];
  const edges = inv?.ikg?.edges || [];
  const nodeById = Object.fromEntries(nodes.map(n => [n.id, n]));
  const processes = nodes.filter(n => n.type === "process");

  // Roots = processes with no incoming spawn edge OR the earliest by first_seen
  const spawnIn = new Set(edges.filter(e => e.type === "spawned").map(e => e.target));
  let roots = processes.filter(p => !spawnIn.has(p.id));
  if (roots.length === 0 && processes.length > 0) roots = [processes[0]];

  // Sort roots by first_seen so the "primary" attack chain is first
  roots.sort((a, b) => String(a.attrs?.first_seen).localeCompare(String(b.attrs?.first_seen)));

  const steps = [];
  const visited = new Set();

  const walk = (procId, depth = 0) => {
    if (visited.has(procId) || depth > 30) return;
    visited.add(procId);
    const p = nodeById[procId];
    if (!p) return;

    // Emit the process node itself
    steps.push({ node: p, incoming: null, depth });

    // Emit outbound side-effects (created / modified / contacted / loaded)
    const sideEffects = edges.filter(e => e.source === procId
                        && ["created", "modified", "contacted", "loaded"].includes(e.type))
                        .slice(0, 6);
    for (const se of sideEffects) {
      const dst = nodeById[se.target];
      if (!dst) continue;
      steps.push({ node: dst, incoming: se.type, depth: depth + 1 });
    }

    // Recurse into spawned children (BFS-ish by first_seen)
    const children = edges.filter(e => e.type === "spawned" && e.source === procId)
                          .map(e => nodeById[e.target]).filter(Boolean);
    children.sort((a, b) => String(a.attrs?.first_seen).localeCompare(String(b.attrs?.first_seen)));
    for (const c of children) {
      walk(c.id, depth + 1);
    }
  };

  for (const r of roots) walk(r.id);
  return steps;
}


export default function AttackPathView({ inv }) {
  const { selection, setSelection } = useSelection();
  const chain = useMemo(() => buildChain(inv), [inv]);

  if (chain.length === 0) {
    return (
      <div className="p-8 text-center" data-testid="attack-path-empty">
        <div className="text-[11px] font-mono" style={{ color: T.inkFaint }}>
          No causality data available for this case.
        </div>
      </div>
    );
  }

  return (
    <div data-testid="attack-path-view"
         className="px-6 py-4 overflow-y-auto"
         style={{ background: T.bg, minHeight: "70vh" }}>
      <div className="max-w-2xl mx-auto flex flex-col items-stretch gap-1">
        {chain.map((step, i) => {
          const tone = NODE_TONE[step.node.type] || NODE_TONE.process;
          const selected = selection?.id === step.node.id
                           || selection?.process_iid === step.node.id;
          return (
            <div key={`${step.node.id}-${i}`}>
              {step.incoming && (
                <div className="flex items-center gap-2 pl-8 py-1"
                     data-testid={`attack-edge-${i}`}>
                  <span className="text-[10px] font-mono uppercase tracking-[1.6px]"
                        style={{ color: T.inkMute }}>
                    │ {EDGE_LABELS[step.incoming] || step.incoming}
                  </span>
                </div>
              )}
              <button
                data-testid={`attack-node-${step.node.id}`}
                onClick={() => setSelection({
                  kind: step.node.type === "process" ? "process" : "event",
                  id: step.node.id,
                  frame_iid: step.node.type !== "process" ? step.node.id : null,
                  process_iid: step.node.type === "process" ? step.node.id : null,
                  source: "attack-path",
                })}
                className="text-left flex items-start gap-3 rounded-lg px-4 py-3 transition-all"
                style={{
                  marginLeft: Math.min(step.depth, 8) * 12,
                  background: selected ? T.paper2 : tone.bg,
                  border: `1px solid ${selected ? tone.br : "transparent"}`,
                  boxShadow: selected ? `0 0 12px ${tone.br}55` : "none",
                  cursor: "pointer",
                }}>
                <span className="text-[18px] leading-none"
                      style={{ color: tone.br }}>{typeIcon(step.node.type)}</span>
                <div className="flex-1 min-w-0">
                  <div className="text-[11px] tracking-[1.4px] uppercase font-mono font-bold"
                       style={{ color: tone.br }}>
                    {step.node.type}
                  </div>
                  <div className="text-[13px] font-mono font-bold truncate"
                       style={{ color: tone.fg }}>
                    {step.node.label}
                  </div>
                  {step.node.attrs?.first_seen && (
                    <div className="text-[10px] font-mono mt-0.5"
                         style={{ color: T.inkMute }}>
                      {step.node.attrs.first_seen}
                    </div>
                  )}
                </div>
              </button>
            </div>
          );
        })}
      </div>

      <div className="mt-6 text-center text-[9px] font-mono"
           style={{ color: T.inkFaint }}>
        Deterministic causality view · derived from the Investigation
        Knowledge Graph · click any node to sync every other view.
      </div>
    </div>
  );
}
