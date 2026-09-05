/**
 * ProcessTreeTab — parent→child projection of the IKG's `spawned` edges.
 * The primary DFIR view. Every node click updates the global
 * SelectionContext so every other tab focuses on the same process.
 */
import { useMemo } from "react";
import { T } from "../theme";
import { useSelection } from "./SelectionContext";

const BAND_TONES = {
  benign: "#4ADE80", informational: "#7DB1D6", low: "#D4C069",
  suspicious: "#F5A34C", malicious: "#F87171", critical: "#FCA5A5",
};


// Flatten the tree into a linear list of { node, verdict, techCount,
// depth, isLastChild } rows — no JSX-level recursion, no Babel infinite
// unfolding, and the render is a single map().
function flattenTree(roots) {
  const out = [];
  const walk = (item, depth) => {
    out.push({
      node:      item.node,
      verdict:   item.verdict,
      techCount: item.techCount,
      childCount: item.childrenNodes.length,
      isSelected: item.isSelected,
      depth,
    });
    for (const child of item.childrenNodes) walk(child, depth + 1);
  };
  for (const r of roots) walk(r, 0);
  return out;
}


export default function ProcessTreeTab({ inv }) {
  const { selection, setSelection } = useSelection();

  const rows = useMemo(() => {
    const nodes = inv?.ikg?.nodes || [];
    const edges = inv?.ikg?.edges || [];
    const nodeById = {}; nodes.forEach(n => (nodeById[n.id] = n));

    // Verdict nodes indexed by the process id they contribute to.
    const procVerdict = {};
    for (const n of nodes) {
      if (n.type !== "verdict" || n.attrs?.layer !== "process") continue;
      const target = edges.find(e => e.type === "contributes_to" && e.source === n.id);
      if (target) procVerdict[target.target] = n;
    }

    // Technique-count per process.
    const techByProc = {};
    for (const e of edges) {
      if (e.type !== "executed_by") continue;
      const nTech = edges.filter(x => x.type === "maps_to" && x.source === e.source).length;
      techByProc[e.target] = (techByProc[e.target] || 0) + nTech;
    }

    // Parent map from spawned edges.
    const childrenByParent = {};
    const parentOfChild = {};
    for (const e of edges) {
      if (e.type !== "spawned") continue;
      (childrenByParent[e.source] || (childrenByParent[e.source] = [])).push(e.target);
      parentOfChild[e.target] = e.source;
    }

    const processNodes = nodes.filter(n => n.type === "process");
    const roots = processNodes.filter(n => !parentOfChild[n.id]);

    const seen = new Set();
    const build = (procId) => {
      if (seen.has(procId)) return null;
      seen.add(procId);
      const node = nodeById[procId];
      if (!node) return null;
      const kids = (childrenByParent[procId] || [])
        .map(build).filter(Boolean);
      const isSel = selection && (
        (selection.kind === "process" && selection.process_iid === procId) ||
        (selection.kind === "event"   && selection.process_iid === procId)
      );
      return {
        node, verdict: procVerdict[procId],
        techCount: techByProc[procId] || 0,
        childrenNodes: kids, isSelected: !!isSel,
      };
    };

    const forest = roots.map(r => build(r.id)).filter(Boolean);
    for (const n of processNodes) {
      if (!seen.has(n.id)) {
        const b = build(n.id);
        if (b) forest.push(b);
      }
    }
    return flattenTree(forest);
  }, [inv, selection]);

  const selectProc = (node) => {
    setSelection({
      kind: "process", id: node.id, process_iid: node.id,
      frame_iid: null, source: "process-tree",
    });
  };

  if (rows.length === 0) {
    return <div className="p-12 text-[11px]" style={{ color: T.inkFaint }}
                data-testid="proctree-empty">
      No processes observed on this device.
    </div>;
  }

  return (
    <div data-testid="process-tree-tab" className="max-w-5xl mx-auto py-8 px-6">
      <div className="mb-4">
        <div className="text-[10px] tracking-[2px] font-bold mb-1"
             style={{ color: T.inkMute }}>PROCESS TREE</div>
        <div className="text-[22px] font-bold" style={{ color: T.ink }}>
          Parent → Child ancestry
        </div>
        <div className="text-[12px] mt-1" style={{ color: T.inkDim }}>
          Every branch is a `spawned` edge in the Investigation Knowledge Graph.
          Click any process to focus every other view on it.
        </div>
      </div>

      <div className="rounded-md p-3"
           style={{ background: T.paper2, border: `1px solid ${T.line}` }}>
        {rows.map((r) => {
          const band = r.verdict?.attrs?.band || "benign";
          const tone = BAND_TONES[band] || BAND_TONES.benign;
          const score = r.verdict?.attrs?.score ?? 0;
          return (
            <div key={r.node.id}
                 data-testid={`proctree-node-${r.node.id}`}
                 className="flex items-center gap-2 py-1"
                 style={{ marginLeft: r.depth * 22 }}>
              <span className="text-[10px]" style={{ color: T.inkFaint }}>
                {r.depth > 0 ? "└─" : "◆"}
              </span>
              <button onClick={() => selectProc(r.node)}
                      data-testid={`proctree-btn-${r.node.id}`}
                      className="flex items-center gap-2 px-2 py-1 rounded hover:bg-white/5"
                      style={{
                        background: r.isSelected ? T.paper2 : "transparent",
                        border: `1px solid ${r.isSelected ? tone : "transparent"}`,
                      }}>
                <span className="text-[12px] font-mono font-semibold"
                      style={{ color: T.ink }}>{r.node.label}</span>
                <span className="text-[9px] font-mono px-1 rounded"
                      style={{ background: T.paper2, color: tone,
                               border: `1px solid ${tone}66` }}>
                  {band.toUpperCase()} {score > 0 && `· ${score}`}
                </span>
                {r.techCount > 0 && (
                  <span className="text-[9px] font-mono"
                        style={{ color: T.inkMute }}>
                    {r.techCount} T·
                  </span>
                )}
                {r.childCount > 0 && (
                  <span className="text-[9px]" style={{ color: T.inkFaint }}>
                    {r.childCount}▸
                  </span>
                )}
              </button>
            </div>
          );
        })}
      </div>

      <div className="text-[10px] font-mono pt-4 border-t mt-4"
           style={{ color: T.inkFaint, borderColor: T.line }}>
        {inv?.header?.process_count || 0} process(es) · deterministic tree from the IKG
      </div>
    </div>
  );
}
