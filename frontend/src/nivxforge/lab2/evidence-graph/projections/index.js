/**
 * Projections turn a CIO into { nodes, edges, empty, note } payloads
 * consumable by React Flow via StageNode. Every projection reads only
 * from `cio` — no external data, no fetch, no derived state. This keeps
 * X-Lab true to the "backend investigates, frontend projects" contract.
 */

const asPct = (v) => {
  if (typeof v !== "number") return null;
  if (v > 1) return Math.round(v);
  return Math.round(v * 100);
};

const kindLabel = (k) => {
  const map = {
    artifact: "ARTIFACT",
    decoded_fragment: "DECODED",
    ioc: "IOC",
    mitre_technique: "MITRE",
    lolbin: "LOLBAS",
    behaviour: "BEHAVIOUR",
    behavior: "BEHAVIOUR",
    verdict: "VERDICT",
    command: "COMMAND",
    script: "SCRIPT",
  };
  return map[(k || "").toLowerCase()] || (k || "").toUpperCase();
};

// ── Investigation projection — full CIO evidence graph, unfiltered.
//    Every node/edge from cio.evidence_graph appears; layout is DAG.
export function projectInvestigation(cio) {
  const g = cio?.evidence_graph || {};
  const rawNodes = g.nodes || [];
  const rawEdges = g.edges || [];
  if (rawNodes.length === 0) return { nodes: [], edges: [], empty: true, note: "cio.evidence_graph is empty" };

  const nodes = rawNodes.map((n) => {
    const attrs = n.attrs || {};
    const subKind = attrs.ioc_kind || attrs.type || "";
    const conf = asPct(n.confidence);
    let subtitle = "";
    if (n.kind === "decoded_fragment") subtitle = attrs.op ? `${attrs.op} · L${attrs.layer ?? "?"}` : `L${attrs.layer ?? "?"}`;
    else if (n.kind === "ioc") subtitle = subKind || "indicator";
    else if (n.kind === "mitre_technique") subtitle = attrs.tactic || "technique";
    else if (n.kind === "lolbin") subtitle = (attrs.techniques || []).join(" · ") || "LOLBin";
    else if (n.kind === "behaviour" || n.kind === "behavior") subtitle = attrs.tactic || attrs.behaviour_class || "behaviour";
    else if (n.kind === "verdict") subtitle = attrs.class || attrs.verdict_class || "verdict";
    else if (n.kind === "artifact") subtitle = attrs.role || "seed";
    return {
      id: n.id,
      type: "stage",
      data: {
        id: n.id,
        title: (n.label || n.name || n.id).toString().slice(0, 60),
        subtitle: `${kindLabel(n.kind)} · ${subtitle}`.slice(0, 80),
        kind: n.kind,
        subKind,
        class: n.class || attrs.class || attrs.severity,
        confidence: conf,
        hot: n.kind === "verdict" || (attrs.class === "critical") || n.hot === true,
        _raw: n,
      },
      position: { x: 0, y: 0 },
    };
  });

  const edges = rawEdges.map((e, i) => ({
    id: e.id || `e${i}`,
    source: e.source,
    target: e.target,
    animated: e.hot === true || e.animated === true,
    label: e.relation || e.label || "",
    labelStyle: { fontSize: 10, fill: "var(--fg-dim, #7C8494)" },
    style: {
      stroke: e.hot ? "var(--crit, #ff5c5c)" : "var(--fg-dim, #4b525f)",
      strokeWidth: e.hot ? 1.5 : 1,
    },
    data: { _raw: e },
  }));

  return { nodes, edges, empty: false, note: "" };
}

// ── Decode Flow projection — linear ladder of decode_chain layers.
export function projectDecodeFlow(cio) {
  const chain = cio?.decode_chain || [];
  if (chain.length === 0) return { nodes: [], edges: [], empty: true, note: "cio.decode_chain is empty" };

  const nodes = chain.map((layer, i) => ({
    id: `dec-${i}`,
    type: "stage",
    data: {
      id: `dec-${i}`,
      title: `L${i} · ${layer.op || layer.name || "layer"}`,
      subtitle: (layer.preview || layer.output_preview || "").toString().slice(0, 70),
      kind: "decoded_fragment",
      class: "context",
      confidence: asPct(layer.confidence),
      hot: false,
      _raw: layer,
    },
    position: { x: 0, y: 0 },
  }));

  const edges = chain.slice(1).map((_, i) => ({
    id: `dec-e${i}`,
    source: `dec-${i}`,
    target: `dec-${i + 1}`,
    animated: true,
    label: "decodes",
    labelStyle: { fontSize: 10, fill: "var(--mint, #55e6b8)" },
    style: { stroke: "var(--mint, #55e6b8)", strokeWidth: 1.4 },
  }));

  return { nodes, edges, empty: false, note: "" };
}

// ── Attack Chain projection — behavioural + IOC + MITRE nodes (no raw decoded
//    fragments), grouped by tactic lane if available.
export function projectAttackChain(cio) {
  const g = cio?.evidence_graph || {};
  const raw = g.nodes || [];
  const rawE = g.edges || [];
  const keep = new Set(["ioc", "mitre_technique", "lolbin", "behaviour", "behavior", "verdict", "artifact"]);
  const nodesById = new Map();
  raw.forEach((n) => { if (keep.has(n.kind)) nodesById.set(n.id, n); });
  if (nodesById.size === 0) return { nodes: [], edges: [], empty: true, note: "no behavioural/attack nodes yet" };

  const nodes = Array.from(nodesById.values()).map((n) => {
    const attrs = n.attrs || {};
    const conf = asPct(n.confidence);
    return {
      id: n.id,
      type: "stage",
      data: {
        id: n.id,
        title: (n.label || n.name || n.id).toString().slice(0, 60),
        subtitle: `${kindLabel(n.kind)} · ${attrs.tactic || attrs.ioc_kind || ""}`.slice(0, 80),
        kind: n.kind,
        subKind: attrs.ioc_kind || "",
        class: attrs.class || n.class,
        confidence: conf,
        hot: attrs.class === "critical" || n.kind === "verdict",
        _raw: n,
      },
      position: { x: 0, y: 0 },
    };
  });

  const edges = rawE
    .filter((e) => nodesById.has(e.source) && nodesById.has(e.target))
    .map((e, i) => ({
      id: e.id || `ae${i}`,
      source: e.source,
      target: e.target,
      animated: e.hot === true,
      label: e.relation || e.label || "",
      labelStyle: { fontSize: 10, fill: "var(--fg-dim, #7C8494)" },
      style: { stroke: e.hot ? "var(--crit, #ff5c5c)" : "var(--fg-dim, #4b525f)", strokeWidth: e.hot ? 1.5 : 1 },
      data: { _raw: e },
    }));

  return { nodes, edges, empty: false, note: "" };
}

// ── MITRE projection — only mitre_technique nodes, grouped by tactic.
//    Edges are the direct predecessors so analysts see what led to each TTP.
export function projectMitre(cio) {
  const g = cio?.evidence_graph || {};
  const all = g.nodes || [];
  const rawE = g.edges || [];
  const mit = all.filter((n) => n.kind === "mitre_technique");
  if (mit.length === 0) return { nodes: [], edges: [], empty: true, note: "no MITRE techniques extracted" };

  // Include the direct sources of each MITRE technique for context.
  const keep = new Set(mit.map((m) => m.id));
  rawE.forEach((e) => { if (keep.has(e.target)) keep.add(e.source); });
  const kept = all.filter((n) => keep.has(n.id));

  const nodes = kept.map((n) => {
    const attrs = n.attrs || {};
    return {
      id: n.id,
      type: "stage",
      data: {
        id: n.id,
        title: (n.label || n.id).toString().slice(0, 60),
        subtitle: n.kind === "mitre_technique"
          ? `${attrs.tactic || "tactic"}${attrs.technique_id ? " · " + attrs.technique_id : ""}`
          : kindLabel(n.kind),
        kind: n.kind,
        subKind: attrs.ioc_kind || "",
        class: attrs.class || n.class,
        confidence: asPct(n.confidence),
        hot: n.kind === "mitre_technique",
        _raw: n,
      },
      position: { x: 0, y: 0 },
    };
  });

  const edges = rawE
    .filter((e) => keep.has(e.source) && keep.has(e.target))
    .map((e, i) => ({
      id: e.id || `me${i}`,
      source: e.source,
      target: e.target,
      animated: true,
      label: e.relation || "informs",
      labelStyle: { fontSize: 10, fill: "var(--gold, #f5c451)" },
      style: { stroke: "var(--gold, #f5c451)", strokeWidth: 1.3 },
      data: { _raw: e },
    }));

  return { nodes, edges, empty: false, note: "" };
}

// ── Timeline projection — verdict.confidence_timeline entries as a linear
//    stage sequence, colour-tinted by class.
export function projectTimeline(cio) {
  const tl = cio?.verdict?.confidence_timeline || [];
  if (tl.length === 0) return { nodes: [], edges: [], empty: true, note: "no confidence timeline yet" };

  const nodes = tl.map((entry, i) => ({
    id: `tl-${i}`,
    type: "stage",
    data: {
      id: `tl-${i}`,
      title: (entry.contributor_label || `Stage ${i + 1}`).toString().slice(0, 60),
      subtitle: `${(entry.contributor_kind || "signal").toString()} · stage ${entry.stage ?? i + 1}`,
      kind: entry.contributor_kind || "behaviour",
      class: entry.class,
      confidence: typeof entry.confidence_pct === "number" ? entry.confidence_pct : null,
      hot: entry.class === "critical",
      badgeText: typeof entry.confidence_pct === "number" ? `${entry.confidence_pct}%` : "",
      _raw: entry,
    },
    position: { x: 0, y: 0 },
  }));

  const edges = tl.slice(1).map((_, i) => ({
    id: `tl-e${i}`,
    source: `tl-${i}`,
    target: `tl-${i + 1}`,
    animated: true,
    label: "",
    style: { stroke: "var(--mint, #55e6b8)", strokeWidth: 1.2 },
  }));

  return { nodes, edges, empty: false, note: "" };
}

export const PROJECTIONS = {
  investigation: { label: "Investigation", fn: projectInvestigation, direction: "LR" },
  decode: { label: "Decode Flow", fn: projectDecodeFlow, direction: "LR" },
  attack: { label: "Attack Chain", fn: projectAttackChain, direction: "LR" },
  mitre: { label: "MITRE", fn: projectMitre, direction: "TB" },
  timeline: { label: "Timeline", fn: projectTimeline, direction: "LR" },
  processtree: { label: "Process Tree", fn: projectProcessTree, direction: "TB" },
};

// ── Process Tree projection — walks process/lolbin/behaviour nodes as a
//    spawn-tree. Uses evidence_graph edges with relation ∈ {spawn, executes,
//    invokes, launches, parent_of, contains} when present. Falls back to
//    "artifact → lolbin → behaviour → verdict" heuristic ordering when the
//    CIO carries no explicit process nodes. Layout defaults TB so the tree
//    reads like a process explorer.
export function projectProcessTree(cio) {
  const g = cio?.evidence_graph || {};
  const rawNodes = g.nodes || [];
  const rawEdges = g.edges || [];
  const spawnRelations = new Set(["spawn", "spawns", "executes", "executed", "invokes", "launches", "parent_of", "contains", "runs"]);

  const isProcessLike = (n) => {
    const k = (n.kind || "").toLowerCase();
    if (k === "process" || k === "lolbin" || k === "lolbas") return true;
    // Behaviour/artifact/verdict count as pseudo-processes so the tree isn't empty on today's CIO.
    if (k === "artifact" || k === "behaviour" || k === "behavior" || k === "verdict") return true;
    if (k === "command" || k === "script") return true;
    return false;
  };

  const procNodes = rawNodes.filter(isProcessLike);
  if (procNodes.length === 0) {
    return { nodes: [], edges: [], empty: true, note: "no process-like nodes in cio.evidence_graph" };
  }

  const keptIds = new Set(procNodes.map((n) => n.id));

  // Prefer explicit spawn/exec edges; otherwise walk any edge that connects two
  // process-like nodes so the tree stays connected.
  const spawnEdges = rawEdges.filter((e) => {
    if (!keptIds.has(e.source) || !keptIds.has(e.target)) return false;
    const rel = (e.relation || e.label || "").toString().toLowerCase();
    if (spawnRelations.has(rel)) return true;
    return true; // fallback — still include (heuristic tree)
  });

  const nodes = procNodes.map((n) => {
    const attrs = n.attrs || {};
    const conf = typeof n.confidence === "number" ? (n.confidence > 1 ? Math.round(n.confidence) : Math.round(n.confidence * 100)) : null;
    return {
      id: n.id,
      type: "stage",
      data: {
        id: n.id,
        title: (attrs.image || attrs.process_name || n.label || n.id).toString().slice(0, 60),
        subtitle: n.kind === "lolbin"
          ? `LOLBIN · ${(attrs.techniques || []).join(" · ") || attrs.binary || ""}`
          : n.kind === "artifact"
            ? `SEED · ${(attrs.role || "input").toString()}`
            : n.kind === "verdict"
              ? `VERDICT · ${attrs.class || "unknown"}`
              : `${(n.kind || "process").toUpperCase()} · ${(attrs.tactic || attrs.behaviour_class || "").toString()}`,
        kind: n.kind,
        subKind: attrs.ioc_kind || "",
        class: attrs.class || n.class,
        confidence: conf,
        hot: attrs.class === "critical" || n.kind === "verdict",
        _raw: n,
      },
      position: { x: 0, y: 0 },
    };
  });

  const edges = spawnEdges.map((e, i) => ({
    id: e.id || `pt-${i}`,
    source: e.source,
    target: e.target,
    animated: e.hot === true || spawnRelations.has((e.relation || "").toString().toLowerCase()),
    label: (e.relation || e.label || "spawns").toString(),
    labelStyle: { fontSize: 10, fill: "var(--mint, #55e6b8)" },
    style: {
      stroke: e.hot ? "var(--crit, #ff5c5c)" : "var(--mint, #55e6b8)",
      strokeWidth: e.hot ? 1.5 : 1.2,
    },
    data: { _raw: e },
  }));

  return { nodes, edges, empty: false, note: "" };
}
