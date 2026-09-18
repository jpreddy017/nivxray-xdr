/**
 * NxGraphCanvas · the causality canvas of the investigation workspace.
 *
 * Renders the authoritative `/api/incidents/{id}/attack-graph` payload as
 * typed NODE CARDS with identifying context and SEMANTIC edges. It draws
 * nothing that the engine did not report:
 *   · an edge with no `evidence_refs` is drawn as INFERRED (dashed, marked)
 *     and never as an observed relationship;
 *   · a node keeps the engine's own `state` (OBSERVED · SUPPORTED ·
 *     POSSIBLE · NOT_OBSERVED);
 *   · no ancestry, timestamp or technique is synthesised to fill space.
 *
 * Layout is deterministic (BFS depth → column, stable order inside a
 * column) so the same incident always draws the same graph.
 */
import React, { useEffect, useMemo, useRef, useState } from "react";
import { Minus, Plus } from "lucide-react";

const W = 196, H = 62, GX = 96, GY = 20, PAD = 40;

const KIND_TOKEN = {
  incident: "INCIDENT", host: "HOST", user: "USER", process: "PROCESS",
  commandline: "COMMAND", event: "EVENT", event_id: "EVENT TYPE",
  file: "FILE", hash: "FILE", registry: "REGISTRY", ip: "NETWORK",
  domain: "NETWORK", url: "NETWORK", network: "NETWORK",
  finding: "FINDING", capability: "CAPABILITY", detection: "DETECTION",
  signature: "DETECTION", match: "CORRELATION", technique: "TECHNIQUE",
  stage: "ATT&CK STAGE", gap: "EVIDENCE GAP", ioc: "IOC",
};

/** Relationship verb — the analyst reads the semantic, the raw `rel`
 *  stays on the relationship row in the details pane. */
export const REL_VERB = {
  EXECUTED: "executed", SPAWNED: "spawned", CREATED: "created",
  ACCESSED: "accessed", CONNECTED_TO: "connected to",
  RESOLVED: "resolved", MODIFIED: "modified",
  AUTHENTICATED_AS: "authenticated as", DROPPED: "dropped",
  SUPPORTED_BY: "evidence of", INVESTIGATED_BY: "investigated by",
  PIVOTED_TO: "pivoted to", DETECTED_BY: "detected by",
  BELONGS_TO: "belongs to", OBSERVED_ON: "observed on",
  RELATED_TO: "related to", CORRELATED_WITH: "correlated with",
};

export function relVerb(rel) {
  if (!rel) return "related to";
  return REL_VERB[String(rel).toUpperCase()]
    || String(rel).replace(/_/g, " ").toLowerCase();
}

export function kindToken(kind) {
  return KIND_TOKEN[String(kind)] || String(kind || "ENTITY").toUpperCase();
}

/** Two identifying lines for a card — engine attributes only. */
export function nodeContext(n) {
  const a = n?.attrs || {};
  const out = [];
  if (a.host) out.push(a.host);
  if (a.user) out.push(a.user);
  if (a.pid != null) out.push(`pid ${a.pid}`);
  if (a.event_id) out.push(`event ${a.event_id}`);
  if (a.tid) out.push(a.tid);
  if (a.capability) out.push(a.capability);
  if (a.verdict) out.push(String(a.verdict).toUpperCase());
  if (a.confidence != null) out.push(`${a.confidence}% confidence`);
  if (a.role) out.push(a.role);
  if (a.suggested_capability) out.push(`needs ${a.suggested_capability}`);
  return out;
}

export default function NxGraphCanvas({
  nodes = [], edges = [], primaryPath = [], altPaths = [],
  selectedId, onSelect, cmd, opts = {}, dimIds,
}) {
  const box = useRef(null);
  const [view, setView] = useState({ k: 1, x: 0, y: 0 });
  const [drag, setDrag] = useState(null);
  const [expanded, setExpanded] = useState(() => new Set());

  const byId = useMemo(() => {
    const m = new Map();
    nodes.forEach((n) => m.set(n.id, n));
    return m;
  }, [nodes]);

  /* ── depth (column) per node · BFS from the incident / sources ── */
  const depth = useMemo(() => {
    const out = new Map();
    const adj = new Map();
    const indeg = new Map();
    nodes.forEach((n) => { adj.set(n.id, []); indeg.set(n.id, 0); });
    edges.forEach((e) => {
      if (!adj.has(e.src) || !adj.has(e.dst)) return;
      adj.get(e.src).push(e.dst);
      indeg.set(e.dst, (indeg.get(e.dst) || 0) + 1);
    });
    const roots = nodes
      .filter((n) => n.kind === "incident" || (indeg.get(n.id) || 0) === 0)
      .map((n) => n.id);
    const q = roots.length ? [...roots] : nodes.slice(0, 1).map((n) => n.id);
    q.forEach((id) => out.set(id, 0));
    while (q.length) {
      const id = q.shift();
      const d = out.get(id) || 0;
      (adj.get(id) || []).forEach((nx) => {
        if (out.has(nx)) return;
        out.set(nx, d + 1);
        q.push(nx);
      });
    }
    let orphan = 0;
    nodes.forEach((n) => { if (!out.has(n.id)) orphan = 1; });
    if (orphan) {
      const max = Math.max(0, ...Array.from(out.values()));
      nodes.forEach((n) => { if (!out.has(n.id)) out.set(n.id, max + 1); });
    }
    return out;
  }, [nodes, edges]);

  /* ── grouping (progressive disclosure of repeated classes) ────── */
  const { cells, groupOf } = useMemo(() => {
    const cols = new Map();
    nodes.forEach((n) => {
      const d = depth.get(n.id) || 0;
      if (!cols.has(d)) cols.set(d, []);
      cols.get(d).push(n);
    });
    const list = [];
    const gmap = new Map();
    Array.from(cols.keys()).sort((a, b) => a - b).forEach((d) => {
      const col = cols.get(d).slice().sort((a, b) =>
        String(a.kind).localeCompare(String(b.kind))
        || String(a.label).localeCompare(String(b.label)));
      if (!opts.groupSimilar) { col.forEach((n) => list.push({ d, node: n })); return; }
      const buckets = new Map();
      col.forEach((n) => {
        const k = `${n.kind}|${n.state}`;
        if (!buckets.has(k)) buckets.set(k, []);
        buckets.get(k).push(n);
      });
      buckets.forEach((members, key) => {
        const gid = `group:${d}:${key}`;
        if (members.length < 3 || expanded.has(gid)) {
          members.forEach((n) => list.push({ d, node: n }));
          return;
        }
        members.forEach((n) => gmap.set(n.id, gid));
        list.push({ d, group: {
          id: gid, kind: members[0].kind, state: members[0].state,
          label: `${members.length} × ${kindToken(members[0].kind)}`,
          members: members.map((m) => m.id),
        } });
      });
    });
    const perCol = new Map();
    const placed = list.map((it) => {
      const row = perCol.get(it.d) || 0;
      perCol.set(it.d, row + 1);
      return { ...it, x: PAD + it.d * (W + GX), y: PAD + row * (H + GY) };
    });
    return { cells: placed, groupOf: gmap };
  }, [nodes, depth, opts.groupSimilar, expanded]);

  const pos = useMemo(() => {
    const m = new Map();
    cells.forEach((c) => {
      if (c.group) {
        m.set(c.group.id, c);
        c.group.members.forEach((id) => m.set(id, c));
      } else m.set(c.node.id, c);
    });
    return m;
  }, [cells]);

  const neighbors = useMemo(() => {
    const s = new Set();
    if (!selectedId) return s;
    edges.forEach((e) => {
      if (e.src === selectedId) s.add(e.dst);
      if (e.dst === selectedId) s.add(e.src);
    });
    return s;
  }, [edges, selectedId]);

  const hotPath = useMemo(() => {
    const s = new Set();
    if (opts.showAllPaths) {
      [primaryPath, ...(altPaths || [])].forEach((p) =>
        (p || []).forEach((id) => s.add(id)));
    }
    return s;
  }, [opts.showAllPaths, primaryPath, altPaths]);

  const drawEdges = useMemo(() => {
    const seen = new Set();
    const out = [];
    edges.forEach((e) => {
      const a = pos.get(e.src);
      const b = pos.get(e.dst);
      if (!a || !b) return;
      const sid = a.group ? a.group.id : e.src;
      const did = b.group ? b.group.id : e.dst;
      if (sid === did) return;
      const key = `${sid}|${e.rel}|${did}`;
      if (seen.has(key)) return;
      seen.add(key);
      const inferred = !(e.evidence_refs || []).length;
      out.push({ ...e, sid, did, a, b, inferred });
    });
    return out;
  }, [edges, pos]);

  const extent = useMemo(() => {
    let mx = 600, my = 420;
    cells.forEach((c) => { mx = Math.max(mx, c.x + W + PAD);
                           my = Math.max(my, c.y + H + PAD); });
    return { w: mx, h: my };
  }, [cells]);

  /* ── imperative view commands from the rail ───────────────────── */
  useEffect(() => {
    if (!cmd?.kind) return;
    if (cmd.kind === "center") { setView({ k: 1, x: 0, y: 0 }); return; }
    if (cmd.kind === "fit") {
      const el = box.current;
      if (!el) return;
      const k = Math.min(el.clientWidth / extent.w,
                         el.clientHeight / extent.h, 1.4);
      setView({ k: Math.max(0.25, k), x: 0, y: 0 });
    }
  }, [cmd, extent.w, extent.h]);

  const onWheel = (e) => {
    e.preventDefault();
    setView((v) => ({ ...v,
      k: Math.min(2.2, Math.max(0.25, v.k * (e.deltaY > 0 ? 0.92 : 1.08))) }));
  };

  const cardTone = (n) => {
    if (!opts.overlays?.risk) return undefined;
    const a = n.attrs || {};
    const risky = String(a.verdict || "").toLowerCase() === "malicious"
      || String(a.verdict || "").toLowerCase() === "suspicious"
      || n.kind === "detection" || n.kind === "gap";
    return risky ? "1" : undefined;
  };

  const isDim = (id) => {
    if (dimIds && dimIds.size && !dimIds.has(id)) return "1";
    if (opts.focusSelection && selectedId
        && id !== selectedId && !neighbors.has(id)) return "1";
    if (hotPath.size && !hotPath.has(id)) return "1";
    return undefined;
  };

  return (
    <div className="inv-cv" ref={box} data-drag={drag ? "1" : undefined}
         data-testid="inv-graph-canvas"
         onWheel={onWheel}
         onMouseDown={(e) => setDrag({ x: e.clientX, y: e.clientY,
                                       ox: view.x, oy: view.y })}
         onMouseMove={(e) => {
           if (!drag) return;
           setView((v) => ({ ...v, x: drag.ox + (e.clientX - drag.x),
                                    y: drag.oy + (e.clientY - drag.y) }));
         }}
         onMouseUp={() => setDrag(null)}
         onMouseLeave={() => setDrag(null)}>
      <svg width="100%" height="100%" role="img"
           aria-label="incident causality graph">
        <g transform={`translate(${view.x},${view.y}) scale(${view.k})`}>
          {drawEdges.map((e) => {
            const x1 = e.a.x + W, y1 = e.a.y + H / 2;
            const x2 = e.b.x, y2 = e.b.y + H / 2;
            const mx = (x1 + x2) / 2;
            const hot = hotPath.has(e.src) && hotPath.has(e.dst);
            const dim = isDim(e.src) || isDim(e.dst);
            const tech = opts.overlays?.attack && e.technique_id
              ? ` · ${e.technique_id}` : "";
            return (
              <g key={e.id || `${e.sid}${e.rel}${e.did}`}>
                <path className="g-edge" data-inferred={e.inferred ? "1" : undefined}
                      data-hot={hot ? "1" : undefined} data-dim={dim}
                      d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`}
                      markerEnd="url(#nx-arrow)" />
                <text className="g-edge__l" x={mx} y={(y1 + y2) / 2 - 4}
                      textAnchor="middle"
                      data-inferred={e.inferred ? "1" : undefined}
                      opacity={dim ? 0.2 : 1}>
                  {relVerb(e.rel)}{tech}{e.inferred ? " · inferred" : ""}
                </text>
              </g>
            );
          })}

          {cells.map((c) => {
            const isGroup = Boolean(c.group);
            const n = isGroup ? c.group : c.node;
            const ctx = isGroup
              ? [`${c.group.members.length} entities of one class`,
                 "click to expand"]
              : nodeContext(c.node);
            const conf = !isGroup && opts.overlays?.confidence
              && c.node.attrs?.confidence != null
              ? `${c.node.attrs.confidence}%` : null;
            return (
              <g key={n.id} className="g-card" transform={`translate(${c.x},${c.y})`}
                 data-sel={selectedId === n.id ? "1" : undefined}
                 data-neighbor={opts.showNeighbors && neighbors.has(n.id)
                   ? "1" : undefined}
                 data-risk={isGroup ? undefined : cardTone(c.node)}
                 data-dim={isDim(n.id)}
                 data-testid={`inv-graph-node-${n.id}`}
                 onClick={(e) => {
                   e.stopPropagation();
                   if (isGroup) {
                     setExpanded((p) => new Set(p).add(n.id));
                     return;
                   }
                   onSelect && onSelect(n.id);
                 }}>
                <rect className="g-card__bg" width={W} height={H} />
                <text className="g-card__kind" x={9} y={14}>{kindToken(n.kind)}</text>
                <text className="g-card__state" x={W - 9} y={14} textAnchor="end"
                      fill={n.state === "OBSERVED" ? "var(--nx-ok, #22c55e)"
                        : n.state === "NOT_OBSERVED" ? "var(--nx-faint, #6b7280)"
                        : "var(--nx-high, #f59e0b)"}>
                  {String(n.state || "").replace("_", " ")}
                </text>
                <text className="g-card__label" x={9} y={33}>
                  {String(n.label || n.id).slice(0, 26)}
                </text>
                <text className="g-card__sub" x={9} y={46}>
                  {(ctx[0] || "no further identifying context").slice(0, 32)}
                </text>
                <text className="g-card__sub" x={9} y={56}>
                  {(conf || ctx[1] || "").slice(0, 32)}
                </text>
              </g>
            );
          })}
        </g>
        <defs>
          <marker id="nx-arrow" markerWidth="7" markerHeight="7" refX="6"
                  refY="3" orient="auto">
            <path d="M0,0 L6,3 L0,6 z" fill="var(--nx-bd-strong, #4b5563)" />
          </marker>
        </defs>
      </svg>

      <div className="inv-cv__hud">
        <button className="inv-chip" data-testid="inv-graph-zoom-out"
                onClick={() => setView((v) => ({ ...v,
                  k: Math.max(0.25, v.k * 0.9) }))}>
          <Minus size={10} />
        </button>
        <span className="inv-chip" style={{ cursor: "default" }}
              data-testid="inv-graph-zoom">{Math.round(view.k * 100)}%</span>
        <button className="inv-chip" data-testid="inv-graph-zoom-in"
                onClick={() => setView((v) => ({ ...v,
                  k: Math.min(2.2, v.k * 1.1) }))}>
          <Plus size={10} />
        </button>
      </div>

      {opts.showLegend && (
        <div className="inv-cv__legend" data-testid="inv-graph-legend">
          <b>Relationships</b> — solid: observed, carries evidence ·
          dashed amber: inferred, no evidence reference on the edge.<br />
          <b>Node state</b> — OBSERVED evidence exists · SUPPORTED derived ·
          NOT OBSERVED the engine looked and found nothing.
          {opts.overlays?.risk && <><br /><b>Risk ring</b> — amber border marks
            a malicious/suspicious verdict, a detection or an evidence gap.</>}
        </div>
      )}
    </div>
  );
}
