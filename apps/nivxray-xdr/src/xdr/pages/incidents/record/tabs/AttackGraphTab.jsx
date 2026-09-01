/**
 * AttackGraphTab · Round 35 · Operational MITRE ATT&CK Chain Graph.
 *
 * Consumes `GET /api/incidents/{id}/attack-graph`.  Renders the
 * governed evidence graph as an interactive SVG canvas:
 *
 *   [Entities] → [Events / Event IDs] → [Processes / Commandlines] →
 *   [MITRE Techniques] → [Attack-cycle Stages] → [Gaps]
 *
 * NOT_OBSERVED stages surface as gap markers only, never as fake
 * nodes.  Every click opens the right-side Evidence Inspector with
 * the concrete governed provenance for that node or edge.
 */
import React, { useEffect, useMemo, useState } from "react";
import { Loader2 } from "lucide-react";

import api from "@/lib/api";


// ── State grammar ──────────────────────────────────────────────────
const STATE_TONE = {
  OBSERVED:     { fill: "#7c3aed", stroke: "#a78bfa", label: "●" },
  SUPPORTED:    { fill: "#4c1d95", stroke: "#8b5cf6", label: "◐" },
  POSSIBLE:     { fill: "#1e293b", stroke: "#94a3b8", label: "○" },
  NOT_OBSERVED: { fill: "#0f172a", stroke: "#334155", label: "—" },
};

// ── Kind → column (deterministic left-to-right layout) ─────────────
const KIND_COLUMN = {
  incident:     0,
  host:         1,
  user:         1,
  event:        2,
  event_id:     2,
  signature:    2,
  process:      3,
  commandline:  3,
  ip:           3,
  hash:         3,
  finding:      4,
  capability:   4,
  technique:    5,
  stage:        6,
  gap:          7,
};

// ── Kind → default toggle group ────────────────────────────────────
const KIND_LAYER = {
  incident: "entities",  host: "entities",  user: "entities",
  ip: "entities",        hash: "entities",
  event: "events",       event_id: "events",  signature: "events",
  process: "processes",  commandline: "processes",
  finding: "findings",   capability: "capabilities",
  technique: "mitre",    stage: "mitre",
  gap: "gaps",
};


function TonedNode({ node, x, y, w = 200, h = 34, onClick, focused, dimmed }) {
  const tone = STATE_TONE[node.state] || STATE_TONE.NOT_OBSERVED;
  const stroke = focused ? "#fbbf24" : tone.stroke;
  return (
    <g style={{ opacity: dimmed ? 0.25 : 1, cursor: "pointer",
                  transition: "opacity 220ms ease" }}
        onClick={onClick}
        data-testid={`xdr-ag-node-${node.id}`}>
      <rect x={x} y={y} width={w} height={h} rx={6}
             fill={tone.fill} stroke={stroke} strokeWidth={focused ? 2 : 1} />
      <text x={x + 8} y={y + 14} fontSize={9} fontFamily="ui-monospace, monospace"
             fill="#e2e8f0" opacity={0.7}>
        {node.kind.toUpperCase()} · {node.state}
      </text>
      <text x={x + 8} y={y + 27} fontSize={11} fontFamily="ui-sans-serif"
             fill="#f8fafc" style={{ fontWeight: 500 }}>
        {(node.label || "").length > 32
          ? (node.label || "").slice(0, 30) + "…"
          : node.label}
      </text>
    </g>
  );
}


export default function AttackGraphTab({ incident }) {
  const [graph, setGraph] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedId, setSelectedId] = useState(null);
  const [selectedKind, setSelectedKind] = useState(null); // "node" | "edge"
  const [layers, setLayers] = useState({
    entities: true, events: true, processes: true, findings: true,
    capabilities: true, mitre: true, gaps: false,
  });
  const [timeMax, setTimeMax] = useState(100); // slider 0-100

  useEffect(() => {
    if (!incident?.id) return undefined;
    let cancelled = false;
    (async () => {
      setLoading(true); setError(null);
      try {
        const { data } = await api.get(`/incidents/${incident.id}/attack-graph`);
        if (!cancelled) setGraph(data);
      } catch (e) {
        if (!cancelled) setError(e?.message || String(e));
      } finally { if (!cancelled) setLoading(false); }
    })();
    return () => { cancelled = true; };
  }, [incident?.id]);

  // Deterministic layered layout.
  const layout = useMemo(() => {
    if (!graph) return null;
    const nodes = graph.nodes.filter(n => layers[KIND_LAYER[n.kind] || "entities"]);
    const byCol = new Map();
    for (const n of nodes) {
      const c = KIND_COLUMN[n.kind] ?? 3;
      if (!byCol.has(c)) byCol.set(c, []);
      byCol.get(c).push(n);
    }
    // Deterministic sort within column.
    for (const arr of byCol.values()) {
      arr.sort((a, b) => (a.state === b.state ? 0
                                : a.state === "OBSERVED" ? -1
                                : b.state === "OBSERVED" ? 1
                                : a.label.localeCompare(b.label)));
    }
    // Position.
    const colWidth = 240, rowHeight = 50, topPad = 20, leftPad = 20;
    const pos = new Map();
    for (const [col, arr] of byCol.entries()) {
      arr.forEach((n, i) => {
        pos.set(n.id, {
          x: leftPad + col * colWidth,
          y: topPad + i * rowHeight,
        });
      });
    }
    const maxCol = byCol.size ? Math.max(...byCol.keys()) : 0;
    const maxRow = byCol.size ? Math.max(...Array.from(byCol.values(),
                                                                  a => a.length)) : 0;
    return {
      nodes, pos,
      width:  leftPad + (maxCol + 1) * colWidth + 20,
      height: topPad + Math.max(maxRow, 6) * rowHeight + 40,
    };
  }, [graph, layers]);

  const timelineWindow = useMemo(() => {
    if (!graph || !graph.timeline || graph.timeline.length === 0) return null;
    const total = graph.timeline.length;
    const cut = Math.max(1, Math.round(total * timeMax / 100));
    return new Set(graph.timeline.slice(0, cut).map(
      t => `${t.src}|${t.rel}|${t.dst}`
    ));
  }, [graph, timeMax]);

  if (loading) return (
    <div className="rl-loading" data-testid="xdr-record-attack-graph-loading">
      <Loader2 size={12} className="rl-spin" style={{ verticalAlign: "-2px", marginRight: 6 }} />
      COMPOSING ATTACK GRAPH…
    </div>
  );
  if (error && !graph) return <div className="rl-error">{String(error)}</div>;
  if (!graph) return null;

  const nodeMap = new Map(graph.nodes.map(n => [n.id, n]));
  const visibleNodeIds = new Set((layout?.nodes || []).map(n => n.id));
  const visibleEdges = (graph.edges || []).filter(
    e => visibleNodeIds.has(e.src) && visibleNodeIds.has(e.dst)
  );

  const selected = selectedId ? (selectedKind === "node"
    ? nodeMap.get(selectedId)
    : (graph.edges.find(e => e.id === selectedId))) : null;

  return (
    <div data-testid="xdr-record-attack-graph" style={{ display: "grid",
                                                          gridTemplateColumns: "1fr 340px",
                                                          gap: 12 }}>
      {/* ── Canvas ───────────────────────────────────────────── */}
      <div style={{ background: "#0b1220", border: "1px solid #1e293b",
                       borderRadius: 6, overflow: "hidden" }}>
        {/* Top toolbar */}
        <div style={{ display: "flex", gap: 12, padding: 10,
                         borderBottom: "1px solid #1e293b", color: "#e2e8f0",
                         alignItems: "center", flexWrap: "wrap" }}>
          <div style={{ fontSize: 12, fontFamily: "ui-monospace, monospace" }}>
            <b>{graph.counts.nodes}</b> nodes ·{" "}
            <b>{visibleEdges.length}</b>/{graph.counts.edges} edges ·{" "}
            <b>{graph.counts.stages_observed}</b> observed ·{" "}
            <b>{graph.counts.stages_supported}</b> supported ·{" "}
            <b>{graph.counts.gaps}</b> gaps
          </div>
          <div style={{ marginLeft: "auto", display: "flex", gap: 12,
                          fontSize: 11 }}>
            {Object.keys(layers).map(k => (
              <label key={k} style={{ cursor: "pointer",
                                          color: layers[k] ? "#a78bfa" : "#64748b" }}
                      data-testid={`xdr-ag-layer-${k}`}>
                <input type="checkbox" checked={layers[k]}
                        onChange={() => setLayers(l => ({ ...l, [k]: !l[k] }))}
                        style={{ verticalAlign: "-2px", marginRight: 4 }} />
                {k}
              </label>
            ))}
          </div>
        </div>

        {/* Timeline scrubber */}
        {graph.timeline.length > 0 && (
          <div style={{ padding: "8px 12px", borderBottom: "1px solid #1e293b",
                          color: "#94a3b8", fontSize: 11, display: "flex",
                          alignItems: "center", gap: 12 }}
                data-testid="xdr-ag-timeline">
            <span>TIMELINE</span>
            <input type="range" min="0" max="100" value={timeMax}
                    onChange={(e) => setTimeMax(parseInt(e.target.value, 10))}
                    style={{ flex: 1 }}
                    data-testid="xdr-ag-timeline-scrubber" />
            <span className="mono">{timeMax}% · {timelineWindow ? timelineWindow.size : 0} event(s)</span>
          </div>
        )}

        {/* SVG graph */}
        <div style={{ overflow: "auto", maxHeight: 720 }}>
          <svg width={layout?.width || 800}
                height={layout?.height || 400}
                data-testid="xdr-ag-svg"
                style={{ display: "block" }}>
            {/* Edges */}
            {visibleEdges.map(e => {
              const s = layout.pos.get(e.src);
              const d = layout.pos.get(e.dst);
              if (!s || !d) return null;
              const dimmed = timelineWindow && e.timestamp
                && !timelineWindow.has(`${e.src}|${e.rel}|${e.dst}`);
              const tone = STATE_TONE[e.state] || STATE_TONE.NOT_OBSERVED;
              return (
                <g key={e.id}
                    onClick={() => { setSelectedId(e.id); setSelectedKind("edge"); }}
                    style={{ cursor: "pointer", opacity: dimmed ? 0.15 : 0.7 }}
                    data-testid={`xdr-ag-edge-${e.id}`}>
                  <line x1={s.x + 200} y1={s.y + 17}
                         x2={d.x} y2={d.y + 17}
                         stroke={selectedId === e.id ? "#fbbf24" : tone.stroke}
                         strokeWidth={selectedId === e.id ? 2 : 1}
                         strokeDasharray={e.state === "POSSIBLE" ? "4 3"
                                              : e.state === "NOT_OBSERVED" ? "2 3" : "0"} />
                  <text x={(s.x + 200 + d.x) / 2}
                         y={(s.y + d.y) / 2 + 14}
                         fontSize={8} fontFamily="ui-monospace, monospace"
                         fill="#94a3b8" textAnchor="middle">
                    {e.rel}
                  </text>
                </g>
              );
            })}
            {/* Nodes */}
            {(layout?.nodes || []).map(n => {
              const p = layout.pos.get(n.id);
              if (!p) return null;
              return (
                <TonedNode key={n.id} node={n} x={p.x} y={p.y}
                              focused={selectedId === n.id && selectedKind === "node"}
                              onClick={() => { setSelectedId(n.id); setSelectedKind("node"); }} />
              );
            })}
          </svg>
        </div>

        {/* Metrics footer */}
        <div style={{ padding: 10, borderTop: "1px solid #1e293b",
                         color: "#94a3b8", fontSize: 11,
                         display: "flex", gap: 16, flexWrap: "wrap" }}
              data-testid="xdr-ag-metrics">
          {Object.entries(graph.metrics).map(([k, v]) => (
            <span key={k}>
              {k.replace(/_/g, " ")}: <b style={{ color: "#e2e8f0" }}>{v}%</b>
            </span>
          ))}
        </div>
      </div>

      {/* ── Evidence Inspector ─────────────────────────────── */}
      <div style={{ background: "#f8fafc", border: "1px solid #e2e8f0",
                       borderRadius: 6, padding: 12, fontSize: 12,
                       maxHeight: 820, overflow: "auto" }}
            data-testid="xdr-ag-inspector">
        <div style={{ fontWeight: 600, marginBottom: 8, fontSize: 13 }}>
          Evidence Inspector
        </div>
        {!selected && (
          <div style={{ opacity: 0.55 }}>
            Click any node or edge to inspect its governed evidence,
            techniques, findings, and provenance.
          </div>
        )}
        {selected && selectedKind === "node" && (
          <div>
            <div className="mono" style={{ fontSize: 10, opacity: 0.55 }}>
              {selected.id}
            </div>
            <div style={{ fontSize: 15, fontWeight: 600, marginTop: 4 }}>
              {selected.label}
            </div>
            <div style={{ marginTop: 4 }}>
              <span className="mono" style={{ fontSize: 11 }}>
                {selected.kind}
              </span>{" · "}
              <span style={{ color: STATE_TONE[selected.state]?.stroke }}>
                {STATE_TONE[selected.state]?.label} {selected.state}
              </span>
            </div>
            {selected.attrs && Object.keys(selected.attrs).length > 0 && (
              <div style={{ marginTop: 10 }}>
                <div style={{ fontWeight: 600, marginBottom: 4 }}>Attributes</div>
                <table style={{ fontSize: 11, width: "100%" }}>
                  <tbody>
                    {Object.entries(selected.attrs).map(([k, v]) => (
                      <tr key={k}>
                        <td style={{ opacity: 0.6, verticalAlign: "top",
                                          paddingRight: 8, width: 90 }}>
                          {k}
                        </td>
                        <td className="mono" style={{ wordBreak: "break-all" }}>
                          {typeof v === "object" ? JSON.stringify(v) : String(v)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {/* Incoming + outgoing edges */}
            <div style={{ marginTop: 10 }}>
              <div style={{ fontWeight: 600, marginBottom: 4 }}>Connections</div>
              {graph.edges.filter(e => e.src === selected.id || e.dst === selected.id)
                            .slice(0, 20).map(e => (
                <div key={e.id} style={{ padding: "4px 0",
                                                borderBottom: "1px dashed #e2e8f0" }}>
                  <span className="mono" style={{ fontSize: 10, opacity: 0.6 }}>
                    {e.src === selected.id ? "→" : "←"}
                  </span>{" "}
                  <b>{e.rel}</b>{" "}
                  <span className="mono" style={{ fontSize: 10 }}>
                    {(nodeMap.get(e.src === selected.id ? e.dst : e.src)?.label
                        || "").slice(0, 40)}
                  </span>
                  <div style={{ opacity: 0.55, fontSize: 10 }}>{e.reason}</div>
                </div>
              ))}
            </div>
          </div>
        )}
        {selected && selectedKind === "edge" && (
          <div>
            <div className="mono" style={{ fontSize: 10, opacity: 0.55 }}>
              {selected.id}
            </div>
            <div style={{ fontSize: 15, fontWeight: 600, marginTop: 4 }}>
              {selected.rel}
            </div>
            <div style={{ marginTop: 6, fontSize: 11 }}>
              <div><b>State:</b> {selected.state}</div>
              <div><b>Reason:</b> {selected.reason}</div>
              {selected.timestamp && <div><b>When:</b> {selected.timestamp}</div>}
              {selected.event_id && <div><b>Event ID:</b> {selected.event_id}</div>}
              {selected.technique_id && <div><b>Technique:</b> {selected.technique_id}</div>}
              <div><b>Source:</b> {selected.source}</div>
            </div>
            {selected.evidence_refs.length > 0 && (
              <div style={{ marginTop: 8 }}>
                <b>Evidence refs</b>
                <ul className="mono" style={{ fontSize: 10, paddingLeft: 16 }}>
                  {selected.evidence_refs.slice(0, 8).map(r => <li key={r}>{r}</li>)}
                </ul>
              </div>
            )}
            {selected.finding_ids.length > 0 && (
              <div style={{ marginTop: 8 }}>
                <b>Findings</b>
                <ul className="mono" style={{ fontSize: 10, paddingLeft: 16 }}>
                  {selected.finding_ids.slice(0, 8).map(r => <li key={r}>{r}</li>)}
                </ul>
              </div>
            )}
            <div style={{ marginTop: 10, borderTop: "1px solid #e2e8f0",
                             paddingTop: 8 }}>
              <div><b>Endpoints</b></div>
              <div style={{ fontSize: 11, marginTop: 4 }}>
                <div>src: {nodeMap.get(selected.src)?.label}</div>
                <div>dst: {nodeMap.get(selected.dst)?.label}</div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
