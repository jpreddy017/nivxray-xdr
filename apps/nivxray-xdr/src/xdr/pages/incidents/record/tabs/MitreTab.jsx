/**
 * MitreTab · Round 21 · Evidence-First ATT&CK Attack-Chain Graph
 * ──────────────────────────────────────────────────────────────
 *
 * Reads:
 *   GET /api/admin/content-supply-chain/incidents/:id/attack-chain-graph
 *
 * NivXRay does NOT visualize what ATT&CK says COULD have happened.
 * It visualizes what NivXRay can SUBSTANTIATE FROM COLLECTED EVIDENCE,
 * with confidence STATES (CONFIRMED / SUPPORTED / INSUFFICIENT_EVIDENCE
 * / NOT_OBSERVED / UNKNOWN) — never probability estimates.
 *
 * The graph is operational, not decorative:
 *   · Click a node → right-side proof panel (why mapped · evidence ids
 *     · entities · telemetry sources · related recommendations).
 *   · Click an edge → the shared entity / evidence proof.
 *   · Filter by confidence / tactic.
 *   · Zoom / pan / fit.
 */
import React, { useEffect, useMemo, useRef, useState } from "react";
import { Loader2, ShieldCheck, ChevronRight, ZoomIn, ZoomOut,
                Maximize2, X } from "lucide-react";
import api from "@/lib/api";


const CONF_COLOR = {
  CONFIRMED:              "var(--mint)",
  SUPPORTED:              "#38bdf8",
  INSUFFICIENT_EVIDENCE:  "var(--amber)",
  NOT_OBSERVED:           "var(--faint)",
  UNKNOWN:                "var(--faint)",
};
const CONF_LABEL = {
  CONFIRMED:             "CONFIRMED",
  SUPPORTED:             "SUPPORTED",
  INSUFFICIENT_EVIDENCE: "INSUFFICIENT EVIDENCE",
  NOT_OBSERVED:          "NOT OBSERVED",
  UNKNOWN:               "UNKNOWN",
};


export default function MitreTab({ incident }) {
  const [data,    setData]    = useState(null);
  const [loading, setLoading] = useState(true);
  const [err,     setErr]     = useState(null);
  const [sel,     setSel]     = useState(null);      // { kind:'node'|'edge', ref }
  const [confFilter, setConfFilter] = useState(new Set(
    ["CONFIRMED", "SUPPORTED", "INSUFFICIENT_EVIDENCE"]));
  const [tacticFilter, setTacticFilter] = useState(null);
  const [zoom, setZoom] = useState(1);

  useEffect(() => {
    if (!incident?.id) return;
    let cancelled = false;
    setLoading(true); setErr(null);
    (async () => {
      try {
        const r = await api.get(
          `/admin/content-supply-chain/incidents/${incident.id}/attack-chain-graph`);
        if (!cancelled) setData(r.data);
      } catch (e) {
        if (!cancelled) setErr(e?.response?.data?.detail
                                          || e?.message || "unavailable");
      } finally { if (!cancelled) setLoading(false); }
    })();
    return () => { cancelled = true; };
  }, [incident?.id]);

  const filteredNodes = useMemo(() => {
    if (!data?.nodes) return [];
    return data.nodes.filter((n) =>
      confFilter.has(n.confidence)
      && (!tacticFilter || n.tactic === tacticFilter));
  }, [data, confFilter, tacticFilter]);

  const filteredIds = new Set(filteredNodes.map((n) => n.id));
  const filteredEdges = (data?.edges || []).filter((e) =>
    filteredIds.has(e.source) && filteredIds.has(e.target));

  if (loading) return (
    <div style={emptyBox} data-testid="attack-graph-loading">
      <Loader2 size={13} className="rl-spin" /> Composing evidence-first
      attack chain…
    </div>
  );
  if (err || !data || data.state !== "READY") return (
    <div style={{...emptyBox, color: "var(--amber)"}}
              data-testid="attack-graph-error">
      {err || data?.reason || "Attack chain graph unavailable"}
    </div>
  );

  return (
    <div data-testid="attack-graph-tab">
      <Header data={data} confFilter={confFilter}
                    setConfFilter={setConfFilter}
                    tacticFilter={tacticFilter}
                    setTacticFilter={setTacticFilter} />

      <div style={{ display: "grid",
                          gridTemplateColumns: "1fr 320px",
                          gap: 10 }}>
        <GraphCanvas nodes={filteredNodes} edges={filteredEdges}
                              zoom={zoom} setZoom={setZoom}
                              sel={sel} setSel={setSel} />
        <DetailPanel sel={sel} nodes={data.nodes} edges={data.edges}
                              onClear={() => setSel(null)} />
      </div>
      <Contract note={data.honesty_note} />
    </div>
  );
}


function Header({ data, confFilter, setConfFilter,
                        tacticFilter, setTacticFilter }) {
  const c = data.counts.by_confidence || {};
  const tactics = data.counts.tactics_present || [];
  const toggle = (k) => {
    const next = new Set(confFilter);
    next.has(k) ? next.delete(k) : next.add(k);
    setConfFilter(next);
  };
  return (
    <div style={{ padding: "8px 10px", marginBottom: 10,
                        border: "1px solid var(--border)",
                        background: "var(--panel2)", borderRadius: 4 }}>
      <div style={{ display: "flex", gap: 10, alignItems: "center",
                          flexWrap: "wrap" }}>
        <ShieldCheck size={12} style={{ color: "#a78bfa" }} />
        <b style={{ fontFamily: "var(--mono)", fontSize: 11 }}>
          ATT&CK Attack Chain · Evidence-First
        </b>
        <span style={{ fontFamily: "var(--mono)", fontSize: 10,
                          color: "var(--faint)" }}>
          {data.counts.nodes} node{data.counts.nodes === 1 ? "" : "s"} ·
          {" "}{data.counts.edges} edge{data.counts.edges === 1 ? "" : "s"}
        </span>
        <span style={{ flex: 1 }} />
        {["CONFIRMED", "SUPPORTED", "INSUFFICIENT_EVIDENCE",
          "NOT_OBSERVED", "UNKNOWN"].map((k) => (
          <button key={k}
                        data-testid={`attack-graph-filter-${k}`}
                        onClick={() => toggle(k)}
                        style={{ ...pill(CONF_COLOR[k]),
                                        opacity: confFilter.has(k) ? 1 : 0.35,
                                        cursor: "pointer",
                                        background: confFilter.has(k)
                                          ? `${CONF_COLOR[k]}15`
                                          : "transparent" }}>
            {CONF_LABEL[k]} · {c[k] || 0}
          </button>
        ))}
      </div>
      {tactics.length > 0 && (
        <div style={{ marginTop: 6, display: "flex", gap: 4,
                            flexWrap: "wrap" }}>
          <button onClick={() => setTacticFilter(null)}
                        style={{...pill("var(--faint)"),
                                        opacity: !tacticFilter ? 1 : 0.4,
                                        cursor: "pointer"}}>
            all tactics
          </button>
          {tactics.map((t) => (
            <button key={t}
                          data-testid={`attack-graph-tactic-${t}`}
                          onClick={() => setTacticFilter(t === tacticFilter
                                                                        ? null : t)}
                          style={{...pill("#38bdf8"),
                                          opacity: t === tacticFilter ? 1 : 0.5,
                                          cursor: "pointer"}}>
              {t}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}


// ── Graph canvas ─────────────────────────────────────────────
// Simple deterministic layered layout: x = tactic_index, y = insertion
// order within tactic.  No external libs.

const NODE_W = 172;
const NODE_H = 62;
const COL_GAP = 210;
const ROW_GAP = 82;

function GraphCanvas({ nodes, edges, zoom, setZoom, sel, setSel }) {
  const svgRef = useRef(null);

  // Layered coordinate assignment.
  const byTactic = {};
  nodes.forEach((n) => (byTactic[n.tactic_index] ||= []).push(n));
  const cols = Object.keys(byTactic).map(Number).sort((a,b)=>a-b);
  const positioned = {};
  cols.forEach((col, ci) => {
    byTactic[col].forEach((n, ri) => {
      positioned[n.id] = {
        x: 40 + ci * COL_GAP,
        y: 40 + ri * ROW_GAP,
      };
    });
  });
  const width  = 80 + cols.length * COL_GAP;
  const height = 80 + Math.max(1, ...cols.map((c) => byTactic[c].length))
                          * ROW_GAP;

  const onNode = (n) => setSel({ kind: "node", ref: n.id });
  const onEdge = (e) => setSel({ kind: "edge", ref: e.id });

  return (
    <div style={{ border: "1px solid var(--border)",
                        borderRadius: 4, background: "var(--panel)",
                        position: "relative", overflow: "hidden",
                        minHeight: 380 }}
              data-testid="attack-graph-canvas">
      <div style={{ position: "absolute", top: 6, right: 6, zIndex: 2,
                          display: "flex", gap: 4 }}>
        <button style={iconBtn}
                      data-testid="attack-graph-zoom-in"
                      onClick={() => setZoom(Math.min(1.8, zoom + 0.15))}>
          <ZoomIn size={11} />
        </button>
        <button style={iconBtn}
                      data-testid="attack-graph-zoom-out"
                      onClick={() => setZoom(Math.max(0.4, zoom - 0.15))}>
          <ZoomOut size={11} />
        </button>
        <button style={iconBtn}
                      data-testid="attack-graph-fit"
                      onClick={() => setZoom(1)}>
          <Maximize2 size={11} />
        </button>
      </div>
      <div style={{ transform: `scale(${zoom})`,
                          transformOrigin: "top left",
                          transition: "transform 120ms ease-out" }}>
        <svg ref={svgRef} width={width} height={height}
                  style={{ display: "block" }}>
          <defs>
            <marker id="arrow" viewBox="0 -5 10 10" refX="10" refY="0"
                        markerWidth="6" markerHeight="6" orient="auto">
              <path d="M0,-5L10,0L0,5" fill="var(--faint)" />
            </marker>
          </defs>
          {edges.map((e) => {
            const s = positioned[e.source], t = positioned[e.target];
            if (!s || !t) return null;
            const x1 = s.x + NODE_W, y1 = s.y + NODE_H / 2;
            const x2 = t.x,             y2 = t.y + NODE_H / 2;
            const mid = (x1 + x2) / 2;
            const isSel = sel?.kind === "edge" && sel.ref === e.id;
            const color = CONF_COLOR[e.confidence] || "var(--faint)";
            return (
              <g key={e.id} onClick={() => onEdge(e)}
                    style={{ cursor: "pointer" }}
                    data-testid={`attack-graph-edge-${e.id}`}>
                <path d={`M${x1},${y1} C${mid},${y1} ${mid},${y2} ${x2},${y2}`}
                          fill="none" stroke={color}
                          strokeWidth={isSel ? 2.5 : 1.5}
                          strokeDasharray={e.confidence === "SUPPORTED"
                            ? "5 3" : (e.confidence
                                              === "INSUFFICIENT_EVIDENCE"
                                              ? "2 3" : null)}
                          markerEnd="url(#arrow)"
                          opacity={isSel ? 1 : 0.75} />
              </g>
            );
          })}
          {nodes.map((n) => {
            const p = positioned[n.id];
            if (!p) return null;
            const color = CONF_COLOR[n.confidence] || "var(--faint)";
            const isSel = sel?.kind === "node" && sel.ref === n.id;
            return (
              <g key={n.id} transform={`translate(${p.x},${p.y})`}
                    onClick={() => onNode(n)}
                    style={{ cursor: "pointer" }}
                    data-testid={`attack-graph-node-${n.id}`}>
                <rect width={NODE_W} height={NODE_H} rx={4}
                          fill="var(--panel2)"
                          stroke={color}
                          strokeWidth={isSel ? 2.5 : 1.4} />
                <text x={10} y={17} fontFamily="var(--mono)"
                          fontSize="10" fill={color} fontWeight={700}>
                  {n.id}
                </text>
                <text x={10} y={34} fontFamily="var(--sans)"
                          fontSize="11" fill="var(--text)">
                  {(n.object_name || "").slice(0, 22)}
                </text>
                <text x={10} y={50} fontFamily="var(--mono)"
                          fontSize="9" fill="var(--faint)">
                  {n.tactic} · {CONF_LABEL[n.confidence]}
                </text>
              </g>
            );
          })}
        </svg>
      </div>
      {nodes.length === 0 && (
        <div style={{ position: "absolute", inset: 0,
                            display: "flex", alignItems: "center",
                            justifyContent: "center",
                            color: "var(--faint)",
                            fontFamily: "var(--mono)", fontSize: 11 }}>
          No ATT&CK technique substantiated by this incident's evidence.
        </div>
      )}
    </div>
  );
}


// ── Right-side detail panel ──────────────────────────────────

function DetailPanel({ sel, nodes, edges, onClear }) {
  if (!sel) return (
    <div style={panel}
              data-testid="attack-graph-panel-empty">
      <div style={panelTitle}>Selected</div>
      <div style={{ fontSize: 11, color: "var(--faint)",
                          fontFamily: "var(--mono)" }}>
        Click any node or edge to inspect its evidence, entities,
        telemetry source, and related recommendations.
      </div>
    </div>
  );
  if (sel.kind === "node") {
    const n = nodes.find((x) => x.id === sel.ref);
    if (!n) return null;
    return <NodePanel n={n} onClear={onClear} />;
  }
  const e = edges.find((x) => x.id === sel.ref);
  if (!e) return null;
  return <EdgePanel e={e} nodes={nodes} onClear={onClear} />;
}


function NodePanel({ n, onClear }) {
  const color = CONF_COLOR[n.confidence] || "var(--faint)";
  return (
    <div style={panel} data-testid={`attack-graph-panel-node-${n.id}`}>
      <div style={{...panelTitle, display: "flex", alignItems: "center",
                          gap: 6}}>
        <b style={{ color, fontFamily: "var(--mono)" }}>{n.id}</b>
        <span style={{ flex: 1 }} />
        <button onClick={onClear} style={iconBtn}
                      data-testid={`attack-graph-panel-close-${n.id}`}>
          <X size={10} />
        </button>
      </div>
      <div style={{ fontSize: 12, color: "var(--text)",
                          marginBottom: 6 }}>
        {n.object_name}
      </div>
      <Row k="Tactic"     v={n.tactic} />
      <Row k="Confidence" v={CONF_LABEL[n.confidence]}
                color={color} bold />
      <Row k="Why mapped"  v={n.why_mapped || "—"} />
      <Row k="Method"      v={n.mapping_method || "—"} />
      <Row k="Telemetry"   v={(n.telemetry_sources || []).join(", ") || "—"} />
      <Row k="Evidence"    v={(n.evidence_ids || []).join(", ") || "—"} />
      <Row k="Source refs" v={(n.source_refs || []).join(", ") || "—"} />
      {n.entities?.length > 0 && (
        <Section title={`Entities (${n.entities.length})`}>
          {n.entities.map((e, i) => (
            <div key={i} style={row}
                    data-testid={`attack-graph-panel-entity-${i}`}>
              <span style={{ color: "var(--faint)",
                                    fontFamily: "var(--mono)",
                                    fontSize: 10 }}>{e.kind}</span>
              <span style={{ fontSize: 11, color: "var(--text-dim)" }}>
                {String(e.value).slice(0, 40)}
              </span>
            </div>
          ))}
        </Section>
      )}
      {n.related_recommendations?.length > 0 && (
        <Section title={`Related recommendations (${n.related_recommendations.length})`}>
          {n.related_recommendations.slice(0, 6).map((r, i) => (
            <div key={i} style={row}>
              <span style={{ fontSize: 10,
                                    fontFamily: "var(--mono)",
                                    color: "var(--faint)" }}>
                {r.state || "—"}
              </span>
              <span style={{ fontSize: 11, color: "var(--cyan)",
                                    fontFamily: "var(--mono)" }}>
                {r.action}
              </span>
            </div>
          ))}
        </Section>
      )}
      <a href={`https://attack.mitre.org/techniques/${n.id.replace(".", "/")}/`}
          target="_blank" rel="noreferrer"
          style={{ display: "inline-flex", alignItems: "center",
                        gap: 4, marginTop: 8, fontSize: 10,
                        fontFamily: "var(--mono)", color: "#a78bfa" }}>
        attack.mitre.org <ChevronRight size={9} />
      </a>
    </div>
  );
}


function EdgePanel({ e, nodes, onClear }) {
  const src = nodes.find((n) => n.id === e.source);
  const dst = nodes.find((n) => n.id === e.target);
  const color = CONF_COLOR[e.confidence] || "var(--faint)";
  return (
    <div style={panel} data-testid={`attack-graph-panel-edge-${e.id}`}>
      <div style={{...panelTitle, display: "flex", alignItems: "center",
                          gap: 6}}>
        <b style={{ fontFamily: "var(--mono)", color: "var(--text-dim)" }}>
          EDGE
        </b>
        <span style={{ flex: 1 }} />
        <button onClick={onClear} style={iconBtn}>
          <X size={10} />
        </button>
      </div>
      <Row k="From" v={`${src?.id} · ${src?.object_name}`} />
      <Row k="To"   v={`${dst?.id} · ${dst?.object_name}`} />
      <Row k="Confidence" v={CONF_LABEL[e.confidence]} color={color} bold />
      <Row k="Why this edge exists"
                v={e.proof?.reason === "shared_entity"
                        ? `Shared entity between the two techniques (${e.proof.shared_count} shared)`
                        : "Shared canonical evidence reference"} />
      {e.proof?.shared && (
        <Section title="Shared entities">
          {e.proof.shared.map((s, i) => (
            <div key={i} style={row}>
              <span style={{ fontFamily: "var(--mono)", fontSize: 10,
                                    color: "var(--faint)" }}>{s.kind}</span>
              <span style={{ fontSize: 11,
                                    color: "var(--text-dim)" }}>{s.value}</span>
            </div>
          ))}
        </Section>
      )}
      {e.proof?.shared_refs && (
        <Section title="Shared evidence refs">
          {e.proof.shared_refs.map((r, i) => (
            <div key={i} style={{ fontFamily: "var(--mono)",
                                              fontSize: 10,
                                              color: "var(--faint)" }}>{r}</div>
          ))}
        </Section>
      )}
    </div>
  );
}


// ── Reusable primitives ──────────────────────────────────────

function Row({ k, v, color, bold }) {
  return (
    <div style={{ display: "grid",
                        gridTemplateColumns: "108px 1fr", gap: 6,
                        padding: "3px 0",
                        borderBottom: "1px dashed rgba(255,255,255,0.05)"}}>
      <span style={{ fontFamily: "var(--mono)", fontSize: 10,
                          color: "var(--faint)" }}>{k}</span>
      <span style={{ fontSize: 11.5,
                            color: color || "var(--text-dim)",
                            fontWeight: bold ? 700 : 400,
                            lineHeight: 1.45 }}>{v || "—"}</span>
    </div>
  );
}
function Section({ title, children }) {
  return (
    <div style={{ marginTop: 8 }}>
      <div style={{ fontFamily: "var(--mono)", fontSize: 10,
                          color: "var(--faint)", fontWeight: 700,
                          marginBottom: 3 }}>{title}</div>
      {children}
    </div>
  );
}
function Contract({ note }) {
  return (
    <div style={{ marginTop: 12, padding: 10,
                        border: "1px dashed var(--border)",
                        borderRadius: 3, background: "var(--panel2)",
                        fontFamily: "var(--mono)", fontSize: 10,
                        color: "var(--faint)", lineHeight: 1.55 }}
              data-testid="attack-graph-contract">
      <b style={{ color: "var(--text-dim)" }}>EVIDENCE-FIRST CONTRACT · </b>
      {note}
    </div>
  );
}


const pill = (color) => ({
  padding: "1px 6px", border: `1px solid ${color}`, color,
  borderRadius: 2, fontFamily: "var(--mono)", fontSize: 9,
  fontWeight: 700, whiteSpace: "nowrap",
});
const row = { display: "grid",
                    gridTemplateColumns: "72px 1fr", gap: 6,
                    padding: "2px 0" };
const panel = {
  border: "1px solid var(--border)", borderRadius: 3,
  background: "var(--panel2)", padding: 10, minHeight: 380,
};
const panelTitle = {
  fontFamily: "var(--mono)", fontSize: 10, color: "var(--faint)",
  fontWeight: 700, marginBottom: 6,
};
const iconBtn = {
  padding: "3px 5px", fontSize: 10, fontFamily: "var(--mono)",
  color: "var(--text-dim)", background: "var(--panel2)",
  border: "1px solid var(--border)", borderRadius: 2, cursor: "pointer",
};
const emptyBox = {
  padding: 14, fontFamily: "var(--mono)", fontSize: 11,
  color: "var(--faint)", border: "1px dashed var(--border)",
  borderRadius: 4, background: "var(--panel2)",
};
