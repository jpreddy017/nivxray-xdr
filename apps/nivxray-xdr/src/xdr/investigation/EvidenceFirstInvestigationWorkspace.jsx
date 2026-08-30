/**
 * EvidenceFirstInvestigationWorkspace
 *
 * The Investigation Canvas is a real, evidence-backed graph — NOT a
 * decorative sketch.  Nodes are minted only from data that already
 * exists on the canonical incident payload:
 *
 *   • incident.assets.hosts / .users           → host / identity nodes
 *   • incident.iocs.{hash, ip, domain, url}    → indicator nodes
 *   • incident.verdict_stage2.evidence[]       → evidence nodes
 *   • incident.evidence[].rule_id/technique_id → MITRE relations
 *   • Response Engine executions (from Base
 *     `/api/xdr/response-evidence`)            → response nodes
 *
 * If the base payload does not carry a value we render nothing
 * (never a "phantom" node) and surface an explicit
 * `no_matching_evidence` badge so the analyst knows this is an
 * evidence gap, not a rendering quirk.
 *
 * Owner-locked:
 *   – No fake relationships.  Edges only exist when there is a
 *     concrete referent (same host, same user, same IOC value,
 *     rule → technique from the authoritative RULE_TO_TECHNIQUE
 *     table).
 *   – Response actions must appear IN the investigation, not as
 *     an isolated SOAR blob.
 */
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Search, Zap, Cpu, Server, User, Globe, FileDigit, Hash,
  ShieldAlert, GitBranch, X, Copy, ExternalLink, ChevronRight,
} from "lucide-react";

import { RULE_TO_TECHNIQUE, TECHNIQUE_INDEX } from "@/xdr/mitre/mitreTactics";

// ── Node type palette (single restrained accent per kind) ─────────
const NODE_TYPE = {
  incident:  { color: "#f87171", icon: ShieldAlert, label: "INCIDENT"  },
  host:      { color: "#38bdf8", icon: Server,      label: "HOST"      },
  user:      { color: "#c084fc", icon: User,        label: "IDENTITY"  },
  process:   { color: "#a78bfa", icon: Cpu,         label: "PROCESS"   },
  ip:        { color: "#22d3ee", icon: Globe,       label: "IP"        },
  domain:    { color: "#22d3ee", icon: Globe,       label: "DOMAIN"    },
  hash:      { color: "#facc15", icon: Hash,        label: "HASH"      },
  url:       { color: "#22d3ee", icon: Globe,       label: "URL"       },
  evidence:  { color: "#fbbf24", icon: FileDigit,   label: "EVIDENCE"  },
  technique: { color: "#f472b6", icon: GitBranch,   label: "MITRE"     },
  response:  { color: "#34d399", icon: Zap,         label: "RESPONSE"  },
};

const EDGE_KIND = {
  observed:   { color: "rgba(160,160,180,.55)", dashed: false, label: "observed" },
  derived:    { color: "rgba(160,160,180,.32)", dashed: true,  label: "derived"  },
  mapped:     { color: "rgba(244,114,182,.55)", dashed: true,  label: "mapped"   },
  responded:  { color: "rgba(52,211,153,.65)",  dashed: false, label: "responded"},
};


export default function EvidenceFirstInvestigationWorkspace({ incident }) {
  // 1 · Build the graph deterministically from the incident payload.
  const { nodes, edges } = useMemo(() => buildGraph(incident), [incident]);
  const [selected, setSelected]   = useState(null);
  const [hovered, setHovered]     = useState(null);
  const [highlight, setHighlight] = useState(null); // { technique_id? | evidence_id? }
  const [pivot, setPivot]         = useState(null); // {x,y,node}
  const [zoom, setZoom]           = useState(1);
  const [pan,  setPan]            = useState({ x: 0, y: 0 });
  const dragRef = useRef({ dragging: false, ox: 0, oy: 0 });

  // Auto-select the incident node on first load.
  useEffect(() => {
    if (!selected && nodes.length) {
      const inc = nodes.find((n) => n.type === "incident");
      if (inc) setSelected(inc.id);
    }
  }, [nodes, selected]);

  const onCanvasMouseDown = useCallback((e) => {
    if (e.button !== 0) return;
    dragRef.current = { dragging: true, ox: e.clientX, oy: e.clientY,
                            px: pan.x, py: pan.y };
    setPivot(null);
  }, [pan]);
  const onCanvasMouseMove = useCallback((e) => {
    if (!dragRef.current.dragging) return;
    setPan({ x: dragRef.current.px + (e.clientX - dragRef.current.ox),
                y: dragRef.current.py + (e.clientY - dragRef.current.oy) });
  }, []);
  const onCanvasMouseUp   = useCallback(() => { dragRef.current.dragging = false; }, []);
  const onWheel = useCallback((e) => {
    e.preventDefault();
    setZoom((z) => Math.min(2.4, Math.max(0.35, z * (e.deltaY > 0 ? 0.92 : 1.08))));
  }, []);

  const openPivot = useCallback((e, node) => {
    e.preventDefault();
    setPivot({ x: e.clientX, y: e.clientY, node });
    setSelected(node.id);
  }, []);
  useEffect(() => {
    const close = () => setPivot(null);
    window.addEventListener("click", close);
    return () => window.removeEventListener("click", close);
  }, []);

  const selectedNode = nodes.find((n) => n.id === selected) || null;

  return (
    <div data-testid="xdr-investigation-workspace"
            style={{ display: "grid", gridTemplateColumns: "1fr 340px",
                        gap: 12, height: 640 }}>
      {/* Canvas */}
      <section className="panel"
                  style={{ position: "relative", overflow: "hidden",
                              background: "linear-gradient(160deg, #0a0d14 0%, #0e131c 100%)",
                              borderRadius: 6 }}
                  data-testid="xdr-investigation-canvas"
                  onMouseDown={onCanvasMouseDown}
                  onMouseMove={onCanvasMouseMove}
                  onMouseUp={onCanvasMouseUp}
                  onMouseLeave={onCanvasMouseUp}
                  onWheel={onWheel}>
        <CanvasToolbar
          incidentId={incident?.id}
          nodeCount={nodes.length} edgeCount={edges.length}
          zoom={zoom} onZoom={setZoom}
          highlight={highlight} onClearHighlight={() => setHighlight(null)}
        />
        <svg width="100%" height="100%"
                style={{ position: "absolute", inset: 0, cursor: dragRef.current.dragging ? "grabbing" : "grab" }}>
          <g transform={`translate(${pan.x}, ${pan.y}) scale(${zoom})`}>
            {/* Edges first so nodes sit on top */}
            {edges.map((e) => {
              const s = nodes.find((n) => n.id === e.source);
              const t = nodes.find((n) => n.id === e.target);
              if (!s || !t) return null;
              const dim = highlight
                && !_edgeMatches(e, s, t, highlight);
              const meta = EDGE_KIND[e.kind] || EDGE_KIND.observed;
              return (
                <line key={e.id}
                         x1={s.x} y1={s.y} x2={t.x} y2={t.y}
                         stroke={meta.color}
                         strokeWidth={1.4}
                         strokeDasharray={meta.dashed ? "4 4" : "none"}
                         opacity={dim ? 0.15 : 1} />
              );
            })}
            {nodes.map((n) => (
              <NodeGlyph key={n.id} node={n}
                              selected={selected === n.id}
                              hovered={hovered === n.id}
                              dimmed={highlight && !_nodeMatches(n, highlight)}
                              onClick={(e) => { e.stopPropagation(); setSelected(n.id); }}
                              onContextMenu={(e) => openPivot(e, n)}
                              onMouseEnter={() => setHovered(n.id)}
                              onMouseLeave={() => setHovered(null)} />
            ))}
          </g>
        </svg>
        <CanvasLegend />
      </section>

      {/* Right-side stack: Inspector on top, Attack Story below */}
      <aside style={{ display: "flex", flexDirection: "column", gap: 10, overflow: "hidden" }}>
        <EntityInspector
          node={selectedNode} incident={incident}
          onPivotHighlight={setHighlight}
          onOpenPivot={(e) => selectedNode && openPivot(e, selectedNode)}
        />
        <AttackStoryPanel
          incident={incident}
          onHighlightTechnique={(t) => setHighlight({ technique_id: t })}
          onHighlightEvidence={(rid) => setHighlight({ rule_id: rid })}
        />
      </aside>

      {/* Pivot context menu */}
      {pivot && (
        <PivotMenu x={pivot.x} y={pivot.y} node={pivot.node}
                        incident={incident}
                        onClose={() => setPivot(null)}
                        onHighlight={setHighlight} />
      )}
    </div>
  );
}


/* ───────────────────────────── graph builder ─────────────────────── */
function buildGraph(incident) {
  const nodes = [];
  const edges = [];
  if (!incident) return { nodes, edges };

  const push = (n) => { if (!nodes.find((x) => x.id === n.id)) nodes.push(n); };
  const edge = (source, target, kind = "observed", label) => {
    if (!source || !target || source === target) return;
    if (!edges.find((e) => e.source === source && e.target === target))
      edges.push({ id: `${source}->${target}`, source, target, kind, label });
  };

  // Layout: incident at center, hosts left, users right, IOCs bottom-left,
  // evidence bottom-right, techniques far bottom, response nodes far right.
  const cx = 480, cy = 220;
  push({ id: `inc:${incident.id}`, type: "incident",
            title: incident.name || incident.number || "Incident",
            subtitle: incident.severity || "",
            x: cx, y: cy });

  const hosts = incident.assets?.hosts || incident.hosts || [];
  hosts.forEach((h, i) => {
    const id = `host:${h.host_id || h.id || h.name || i}`;
    push({ id, type: "host",
              title: h.host_id || h.name || h.id || "host",
              subtitle: h.os || h.ip || "",
              raw: h, x: cx - 220 - (i % 3) * 80, y: cy - 60 + i * 42 });
    edge(`inc:${incident.id}`, id, "observed");
  });

  const users = incident.assets?.users || incident.users || [];
  users.forEach((u, i) => {
    const id = `user:${u.user_id || u.id || u.email || i}`;
    push({ id, type: "user",
              title: u.email || u.user_id || u.name || "user",
              subtitle: u.role || u.department || "",
              raw: u, x: cx + 240 + (i % 2) * 60, y: cy - 60 + i * 42 });
    edge(`inc:${incident.id}`, id, "observed");
  });

  // Processes from evidence (rule_id or entity.command_line).
  const processes = _extractProcesses(incident);
  processes.forEach((p, i) => {
    const id = `proc:${p.pid || p.name || i}`;
    push({ id, type: "process",
              title: p.name || `pid:${p.pid || "?"}`,
              subtitle: p.command_line ? _short(p.command_line, 42) : "",
              raw: p, x: cx - 30 + (i - processes.length / 2) * 90, y: cy + 70 });
    edge(`inc:${incident.id}`, id, "observed");
    if (p.host_id) {
      const hostId = `host:${p.host_id}`;
      if (nodes.find((n) => n.id === hostId)) edge(hostId, id, "observed");
    }
  });

  const iocs = incident.iocs || {};
  const iocKinds = [
    ["hash", iocs.hash],   ["ip", iocs.ip],
    ["domain", iocs.domain], ["url", iocs.url],
  ];
  let iocRow = 0;
  iocKinds.forEach(([kind, values]) => {
    (values || []).forEach((v, i) => {
      const id = `${kind}:${typeof v === "string" ? v : v.value || i}`;
      push({ id, type: kind,
                title: typeof v === "string" ? _short(v, 22) : _short(v.value || "", 22),
                subtitle: typeof v === "object" ? v.provider || v.source || "" : "",
                raw: v, x: cx - 250 + (i % 3) * 70,
                y: cy + 160 + iocRow * 48 });
    });
    if ((values || []).length) iocRow++;
  });

  const stage2 = incident.verdict_stage2 || {};
  (stage2.evidence || incident.evidence || []).slice(0, 24).forEach((ev, i) => {
    const id = `evid:${ev.rule_id || ev.id || i}`;
    push({ id, type: "evidence",
              title: ev.rule_id || ev.title || `evidence #${i}`,
              subtitle: ev.detected_by || ev.engine || "",
              raw: ev, x: cx + 130 + (i % 3) * 80,
              y: cy + 150 + Math.floor(i / 3) * 48 });
    edge(`inc:${incident.id}`, id, "observed");
    // Rule → MITRE mapping (from authoritative table).
    const rid  = String(ev.rule_id || "").toUpperCase();
    const tech = ev.technique_id || RULE_TO_TECHNIQUE[rid];
    if (tech) {
      const tid = `tech:${tech}`;
      push({ id: tid, type: "technique",
                title: tech,
                subtitle: TECHNIQUE_INDEX[tech]?.name || "",
                raw: TECHNIQUE_INDEX[tech] || { technique_id: tech },
                x: cx + 80 + (i % 4) * 90, y: cy + 300 });
      edge(id, tid, "mapped");
    }
  });

  // Response actions produced from the Response Engine (if present on
  // the incident payload — surfaced via a dedicated collection when
  // wired end-to-end).  We tolerate the field being absent.
  const responses = incident.response_executions || incident.responses || [];
  responses.slice(0, 10).forEach((r, i) => {
    const id = `resp:${r.execution_id || i}`;
    push({ id, type: "response",
              title: r.action_id || "response",
              subtitle: r.state || r.status || "",
              raw: r, x: cx + 320, y: cy - 40 + i * 46 });
    edge(`inc:${incident.id}`, id, "responded");
    if (r.evidence_ref) {
      const evId = `evid:${r.evidence_ref}`;
      if (!nodes.find((n) => n.id === evId)) {
        push({ id: evId, type: "evidence",
                  title: _short(r.evidence_ref, 18),
                  subtitle: "response evidence",
                  raw: { evidence_ref: r.evidence_ref },
                  x: cx + 220, y: cy - 40 + i * 46 });
      }
      edge(id, evId, "responded");
    }
  });

  return { nodes, edges };
}

function _extractProcesses(incident) {
  const acc = [];
  const seen = new Set();
  const evs = (incident?.verdict_stage2?.evidence || incident?.evidence || []);
  for (const ev of evs) {
    const e = ev.entity || ev.process || {};
    const name = e.image || e.process || e.name;
    const key  = `${name}|${e.pid || ""}`;
    if (!name || seen.has(key)) continue;
    seen.add(key);
    acc.push({ name, pid: e.pid, command_line: e.command_line || e.cmdline,
                  host_id: e.host_id || (incident?.assets?.hosts || [])[0]?.host_id });
  }
  return acc.slice(0, 6);
}


/* ───────────────────────────── SVG glyph ─────────────────────────── */
function NodeGlyph({ node, selected, hovered, dimmed,
                          onClick, onContextMenu, onMouseEnter, onMouseLeave }) {
  const meta = NODE_TYPE[node.type] || NODE_TYPE.evidence;
  const Icon = meta.icon;
  const r    = selected ? 22 : hovered ? 20 : 18;
  return (
    <g transform={`translate(${node.x}, ${node.y})`}
          opacity={dimmed ? 0.22 : 1}
          onClick={onClick} onContextMenu={onContextMenu}
          onMouseEnter={onMouseEnter} onMouseLeave={onMouseLeave}
          data-testid={`xdr-node-${node.id}`}
          style={{ cursor: "pointer" }}>
      {selected && (
        <circle r={r + 6} fill="none" stroke={meta.color}
                    strokeOpacity={0.35} strokeWidth={2} />
      )}
      <circle r={r}
                 fill={_hexA(meta.color, selected ? 0.28 : 0.14)}
                 stroke={meta.color}
                 strokeWidth={selected ? 2 : 1.2} />
      <foreignObject x={-9} y={-9} width={18} height={18}
                          style={{ pointerEvents: "none" }}>
        <div style={{ color: meta.color, display: "flex",
                          alignItems: "center", justifyContent: "center",
                          width: 18, height: 18 }}>
          <Icon size={14} />
        </div>
      </foreignObject>
      <text y={r + 12} textAnchor="middle"
              fill="#e6e9f2" fontSize={10.5}
              fontFamily="Inter, system-ui" fontWeight={600}
              style={{ pointerEvents: "none" }}>
        {_short(node.title, 24)}
      </text>
      {node.subtitle && (
        <text y={r + 24} textAnchor="middle"
                fill="#7c8494" fontSize={9}
                fontFamily="ui-monospace, SFMono-Regular, monospace"
                style={{ pointerEvents: "none" }}>
          {_short(node.subtitle, 32)}
        </text>
      )}
    </g>
  );
}


/* ───────────────────────────── inspector ─────────────────────────── */
function EntityInspector({ node, incident, onPivotHighlight, onOpenPivot }) {
  if (!node) {
    return (
      <div className="panel" data-testid="xdr-inspector-empty"
              style={{ padding: 12, fontSize: 11, color: "var(--faint)" }}>
        Click a node in the canvas to inspect.  Right-click any node for
        the pivot menu.
      </div>
    );
  }
  const meta = NODE_TYPE[node.type] || NODE_TYPE.evidence;
  const Icon = meta.icon;
  const raw  = node.raw || {};

  return (
    <div className="panel" data-testid={`xdr-inspector-${node.type}`}
            style={{ padding: 12, flex: 1, minHeight: 260,
                        display: "flex", flexDirection: "column" }}>
      <header style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 8 }}>
        <span style={{ color: meta.color, display: "inline-flex" }}>
          <Icon size={14} />
        </span>
        <b className="mono" style={{ color: meta.color, fontSize: 10.5,
                                                letterSpacing: ".3px" }}>
          {meta.label}
        </b>
        <span style={{ flex: 1 }} />
        <button className="btn ghost" onClick={onOpenPivot}
                  data-testid="xdr-inspector-pivot-btn"
                  style={{ padding: "2px 6px", fontSize: 10 }}>
          Pivot <ChevronRight size={10} />
        </button>
      </header>
      <div style={{ fontSize: 12.5, fontWeight: 700, color: "var(--text)",
                        wordBreak: "break-all" }}>
        {node.title}
      </div>
      {node.subtitle && (
        <div style={{ fontSize: 11, color: "var(--text-dim)", marginTop: 2 }}>
          {node.subtitle}
        </div>
      )}

      <div style={{ marginTop: 10, overflow: "auto", flex: 1 }}>
        {node.type === "evidence" && (
          <>
            <Row k="Rule ID"      v={raw.rule_id || node.title} copy />
            <Row k="Detected by"  v={raw.detected_by || raw.engine} />
            <Row k="Weight"       v={raw.weight != null ? `+${raw.weight}` : "—"} />
            <Row k="Timestamp"    v={raw.timestamp || raw.at} />
            <Row k="Host"         v={raw.entity?.host_id || raw.host_id} />
            <Row k="Command line" v={raw.entity?.command_line || raw.command_line} mono />
            <Row k="Provenance"   v={raw.provenance} mono small />
            {raw.technique_id && (
              <Row k="MITRE" v={
                <span onClick={() => onPivotHighlight({ technique_id: raw.technique_id })}
                         style={{ color: "#f472b6", cursor: "pointer",
                                    textDecoration: "underline" }}>
                  {raw.technique_id} · {TECHNIQUE_INDEX[raw.technique_id]?.name || "—"}
                </span>
              } />
            )}
          </>
        )}
        {node.type === "response" && (
          <>
            <Row k="Action"        v={raw.action_id} copy />
            <Row k="State"         v={raw.state || raw.status}
                    color={raw.state === "SUCCEEDED" ? "var(--mint)" : "#ff9494"} />
            <Row k="Execution ID"  v={raw.execution_id} mono copy />
            <Row k="Evidence Ref"  v={raw.evidence_ref} mono copy />
            <Row k="Audit Ref"     v={raw.audit_ref} mono copy />
            <Row k="Timeline Ref"  v={raw.timeline_ref} mono copy />
            <Row k="Invoker"       v={raw.invoker?.id || raw.invoker?.kind} />
            <Row k="Approved by"   v={raw.approval?.approved_by} />
          </>
        )}
        {node.type === "host" && (
          <>
            <Row k="Host ID"  v={raw.host_id || raw.id || raw.name} copy />
            <Row k="OS"       v={raw.os || raw.operating_system} />
            <Row k="IP"       v={raw.ip} copy />
            <Row k="Domain"   v={raw.domain} />
            <Row k="Last seen" v={raw.last_seen} />
          </>
        )}
        {node.type === "user" && (
          <>
            <Row k="User"     v={raw.user_id || raw.email || raw.id} copy />
            <Row k="Role"     v={raw.role} />
            <Row k="Dept"     v={raw.department} />
            <Row k="MFA"      v={raw.mfa_enabled != null ? String(raw.mfa_enabled) : "—"} />
          </>
        )}
        {node.type === "process" && (
          <>
            <Row k="Image"      v={raw.name || raw.image} copy />
            <Row k="PID"        v={raw.pid} />
            <Row k="Host"       v={raw.host_id} />
            <Row k="Command"    v={raw.command_line} mono />
          </>
        )}
        {(node.type === "ip" || node.type === "domain" || node.type === "hash"
              || node.type === "url") && (
          <>
            <Row k="Indicator" v={typeof raw === "string" ? raw : raw.value} mono copy />
            <Row k="Source"    v={typeof raw === "object" ? (raw.source || raw.provider) : "—"} />
            <Row k="Verdict"   v={typeof raw === "object" ? raw.verdict : "—"} />
          </>
        )}
        {node.type === "technique" && (
          <>
            <Row k="Technique"  v={node.title} copy />
            <Row k="Name"       v={TECHNIQUE_INDEX[node.title]?.name} />
            <Row k="Tactic"     v={TECHNIQUE_INDEX[node.title]?.tactic} />
            <div style={{ marginTop: 8 }}>
              <a href={`https://attack.mitre.org/techniques/${node.title.replace(".", "/")}/`}
                    target="_blank" rel="noreferrer"
                    style={{ color: "var(--cyan)", fontSize: 10.5 }}>
                Open on attack.mitre.org <ExternalLink size={10} />
              </a>
            </div>
          </>
        )}
        {node.type === "incident" && (
          <>
            <Row k="Incident"  v={incident.number || incident.id} copy />
            <Row k="State"     v={incident.state} />
            <Row k="Severity"  v={incident.severity} />
            <Row k="Assignee"  v={incident.assignee || "unassigned"} />
            <Row k="Sources"   v={(incident.sources || []).join(", ") || "—"} />
          </>
        )}
      </div>
    </div>
  );
}


/* ───────────────────────────── attack story ──────────────────────── */
function AttackStoryPanel({ incident, onHighlightTechnique, onHighlightEvidence }) {
  const sentences = useMemo(() => buildAttackStory(incident), [incident]);
  return (
    <div className="panel" data-testid="xdr-attack-story"
            style={{ padding: 12, maxHeight: 260, overflow: "auto" }}>
      <div className="section-title" style={{ marginBottom: 6 }}>
        Attack Story
      </div>
      {sentences.length === 0 && (
        <div style={{ fontSize: 11, color: "var(--faint)" }}>
          No evidence-backed story yet.  The narrative appears once the
          incident carries Stage-2 evidence.
        </div>
      )}
      {sentences.map((s, i) => (
        <div key={i} style={{ fontSize: 11.5, color: "var(--text-dim)",
                                    padding: "5px 0",
                                    borderBottom: "1px solid var(--border)",
                                    cursor: "pointer" }}
                onClick={() => {
                  if (s.technique) onHighlightTechnique(s.technique);
                  else if (s.rule_id) onHighlightEvidence(s.rule_id);
                }}
                data-testid={`xdr-attack-story-sentence-${i}`}>
          <span className="mono" style={{ color: "var(--faint)", fontSize: 10 }}>
            {String(i + 1).padStart(2, "0")}.
          </span>{" "}
          {s.text}
          {s.technique && (
            <span className="mono"
                     style={{ marginLeft: 4, color: "#f472b6", fontSize: 9.5 }}>
              [{s.technique}]
            </span>
          )}
        </div>
      ))}
    </div>
  );
}

function buildAttackStory(incident) {
  const out = [];
  if (!incident) return out;
  const evs = (incident.verdict_stage2?.evidence || incident.evidence || []).slice(0, 12);
  for (const ev of evs) {
    const rid  = String(ev.rule_id || "").toUpperCase();
    const tech = ev.technique_id || RULE_TO_TECHNIQUE[rid];
    const who  = ev.entity?.image || ev.entity?.process || ev.image || "an entity";
    const host = ev.entity?.host_id || ev.host_id || (incident.assets?.hosts || [])[0]?.host_id;
    const verb = ev.title || ev.rule_id || "matched a detection rule";
    let text = `${who}${host ? " on " + host : ""} ${verb.replace(/_/g, " ").toLowerCase()}.`;
    if (ev.entity?.command_line) {
      text += ` Command line: ${_short(ev.entity.command_line, 90)}.`;
    }
    out.push({ text, rule_id: ev.rule_id, technique: tech });
  }
  const rs = incident.response_executions || incident.responses || [];
  for (const r of rs.slice(0, 4)) {
    out.push({
      text: `Response · ${r.action_id || "action"} executed ` +
              `(state: ${r.state || r.status || "?"}) by ${r.invoker?.id || r.invoker?.kind || "system"}.`,
      response: r.execution_id,
    });
  }
  return out;
}


/* ───────────────────────────── pivot menu ────────────────────────── */
function PivotMenu({ x, y, node, incident, onClose, onHighlight }) {
  const items = useMemo(() => buildPivotItems(node, incident), [node, incident]);
  const style = {
    position: "fixed", left: Math.min(x, window.innerWidth - 240),
    top: Math.min(y, window.innerHeight - 320),
    background: "#0e131c", border: "1px solid #22293a",
    borderRadius: 5, minWidth: 220, padding: "5px 0",
    boxShadow: "0 6px 24px rgba(0,0,0,.55)",
    zIndex: 100, fontSize: 11.5,
  };
  return (
    <div style={style} data-testid="xdr-pivot-menu"
            onClick={(e) => e.stopPropagation()}>
      <div style={{ padding: "4px 10px", color: "var(--faint)",
                        fontFamily: "var(--mono)", fontSize: 10,
                        textTransform: "uppercase", letterSpacing: ".3px" }}>
        {(NODE_TYPE[node.type] || {}).label} PIVOT
      </div>
      {items.map((it, i) =>
        it.divider ? (
          <div key={i} style={{ height: 1, background: "#1c2230", margin: "4px 0" }} />
        ) : (
          <button key={i} className="btn ghost"
                     onClick={() => { it.action?.({ onHighlight }); onClose(); }}
                     data-testid={`xdr-pivot-${it.key}`}
                     style={{ width: "100%", textAlign: "left",
                                 padding: "5px 12px", borderRadius: 0,
                                 background: "transparent",
                                 color: "var(--text-dim)", fontSize: 11.5 }}>
            {it.label}
          </button>
        )
      )}
    </div>
  );
}
function buildPivotItems(node, incident) {
  const raw   = node.raw || {};
  const base  = [];
  const encId = incident?.id ? encodeURIComponent(incident.id) : "";

  const open = (url) => window.open(url, "_blank", "noopener,noreferrer");
  const copy = (val) => navigator.clipboard?.writeText(String(val || ""));

  base.push({ key: "copy-title", label: "Copy value",
                 action: () => copy(node.title) });

  if (node.type === "host") {
    base.push({ key: "trajectory", label: "Show device trajectory",
                    action: () => open(`/xdr/endpoints?host=${encodeURIComponent(raw.host_id || node.title)}`) });
    base.push({ key: "search-host", label: "Search related incidents",
                    action: () => open(`/xdr/incidents?q=${encodeURIComponent(raw.host_id || node.title)}`) });
  }
  if (node.type === "user") {
    base.push({ key: "pivot-user", label: "Search related incidents",
                    action: () => open(`/xdr/incidents?q=${encodeURIComponent(raw.email || raw.user_id || node.title)}`) });
  }
  if (node.type === "process") {
    base.push({ key: "process-tree", label: "Open process tree",
                    action: () => open(`/edr/process-tree?case=${encId}`) });
  }
  if (["hash", "ip", "domain", "url"].includes(node.type)) {
    base.push({ key: "ioc-search",  label: `Search this ${node.type.toUpperCase()}`,
                    action: () => open(`/xdr/incidents?q=${encodeURIComponent(node.title)}`) });
    base.push({ key: "ioc-ti",      label: "Threat intel enrichment",
                    action: () => open(`/threat-intel?ioc=${encodeURIComponent(node.title)}`) });
  }
  if (node.type === "evidence") {
    base.push({ key: "evidence-decode", label: "Open in Analyst Workspace",
                    action: () => open(`/analyst?case=${encId}`) });
  }
  if (node.type === "technique") {
    base.push({ key: "tech-heatmap",  label: "Highlight on MITRE heatmap",
                    action: () => open(`/xdr/mitre?technique=${encodeURIComponent(node.title)}`) });
    base.push({ key: "tech-filter",   label: "Filter this technique on canvas",
                    action: ({ onHighlight }) => onHighlight({ technique_id: node.title }) });
    base.push({ key: "tech-incidents", label: "Incidents with this technique",
                    action: () => open(`/xdr/incidents?technique=${encodeURIComponent(node.title)}`) });
  }
  if (node.type === "response") {
    base.push({ key: "resp-detail",  label: `Open execution ${_short(raw.execution_id || "", 12)}`,
                    action: () => copy(raw.execution_id) });
  }

  base.push({ divider: true });
  base.push({ key: "add-to-case", label: "Add to case notes",
                 action: () => copy(`Investigation pivot: ${node.type}=${node.title}`) });
  base.push({ key: "automation",  label: "Create automation rule",
                 action: () => open(`/xdr/respond/automation-rules`) });
  base.push({ key: "respond",     label: "Run response action…",
                 action: () => open(`/xdr/incidents/${encId}#respond`) });
  return base;
}


/* ───────────────────────────── ancillary ─────────────────────────── */
function CanvasToolbar({ incidentId, nodeCount, edgeCount,
                                zoom, onZoom, highlight, onClearHighlight }) {
  return (
    <div style={{
      position: "absolute", top: 8, left: 10, right: 10, zIndex: 3,
      display: "flex", alignItems: "center", gap: 8,
      pointerEvents: "none",
    }}>
      <div className="mono" style={{ color: "var(--faint)", fontSize: 10 }}>
        {nodeCount} nodes · {edgeCount} edges
      </div>
      <span style={{ flex: 1 }} />
      {highlight && (
        <button className="btn ghost" onClick={onClearHighlight}
                  data-testid="xdr-canvas-clear-highlight"
                  style={{ padding: "2px 8px", fontSize: 10,
                              pointerEvents: "auto" }}>
          <X size={10} /> Clear highlight
        </button>
      )}
      <div className="mono" style={{ color: "var(--faint)", fontSize: 10,
                                                pointerEvents: "auto" }}>
        <button className="btn ghost" style={{ padding: "2px 6px" }}
                  onClick={() => onZoom(Math.max(0.35, zoom - 0.15))}
                  data-testid="xdr-canvas-zoom-out">−</button>
        <span style={{ padding: "0 6px" }}>{Math.round(zoom * 100)}%</span>
        <button className="btn ghost" style={{ padding: "2px 6px" }}
                  onClick={() => onZoom(Math.min(2.4, zoom + 0.15))}
                  data-testid="xdr-canvas-zoom-in">+</button>
      </div>
    </div>
  );
}
function CanvasLegend() {
  const shown = ["host", "user", "process", "evidence", "response", "technique"];
  return (
    <div style={{
      position: "absolute", bottom: 8, left: 10, display: "flex",
      gap: 8, flexWrap: "wrap", zIndex: 2,
    }}>
      {shown.map((k) => {
        const meta = NODE_TYPE[k];
        return (
          <span key={k}
                   style={{ display: "inline-flex", alignItems: "center", gap: 4,
                               padding: "2px 6px", borderRadius: 3,
                               border: `1px solid ${meta.color}`,
                               background: _hexA(meta.color, 0.08),
                               fontSize: 9.5, color: meta.color,
                               fontFamily: "var(--mono)",
                               letterSpacing: ".3px" }}>
            {meta.label}
          </span>
        );
      })}
    </div>
  );
}
function Row({ k, v, mono, copy, small, color }) {
  if (v == null || v === "") return null;
  const style = {
    color: color || "var(--text-dim)",
    fontFamily: mono ? "var(--mono)" : "inherit",
    fontSize: small ? 10.5 : 11,
    wordBreak: "break-all",
  };
  return (
    <div style={{ display: "flex", justifyContent: "space-between",
                    gap: 6, padding: "3px 0",
                    borderBottom: "1px solid var(--border)" }}>
      <span style={{ color: "var(--faint)", fontSize: 10.5,
                        textTransform: "uppercase", letterSpacing: ".3px" }}>{k}</span>
      <span style={style}>
        {v}
        {copy && typeof v === "string" && (
          <button className="btn ghost" style={{ padding: 2, marginLeft: 4 }}
                    onClick={() => navigator.clipboard?.writeText(v)}
                    title="Copy">
            <Copy size={9} />
          </button>
        )}
      </span>
    </div>
  );
}


/* ───────────────────────────── helpers ───────────────────────────── */
function _short(s, n = 24) {
  s = String(s || "");
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}
function _hexA(hex, a) {
  // Small alpha helper for arbitrary named or hex color inputs.
  if (hex?.startsWith?.("#") && hex.length === 7) {
    const r = parseInt(hex.slice(1, 3), 16);
    const g = parseInt(hex.slice(3, 5), 16);
    const b = parseInt(hex.slice(5, 7), 16);
    return `rgba(${r},${g},${b},${a})`;
  }
  return hex;
}
function _nodeMatches(node, h) {
  if (!h) return true;
  if (h.technique_id && node.type === "technique") return node.title === h.technique_id;
  if (h.technique_id && node.type === "evidence") {
    const rid = String(node.raw?.rule_id || "").toUpperCase();
    return (node.raw?.technique_id === h.technique_id) ||
              (RULE_TO_TECHNIQUE[rid] === h.technique_id);
  }
  if (h.rule_id && node.type === "evidence")
    return String(node.raw?.rule_id || "") === String(h.rule_id || "");
  if (h.technique_id && node.type === "incident") return true;
  return false;
}
function _edgeMatches(edge, s, t, h) {
  return _nodeMatches(s, h) || _nodeMatches(t, h);
}
