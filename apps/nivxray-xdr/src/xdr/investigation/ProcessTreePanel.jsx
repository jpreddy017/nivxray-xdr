/**
 * ProcessTreePanel — Predicted Process Tree visual (NivXRay Tool style).
 *
 * Owner directive (2026-02-30, refined with SOC-100-scenarios PDF):
 *
 *   Process Tree                = visual of canonical process evidence
 *   Process Genealogy           = reusable behavioral analytics
 *   ATT&CK Chain / Attack Story = evidence-backed behavioral sequence
 *
 * Every relationship, genealogy observation and ATT&CK transition
 * MUST be traceable to canonical evidence.  Absence of evidence
 * remains absence — we do NOT interpolate.
 *
 * Evidence-state distinctions preserved (from the PDF):
 *   CAPABILITY · ATTEMPTED · OBSERVED · EXECUTED · CORRELATED ·
 *   CONFIRMED_IMPACT
 * The Verdict Engine remains the ONLY authoritative producer of
 * MALICIOUS.  Process behaviour is an OBSERVATION.
 */
import React, { useEffect, useMemo, useState } from "react";
import { Cpu, ChevronDown, ChevronUp, Copy, Info, Search } from "lucide-react";

import { TECHNIQUE_INDEX } from "@/xdr/mitre/mitreTactics";
import { useSelection } from "@/xdr/investigation/WorkspaceSelectionContext";
import api from "@/lib/api";


// Rare / suspicious parent-child rules (SOC-scenario grounded).
const SUSPICIOUS_RULES = [
  { name: "Office → script interpreter",
      parent: /winword|excel|powerpnt|outlook/i,
      child:  /powershell|cmd|wscript|cscript|mshta/i },
  { name: "Browser → unusual child",
      parent: /chrome|firefox|msedge|iexplore|safari/i,
      child:  /powershell|cmd|wscript|cscript|mshta|regsvr32|rundll32/i },
  { name: "Service → shell",
      parent: /services\.exe|svchost\.exe/i,
      child:  /powershell|cmd|wscript|cscript/i },
  { name: "Web server → shell",
      parent: /w3wp|nginx|httpd|apache/i,
      child:  /powershell|cmd|sh|bash/i },
  { name: "PowerShell → LOLBIN",
      parent: /powershell/i,
      child:  /rundll32|regsvr32|mshta|certutil|bitsadmin|msbuild|installutil|wmic|vssadmin/i },
  { name: "LOLBIN → network stack",
      parent: /rundll32|regsvr32|mshta|certutil|bitsadmin/i,
      child:  /powershell|cmd|curl|wget/i },
];


// Node accent per evidence state.  Colours are cues, NEVER verdicts.
const STATE_COLOR = {
  CAPABILITY:       "#94a3b8",
  ATTEMPTED:        "#facc15",
  OBSERVED:         "#eab308",
  EXECUTED:         "#f97316",
  CORRELATED:       "#a78bfa",
  CONFIRMED_IMPACT: "#f87171",
  SUSPICIOUS:       "#f87171",   // rare parent-child observation
  DETECTED:         "#facc15",
};

// Layout constants for the graph.
const NODE_W = 260;
const NODE_H = 66;
const H_GAP  = 40;
const V_GAP  = 30;


export default function ProcessTreePanel({ incident }) {
  const { selection, setSelection } = useSelection();
  const [enrichment, setEnrichment] = useState(null);
  const [q, setQ] = useState("");
  const [collapsed, setCollapsed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!incident?.id) return;
      try {
        const r = await api.get("/edr/process-tree",
                                    { params: { incident_id: incident.id }});
        if (!cancelled) setEnrichment(r?.data || null);
      } catch { if (!cancelled) setEnrichment(null); }
    })();
    return () => { cancelled = true; };
  }, [incident?.id]);

  const { nodes, edges, roots, procById } = useMemo(
    () => buildCanonicalGraph(incident, enrichment),
    [incident, enrichment]);

  // Auto-layout: BFS from each root, columns per depth, rows within.
  const laidOut = useMemo(
    () => autoLayout(nodes, edges, roots), [nodes, edges, roots]);

  const selectedId = selection?.kind === "process"
    ? `proc:${selection?.ref?.pid || selection?.ref?.name || ""}`
    : null;

  const filtered = useMemo(() => {
    if (!q.trim()) return nodes;
    const s = q.trim().toLowerCase();
    return nodes.filter((n) =>
        (n.name || "").toLowerCase().includes(s)
     || String(n.pid || "").includes(s)
     || (n.command_line || "").toLowerCase().includes(s)
     || (n.sha256 || "").toLowerCase().includes(s));
  }, [nodes, q]);
  const filteredIds = new Set(filtered.map((n) => n.id));

  const empty = nodes.length === 0;
  const { W, H } = boundsFrom(laidOut, empty);

  const selectedProc = selectedId ? procById[selectedId] : null;

  return (
    <section data-testid="xdr-process-tree-panel" style={{ marginTop: 14 }}>
      <div style={header}>
        <Cpu size={13} style={{ color: "#a78bfa" }} />
        <b style={{ fontFamily: "var(--mono)", fontSize: 12,
                                letterSpacing: 0.3 }}>PREDICTED PROCESS TREE</b>
        <span style={metaChip}>
          {nodes.length} process{nodes.length === 1 ? "" : "es"} · {roots.length} root{roots.length === 1 ? "" : "s"} · {edges.length} edge{edges.length === 1 ? "" : "s"}
        </span>
        <span style={{ fontSize: 9.5, color: "var(--faint)",
                                    fontFamily: "var(--mono)" }}>
          observations · never verdicts
        </span>
        <span style={{ flex: 1 }} />
        <div style={{ position: "relative", display: "flex",
                                gap: 4, alignItems: "center" }}>
          <Search size={11} style={{ color: "var(--faint)" }} />
          <input value={q}
                       onChange={(e) => setQ(e.target.value)}
                       placeholder="pid · image · command · sha256"
                       data-testid="xdr-process-tree-search"
                       style={inputStyle} />
        </div>
        <button type="button"
                      data-testid="xdr-process-tree-toggle"
                      onClick={() => setCollapsed((c) => !c)}
                      style={ctrlBtn}>
          {collapsed ? <><ChevronDown size={10} /> OPEN</>
                                    : <><ChevronUp size={10} /> COLLAPSE</>}
        </button>
      </div>

      {!collapsed && (
        <div style={grid}>
          <div style={leftCol}>
            {empty ? (
              <div style={{ padding: 12, fontSize: 11, color: "var(--faint)",
                                            fontFamily: "var(--mono)",
                                            border: "1px dashed var(--border)",
                                            borderRadius: 3, display: "flex",
                                            alignItems: "center" }}
                          data-testid="xdr-process-tree-empty">
                <Info size={12} style={{ marginRight: 6 }} />
                No process evidence in this investigation.  Nodes are
                extracted from `verdict_stage2.evidence[]` + the canonical
                timeline — nothing is fabricated.
              </div>
            ) : (
              <div style={{ overflow: "auto", padding: 10,
                                            background: "var(--panel)",
                                            border: "1px solid var(--border)",
                                            borderRadius: 3 }}
                          data-testid="xdr-process-tree-canvas">
                <svg width={W} height={H}
                          style={{ display: "block" }}>
                  {/* Curved edges parent → child */}
                  {edges.map((e) => {
                    const a = laidOut[e.from];
                    const b = laidOut[e.to];
                    if (!a || !b) return null;
                    const ax = a.x + NODE_W, ay = a.y + NODE_H / 2;
                    const bx = b.x,          by = b.y + NODE_H / 2;
                    const midX = (ax + bx) / 2;
                    return (
                      <path key={`${e.from}->${e.to}`}
                                  data-testid={`xdr-proc-edge-${e.from}-${e.to}`}
                                  d={`M ${ax} ${ay}
                                         C ${midX} ${ay}, ${midX} ${by}, ${bx} ${by}`}
                                  fill="none"
                                  stroke="rgba(200,200,220,0.32)"
                                  strokeWidth={1.2} />
                    );
                  })}
                  {nodes.map((n) => {
                    const p = laidOut[n.id];
                    if (!p) return null;
                    const active   = selectedId === n.id;
                    const inFilter = filteredIds.has(n.id);
                    const primary  = pickAccent(n);
                    return (
                      <g key={n.id}
                              transform={`translate(${p.x}, ${p.y})`}
                              opacity={inFilter ? 1 : 0.28}
                              onClick={() => setSelection({
                                kind: "process",
                                ref: { pid: n.pid, name: n.name, id: n.id },
                                source: "process-tree-graph",
                              })}
                              data-testid={`xdr-proc-node-${n.id}`}
                              style={{ cursor: "pointer" }}>
                        <rect width={NODE_W} height={NODE_H} rx={6} ry={6}
                                    fill={active ? "rgba(250,204,21,0.10)"
                                                                : "rgba(20,25,35,0.9)"}
                                    stroke={primary}
                                    strokeWidth={active ? 1.8 : 1.2} />
                        <text x={12} y={20}
                                    fill={primary}
                                    fontFamily="var(--mono)"
                                    fontSize={12}
                                    fontWeight={700}>
                          {n.name}
                        </text>
                        <text x={12} y={36}
                                    fill="var(--faint)"
                                    fontFamily="var(--mono)"
                                    fontSize={10}>
                          {n.tactic_hint || "—"}
                        </text>
                        <text x={12} y={54}
                                    fill="var(--text-dim)"
                                    fontFamily="var(--mono)"
                                    fontSize={10}>
                          {n.techniques.slice(0, 4).join(", ") || (n.pid != null ? `pid:${n.pid}` : "")}
                        </text>
                        {/* Evidence-state badge */}
                        <g transform={`translate(${NODE_W - 12}, 12)`}>
                          {n.states.map((s, i) => (
                            <rect key={s} x={-8 - i * 12} y={-8}
                                        width={10} height={10} rx={2}
                                        fill={STATE_COLOR[s] || "var(--faint)"}
                                        opacity={0.85}>
                              <title>{s}</title>
                            </rect>
                          ))}
                        </g>
                      </g>
                    );
                  })}
                </svg>
              </div>
            )}
          </div>

          <div style={rightCol}
                     data-testid="xdr-process-details-pane">
            {selectedProc
              ? <ProcessDetails proc={selectedProc} />
              : <div style={{ padding: 12, fontSize: 11, color: "var(--faint)",
                                            fontFamily: "var(--mono)" }}
                          data-testid="xdr-process-details-empty">
                    Click a process to inspect command line · hash · signer ·
                    network · detections · ATT&CK · evidence-state
                    (CAPABILITY / ATTEMPTED / OBSERVED / EXECUTED /
                    CORRELATED / CONFIRMED_IMPACT).
                  </div>}
          </div>
        </div>
      )}
    </section>
  );
}


// ── Process details pane ──────────────────────────────────────────
function ProcessDetails({ proc }) {
  return (
    <div>
      <div style={{ padding: "8px 10px",
                              borderBottom: "1px solid var(--border)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6,
                                flexWrap: "wrap" }}>
          <Cpu size={12} style={{ color: pickAccent(proc) }} />
          <b style={{ fontSize: 12, fontFamily: "var(--mono)" }}>
            {proc.name}
          </b>
          {proc.pid !== undefined && proc.pid !== null && (
            <span style={{ fontSize: 10, color: "var(--faint)",
                                        fontFamily: "var(--mono)" }}>
              pid:{proc.pid}
            </span>
          )}
        </div>
        <div style={{ display: "flex", gap: 4, marginTop: 4, flexWrap: "wrap" }}>
          {proc.states.map((s) => (
            <span key={s}
                        data-testid={`xdr-proc-state-${proc.id}-${s}`}
                        style={{ padding: "0 6px", fontSize: 9,
                                        fontFamily: "var(--mono)", fontWeight: 700,
                                        border: `1px solid ${STATE_COLOR[s]}`,
                                        color: STATE_COLOR[s], borderRadius: 2 }}>
              {s}
            </span>
          ))}
        </div>
      </div>
      <div style={{ padding: 10, fontSize: 11, fontFamily: "var(--mono)",
                              color: "var(--text)" }}>
        <KV k="image"          v={proc.image_path || proc.name} />
        <KV k="pid"            v={proc.pid} />
        <KV k="ppid"           v={proc.ppid} />
        <KV k="process_guid"   v={proc.process_guid} />
        <KV k="user"           v={proc.user} />
        <KV k="host"           v={proc.host} />
        <KV k="command_line"   v={proc.command_line} multi />
        <KV k="sha256"         v={proc.sha256} multi />
        <KV k="signer"         v={proc.signer} />
        <KV k="signature"      v={proc.signature_status} />
        <KV k="integrity"      v={proc.integrity_level} />
        <KV k="techniques"     v={proc.techniques.join(", ")} />
        <KV k="detections"
              v={proc.detections.map((d) => `${d.rule_id} (w=${d.weight ?? "—"})`)
                                                    .join(" · ") || null} />
        <KV k="evidence refs"
              v={proc.evidence_refs.join(", ") || null} />
      </div>
    </div>
  );
}

function KV({ k, v, multi }) {
  const missing = v === undefined || v === null || v === "";
  return (
    <div style={{ display: "flex", gap: 6, padding: "2px 0",
                            alignItems: multi ? "flex-start" : "center" }}
                data-testid={`xdr-kv-${k}`}>
      <span style={{ minWidth: 120, fontSize: 9, color: "var(--faint)",
                              textTransform: "uppercase", letterSpacing: 0.3,
                              fontWeight: 700 }}>
        {k}
      </span>
      <span style={{ flex: 1, color: missing ? "var(--faint)" : "var(--text)",
                              wordBreak: multi ? "break-all" : "normal",
                              fontStyle: missing ? "italic" : "normal" }}>
        {missing ? "—" : String(v)}
      </span>
      {!missing && !multi && (
        <button type="button" title="Copy"
                      onClick={() => navigator.clipboard?.writeText(String(v))}
                      style={{ background: "none", border: "none",
                                      color: "var(--faint)", cursor: "pointer" }}>
          <Copy size={9} />
        </button>
      )}
    </div>
  );
}


// ── Canonical graph builder ───────────────────────────────────────
function buildCanonicalGraph(incident, enrichment) {
  const byKey = new Map();
  const evs = (incident?.verdict_stage2?.evidence || incident?.evidence || []);
  const hosts = incident?.assets?.hosts || incident?.hosts || [];
  const defaultHost = hosts[0]?.host_id || hosts[0]?.name || hosts[0]?.id;

  const upsert = (rec) => {
    const key = `proc:${rec.pid ?? rec.name}`;
    let existing = byKey.get(key);
    if (!existing) {
      existing = {
        id: key,
        name: rec.name,
        pid: rec.pid ?? null,
        ppid: rec.ppid ?? rec.parent_pid ?? null,
        parent_name: rec.parent_name || null,
        parent_id: null,
        child_ids: [],
        command_line: rec.command_line || rec.cmdline || null,
        image_path: rec.image_path || rec.path || null,
        user: rec.user || null,
        host: rec.host || rec.host_id || defaultHost || null,
        sha256: rec.sha256 || rec.hash || null,
        signer: rec.signer || null,
        signature_status: rec.signature_status || null,
        integrity_level: rec.integrity_level || null,
        process_guid: rec.process_guid || null,
        first_seen: rec.first_seen || null,
        last_seen:  rec.last_seen  || null,
        techniques: [],
        tactic_hint: null,
        detections: [],
        evidence_refs: [],
        states: [],
      };
      byKey.set(key, existing);
    } else {
      for (const k of Object.keys(existing)) {
        if (existing[k] == null && rec[k] != null) existing[k] = rec[k];
      }
    }
    return existing;
  };

  for (const ev of evs) {
    const e = ev.entity || ev.process || {};
    const name = e.image || e.process || e.name;
    if (!name) continue;
    const node = upsert({
      name,
      pid: e.pid,
      ppid: e.ppid ?? e.parent_pid,
      parent_name: e.parent_name || e.parent_image,
      command_line: e.command_line || e.cmdline,
      user: e.user, host: e.host_id,
      sha256: e.sha256 || e.hash,
      signer: e.signer, signature_status: e.signature_status,
      integrity_level: e.integrity_level,
      process_guid: e.process_guid,
      first_seen: e.first_seen || ev.timestamp,
      last_seen:  e.last_seen  || ev.timestamp,
    });
    if (ev.rule_id) {
      node.detections.push({ rule_id: ev.rule_id, weight: ev.weight,
                                          detected_by: ev.detected_by || ev.engine });
    }
    const tech = ev.technique_id;
    if (tech && !node.techniques.includes(tech)) {
      node.techniques.push(tech);
      const meta = TECHNIQUE_INDEX[tech];
      if (meta?.tactic && !node.tactic_hint) node.tactic_hint = meta.tactic;
    }
    if (ev.evidence_ref?.rule_id || ev.id)
      node.evidence_refs.push(ev.evidence_ref?.rule_id || ev.id);
  }

  // Direct process arrays surfaced by the incident payload.  Accepts
  // both incident.processes[] and incident.process_tree[] (either
  // flat or nested via children[]).  Fields consumed:
  //   { name/image, pid, ppid/parent_pid, command_line, sha256,
  //     signer, user, host, techniques[], detections[] }
  const flatten = (list, out) => {
    for (const p of (list || [])) {
      if (!p) continue;
      out.push(p);
      if (Array.isArray(p.children)) flatten(p.children, out);
    }
    return out;
  };
  const flatProcs = [
    ...flatten(incident?.processes, []),
    ...flatten(incident?.process_tree, []),
  ];
  for (const p of flatProcs) {
    const name = p.name || p.image;
    if (!name) continue;
    const node = upsert({
      name,
      pid: p.pid,
      ppid: p.ppid ?? p.parent_pid,
      parent_name: p.parent_name || p.parent_image,
      command_line: p.command_line || p.cmdline,
      user: p.user, host: p.host_id || p.host,
      sha256: p.sha256 || p.hash,
      signer: p.signer, signature_status: p.signature_status,
      integrity_level: p.integrity_level,
      process_guid: p.process_guid || p.guid,
      first_seen: p.first_seen || p.start_time,
      last_seen:  p.last_seen  || p.end_time,
    });
    for (const t of (p.techniques || p.attack_techniques || [])) {
      if (!node.techniques.includes(t)) {
        node.techniques.push(t);
        const meta = TECHNIQUE_INDEX[t];
        if (meta?.tactic && !node.tactic_hint) node.tactic_hint = meta.tactic;
      }
    }
    for (const d of (p.detections || [])) node.detections.push(d);
  }

  // Enrichment adapter
  for (const en of (enrichment?.nodes || [])) {
    upsert({
      name: en.process,
      pid: en.entity_id?.startsWith("pid:")
                ? Number(en.entity_id.slice(4))
                : null,
      command_line: en.command_line,
      image_path: en.path,
      user: en.user, host: en.host,
      first_seen: en.first_seen, last_seen: en.last_seen,
    });
  }

  // parent_id resolution
  const byPid = new Map();
  for (const n of byKey.values()) {
    if (n.pid != null) byPid.set(String(n.pid), n);
  }
  for (const n of byKey.values()) {
    if (!n.parent_id && n.ppid != null && byPid.has(String(n.ppid))) {
      n.parent_id = byPid.get(String(n.ppid)).id;
    }
  }
  for (const n of byKey.values()) {
    if (n.parent_id) {
      const parent = byKey.get(n.parent_id);
      if (parent && !parent.child_ids.includes(n.id))
        parent.child_ids.push(n.id);
    }
  }

  // Evidence-state annotations — deterministic, never verdicts.
  for (const n of byKey.values()) {
    const s = new Set(["OBSERVED"]);   // presence in evidence = OBSERVED
    if (n.detections.length) s.add("DETECTED");
    // Suspicious parent-child = OBSERVATION only (SOC-scenario grounded).
    if (n.parent_id) {
      const p = byKey.get(n.parent_id);
      if (p) {
        for (const rule of SUSPICIOUS_RULES) {
          if (rule.parent.test(p.name) && rule.child.test(n.name)) {
            s.add("SUSPICIOUS");
            break;
          }
        }
      }
    } else if (n.parent_name) {
      for (const rule of SUSPICIOUS_RULES) {
        if (rule.parent.test(n.parent_name) && rule.child.test(n.name)) {
          s.add("SUSPICIOUS");
          break;
        }
      }
    }
    n.states = Array.from(s);
  }

  const nodes = Array.from(byKey.values());
  const roots = nodes.filter((n) => !n.parent_id).map((n) => n.id);
  const edges = [];
  for (const n of nodes) {
    if (n.parent_id) edges.push({ from: n.parent_id, to: n.id });
  }

  return { nodes, edges, roots,
              procById: Object.fromEntries(nodes.map((n) => [n.id, n])) };
}


// ── Deterministic BFS auto-layout ─────────────────────────────────
function autoLayout(nodes, edges, roots) {
  const depth = new Map();
  const kids  = new Map();
  for (const n of nodes) kids.set(n.id, []);
  for (const e of edges) kids.get(e.from).push(e.to);

  const queue = roots.map((r) => [r, 0]);
  while (queue.length) {
    const [id, d] = queue.shift();
    if (depth.has(id)) continue;
    depth.set(id, d);
    for (const k of kids.get(id) || []) queue.push([k, d + 1]);
  }
  // Assign column index and row within column.
  const byDepth = {};
  for (const n of nodes) {
    const d = depth.get(n.id) ?? 0;
    if (!byDepth[d]) byDepth[d] = [];
    byDepth[d].push(n.id);
  }
  const out = {};
  for (const [d, list] of Object.entries(byDepth)) {
    list.forEach((id, row) => {
      out[id] = {
        x: 20 + Number(d) * (NODE_W + H_GAP),
        y: 20 + row * (NODE_H + V_GAP),
      };
    });
  }
  return out;
}


function boundsFrom(laid, empty) {
  if (empty) return { W: 300, H: 120 };
  let W = 400, H = 200;
  for (const p of Object.values(laid)) {
    W = Math.max(W, p.x + NODE_W + 40);
    H = Math.max(H, p.y + NODE_H + 40);
  }
  return { W, H };
}


function pickAccent(n) {
  if (n.states.includes("CONFIRMED_IMPACT")) return STATE_COLOR.CONFIRMED_IMPACT;
  if (n.states.includes("SUSPICIOUS"))       return STATE_COLOR.SUSPICIOUS;
  if (n.states.includes("EXECUTED"))         return STATE_COLOR.EXECUTED;
  if (n.states.includes("CORRELATED"))       return STATE_COLOR.CORRELATED;
  if (n.states.includes("DETECTED"))         return STATE_COLOR.DETECTED;
  return STATE_COLOR.OBSERVED;
}


// ── styles ────────────────────────────────────────────────────────
const header = {
  display: "flex", alignItems: "center", gap: 8, marginBottom: 8,
  padding: "0 4px", flexWrap: "wrap",
};
const metaChip = {
  padding: "1px 6px", fontSize: 9.5, fontFamily: "var(--mono)",
  fontWeight: 700, background: "var(--panel2)",
  border: "1px solid var(--border)", borderRadius: 2,
  color: "var(--faint)",
};
const grid = {
  display: "grid", gridTemplateColumns: "1.6fr 1fr", gap: 10,
};
const leftCol = { minWidth: 0 };
const rightCol = {
  border: "1px solid var(--border)", borderRadius: 3,
  background: "var(--panel)", minHeight: 200,
};
const inputStyle = {
  padding: "3px 6px", background: "var(--panel2)",
  border: "1px solid var(--border)", color: "var(--text)",
  fontSize: 10.5, borderRadius: 2, fontFamily: "var(--mono)",
  minWidth: 200,
};
const ctrlBtn = {
  padding: "3px 8px", fontSize: 10, fontWeight: 700,
  background: "var(--panel2)", border: "1px solid var(--border)",
  color: "var(--text-dim)", borderRadius: 2, cursor: "pointer",
  fontFamily: "var(--mono)", display: "inline-flex",
  alignItems: "center", gap: 3,
};
