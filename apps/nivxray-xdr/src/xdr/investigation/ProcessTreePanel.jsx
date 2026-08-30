/**
 * ProcessTreePanel — first-class Investigation surface.
 *
 * Data-source hierarchy (owner-locked directive · 2026-02-30):
 *
 *   Collector telemetry
 *          ↓
 *   Canonical Process Evidence  ← extracted from incident payload
 *          ↓                       (the same source Evidence Trajectory uses)
 *   Evidence Graph  (source of truth for this incident)
 *          ↓
 *   Canonical Process Tree      ← this panel
 *          ↘
 *    Optional enrichment adapter:  GET /api/edr/process-tree
 *                                  (fills additional NivXRay-Tool fields
 *                                   when the incident id is present in
 *                                   workspace_cases; NEVER a competing tree)
 *
 * Never fabricate a parent.  Unknown parent → honest "unknown parent"
 * root — Windows genealogy allows this legitimately (parents can
 * disappear before the collector queries the system).
 *
 * Badges (never a verdict):
 *   OBSERVED    process appears in evidence
 *   DETECTED    a detection rule fired on this process
 *   CORRELATED  process participates in a correlation match
 *   SUSPICIOUS  rare parent-child (Office→script, browser→shell, etc.)
 *
 * The badge SUSPICIOUS is an *observation*, not a verdict.  The
 * containing incident's Verdict Engine keeps its authoritative role.
 */
import React, { useEffect, useMemo, useState } from "react";
import { ChevronDown, ChevronRight, Cpu, Search, Filter,
                Copy, ExternalLink, Info } from "lucide-react";

import { RULE_TO_TECHNIQUE, TECHNIQUE_INDEX }
    from "@/xdr/mitre/mitreTactics";
import { useSelection } from "@/xdr/investigation/WorkspaceSelectionContext";
import api from "@/lib/api";


// ── Rare / suspicious parent-child rules (observations, NOT verdicts) ─
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
      child:  /rundll32|regsvr32|mshta|certutil|bitsadmin|msbuild|installutil/i },
  { name: "LOLBIN → network stack",
      parent: /rundll32|regsvr32|mshta|certutil|bitsadmin/i,
      child:  /powershell|cmd|curl|wget/i },
];

const SEV_COLOR = {
  OBSERVED:   "var(--faint)",
  DETECTED:   "var(--amber)",
  CORRELATED: "#a78bfa",
  SUSPICIOUS: "#f87171",
};


export default function ProcessTreePanel({ incident }) {
  const { selection, setSelection } = useSelection();
  const [enrichment, setEnrichment] = useState(null);
  const [query, setQuery]     = useState("");
  const [expanded, setExpanded] = useState({});
  const [onlySus, setOnlySus] = useState(false);

  // ── Enrichment (best-effort · never blocks render) ─────────────
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

  // ── Canonical process evidence + tree ──────────────────────────
  const { nodes, roots, procById } = useMemo(
    () => buildCanonicalTree(incident, enrichment),
    [incident, enrichment]);

  // Auto-expand roots on first render
  useEffect(() => {
    if (Object.keys(expanded).length === 0 && roots.length) {
      setExpanded(Object.fromEntries(roots.map((r) => [r, true])));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [roots.join(",")]);

  const selectedId = selection?.kind === "process"
    ? `proc:${selection?.ref?.pid || selection?.ref?.name || ""}`
    : null;

  const filtered = useMemo(() => {
    if (!query.trim() && !onlySus) return nodes;
    const q = query.trim().toLowerCase();
    return nodes.filter((n) => {
      if (onlySus && !(n.badges || []).includes("SUSPICIOUS")) return false;
      if (!q) return true;
      return (n.name || "").toLowerCase().includes(q)
          || String(n.pid || "").includes(q)
          || (n.command_line || "").toLowerCase().includes(q)
          || (n.sha256 || "").toLowerCase().includes(q);
    });
  }, [nodes, query, onlySus]);

  const filteredIds = new Set(filtered.map((n) => n.id));

  const selectedProc = useMemo(() => {
    if (!selectedId) return null;
    return procById[selectedId] || null;
  }, [selectedId, procById]);

  const empty = nodes.length === 0;

  return (
    <section data-testid="xdr-process-tree-panel"
                 style={{ marginTop: 14 }}>
      <div style={header}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <Cpu size={13} style={{ color: "var(--cyan)" }} />
          <b style={{ fontFamily: "var(--mono)", fontSize: 12,
                                letterSpacing: ".3px" }}>
            PROCESS TREE
          </b>
          <span style={{ padding: "1px 6px", fontSize: 9.5,
                                    fontFamily: "var(--mono)", fontWeight: 700,
                                    background: "var(--panel2)",
                                    border: "1px solid var(--border)",
                                    borderRadius: 2, color: "var(--faint)" }}>
            {nodes.length} process{nodes.length === 1 ? "" : "es"} · {roots.length} root{roots.length === 1 ? "" : "s"}
          </span>
          <span style={{ fontSize: 9.5, color: "var(--faint)",
                                    fontFamily: "var(--mono)" }}>
            observations · never verdicts
          </span>
        </div>
      </div>

      {empty ? (
        <div style={emptyBox} data-testid="xdr-process-tree-empty">
          <Info size={12} style={{ marginRight: 6 }} />
          No process evidence in this investigation.  Process nodes are
          extracted from `verdict_stage2.evidence[]` and the incident's
          canonical timeline — nothing is fabricated.
        </div>
      ) : (
        <div style={grid}>
          <div style={leftCol}>
            <div style={{ display: "flex", gap: 6, marginBottom: 6,
                                    alignItems: "center", padding: "0 6px" }}>
              <Search size={11} style={{ color: "var(--faint)" }} />
              <input value={query}
                          onChange={(e) => setQuery(e.target.value)}
                          placeholder="pid · image · command · sha256"
                          data-testid="xdr-process-tree-search"
                          style={inputStyle} />
              <button type="button"
                            data-testid="xdr-process-tree-only-suspicious"
                            onClick={() => setOnlySus((s) => !s)}
                            style={{ ...pillBtn,
                                            borderColor: onlySus ? "#f87171" : "var(--border)",
                                            color:       onlySus ? "#f87171" : "var(--faint)" }}>
                <Filter size={9} /> only suspicious
              </button>
            </div>
            <div style={{ maxHeight: 480, overflow: "auto",
                                    padding: "0 6px 6px" }}>
              {roots.map((rootId) => (
                <TreeBranch key={rootId}
                                        nodeId={rootId}
                                        nodes={nodes}
                                        expanded={expanded}
                                        setExpanded={setExpanded}
                                        selectedId={selectedId}
                                        onSelect={(n) => setSelection({
                                          kind: "process", ref: { pid: n.pid, name: n.name, id: n.id },
                                          source: "process-tree",
                                        })}
                                        filteredIds={filteredIds}
                                        depth={0} />
              ))}
            </div>
          </div>

          <div style={rightCol}
                     data-testid="xdr-process-details-pane">
            {selectedProc
              ? <ProcessDetails proc={selectedProc} />
              : <div style={{ padding: 12, fontSize: 11, color: "var(--faint)",
                                            fontFamily: "var(--mono)" }}
                          data-testid="xdr-process-details-empty">
                    Select a process in the tree to inspect its command line,
                    hash, signer, network activity, detections, ATT&CK
                    techniques and supporting evidence.
                  </div>}
          </div>
        </div>
      )}
    </section>
  );
}


// ── Tree branch (recursive) ───────────────────────────────────────
function TreeBranch({ nodeId, nodes, expanded, setExpanded, selectedId,
                                    onSelect, filteredIds, depth }) {
  const node = nodes.find((n) => n.id === nodeId);
  if (!node) return null;
  const kids = node.child_ids
                        .map((cid) => nodes.find((x) => x.id === cid))
                        .filter(Boolean);
  const isOpen = expanded[nodeId];
  const inFilter = filteredIds.has(nodeId);
  const highlighted = selectedId === nodeId;

  const toggle = (e) => {
    e.stopPropagation();
    setExpanded((cur) => ({ ...cur, [nodeId]: !cur[nodeId] }));
  };

  return (
    <div data-testid={`xdr-proc-branch-${nodeId}`}>
      <div onClick={() => onSelect(node)}
                style={{ ...branchRow,
                                paddingLeft: 6 + depth * 14,
                                background: highlighted ? "rgba(56,189,248,0.12)" : "transparent",
                                opacity:    inFilter ? 1 : 0.35 }}
                data-testid={`xdr-proc-row-${nodeId}`}>
        {kids.length ? (
          <button type="button" onClick={toggle}
                        data-testid={`xdr-proc-toggle-${nodeId}`}
                        style={toggleBtn}>
            {isOpen ? <ChevronDown size={10} /> : <ChevronRight size={10} />}
          </button>
        ) : <span style={{ width: 14, display: "inline-block" }} />}

        <Cpu size={10} style={{ color: "#a78bfa", flexShrink: 0 }} />

        <div style={{ display: "flex", gap: 4, alignItems: "center",
                                flexWrap: "wrap", flex: 1, minWidth: 0 }}>
          <span style={{ color: "var(--text)", fontWeight: 600 }}>
            {node.name}
          </span>
          {node.pid !== undefined && node.pid !== null && (
            <span style={{ fontSize: 9.5, color: "var(--faint)" }}>
              pid:{node.pid}
            </span>
          )}
          {node.badges.map((b) => (
            <span key={b}
                        data-testid={`xdr-proc-badge-${nodeId}-${b}`}
                        style={{ ...badgeChip,
                                        borderColor: SEV_COLOR[b],
                                        color:       SEV_COLOR[b] }}>
              {b}
            </span>
          ))}
          {node.command_line && (
            <span style={{ fontSize: 9.5, color: "var(--faint)",
                                        whiteSpace: "nowrap",
                                        overflow: "hidden", textOverflow: "ellipsis",
                                        maxWidth: 320 }}
                        title={node.command_line}>
              · {node.command_line}
            </span>
          )}
        </div>
      </div>
      {isOpen && kids.map((k) => (
        <TreeBranch key={k.id}
                              nodeId={k.id}
                              nodes={nodes}
                              expanded={expanded}
                              setExpanded={setExpanded}
                              selectedId={selectedId}
                              onSelect={onSelect}
                              filteredIds={filteredIds}
                              depth={depth + 1} />
      ))}
    </div>
  );
}


// ── Process details pane ──────────────────────────────────────────
function ProcessDetails({ proc }) {
  const [tab, setTab] = useState("overview");
  const tabs = [
    ["overview",    "Overview"],
    ["cmdline",     "Command Line"],
    ["hash",        "Hash / Signer"],
    ["network",     "Network"],
    ["detections",  "Detections"],
    ["attck",       "ATT&CK"],
    ["evidence",    "Evidence"],
  ];
  return (
    <div>
      <div style={{ padding: "8px 10px",
                              borderBottom: "1px solid var(--border)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6,
                                flexWrap: "wrap" }}>
          <Cpu size={12} style={{ color: "#a78bfa" }} />
          <b style={{ fontSize: 12, fontFamily: "var(--mono)" }}>
            {proc.name}
          </b>
          {proc.pid !== undefined && proc.pid !== null && (
            <span style={{ fontSize: 10, color: "var(--faint)",
                                        fontFamily: "var(--mono)" }}>
              pid:{proc.pid}
            </span>
          )}
          {proc.badges.map((b) => (
            <span key={b} style={{ ...badgeChip,
                                                    borderColor: SEV_COLOR[b],
                                                    color:       SEV_COLOR[b] }}>
              {b}
            </span>
          ))}
        </div>
      </div>
      <div style={{ display: "flex", gap: 2, padding: "4px 6px",
                              borderBottom: "1px solid var(--border)",
                              flexWrap: "wrap" }}>
        {tabs.map(([k, l]) => (
          <button key={k} type="button"
                        data-testid={`xdr-proc-detail-tab-${k}`}
                        onClick={() => setTab(k)}
                        style={{ ...pillBtn,
                                        borderColor: tab === k ? "var(--cyan)" : "var(--border)",
                                        color:       tab === k ? "var(--cyan)" : "var(--faint)" }}>
            {l}
          </button>
        ))}
      </div>
      <div style={{ padding: 10, fontSize: 11, fontFamily: "var(--mono)",
                              color: "var(--text)" }}>
        {tab === "overview"   && <OverviewTab   proc={proc} />}
        {tab === "cmdline"    && <KVRow k="command_line" v={proc.command_line} multi />}
        {tab === "hash"       && (
          <>
            <KVRow k="sha256"           v={proc.sha256} multi />
            <KVRow k="signer"           v={proc.signer} />
            <KVRow k="signature_status" v={proc.signature_status} />
            <KVRow k="integrity_level"  v={proc.integrity_level} />
          </>
        )}
        {tab === "network"    && (
          proc.network_connections?.length ? (
            proc.network_connections.map((n, i) => (
              <div key={i} style={rowLine} data-testid={`xdr-proc-net-${i}`}>
                <span style={{ color: "var(--cyan)" }}>
                  {n.direction || "?"} · {n.destination || n.dst_ip}:{n.dst_port ?? "?"}
                </span>
                <span style={{ color: "var(--faint)" }}>{n.protocol || "?"}</span>
              </div>
            ))
          ) : <Missing what="No network connections observed for this process" />
        )}
        {tab === "detections" && (
          proc.detections?.length ? proc.detections.map((d, i) => (
            <div key={i} style={rowLine} data-testid={`xdr-proc-det-${i}`}>
              <span style={{ color: "var(--amber)" }}>{d.rule_id || d.rule}</span>
              <span style={{ color: "var(--faint)" }}>
                weight {d.weight ?? "—"} · {d.detected_by || d.engine || "engine"}
              </span>
            </div>
          )) : <Missing what="No detections fired on this process" />
        )}
        {tab === "attck"      && (
          proc.techniques?.length ? proc.techniques.map((t) => (
            <div key={t} style={rowLine} data-testid={`xdr-proc-tech-${t}`}>
              <span style={{ color: "#f472b6" }}>{t}</span>
              <span style={{ color: "var(--faint)" }}>
                {TECHNIQUE_INDEX[t]?.name || "—"}
              </span>
            </div>
          )) : <Missing what="No ATT&CK techniques mapped for this process" />
        )}
        {tab === "evidence"   && (
          proc.evidence_refs?.length ? proc.evidence_refs.map((e, i) => (
            <div key={i} style={rowLine} data-testid={`xdr-proc-evid-${i}`}>
              <span style={{ color: "var(--faint)" }}>{e}</span>
            </div>
          )) : <Missing what="No evidence references for this process" />
        )}
      </div>
    </div>
  );
}


function OverviewTab({ proc }) {
  return (
    <>
      <KVRow k="image"          v={proc.image_path || proc.name} />
      <KVRow k="pid"            v={proc.pid} />
      <KVRow k="ppid"           v={proc.ppid} />
      <KVRow k="process_guid"   v={proc.process_guid} />
      <KVRow k="user"           v={proc.user} />
      <KVRow k="host"           v={proc.host} />
      <KVRow k="creation_time"  v={proc.first_seen} />
      <KVRow k="termination"    v={proc.last_seen} />
      <KVRow k="integrity"      v={proc.integrity_level} />
      <KVRow k="signer"         v={proc.signer} />
      <KVRow k="parent"         v={proc.parent_name
                                          ? `${proc.parent_name}${proc.ppid ? " · pid:" + proc.ppid : ""}`
                                          : (proc.ppid ? `pid:${proc.ppid}` : null)} />
    </>
  );
}


function KVRow({ k, v, multi }) {
  const missing = v === undefined || v === null || v === "";
  return (
    <div style={{ display: "flex", gap: 6, padding: "2px 0",
                            alignItems: multi ? "flex-start" : "center" }}
                data-testid={`xdr-kv-${k}`}>
      <span style={{ minWidth: 130, fontSize: 9.5, color: "var(--faint)",
                              textTransform: "uppercase", letterSpacing: ".3px",
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


function Missing({ what }) {
  return (
    <div style={{ color: "var(--faint)", fontStyle: "italic",
                            fontSize: 10.5 }}>
      {what} — never fabricated.
    </div>
  );
}


// ── Canonical process evidence extractor ──────────────────────────
// Consumes the incident payload (same source Evidence Trajectory
// uses).  Adds enrichment from /api/edr/process-tree when available.
function buildCanonicalTree(incident, enrichment) {
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
        network_connections: [],
        detections: [],
        techniques: [],
        evidence_refs: [],
        badges: [],
      };
      byKey.set(key, existing);
    } else {
      // Deterministic merge: keep first non-null value
      for (const k of Object.keys(existing)) {
        if (existing[k] == null && rec[k] != null) existing[k] = rec[k];
      }
    }
    return existing;
  };

  // 1 · Extract processes from evidence rows
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
    // Attach evidence + rule + technique to this process
    if (ev.rule_id) {
      node.detections.push({ rule_id: ev.rule_id,
                                          weight: ev.weight,
                                          detected_by: ev.detected_by || ev.engine });
      const tech = ev.technique_id || RULE_TO_TECHNIQUE[String(ev.rule_id).toUpperCase()];
      if (tech && !node.techniques.includes(tech))
        node.techniques.push(tech);
    }
    if (ev.evidence_ref?.rule_id || ev.id)
      node.evidence_refs.push(ev.evidence_ref?.rule_id || ev.id);
  }

  // 2 · Optional enrichment from /api/edr/process-tree
  const enrichedNodes = enrichment?.nodes || [];
  for (const en of enrichedNodes) {
    const node = upsert({
      name: en.process,
      pid: en.entity_id?.startsWith("pid:")
                ? Number(en.entity_id.slice(4))
                : (Number(String(en.entity_id).match(/\d+/)?.[0] || 0) || null),
      command_line: en.command_line,
      image_path: en.path,
      user: en.user, host: en.host,
      first_seen: en.first_seen, last_seen: en.last_seen,
    });
    // Wire parent from enrichment (deterministic parent_id from adapter)
    if (en.parent_id) node.parent_id = `proc:${en.parent_id}`;
    if (en.event_ids?.length) {
      for (const eid of en.event_ids) {
        if (!node.evidence_refs.includes(eid)) node.evidence_refs.push(eid);
      }
    }
  }

  // 3 · Compute parent_id by ppid matching within the incident scope
  const byPid = new Map();
  for (const n of byKey.values()) {
    if (n.pid != null) byPid.set(String(n.pid), n);
  }
  for (const n of byKey.values()) {
    if (!n.parent_id && n.ppid != null && byPid.has(String(n.ppid))) {
      n.parent_id = byPid.get(String(n.ppid)).id;
    }
  }
  // 4 · Wire child_ids
  for (const n of byKey.values()) {
    if (n.parent_id) {
      const parent = byKey.get(n.parent_id);
      if (parent && !parent.child_ids.includes(n.id))
        parent.child_ids.push(n.id);
    }
  }

  // 5 · Behavioral analytics — SUSPICIOUS badge for rare parent-child
  for (const n of byKey.values()) {
    const badges = new Set();
    badges.add("OBSERVED");
    if (n.detections.length) badges.add("DETECTED");
    // rare parent-child
    if (n.parent_id) {
      const parent = byKey.get(n.parent_id);
      if (parent) {
        for (const rule of SUSPICIOUS_RULES) {
          if (rule.parent.test(parent.name) && rule.child.test(n.name)) {
            badges.add("SUSPICIOUS");
            break;
          }
        }
      }
    } else if (n.parent_name) {
      for (const rule of SUSPICIOUS_RULES) {
        if (rule.parent.test(n.parent_name) && rule.child.test(n.name)) {
          badges.add("SUSPICIOUS");
          break;
        }
      }
    }
    n.badges = Array.from(badges);
  }

  const nodes = Array.from(byKey.values());
  // 6 · Determine roots — honest "unknown parent" root when parent
  //     evidence is missing.  NEVER fabricate.
  const roots = nodes
    .filter((n) => !n.parent_id)
    .map((n) => n.id);

  const procById = Object.fromEntries(nodes.map((n) => [n.id, n]));
  return { nodes, roots, procById };
}


// ── styles ────────────────────────────────────────────────────────
const header = {
  display: "flex", alignItems: "center", justifyContent: "space-between",
  marginBottom: 8, padding: "0 4px",
};
const grid = {
  display: "grid", gridTemplateColumns: "1.4fr 1fr", gap: 10,
  border: "1px solid var(--border)", borderRadius: 3,
  background: "var(--panel)",
};
const leftCol = {
  borderRight: "1px solid var(--border)", padding: "8px 0", minWidth: 0,
};
const rightCol = { padding: 0, minHeight: 200 };
const branchRow = {
  display: "flex", gap: 5, alignItems: "center",
  padding: "3px 6px", cursor: "pointer",
  fontFamily: "var(--mono)", fontSize: 11,
  borderRadius: 2,
};
const toggleBtn = {
  background: "none", border: "none", color: "var(--faint)",
  cursor: "pointer", padding: 0, width: 14,
  display: "inline-flex", alignItems: "center",
};
const badgeChip = {
  padding: "0 5px", fontSize: 8.5, fontFamily: "var(--mono)",
  fontWeight: 700, border: "1px solid", borderRadius: 2,
  letterSpacing: ".3px",
};
const inputStyle = {
  flex: 1, padding: "3px 6px", background: "var(--panel2)",
  border: "1px solid var(--border)", color: "var(--text)",
  fontSize: 10.5, borderRadius: 2, fontFamily: "var(--mono)",
};
const pillBtn = {
  padding: "2px 6px", fontSize: 9.5, fontFamily: "var(--mono)",
  fontWeight: 700, border: "1px solid",
  borderRadius: 2, background: "var(--panel2)", cursor: "pointer",
  display: "inline-flex", alignItems: "center", gap: 3,
};
const emptyBox = {
  padding: "10px 12px", fontSize: 11, fontFamily: "var(--mono)",
  color: "var(--faint)", border: "1px dashed var(--border)",
  borderRadius: 3, display: "flex", alignItems: "center",
};
const rowLine = {
  display: "flex", justifyContent: "space-between", gap: 8,
  padding: "3px 0", borderBottom: "1px dashed var(--border)",
};
