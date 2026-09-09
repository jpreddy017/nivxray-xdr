/**
 * EvidenceCard — the ONE drill-down component. Same look and same data
 * whether the analyst clicked an event on Trajectory, a sentence on Story,
 * a node on Process Tree, a node on Evidence Graph, or a technique on ATT&CK.
 *
 * v2 (Phase 4.3 · UX Polish sprint):
 *   · Always visible on the right rail.
 *   · When no event is selected → renders a rich CASE OVERVIEW
 *     (verdict + attack story + counters + MITRE + recommendation) so
 *     the panel is never blank.
 *   · When an event/process is selected → renders the drill-down
 *     evidence view (previous behaviour, preserved).
 *   · Working download buttons (JSON · Markdown · STIX 2.1).
 *   · Fully scrollable body — content never disappears.
 */
import { useMemo, useCallback } from "react";
import { useNavigate, useParams, useSearchParams } from "react-router-dom";
import { toast } from "sonner";
import { T } from "../theme";
import { useSelection } from "./SelectionContext";

const BAND_TONES = {
  benign: "#4ADE80", informational: "#7DB1D6", low: "#D4C069",
  suspicious: "#F5A34C", malicious: "#F87171", critical: "#FCA5A5",
};

// ─── MITRE technique ID → human-readable name (analyst-friendly).
// The engine emits IDs; analysts read this dictionary.
const TECHNIQUE_NAMES = {
  T1003:     "OS Credential Dumping",
  "T1003.001":"LSASS Memory",
  T1021:     "Remote Services",
  "T1021.002":"SMB / Admin Shares",
  "T1021.006":"WinRM",
  T1027:     "Obfuscated Files or Information",
  T1041:     "Exfiltration Over C2",
  T1053:     "Scheduled Task/Job",
  "T1053.005":"Scheduled Task",
  T1059:     "Command and Scripting Interpreter",
  "T1059.001":"PowerShell",
  "T1059.003":"Windows Command Shell",
  "T1059.005":"Visual Basic",
  T1071:     "Application Layer Protocol",
  "T1071.001":"Web Protocols",
  T1082:     "System Information Discovery",
  T1105:     "Ingress Tool Transfer",
  T1140:     "Deobfuscate/Decode Files",
  T1197:     "BITS Jobs",
  T1218:     "Signed Binary Proxy Execution",
  "T1218.005":"Mshta",
  "T1218.007":"Msiexec",
  "T1218.010":"Regsvr32",
  "T1218.011":"Rundll32",
  T1486:     "Data Encrypted for Impact",
  T1490:     "Inhibit System Recovery",
  T1543:     "Create or Modify System Process",
  "T1543.003":"Windows Service",
  T1547:     "Boot or Logon Autostart Execution",
  "T1547.001":"Registry Run Keys / Startup Folder",
  "T1547.004":"Winlogon Helper DLL",
  T1562:     "Impair Defenses",
  "T1562.001":"Disable or Modify Tools",
};

const techName = (id) => TECHNIQUE_NAMES[id] || TECHNIQUE_NAMES[String(id).split(".",1)[0]] || "";

// Any label starting with `ent_`, `proc_`, `evt_`, `net_`, `file_`, `reg_`
// is an internal graph iid → never surface it. Fallback = the type label.
const _INTERNAL_ID_RE = /^(ent|proc|evt|net|file|reg|cmd|user|dev)_[0-9a-f]{4,}/i;
const readableName = (label, fallback = "process") =>
  (!label || _INTERNAL_ID_RE.test(String(label))) ? fallback : String(label);

function Row({ label, value, mono = true }) {
  if (value === null || value === undefined || value === "") return null;
  return (
    <div className="flex items-baseline gap-3 text-[11px] py-0.5"
         data-testid={`ec-row-${label.toLowerCase().replace(/\s+/g, "-")}`}>
      <span className="text-[9px] tracking-[1.2px] font-bold"
            style={{ color: T.inkMute, minWidth: 100 }}>{label}</span>
      <span className={"flex-1 min-w-0 truncate " + (mono ? "font-mono" : "")}
            style={{ color: T.ink }} title={String(value)}>
        {String(value)}
      </span>
    </div>
  );
}

function Section({ label, children }) {
  return (
    <div className="pt-2.5" data-testid={`ec-section-${label.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`}>
      <div className="text-[9px] tracking-[1.5px] font-bold mb-1 pb-1 border-b"
           style={{ color: T.inkMute, borderColor: T.line }}>{label}</div>
      {children}
    </div>
  );
}

// Kill-chain order — the visual progress bar walks these left → right.
const KILL_CHAIN = [
  { key: "initial_access",    short: "Initial Access" },
  { key: "execution",         short: "Execution" },
  { key: "persistence",       short: "Persistence" },
  { key: "defense_evasion",   short: "Defense Evasion" },
  { key: "credential_access", short: "Credential Access" },
  { key: "discovery",         short: "Discovery" },
  { key: "lateral_movement",  short: "Lateral Movement" },
  { key: "c2",                short: "C2" },
  { key: "impact",            short: "Impact" },
];

// Human-friendly label for the "current stage" indicator on the Case Status.
function currentStage(summary) {
  const observed = KILL_CHAIN.filter(k => summary[k.key]);
  return observed.length ? observed[observed.length - 1].short : "Reconnaissance";
}

function AttackProgress({ summary }) {
  const observed = new Set(KILL_CHAIN.filter(k => summary[k.key]).map(k => k.key));
  const pct = Math.round((observed.size / KILL_CHAIN.length) * 100);
  return (
    <div data-testid="attack-progress">
      <div className="flex items-center justify-between mb-1">
        <span className="text-[9px] tracking-[1.5px] font-bold"
              style={{ color: T.inkMute }}>ATTACK PROGRESS</span>
        <span className="text-[10px] font-mono font-bold"
              style={{ color: T.ink }}>{observed.size}/{KILL_CHAIN.length} · {pct}%</span>
      </div>
      <div className="flex gap-0.5 mb-2">
        {KILL_CHAIN.map(k => (
          <div key={k.key}
               data-testid={`ap-cell-${k.key}`}
               title={`${k.short} · ${observed.has(k.key) ? "OBSERVED" : "not observed"}`}
               className="flex-1 h-2 rounded-sm"
               style={{ background: observed.has(k.key)
                                    ? "#F87171"
                                    : "rgba(255,255,255,0.06)" }} />
        ))}
      </div>
      <div className="grid grid-cols-3 gap-x-2 gap-y-0.5">
        {KILL_CHAIN.map(k => {
          const hit = observed.has(k.key);
          return (
            <div key={k.key} className="flex items-center gap-1 text-[10px] font-mono">
              <span style={{ color: hit ? "#F87171" : T.inkFaint }}>
                {hit ? "✔" : "·"}
              </span>
              <span style={{ color: hit ? T.ink : T.inkMute }}>
                {k.short}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}


// ─── Case Overview (empty-selection default) ──────────────────────
function CaseOverview({ inv, caseId, onDownload, onTacticSelect }) {
  const h = inv?.header || {};
  const band = h.verdict_band || "benign";
  const tone = BAND_TONES[band] || BAND_TONES.benign;
  const story = (inv?.story || []).slice(0, 10);
  const ikg = inv?.ikg || {};
  const counts = useMemo(() => {
    const nodes = ikg.nodes || [];
    return {
      processes: nodes.filter(n => n.type === "process").length,
      files:     nodes.filter(n => n.type === "file").length,
      registry:  nodes.filter(n => n.type === "registry").length,
      network:   nodes.filter(n => n.type === "network").length,
      techniques:nodes.filter(n => n.type === "technique").length,
      evidence:  nodes.filter(n => ["file","registry","network"].includes(n.type)).length,
    };
  }, [ikg]);

  // Unique tactics on the device verdict
  const tactics = useMemo(() => {
    const dev = inv?.verdicts?.device || {};
    return Array.from(new Set(dev.mitre_tactics || h.mitre_tactics || []));
  }, [inv, h]);

  // ── Executive summary attribution (each phase → binary+technique) ──
  const summary = useMemo(() => extractExecutiveSummary(inv), [inv]);

  // "Investigation Complete" heuristic — presence of core artefacts.
  const investComplete = useMemo(() => {
    let hit = 0, total = 5;
    if ((h.event_count || 0) > 0)        hit++;
    if (counts.processes > 0)            hit++;
    if (counts.techniques > 0)           hit++;
    if (story.length > 0)                hit++;
    if (h.confidence != null)            hit++;
    return Math.round(hit / total * 100);
  }, [h, counts, story]);

  const recommendation = useMemo(() => {
    if (band === "critical" || band === "malicious") {
      return "Immediately isolate the affected endpoint(s). Preserve volatile memory. Reset credentials for every user active on the host. Escalate to IR on-call.";
    }
    if (band === "suspicious") {
      return "Investigate the highlighted process chain and network artefacts. Confirm whether the parent-child relationship is authorised.";
    }
    if (band === "low" || band === "informational") {
      return "No immediate action required. Retain the evidence for baselining and trend analysis.";
    }
    return "No malicious activity observed. Case may be closed after standard analyst review.";
  }, [band]);

  const stage = currentStage(summary);

  return (
    <>
      {/* Case Status — the "dashboard within the case". */}
      <div className="rounded-md px-3 py-2.5 mb-1"
           style={{ background: T.paper2, border: `1px solid ${T.line}` }}
           data-testid="ec-case-status">
        <div className="text-[9px] tracking-[1.5px] font-bold mb-1.5"
             style={{ color: T.inkMute }}>CASE STATUS</div>
        <div className="grid grid-cols-2 gap-y-0.5">
          <Row label="Risk"          value={String(band).toUpperCase()} />
          <Row label="Confidence"    value={h.confidence != null ? `${h.confidence}%` : "—"} />
          <Row label="Stage"         value={stage} />
          <Row label="Duration"      value={summary.duration || "—"} />
          <Row label="Techniques"    value={counts.techniques} />
          <Row label="Processes"     value={counts.processes} />
          <Row label="Evidence"      value={counts.evidence} />
          <Row label="Investigation" value={`${investComplete}%`} />
        </div>
      </div>

      <Section label="Attack Progress">
        <AttackProgress summary={summary} />
      </Section>

      <Section label="Executive Summary">
        {KILL_CHAIN.map(({ key, short }) => {
          const val = summary[key];
          const observed = Boolean(val);
          return (
            <button key={key}
                    data-testid={`ec-exec-${key}`}
                    onClick={() => observed && onTacticSelect(key, val)}
                    disabled={!observed}
                    className="w-full text-left flex items-baseline gap-3 text-[11px] py-1 rounded transition-colors"
                    style={{
                      background: "transparent",
                      cursor: observed ? "pointer" : "default",
                      opacity: observed ? 1 : 0.55,
                    }}>
              <span className="text-[9px] tracking-[1.2px] font-bold"
                    style={{ color: observed ? "#F87171" : T.inkMute, minWidth: 100 }}>
                {short}
              </span>
              <span className="flex-1 min-w-0 font-mono truncate"
                    style={{ color: observed ? T.ink : T.inkFaint }}
                    title={observed ? val : "Not Observed"}>
                {observed ? val : "Not Observed"}
              </span>
            </button>
          );
        })}
      </Section>

      {story.length > 0 && (
        <Section label="Attack Story">
          <div className="space-y-1.5 mt-1">
            {story.map((s, i) => (
              <div key={i} data-testid={`ec-story-${i}`}
                   className="text-[11px] leading-snug"
                   style={{ color: T.inkDim }}>
                <span className="font-mono text-[10px] mr-2"
                      style={{ color: tone }}>›</span>
                {readableStorySentence(s.text || s.sentence || "")}
              </div>
            ))}
          </div>
        </Section>
      )}

      {tactics.length > 0 && (
        <Section label="MITRE Tactics">
          <div className="flex flex-wrap gap-1 mt-1">
            {tactics.map(t => (
              <span key={t}
                    data-testid={`ec-tactic-${t}`}
                    className="text-[10px] font-mono px-1.5 py-0.5 rounded"
                    style={{ background: T.paper2, color: T.ink,
                             border: `1px solid ${T.line}` }}>
                {String(t).replace(/_/g, " ")}
              </span>
            ))}
          </div>
        </Section>
      )}

      <Section label="Recommendation">
        <div className="text-[11px] leading-relaxed pt-1"
             style={{ color: T.ink }} data-testid="ec-recommendation">
          {recommendation}
        </div>
      </Section>

      <Section label="Download">
        <div className="flex flex-wrap gap-1.5 mt-1">
          {["json", "markdown", "stix"].map(fmt => (
            <button key={fmt}
                    data-testid={`ec-download-${fmt}`}
                    onClick={() => onDownload(fmt)}
                    className="text-[10px] px-2 py-1 rounded font-mono uppercase transition-colors"
                    style={{ background: T.paper2, color: T.ink,
                             border: `1px solid ${T.line}` }}>
              {fmt}
            </button>
          ))}
        </div>
        <div className="text-[9px] mt-1 font-mono" style={{ color: T.inkFaint }}>
          Report is generated deterministically from the IKG.
        </div>
      </Section>
    </>
  );
}

// Replace `ent_process_a5fb…` and similar internal ids in any string.
function readableStorySentence(s) {
  return String(s).replace(/ent_process_[0-9a-f]+/gi, "process")
                  .replace(/ent_file_[0-9a-f]+/gi, "file")
                  .replace(/ent_network_[0-9a-f]+/gi, "endpoint")
                  .replace(/ent_registry_[0-9a-f]+/gi, "registry key")
                  .replace(/proc_[0-9a-f]+/gi, "process")
                  .replace(/evt_[0-9a-f]+/gi, "event");
}

// ─── Deterministic attribution of each ATT&CK tactic to the process
// that fired it. Powers the "understand the case in 10 seconds" panel.
function extractExecutiveSummary(inv) {
  const out = {
    duration: "", initial_access: "", execution: "", persistence: "",
    credential_access: "", defense_evasion: "", c2: "", impact: "",
  };
  if (!inv) return out;
  const nodes = inv?.ikg?.nodes || [];
  const edges = inv?.ikg?.edges || [];
  const nodeById = Object.fromEntries(nodes.map(n => [n.id, n]));

  // Duration
  const times = nodes.map(n => n.attrs?.first_seen)
                     .filter(Boolean).map(t => new Date(t).getTime())
                     .filter(t => !Number.isNaN(t));
  if (times.length >= 2) {
    const min = Math.min(...times), max = Math.max(...times);
    const ms = max - min;
    if (ms < 60_000)          out.duration = `${Math.round(ms / 1000)} s`;
    else if (ms < 3600_000)   out.duration = `${Math.round(ms / 60_000)} min`;
    else                       out.duration = `${(ms / 3600_000).toFixed(1)} h`;
  }

  // Index technique nodes by their technique_id so we can find the
  // process that fired each one via: technique ← maps_to ← event → executed_by → process
  const techIdToProc = new Map();       // "T1059" → Set(process labels)
  const techIdToId   = new Map();       // "T1059" → node.id  (for edge lookup)
  for (const n of nodes) {
    if (n.type !== "technique") continue;
    const tid = n.attrs?.technique_id || n.label;
    if (!tid) continue;
    techIdToId.set(tid, n.id);
    techIdToProc.set(tid, new Set());
  }
  for (const e of edges) {
    if (e.type !== "maps_to") continue;
    const tech = nodeById[e.target];
    if (!tech || tech.type !== "technique") continue;
    const tid = tech.attrs?.technique_id || tech.label;
    if (!tid) continue;
    const eb = edges.find(x => x.type === "executed_by" && x.source === e.source);
    const proc = eb ? nodeById[eb.target] : null;
    const label = proc?.label || "";
    if (label) techIdToProc.get(tid)?.add(label);
  }

  // Use the device verdict's tactic_coverage as the ground truth for
  // which techniques belong to which tactic.
  const cov = inv?.verdicts?.device?.tactic_coverage || {};
  const pickTactic = (...names) => {
    for (const n of names) {
      const rec = cov[n];
      if (!rec) continue;
      const techs = (rec.techniques || []).slice(0, 3);
      if (!techs.length) continue;
      const parts = [];
      for (const t of techs) {
        // Accept both bare id ("T1059") and sub ("T1059.001")
        const procs = Array.from(techIdToProc.get(t) || []).map(p => readableName(p, ""));
        const cleaned = procs.filter(Boolean);
        // Fall back to bases if no exact match
        if (!cleaned.length) {
          const base = t.split(".", 1)[0];
          for (const [k, v] of techIdToProc.entries()) {
            if (k === base) cleaned.push(...Array.from(v).map(p => readableName(p, "")).filter(Boolean));
          }
        }
        const tn = techName(t);
        const label = tn ? `${tn} (${t})` : t;
        parts.push(cleaned.length ? `${cleaned[0]} → ${label}` : label);
      }
      return Array.from(new Set(parts)).slice(0, 2).join(" · ");
    }
    return "";
  };
  out.initial_access    = pickTactic("initial_access", "initial-access");
  out.execution         = pickTactic("execution");
  out.persistence       = pickTactic("persistence");
  out.credential_access = pickTactic("credential_access", "credential-access");
  out.defense_evasion   = pickTactic("defense_evasion", "defense-evasion");
  out.c2                = pickTactic("command_and_control", "command-and-control", "c2");
  out.impact            = pickTactic("impact");
  return out;
}

// ═════════════════════════════════════════════════════════════════════
// Main component
// ═════════════════════════════════════════════════════════════════════
export default function EvidenceCard({ inv }) {
  const { selection, clearSelection } = useSelection();
  const { caseId } = useParams();
  const [searchParams, setSearchParams] = useSearchParams();

  const nodes = inv?.ikg?.nodes || [];
  const edges = inv?.ikg?.edges || [];
  const nodeById = useMemo(() => {
    const m = {}; nodes.forEach(n => (m[n.id] = n)); return m;
  }, [nodes]);

  // Resolve current selection → an event node OR a process node.
  const view = useMemo(() => {
    if (!selection) return null;
    let eventNode = null, processNode = null;
    if (selection.kind === "event" && selection.frame_iid) {
      eventNode = nodeById[selection.frame_iid] || null;
      const eb = edges.find(e => e.type === "executed_by" && e.source === selection.frame_iid);
      if (eb) processNode = nodeById[eb.target] || null;
    } else if (selection.kind === "process" && selection.process_iid) {
      processNode = nodeById[selection.process_iid] || null;
    }
    return { eventNode, processNode };
  }, [selection, nodeById, edges]);

  // IKB lookup for the selected process
  const kbEntry = useMemo(() => {
    const pn = view?.processNode;
    if (!pn) return null;
    const label = String(pn.label || "").toLowerCase();
    for (const e of (inv?.ikb?.entries || [])) {
      if (e.kind === "windows_binary" && e.label?.toLowerCase() === label) return e;
    }
    return null;
  }, [view, inv]);

  // ─── Download handler — Case Overview and drill-down share this. ───
  const download = useCallback((fmt) => {
    if (!inv) { toast.error("Investigation not loaded"); return; }
    const filename = `nivxray-${caseId}-${fmt === "markdown" ? "report.md"
                                        : fmt === "stix"     ? "stix.json"
                                                              : "investigation.json"}`;
    let payload = "";
    let mime = "application/json";
    try {
      if (fmt === "json") {
        payload = JSON.stringify(inv, null, 2);
      } else if (fmt === "markdown") {
        payload = renderMarkdown(inv, caseId);
        mime = "text/markdown";
      } else if (fmt === "stix") {
        payload = JSON.stringify(renderStix(inv, caseId), null, 2);
      }
      const blob = new Blob([payload], { type: mime });
      const url = URL.createObjectURL(blob);
      const a = Object.assign(document.createElement("a"),
                              { href: url, download: filename });
      document.body.appendChild(a); a.click(); a.remove();
      URL.revokeObjectURL(url);
      toast.success(`Downloaded ${filename}`);
    } catch (ex) {
      toast.error("Download failed", { description: String(ex) });
    }
  }, [inv, caseId]);

  const jumpTo = (tab, frameIid) => {
    const p = new URLSearchParams(searchParams);
    p.set("tab", tab);
    if (frameIid) p.set("focus", frameIid);
    else p.delete("focus");
    setSearchParams(p, { replace: false });
  };

  // Body content — either Case Overview (empty state) OR drill-down.
  const showOverview = !view || (!view.eventNode && !view.processNode);
  const eventNode = view?.eventNode || null;
  const processNode = view?.processNode || null;
  const ev = eventNode?.attrs || {};
  const proc = processNode?.attrs || {};
  const procId = processNode?.id;

  const parentEdge = procId && edges.find(e => e.type === "spawned" && e.target === procId);
  const parentNode = parentEdge ? nodeById[parentEdge.source] : null;
  const childEdges = procId
    ? edges.filter(e => e.type === "spawned" && e.source === procId).slice(0, 6)
    : [];
  const techniques = eventNode
    ? edges.filter(e => e.type === "maps_to" && e.source === eventNode.id)
             .map(e => nodeById[e.target]).filter(Boolean).slice(0, 6)
    : [];
  const relByType = (t) =>
    procId ? edges.filter(e => e.source === procId && e.type === t)
                    .map(e => nodeById[e.target]).filter(Boolean).slice(0, 4) : [];
  const createdFiles = relByType("created");
  const modified     = relByType("modified");
  const contactedNet = relByType("contacted");

  // Executive-Summary click handler — jumps the workspace to Attack
  // Story with a `?tactic=` focus param so downstream tabs highlight.
  const onTacticSelect = useCallback((tactic /* , valStr */) => {
    const p = new URLSearchParams(searchParams);
    p.set("tab", "story");
    p.set("tactic", tactic);
    setSearchParams(p, { replace: false });
    toast.success(`Focused Attack Story on ${tactic.replace(/_/g," ")}`);
  }, [searchParams, setSearchParams]);

  return (
    <div data-testid="evidence-card"
         className="fixed right-0 top-[132px] bottom-14 z-40 flex flex-col"
         style={{ width: 380, background: T.paper,
                  borderLeft: `1px solid ${T.line}`,
                  boxShadow: "0 0 24px rgba(0,0,0,0.5)" }}>
      {/* Header */}
      <div className="flex items-center justify-between px-3 py-2 border-b"
           style={{ borderColor: T.line }}>
        <div className="flex flex-col min-w-0">
          <span className="text-[9px] tracking-[1.5px] font-bold"
                style={{ color: T.inkMute }}
                data-testid="ec-header-label">
            {showOverview
              ? "CASE OVERVIEW"
              : `EVIDENCE · ${selection?.source || "current"}`}
          </span>
          <span className="text-[12px] font-mono font-bold truncate"
                style={{ color: T.ink }}
                title={showOverview
                  ? (caseId || "—")
                  : (eventNode?.label || processNode?.label || "—")}>
            {showOverview
              ? (caseId || "—")
              : (eventNode?.label || processNode?.label || "—")}
          </span>
        </div>
        {!showOverview && (
          <button onClick={clearSelection}
                  data-testid="ec-close"
                  className="text-[11px] px-2 py-1 rounded hover:bg-white/5"
                  style={{ color: T.inkMute }}>✕</button>
        )}
      </div>

      {/* Body — scrolls independently */}
      <div className="flex-1 overflow-y-auto p-3" data-testid="ec-body">
        {showOverview ? (
          <CaseOverview inv={inv} caseId={caseId} onDownload={download}
                        onTacticSelect={onTacticSelect} />
        ) : (
          <>
            {eventNode && (
              <Section label="Event">
                <Row label="Timestamp"  value={ev.ts} />
                <Row label="Lane"       value={ev.lane} />
                <Row label="Action"     value={ev.action} />
                <Row label="Rule"       value={ev.rule_id} />
                <Row label="Frame IID"  value={eventNode.id} />
              </Section>
            )}
            {processNode && (
              <Section label="Process">
                <Row label="Image"      value={processNode.label} />
                <Row label="First seen" value={proc.first_seen} />
                <Row label="Lane"       value={proc.lane} />
                <Row label="Process IID" value={processNode.id} />
                {ev.cmdline && <Row label="Command" value={ev.cmdline} />}
              </Section>
            )}
            {(parentNode || childEdges.length > 0) && (
              <Section label="Relationships">
                {parentNode && <Row label="Parent" value={parentNode.label} />}
                {childEdges.length > 0 && (
                  <Row label="Children"
                       value={childEdges.map(e => nodeById[e.target]?.label)
                                        .filter(Boolean).join(", ")} />
                )}
                {createdFiles.length > 0 && (
                  <Row label="Files"
                       value={createdFiles.map(f => f.label).join(", ")} />
                )}
                {modified.length > 0 && (
                  <Row label="Registry" value={modified.map(m => m.label).join(", ")} />
                )}
                {contactedNet.length > 0 && (
                  <Row label="Network" value={contactedNet.map(n => n.label).join(", ")} />
                )}
              </Section>
            )}
            {techniques.length > 0 && (
              <Section label="MITRE ATT&CK">
                <div className="flex flex-wrap gap-1 mt-1">
                  {techniques.map(t => (
                    <span key={t.id}
                          data-testid={`ec-technique-${t.attrs?.technique_id}`}
                          className="text-[10px] font-mono px-1.5 py-0.5 rounded"
                          style={{ background: T.paper2, color: T.ink,
                                   border: `1px solid ${T.line}` }}>
                      {t.attrs?.technique_id || t.label}
                    </span>
                  ))}
                </div>
              </Section>
            )}
            {kbEntry && (
              <Section label="Knowledge Base">
                <Row label="Category"    value={kbEntry.category}    mono={false} />
                <Row label="Description" value={kbEntry.description} mono={false} />
              </Section>
            )}
          </>
        )}
      </div>

      {/* Footer — Jump-to bar in drill-down mode, download bar in overview */}
      {!showOverview && (
        <div className="border-t p-2 flex items-center gap-1 flex-wrap"
             style={{ borderColor: T.line }} data-testid="ec-jump-bar">
          <span className="text-[9px] tracking-[1.5px] font-bold mr-1"
                style={{ color: T.inkMute }}>JUMP TO</span>
          {["trajectory", "story", "graph", "process", "attack"].map(tab => (
            <button key={tab}
                    data-testid={`ec-jump-${tab}`}
                    onClick={() => jumpTo(tab, eventNode?.id)}
                    className="text-[10px] px-2 py-1 rounded font-mono hover:bg-white/5"
                    style={{ background: T.paper2, color: T.ink,
                             border: `1px solid ${T.line}` }}>
              {tab}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}


// ═════════════════════════════════════════════════════════════════════
// Report renderers (deterministic, IKG-driven — no LLM)
// ═════════════════════════════════════════════════════════════════════
function renderMarkdown(inv, caseId) {
  const h = inv?.header || {};
  const story = inv?.story || [];
  const dev = inv?.verdicts?.device || {};
  const lines = [];
  lines.push(`# NivXRay Investigation Report`);
  lines.push("");
  lines.push(`**Case:** \`${caseId}\``);
  lines.push(`**Severity:** ${String(h.verdict_band || "benign").toUpperCase()}`);
  lines.push(`**Device Risk:** ${h.device_score ?? "—"}`);
  lines.push(`**Incident Risk:** ${h.incident_score ?? "—"}`);
  lines.push(`**Confidence:** ${h.confidence != null ? `${h.confidence}%` : "—"}`);
  lines.push(`**Events:** ${h.event_count ?? "—"} · **Chains:** ${h.chain_count ?? "—"} · **Processes:** ${h.process_count ?? "—"}`);
  lines.push("");
  lines.push("## Executive Summary");
  lines.push(dev.explanation || "No summary available.");
  lines.push("");
  lines.push("## Attack Story");
  story.forEach(s => lines.push(`- ${s.text || s.sentence || ""}`));
  lines.push("");
  lines.push("## MITRE ATT&CK");
  const tactics = Array.from(new Set(dev.mitre_tactics || []));
  tactics.forEach(t => lines.push(`- ${t}`));
  lines.push("");
  lines.push("## Verdict Reasoning");
  const reasons = inv?.explainability?.positive?.reasons || [];
  reasons.forEach(r => lines.push(`- **${r.kind}** — ${r.text}${r.detail ? ` · _${r.detail}_` : ""}`));
  lines.push("");
  lines.push("---");
  lines.push(`Generated by NivXRay engine v${inv?.engine_version?.verdict || "3.1b"} · IKG v${inv?.engine_version?.ikg || "1.0"}`);
  return lines.join("\n");
}

function renderStix(inv, caseId) {
  const h = inv?.header || {};
  const dev = inv?.verdicts?.device || {};
  const now = new Date().toISOString();
  const objects = [];
  // Incident object
  objects.push({
    type: "incident", spec_version: "2.1",
    id: `incident--${caseId}`,
    created: now, modified: now,
    name: `NivXRay case ${caseId}`,
    description: dev.explanation || "",
    labels: [`severity:${h.verdict_band || "benign"}`,
             `device_score:${h.device_score ?? 0}`,
             `confidence:${h.confidence ?? 0}`],
  });
  // Attack-pattern objects for every MITRE technique
  const techs = Array.from(new Set((dev.mitre_tactics || []).map(String)));
  techs.forEach(t => {
    objects.push({
      type: "attack-pattern", spec_version: "2.1",
      id: `attack-pattern--${t.toLowerCase()}`,
      created: now, modified: now,
      name: t,
      external_references: [{ source_name: "mitre-attack", external_id: t }],
    });
  });
  return { type: "bundle", id: `bundle--${caseId}`, objects };
}
