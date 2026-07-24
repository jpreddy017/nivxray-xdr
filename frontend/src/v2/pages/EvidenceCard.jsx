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

// ─── Case Overview (empty-selection default) ──────────────────────
function CaseOverview({ inv, caseId, onDownload }) {
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
    };
  }, [ikg]);

  // Unique tactics on the device verdict (falls back to header.mitre_tactics)
  const tactics = useMemo(() => {
    const dev = inv?.verdicts?.device || {};
    return Array.from(new Set(dev.mitre_tactics || h.mitre_tactics || []));
  }, [inv, h]);

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

  return (
    <>
      <Section label="Case Overview">
        <Row label="Case"       value={caseId} />
        <Row label="Severity"   value={String(band).toUpperCase()} />
        <Row label="Device Risk" value={h.device_score ?? "—"} />
        <Row label="Incident"   value={h.incident_score ?? "—"} />
        <Row label="Confidence" value={h.confidence != null ? `${h.confidence}%` : "—"} />
        <Row label="Events"     value={h.event_count} />
        <Row label="Chains"     value={h.chain_count} />
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
                {s.text || s.sentence || ""}
              </div>
            ))}
          </div>
        </Section>
      )}

      <Section label="IKG Counts">
        <div className="grid grid-cols-2 gap-y-0.5">
          <Row label="Processes" value={counts.processes} />
          <Row label="Files"     value={counts.files} />
          <Row label="Registry"  value={counts.registry} />
          <Row label="Network"   value={counts.network} />
          <Row label="Techniques" value={counts.techniques} />
        </div>
      </Section>

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
          <CaseOverview inv={inv} caseId={caseId} onDownload={download} />
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
