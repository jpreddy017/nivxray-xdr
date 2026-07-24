/**
 * EvidenceCard — the ONE drill-down component. Same look and same data
 * whether the analyst clicked an event on Trajectory, a sentence on Story,
 * a node on Process Tree, a node on Evidence Graph, or a technique on ATT&CK.
 *
 * Reads the current selection from `SelectionContext` and looks up the
 * matching IKG node from the Investigation model already loaded by the
 * workspace shell.
 *
 * Rendered as a floating right-rail overlay when selection is non-null.
 */
import { useMemo } from "react";
import { useNavigate, useParams, useSearchParams } from "react-router-dom";
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


export default function EvidenceCard({ inv }) {
  const { selection, clearSelection, setSelection } = useSelection();
  const navigate = useNavigate();
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
      // find its executed_by process
      const eb = edges.find(e => e.type === "executed_by" && e.source === selection.frame_iid);
      if (eb) processNode = nodeById[eb.target] || null;
    } else if (selection.kind === "process" && selection.process_iid) {
      processNode = nodeById[selection.process_iid] || null;
    }
    return { eventNode, processNode };
  }, [selection, nodeById, edges]);

  // IKB lookup — HAS to be called before any early return (rules of hooks).
  const kbEntry = useMemo(() => {
    const pn = view?.processNode;
    if (!pn) return null;
    const label = String(pn.label || "").toLowerCase();
    for (const e of (inv?.ikb?.entries || [])) {
      if (e.kind === "windows_binary" && e.label?.toLowerCase() === label) return e;
    }
    return null;
  }, [view, inv]);

  if (!selection || !view || (!view.eventNode && !view.processNode)) return null;

  const { eventNode, processNode } = view;
  const ev = eventNode?.attrs || {};
  const proc = processNode?.attrs || {};
  const procId = processNode?.id;

  // Parent process
  const parentEdge = procId && edges.find(e => e.type === "spawned" && e.target === procId);
  const parentNode = parentEdge ? nodeById[parentEdge.source] : null;

  // Children of this process (spawn out-edges)
  const childEdges = procId
    ? edges.filter(e => e.type === "spawned" && e.source === procId).slice(0, 6)
    : [];

  // Related MITRE techniques on this event
  const techniques = eventNode
    ? edges.filter(e => e.type === "maps_to" && e.source === eventNode.id)
             .map(e => nodeById[e.target]).filter(Boolean).slice(0, 6)
    : [];

  // Related file/network/registry from this process
  const relByType = (edgeType) =>
    procId ? edges.filter(e => e.source === procId && e.type === edgeType)
                    .map(e => nodeById[e.target]).filter(Boolean).slice(0, 4) : [];
  const createdFiles = relByType("created");
  const modified    = relByType("modified");
  const contactedNet = relByType("contacted");

  // Verdict — the aggregate verdict node for this process (if any)
  const processVerdictNode = procId
    ? nodes.find(n => n.type === "verdict"
                   && n.attrs?.layer === "process"
                   && edges.some(e => e.type === "contributes_to"
                                   && e.source === n.id && e.target === procId))
    : null;

  const jumpTo = (tab, frameIid) => {
    const p = new URLSearchParams(searchParams);
    p.set("tab", tab);
    if (frameIid) p.set("focus", frameIid);
    else p.delete("focus");
    setSearchParams(p, { replace: false });
  };

  return (
    <div data-testid="evidence-card"
         className="fixed right-0 top-16 bottom-14 z-40 flex flex-col"
         style={{ width: 380, background: T.paper,
                  borderLeft: `1px solid ${T.line}`,
                  boxShadow: "0 0 24px rgba(0,0,0,0.5)" }}>
      {/* Header */}
      <div className="flex items-center justify-between px-3 py-2 border-b"
           style={{ borderColor: T.line }}>
        <div className="flex flex-col min-w-0">
          <span className="text-[9px] tracking-[1.5px] font-bold"
                style={{ color: T.inkMute }}>EVIDENCE · {selection.source || "current"}</span>
          <span className="text-[12px] font-mono font-bold truncate"
                style={{ color: T.ink }}
                title={eventNode?.label || processNode?.label}>
            {eventNode?.label || processNode?.label || "—"}
          </span>
        </div>
        <button onClick={clearSelection}
                data-testid="ec-close"
                className="text-[11px] px-2 py-1 rounded hover:bg-white/5"
                style={{ color: T.inkMute }}>
          ✕
        </button>
      </div>

      {/* Body — scrolls */}
      <div className="flex-1 overflow-y-auto p-3">
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
              <Row label="Registry"
                   value={modified.map(m => m.label).join(", ")} />
            )}
            {contactedNet.length > 0 && (
              <Row label="Network"
                   value={contactedNet.map(n => n.label).join(", ")} />
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

        {processVerdictNode && (
          <Section label="Verdict">
            <Row label="Layer"      value={processVerdictNode.attrs?.layer} />
            <Row label="Score"      value={processVerdictNode.attrs?.score} />
            <Row label="Band"
                 value={String(processVerdictNode.attrs?.band).toUpperCase()} />
            <Row label="Confidence"
                 value={`${processVerdictNode.attrs?.confidence}%`} />
            {processVerdictNode.attrs?.explanation && (
              <Row label="Explanation"
                   value={processVerdictNode.attrs.explanation} mono={false} />
            )}
          </Section>
        )}

        {kbEntry && (
          <Section label="Knowledge Base">
            <Row label="Category"    value={kbEntry.category}    mono={false} />
            <Row label="Description" value={kbEntry.description} mono={false} />
            {kbEntry.common_abuse?.length > 0 && (
              <div className="mt-2">
                <div className="text-[9px] tracking-[1.2px] font-bold mb-1"
                     style={{ color: T.inkMute }}>KNOWN ABUSE PATTERNS</div>
                <div className="space-y-1">
                  {kbEntry.common_abuse.slice(0, 4).map((a, i) => (
                    <div key={i} className="text-[10px]" style={{ color: T.inkDim }}
                         data-testid={`ec-kb-abuse-${i}`}>
                      <span className="font-mono font-bold"
                            style={{ color: a.severity === "critical" ? "#F87171"
                                          : a.severity === "high"     ? "#F5A34C"
                                                                       : "#D4C069" }}>
                        [{a.severity}]
                      </span>{" "}
                      <span style={{ color: T.ink }}>{a.pattern}</span>
                      {a.reason && (
                        <span style={{ color: T.inkFaint }}> — {a.reason}</span>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
            {kbEntry.detection_guidance?.length > 0 && (
              <div className="mt-2">
                <div className="text-[9px] tracking-[1.2px] font-bold mb-1"
                     style={{ color: T.inkMute }}>DETECTION GUIDANCE</div>
                {kbEntry.detection_guidance.slice(0, 3).map((g, i) => (
                  <div key={i} className="text-[10px]" style={{ color: T.inkDim }}>
                    · {g}
                  </div>
                ))}
              </div>
            )}
            {kbEntry.references?.length > 0 && (
              <div className="mt-2 text-[9px] font-mono"
                   style={{ color: T.inkFaint }}>
                {kbEntry.references.length} reference(s) · IKB v1
              </div>
            )}
          </Section>
        )}
      </div>

      {/* Jump-to footer */}
      <div className="border-t p-2 flex items-center gap-1 flex-wrap"
           style={{ borderColor: T.line }}
           data-testid="ec-jump-bar">
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
    </div>
  );
}
