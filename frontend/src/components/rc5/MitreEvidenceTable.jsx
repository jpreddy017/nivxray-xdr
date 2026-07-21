/**
 * RC5 · MITRE Evidence Table — dense, expandable rows revealing
 * evidence + Sigma/KQL/SPL detection snippets.
 *
 * Props:
 *   mitre: [{ technique_id, sub_technique_id, technique_name,
 *             behavior_tactic, base_confidence, evidence_node_ids?,
 *             detections? }]
 *   navigatorLayer?: {} (for the Open-in-Navigator button)
 */
import React, { useState } from "react";
import { ChevronRight, ExternalLink, Download, Compass } from "lucide-react";
import { toast } from "sonner";

function downloadJSON(obj, filename) {
  const blob = new Blob([JSON.stringify(obj, null, 2)],
                        { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 500);
}

function openInAttackNavigator(layer) {
  navigator.clipboard.writeText(JSON.stringify(layer, null, 2));
  toast.success("ATT&CK Navigator layer copied to clipboard", {
    description: "Paste as JSON in the Layer menu → Import from clipboard.",
  });
  window.open("https://mitre-attack.github.io/attack-navigator/",
              "_blank", "noopener,noreferrer");
}

export const MitreEvidenceTable = ({ mitre, navigatorLayer }) => {
  const [expanded, setExpanded] = useState(() => new Set());
  const toggle = (id) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  if (!mitre?.length) {
    return (
      <div className="text-xs text-slate-500 font-mono py-6 text-center
                      border border-dashed border-slate-800 rounded">
        No MITRE mappings yet.
      </div>
    );
  }

  return (
    <div className="border border-slate-800 rounded bg-slate-950 overflow-hidden"
         data-testid="mitre-evidence-table">
      <div className="flex items-center justify-between px-3 py-2 border-b border-slate-800 bg-slate-900">
        <div className="text-[10px] font-mono uppercase tracking-[0.12em] text-slate-400">
          MITRE ATT&CK · {mitre.length} technique{mitre.length === 1 ? "" : "s"}
        </div>
        <div className="flex gap-2">
          {navigatorLayer ? (
            <>
              <button
                type="button"
                onClick={() => downloadJSON(navigatorLayer, "nivxray-navigator.json")}
                className="text-[10px] font-mono uppercase tracking-wider px-2 py-1
                           border border-slate-700 rounded hover:bg-slate-800
                           transition-colors flex items-center gap-1"
                data-testid="download-navigator-json-btn"
              >
                <Download size={11} /> layer.json
              </button>
              <button
                type="button"
                onClick={() => openInAttackNavigator(navigatorLayer)}
                className="text-[10px] font-mono uppercase tracking-wider px-2 py-1
                           border border-sky-800 text-sky-300 rounded
                           hover:bg-sky-950/40 transition-colors flex items-center gap-1"
                data-testid="open-in-attack-navigator-btn"
              >
                <Compass size={11} /> ATT&CK Navigator
              </button>
            </>
          ) : null}
        </div>
      </div>
      <table className="w-full text-xs">
        <thead className="bg-slate-900/60 border-b border-slate-800">
          <tr className="text-[10px] font-mono uppercase tracking-wider text-slate-500">
            <th className="w-6"></th>
            <th className="text-left px-2 py-1.5">T-code</th>
            <th className="text-left px-2 py-1.5">Sub</th>
            <th className="text-left px-2 py-1.5">Technique</th>
            <th className="text-left px-2 py-1.5">Tactic</th>
            <th className="text-right px-2 py-1.5">Conf</th>
          </tr>
        </thead>
        <tbody>
          {mitre.map((t, i) => {
            const rowId = `${t.technique_id}-${i}`;
            const open = expanded.has(rowId);
            const detections = t.detections || {};
            return (
              <React.Fragment key={rowId}>
                <tr
                  className="border-b border-slate-800 hover:bg-slate-800/50
                             transition-colors duration-150 cursor-pointer"
                  onClick={() => toggle(rowId)}
                  tabIndex={0}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(rowId); }
                  }}
                  data-testid={`mitre-row-${t.technique_id}`}
                >
                  <td className="px-1">
                    <ChevronRight
                      size={12}
                      className={"transition-transform text-slate-500 " +
                                 (open ? "rotate-90" : "")}
                    />
                  </td>
                  <td className="px-2 py-1.5 font-mono text-sky-300 font-semibold">
                    {t.technique_id}
                  </td>
                  <td className="px-2 py-1.5 font-mono text-slate-400">
                    {t.sub_technique_id || "—"}
                  </td>
                  <td className="px-2 py-1.5 text-slate-200">
                    {t.technique_name}
                  </td>
                  <td className="px-2 py-1.5">
                    <span className="text-[10px] font-mono uppercase tracking-wider
                                     text-slate-400 border border-slate-700 rounded
                                     px-1.5 py-0.5">
                      {(t.behavior_tactic || "").replace(/_/g, " ")}
                    </span>
                  </td>
                  <td className="px-2 py-1.5 text-right font-mono text-slate-300">
                    {t.base_confidence ?? "—"}%
                  </td>
                </tr>
                {open ? (
                  <tr className="bg-slate-950">
                    <td colSpan={6} className="px-4 py-3 border-b border-slate-800">
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                        {["sigma", "kql", "spl", "aql"].map((eng) =>
                          detections[eng] ? (
                            <div key={eng} className="space-y-1">
                              <div className="text-[9px] font-mono uppercase tracking-wider
                                              text-slate-500">
                                {eng} detection
                              </div>
                              <pre className="text-[11px] font-mono text-emerald-300
                                              bg-slate-900 border border-slate-800
                                              rounded p-2 whitespace-pre-wrap break-all">
{detections[eng]}
                              </pre>
                            </div>
                          ) : null
                        )}
                        {t.data_sources?.length ? (
                          <div className="space-y-1">
                            <div className="text-[9px] font-mono uppercase tracking-wider
                                            text-slate-500">
                              data sources
                            </div>
                            <ul className="text-[11px] font-mono text-slate-400 space-y-0.5">
                              {t.data_sources.map((ds, k) => (
                                <li key={k}>· {ds}</li>
                              ))}
                            </ul>
                          </div>
                        ) : null}
                        {t.evidence_node_ids?.length ? (
                          <div className="space-y-1 md:col-span-3">
                            <div className="text-[9px] font-mono uppercase tracking-wider
                                            text-slate-500">
                              evidence node IDs
                            </div>
                            <div className="text-[11px] font-mono text-amber-300">
                              {t.evidence_node_ids.join(", ")}
                            </div>
                          </div>
                        ) : null}
                        <a
                          className="md:col-span-3 text-[11px] font-mono text-sky-400
                                     hover:text-sky-300 flex items-center gap-1 mt-1"
                          href={`https://attack.mitre.org/techniques/${
                            t.technique_id
                          }${t.sub_technique_id ? "/" + t.sub_technique_id.split(".")[1] : ""}/`}
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          <ExternalLink size={11} />
                          View on attack.mitre.org
                        </a>
                      </div>
                    </td>
                  </tr>
                ) : null}
              </React.Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
};

export default MitreEvidenceTable;
