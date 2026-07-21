/**
 * RC5 · Behavior Timeline — horizontal timeline grouped by tactic.
 *
 * Props:
 *   behaviors: [{ id, tactic, sub_kind, reconstructed, confidence, evidence_nodes }]
 */
import React from "react";

const TACTIC_STYLE = {
  execution:           { color: "#ef4444", label: "Execution" },
  persistence:         { color: "#a855f7", label: "Persistence" },
  defense_evasion:     { color: "#f59e0b", label: "Defense Evasion" },
  privilege_escalation:{ color: "#f97316", label: "Priv Esc" },
  command_and_control: { color: "#0ea5e9", label: "C2" },
  credential_access:   { color: "#e11d48", label: "Cred Access" },
  discovery:           { color: "#22d3ee", label: "Discovery" },
  collection:          { color: "#38bdf8", label: "Collection" },
  exfiltration:        { color: "#ec4899", label: "Exfil" },
  impact:              { color: "#f43f5e", label: "Impact" },
  lateral_movement:    { color: "#8b5cf6", label: "Lateral" },
  dns_query:           { color: "#0ea5e9", label: "DNS" },
  clipboard:           { color: "#94a3b8", label: "Clipboard" },
  named_pipe:          { color: "#94a3b8", label: "Named Pipe" },
  wmi_subscription:    { color: "#a855f7", label: "WMI Sub" },
};

const orderKeys = Object.keys(TACTIC_STYLE);

export const BehaviorTimeline = ({ behaviors }) => {
  if (!behaviors?.length) {
    return (
      <div className="text-xs text-slate-500 font-mono py-6 text-center border border-dashed border-slate-800 rounded">
        No behaviors extracted yet.
      </div>
    );
  }

  // Group by tactic + preserve insertion order per tactic.
  const grouped = {};
  behaviors.forEach((b) => {
    const t = typeof b.tactic === "string" ? b.tactic : b.tactic?.value || "unknown";
    (grouped[t] ||= []).push(b);
  });

  const orderedTactics = [
    ...orderKeys.filter((k) => grouped[k]),
    ...Object.keys(grouped).filter((k) => !orderKeys.includes(k)),
  ];

  return (
    <div className="border border-slate-800 rounded bg-slate-950 p-3 space-y-3"
         data-testid="behavior-timeline">
      {orderedTactics.map((tactic) => {
        const style = TACTIC_STYLE[tactic] || { color: "#64748b", label: tactic };
        const items = grouped[tactic];
        return (
          <div key={tactic} className="space-y-1">
            <div className="flex items-center gap-2">
              <span
                className="inline-block w-2 h-2 rounded-sm"
                style={{ backgroundColor: style.color }}
              />
              <span className="text-[10px] font-mono uppercase tracking-[0.12em] text-slate-400">
                {style.label}
              </span>
              <span className="text-[10px] font-mono text-slate-600">
                · {items.length} behavior{items.length === 1 ? "" : "s"}
              </span>
              <div className="flex-1 h-px bg-slate-800" />
            </div>
            <div className="flex flex-wrap gap-2 pl-4">
              {items.map((b, i) => (
                <div
                  key={b.id || `${tactic}-${i}`}
                  className="border-l-2 bg-slate-900 hover:bg-slate-800 transition-colors
                             duration-150 px-2 py-1 rounded-sm min-w-[220px] max-w-[340px]"
                  style={{ borderLeftColor: style.color }}
                  data-testid={`behavior-${b.id || `${tactic}-${i}`}`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[10px] font-mono uppercase tracking-wider text-slate-300">
                      {b.sub_kind || "—"}
                    </span>
                    <span className="text-[10px] font-mono text-slate-500">
                      {b.confidence ?? "?"}%
                    </span>
                  </div>
                  <div className="text-[11px] font-mono text-slate-400 truncate mt-0.5">
                    {b.reconstructed || "—"}
                  </div>
                  {b.evidence_nodes?.length ? (
                    <div className="text-[9px] font-mono text-slate-600 mt-1 truncate">
                      evidence: {b.evidence_nodes.join(", ")}
                    </div>
                  ) : null}
                </div>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
};

export default BehaviorTimeline;
