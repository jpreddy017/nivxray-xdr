/**
 * Round 36 · Process Tree view.
 *
 * Single-question projection: "What process executed what?"
 *
 * Pure EDR-style parent → child ancestry using only SPAWNED edges
 * between real process nodes.  Every process discloses commandlines
 * and host/user attributes when the underlying canonical evidence
 * carries them.
 */
import React, { useState } from "react";
import { ChevronRight, ChevronDown, Terminal, Cpu } from "lucide-react";

function ProcessNode({ proc, depth, onSelect, selected }) {
  const [expanded, setExpanded] = useState(true);
  const hasChildren = (proc.children || []).length > 0;
  const isSelected = selected === proc.id;
  return (
    <div data-testid={`xdr-proctree-node-${proc.name}`}>
      <div style={{
              display: "flex", alignItems: "center", gap: 6,
              padding: "6px 8px", marginLeft: depth * 24,
              background: isSelected ? "#1e1b4b" : "#0f172a",
              border: `1px solid ${isSelected ? "#a78bfa" : "#1e293b"}`,
              borderRadius: 3, marginBottom: 4, cursor: "pointer",
              position: "relative",
            }}
            onClick={() => onSelect?.(proc)}>
        <button onClick={(e) => { e.stopPropagation();
                                            setExpanded(v => !v); }}
                 style={{ background: "transparent", border: 0,
                             color: "#94a3b8", padding: 0,
                             visibility: hasChildren ? "visible" : "hidden",
                             display: "flex", alignItems: "center" }}
                 data-testid={`xdr-proctree-toggle-${proc.name}`}>
          {expanded ? <ChevronDown size={12} />
                          : <ChevronRight size={12} />}
        </button>
        <Cpu size={12} style={{ color: proc.role === "parent"
                                           ? "#fca5a5" : "#fdba74" }} />
        <span className="mono" style={{ fontSize: 12,
                                                  color: "#f8fafc",
                                                  fontWeight: 600 }}>
          {proc.name}
        </span>
        {proc.role && (
          <span style={{ fontSize: 9, color: "#94a3b8",
                            background: "#1e293b", padding: "1px 5px",
                            borderRadius: 2, textTransform: "uppercase",
                            letterSpacing: 0.4 }}>
            {proc.role}
          </span>
        )}
        {proc.host && (
          <span style={{ fontSize: 10, color: "#7dd3fc" }}>
            @{proc.host}
          </span>
        )}
        {proc.commandlines && proc.commandlines.length > 0 && (
          <span style={{ marginLeft: "auto", display: "flex",
                              alignItems: "center", gap: 4 }}>
            <Terminal size={11} style={{ color: "#94a3b8" }} />
            <span style={{ color: "#94a3b8", fontSize: 10 }}>
              {proc.commandlines.length}
            </span>
          </span>
        )}
      </div>
      {expanded && proc.commandlines && proc.commandlines.length > 0 && (
        <div style={{ marginLeft: (depth + 1) * 24 + 24,
                          marginBottom: 4 }}>
          {proc.commandlines.map((cli, i) => (
            <div key={i}
                  className="mono"
                  style={{ fontSize: 11, color: "#e2e8f0",
                              background: "#0b0f1a", padding: "3px 8px",
                              borderRadius: 2, marginBottom: 2,
                              border: "1px solid #1e293b",
                              wordBreak: "break-all" }}
                  data-testid={`xdr-proctree-cli-${proc.name}-${i}`}>
              <span style={{ color: "#fca5a5" }}>$</span>{" "}
              {cli.full || cli.label}
            </div>
          ))}
        </div>
      )}
      {expanded && hasChildren && proc.children.map(c => (
        <ProcessNode key={c.id} proc={c} depth={depth + 1}
                            onSelect={onSelect} selected={selected} />
      ))}
    </div>
  );
}

export function ProcessTreeView({ tree, onSelectProcess, selectedId }) {
  if (!tree) return null;
  const roots = tree.roots || [];
  if (roots.length === 0) {
    return (
      <div style={{ padding: 32, textAlign: "center",
                       color: "#94a3b8" }}
            data-testid="xdr-proctree-empty">
        <Cpu size={20} style={{ margin: "0 auto 8px", display: "block",
                                          color: "#475569" }} />
        <div style={{ fontSize: 13, fontWeight: 600, color: "#cbd5e1" }}>
          NO PROCESS EXECUTION TELEMETRY
        </div>
        <div style={{ fontSize: 11, marginTop: 4 }}>
          No parent → child process relationships were established by
          the canonical evidence. NivXRay will not synthesize ancestry.
        </div>
      </div>
    );
  }
  return (
    <div style={{ padding: 12 }} data-testid="xdr-proctree-view">
      <div style={{ marginBottom: 10, color: "#94a3b8", fontSize: 11 }}>
        <span data-testid="xdr-proctree-totals">
          {tree.totals?.processes ?? 0} process(es) · {roots.length} root(s)
        </span>
      </div>
      {roots.map(r => (
        <ProcessNode key={r.id} proc={r} depth={0}
                            onSelect={onSelectProcess} selected={selectedId} />
      ))}
    </div>
  );
}
