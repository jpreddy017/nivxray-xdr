import { useEffect, useMemo, useState } from "react";
import api from "@/lib/api";
import { Copy, Download, TreePine, X, ChevronRight, ChevronDown } from "lucide-react";

/**
 * ProcessTreeView — SVG-rendered NivXRay Process-Tree.
 *
 * • Tactic-coloured nodes (execution / persistence / c2 / defense-evasion / etc)
 * • Click a node to open a right-drawer with cite/MITRE/action detail
 * • Inline "PREDICT TREE" button hits POST /api/analyze/process-tree
 * • Full SOC rationale (verdict/severity/MITRE/LOLBins/Sigma/YARA) below the tree
 *
 * Props: { raw, decoded, autoFetch }
 */

const TACTIC_COLOURS = {
  "execution":            { fill: "#123020", stroke: "#4aa890", label: "#7dd6bf" },  // green
  "persistence":          { fill: "#3a1414", stroke: "#d96c6c", label: "#f2a1a1" },  // red
  "privilege-escalation": { fill: "#3a220f", stroke: "#e27e5d", label: "#f2a889" },  // orange
  "defense-evasion":      { fill: "#332b0f", stroke: "#e6c34a", label: "#f0d878" },  // yellow
  "command-and-control":  { fill: "#2a1a3a", stroke: "#a06cd6", label: "#c4a1f0" },  // purple
  "discovery":            { fill: "#152b3d", stroke: "#5aa2ff", label: "#8ec2ff" },  // blue
  "credential-access":    { fill: "#3a2c14", stroke: "#e6a05a", label: "#f2c37d" },  // amber
  "collection":           { fill: "#1a2d3a", stroke: "#6ea0b8", label: "#a6c9d9" },  // teal
  "exfiltration":         { fill: "#141a3a", stroke: "#6c7fd9", label: "#a1adf2" },  // indigo
  "impact":               { fill: "#3a0f14", stroke: "#e64a5a", label: "#f27888" },  // crimson
  "lateral-movement":     { fill: "#0f3a2c", stroke: "#4ac6a8", label: "#7ddec6" },
  "default":              { fill: "#1a1d21", stroke: "#8b949e", label: "#c0c0c0" },
};

const NODE_W = 260;
const NODE_H = 62;
const X_STEP = 300;
const Y_STEP = 90;

function tacticColour(t) {
  return TACTIC_COLOURS[t] || TACTIC_COLOURS.default;
}

function layoutTree(root) {
  // Simple depth-first layout: each level → x column, sibling → y stacked
  const nodes = [];
  const edges = [];
  let yCursor = 0;
  function walk(n, depth, parentXY) {
    const x = 40 + depth * X_STEP;
    const y = 40 + yCursor * Y_STEP;
    yCursor += 1;
    const me = { ...n, _x: x, _y: y };
    nodes.push(me);
    if (parentXY) edges.push({ from: parentXY, to: { x, y } });
    (n.children || []).forEach((c) => walk(c, depth + 1, { x, y }));
  }
  walk(root, 0, null);
  return { nodes, edges };
}

export default function ProcessTreeView({ raw, decoded, autoFetch = false, onTreeReady }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [tree, setTree] = useState(null);
  const [selected, setSelected] = useState(null);
  const [expanded, setExpanded] = useState(true);

  const fetchTree = async () => {
    if (!raw && !decoded) return;
    setLoading(true); setError("");
    try {
      const r = await api.post("/analyze/process-tree", { raw: raw || "", decoded: decoded || "" });
      setTree(r.data.tree);
      if (onTreeReady) onTreeReady(r.data.tree);
    } catch (e) {
      setError(e?.response?.data?.detail || e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (autoFetch && (raw || decoded)) fetchTree();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autoFetch, decoded]);

  const layout = useMemo(() => tree ? layoutTree(tree.root) : null, [tree]);
  const svgW = layout ? Math.max(...layout.nodes.map((n) => n._x)) + NODE_W + 40 : 800;
  const svgH = layout ? Math.max(...layout.nodes.map((n) => n._y)) + NODE_H + 40 : 300;

  const rationale = tree?.rationale || {};

  return (
    <div className="nvx-card" data-testid="process-tree-card">
      <div className="nvx-card-head">
        <div className="nvx-card-title">
          <span className="dot" style={{ background: "var(--warn)" }} />
          PREDICTED PROCESS TREE
          {tree && <span className="count">{tree.platform.toUpperCase()} · {tree.evidence_source}</span>}
        </div>
        <div className="nvx-card-actions">
          <button className="nvx-btn sm primary" onClick={fetchTree} disabled={loading || (!raw && !decoded)}
                  data-testid="btn-predict-tree" title="Predict downstream process tree via NivXRay LLM Parser">
            <TreePine size={11} /> {loading ? "PREDICTING…" : "PREDICT TREE"}
          </button>
          <button className="nvx-btn sm ghost" onClick={() => setExpanded((v) => !v)} data-testid="btn-tree-expand">
            {expanded ? <ChevronDown size={11} /> : <ChevronRight size={11} />}
            {expanded ? " COLLAPSE" : " EXPAND"}
          </button>
        </div>
      </div>
      {expanded && (
        <div className="nvx-card-body" style={{ padding: 0 }}>
          {error && (
            <div style={{ padding: 12, color: "var(--high)", fontFamily: "JetBrains Mono", fontSize: 11 }} data-testid="tree-error">
              ERROR: {error}
            </div>
          )}
          {!tree && !loading && !error && (
            <div style={{ padding: 18, textAlign: "center", color: "var(--text-mute)",
                          fontFamily: "JetBrains Mono", fontSize: 11 }}>
              Click <b>PREDICT TREE</b> to reconstruct the downstream process tree
              from the decoded payload using the anti-hallucination LLM Parser.
            </div>
          )}
          {tree && (
            <>
              {/* VERDICT STRIP */}
              <div style={{
                padding: "10px 14px", borderBottom: "1px solid var(--border)",
                background: "var(--inset)", display: "grid",
                gridTemplateColumns: "1fr auto auto", gap: 10, alignItems: "center",
              }} data-testid="tree-verdict-strip">
                <div>
                  <div className="mono" style={{ fontSize: 10, color: "var(--text-mute)", letterSpacing: "0.2em" }}>
                    VERDICT
                  </div>
                  <div className="mono" style={{ fontSize: 13, color: "var(--text)", fontWeight: 700, marginTop: 3 }}>
                    {rationale.verdict}
                  </div>
                </div>
                <span className="badge warn" style={{ padding: "4px 12px", fontSize: 11 }}
                      data-testid="tree-severity">
                  {rationale.severity?.toUpperCase()}
                </span>
                <span className="badge" style={{ padding: "4px 12px", fontSize: 11 }}
                      data-testid="tree-confidence">
                  {Math.round((rationale.confidence || 0) * 100)}%
                </span>
              </div>

              {/* SVG TREE */}
              <div style={{ overflow: "auto", maxHeight: 480, background: "var(--bg)" }}
                   data-testid="process-tree-svg-wrap">
                <svg width={svgW} height={svgH}>
                  {layout.edges.map((e, i) => (
                    <path key={`e-${i}`}
                          d={`M ${e.from.x + NODE_W} ${e.from.y + NODE_H / 2}
                              C ${(e.from.x + NODE_W + e.to.x) / 2} ${e.from.y + NODE_H / 2},
                                ${(e.from.x + NODE_W + e.to.x) / 2} ${e.to.y + NODE_H / 2},
                                ${e.to.x} ${e.to.y + NODE_H / 2}`}
                          stroke="#4a4d51" strokeWidth="1.5" fill="none" opacity="0.7" />
                  ))}
                  {layout.nodes.map((n, i) => {
                    const c = tacticColour(n.tactic);
                    const inf = n.evidence?.inferred;
                    return (
                      <g key={n.node_id || i} onClick={() => setSelected(n)}
                         style={{ cursor: "pointer" }} data-testid={`tree-node-${i}`}>
                        <rect x={n._x} y={n._y} width={NODE_W} height={NODE_H} rx={8}
                              fill={c.fill} stroke={c.stroke} strokeWidth={1.6}
                              strokeDasharray={inf ? "4 3" : "0"} />
                        <text x={n._x + 12} y={n._y + 22}
                              fill={c.label} fontSize={12} fontFamily="JetBrains Mono, monospace"
                              fontWeight={700} letterSpacing="0.06em">
                          {(n.process || "?").slice(0, 26)}
                        </text>
                        <text x={n._x + 12} y={n._y + 40}
                              fill="#8b949e" fontSize={10} fontFamily="JetBrains Mono, monospace">
                          {(n.tactic || "").slice(0, 32)} {inf ? "· inferred" : ""}
                        </text>
                        <text x={n._x + 12} y={n._y + 55}
                              fill="#6b6f76" fontSize={9} fontFamily="JetBrains Mono, monospace">
                          {(n.mitre_ids || []).slice(0, 3).join(", ")}
                        </text>
                      </g>
                    );
                  })}
                </svg>
              </div>

              {/* SOC RATIONALE FOOTER */}
              <div style={{ padding: 14, borderTop: "1px solid var(--border)", background: "var(--inset)",
                            display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(180px,1fr))",
                            gap: 10 }}
                   data-testid="tree-rationale">
                <RationaleField label="MITRE" values={rationale.mitre_ids} />
                <RationaleField label="Tactics" values={rationale.tactics} />
                <RationaleField label="LOLBins" values={rationale.lolbins} accent="warn" />
                <RationaleField label="IOC URLs" values={rationale.iocs?.urls} />
                <RationaleField label="IOC IPs" values={rationale.iocs?.ips} />
                <RationaleField label="IOC Files" values={rationale.iocs?.files} />
              </div>

              {(rationale.sigma_opportunities?.length || rationale.yara_opportunities?.length) ? (
                <div style={{ padding: 14, borderTop: "1px solid var(--border)" }} data-testid="tree-hunt-hints">
                  {rationale.sigma_opportunities?.length ? (
                    <HuntSection title="SIGMA HUNT OPPORTUNITIES" items={rationale.sigma_opportunities} />
                  ) : null}
                  {rationale.yara_opportunities?.length ? (
                    <HuntSection title="YARA STRING IDEAS" items={rationale.yara_opportunities} />
                  ) : null}
                </div>
              ) : null}

              {rationale.analyst_summary && (
                <div style={{ padding: 14, borderTop: "1px solid var(--border)" }} data-testid="tree-summary">
                  <div className="mono" style={{ fontSize: 10, color: "var(--text-mute)", letterSpacing: "0.2em", marginBottom: 6 }}>
                    ANALYST SUMMARY
                  </div>
                  <div style={{ fontSize: 12, color: "var(--text-dim)", lineHeight: 1.6 }}>
                    {rationale.analyst_summary}
                  </div>
                </div>
              )}

              {tree.warnings?.length ? (
                <div style={{ padding: 12, borderTop: "1px solid var(--border)",
                              background: "rgba(226,126,93,0.06)" }} data-testid="tree-warnings">
                  <div className="mono" style={{ fontSize: 10, color: "var(--warn)", letterSpacing: "0.14em", marginBottom: 4 }}>
                    ⚠ VALIDATOR WARNINGS
                  </div>
                  {tree.warnings.map((w, i) => (
                    <div key={i} className="mono" style={{ fontSize: 10, color: "var(--text-dim)" }}>· {w}</div>
                  ))}
                </div>
              ) : null}

              {/* ACTIONS */}
              <div style={{ padding: 10, borderTop: "1px solid var(--border)", display: "flex", gap: 6 }}>
                <button className="nvx-btn sm ghost" data-testid="btn-copy-tree-json"
                        onClick={() => navigator.clipboard.writeText(JSON.stringify(tree, null, 2))}>
                  <Copy size={11} /> COPY JSON
                </button>
                <button className="nvx-btn sm ghost" data-testid="btn-download-tree"
                        onClick={() => {
                          const blob = new Blob([JSON.stringify(tree, null, 2)], { type: "application/json" });
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement("a");
                          a.href = url; a.download = `nivxray_process_tree_${tree.tree_id}.json`; a.click();
                          URL.revokeObjectURL(url);
                        }}>
                  <Download size={11} /> DOWNLOAD
                </button>
              </div>
            </>
          )}
        </div>
      )}

      {selected && (
        <NodeDrawer node={selected} onClose={() => setSelected(null)} />
      )}
    </div>
  );
}


function RationaleField({ label, values, accent }) {
  const vs = (values || []).filter(Boolean);
  return (
    <div>
      <div className="mono" style={{ fontSize: 9, color: "var(--text-mute)", letterSpacing: "0.2em", marginBottom: 4 }}>
        {label}
      </div>
      {vs.length ? (
        <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
          {vs.slice(0, 6).map((v, i) => (
            <span key={i} className={`badge ${accent === "warn" ? "warn" : ""}`}
                  style={{ fontSize: 10, padding: "2px 6px", wordBreak: "break-all" }}>
              {String(v).slice(0, 44)}
            </span>
          ))}
        </div>
      ) : (
        <div className="mono" style={{ fontSize: 10, color: "#4a4d51" }}>(none)</div>
      )}
    </div>
  );
}

function HuntSection({ title, items }) {
  return (
    <div style={{ marginBottom: 10 }}>
      <div className="mono" style={{ fontSize: 10, color: "var(--accent)", letterSpacing: "0.18em", marginBottom: 4 }}>
        {title}
      </div>
      {items.map((it, i) => (
        <div key={i} style={{ fontSize: 11, color: "var(--text-dim)", padding: "2px 0" }}>· {it}</div>
      ))}
    </div>
  );
}

function NodeDrawer({ node, onClose }) {
  const ev = node.evidence || {};
  return (
    <div style={{
      position: "fixed", top: 0, right: 0, width: 380, height: "100vh",
      background: "var(--surface)", borderLeft: "1px solid var(--border)",
      zIndex: 100, overflowY: "auto", padding: 16,
      fontFamily: "JetBrains Mono, monospace", fontSize: 11,
    }} data-testid="tree-node-drawer">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14 }}>
        <span style={{ color: "var(--accent)", fontWeight: 700, letterSpacing: "0.14em" }}>{node.process}</span>
        <button className="nvx-btn sm ghost" onClick={onClose} data-testid="btn-close-node-drawer">
          <X size={11} />
        </button>
      </div>
      <DField label="Command line">{node.command_line || "(none)"}</DField>
      {node.executable_path && <DField label="Executable path">{node.executable_path}</DField>}
      {node.action && <DField label="Action">{node.action}</DField>}
      {node.user && <DField label="User">{node.user}</DField>}
      {node.integrity_level && <DField label="Integrity level">{node.integrity_level}</DField>}
      {node.signer && <DField label="Signer">{node.signer}</DField>}
      {node.lolbin && <DField label="LOLBin">yes</DField>}
      <DField label="Tactic">{node.tactic || "(none)"}</DField>
      <DField label="MITRE IDs">{(node.mitre_ids || []).join(", ") || "(none)"}</DField>
      <DField label="Evidence citation">{ev.citation || "(inferred / none)"}</DField>
      <DField label="Confidence">{Math.round((ev.confidence || 0) * 100)}%
        {ev.inferred ? " · inferred" : " · verified"}</DField>
      {node.ts_delta_ms ? <DField label="Δt from parent">{node.ts_delta_ms} ms</DField> : null}
    </div>
  );
}

function DField({ label, children }) {
  return (
    <div style={{ marginBottom: 12 }}>
      <div style={{ color: "var(--text-mute)", letterSpacing: "0.14em", fontSize: 9, marginBottom: 4,
                    textTransform: "uppercase" }}>
        {label}
      </div>
      <div style={{ background: "var(--inset)", padding: "6px 10px", border: "1px solid var(--border)",
                    wordBreak: "break-all", whiteSpace: "pre-wrap", color: "var(--text)" }}>
        {children}
      </div>
    </div>
  );
}
