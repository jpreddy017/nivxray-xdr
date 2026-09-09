import { useMemo, useRef } from "react";
import {
  User, Cog, FileText, HardDrive, Globe, Router, Mail, Database,
  ScrollText, Link as LinkIcon, Skull, Target, Camera, Download,
} from "lucide-react";

/**
 * AttackGraph — Tactical MITRE ATT&CK swim-lane graph.
 * Nodes are grouped into vertical lanes by attack tactic (Initial Access → Impact).
 * Each lane has a phase header. Edges cross lanes to show the kill-chain flow.
 */
const TYPE_ICON = {
  process: Cog, file: FileText, device: HardDrive, user: User,
  url: LinkIcon, ip: Router, domain: Globe, email: Mail,
  hash: FileText, registry: Database, script: ScrollText, action: Target,
};

// MITRE tactic ordering (kill chain) + accent color
const TACTICS_ORDER = [
  ["Reconnaissance",       "#8b949e"],
  ["Resource Development", "#8b949e"],
  ["Initial Access",       "#7fb9ff"],
  ["Execution",            "#d96c6c"],
  ["Persistence",          "#e27e5d"],
  ["Privilege Escalation", "#e27e5d"],
  ["Defense Evasion",      "#c0ca33"],
  ["Credential Access",    "#d96c6c"],
  ["Discovery",            "#8b949e"],
  ["Lateral Movement",     "#7fb9ff"],
  ["Collection",           "#c0ca33"],
  ["Command and Control",  "#d96c6c"],
  ["Exfiltration",         "#d96c6c"],
  ["Impact",               "#d96c6c"],
];
const TACTIC_COLOR = Object.fromEntries(TACTICS_ORDER);

export default function AttackGraph({ nodes = [], edges = [], selectedTactic = null, onTacticClick = null }) {
  const { positions, laneMeta, width, height } = useMemo(() => layout(nodes, edges), [nodes, edges]);
  const svgRef = useRef(null);
  if (!nodes.length) return null;

  const dimNode = (n) => selectedTactic && (n.tactic || "Execution") !== selectedTactic;
  const dimLane = (t)  => selectedTactic && t !== selectedTactic;

  const serializeSvg = () => {
    const el = svgRef.current;
    if (!el) return null;
    const clone = el.cloneNode(true);
    // Inline background so exported PNG matches the app's dark theme
    clone.setAttribute("xmlns", "http://www.w3.org/2000/svg");
    clone.setAttribute("style", "background:#0a0a0c;font-family:'JetBrains Mono',monospace");
    const bg = document.createElementNS("http://www.w3.org/2000/svg", "rect");
    bg.setAttribute("x", "0"); bg.setAttribute("y", "0");
    bg.setAttribute("width", String(width)); bg.setAttribute("height", String(height));
    bg.setAttribute("fill", "#0a0a0c");
    clone.insertBefore(bg, clone.firstChild);
    return new XMLSerializer().serializeToString(clone);
  };

  const downloadSvg = () => {
    const svgStr = serializeSvg();
    if (!svgStr) return;
    const blob = new Blob([svgStr], { type: "image/svg+xml;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `nivxray_attack_graph_${new Date().toISOString().replace(/[:.]/g, "-")}.svg`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const downloadPng = () => {
    const svgStr = serializeSvg();
    if (!svgStr) return;
    const scale = 2; // hi-DPI export
    const canvas = document.createElement("canvas");
    canvas.width = width * scale;
    canvas.height = height * scale;
    const ctx = canvas.getContext("2d");
    // paint background in case the SVG background rect doesn't render on some browsers
    ctx.fillStyle = "#0a0a0c";
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    const img = new Image();
    img.onload = () => {
      ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
      canvas.toBlob((blob) => {
        if (!blob) return;
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `nivxray_attack_graph_${new Date().toISOString().replace(/[:.]/g, "-")}.png`;
        a.click();
        URL.revokeObjectURL(url);
      }, "image/png");
    };
    img.onerror = () => alert("Snapshot failed — please try SVG export instead.");
    img.src = "data:image/svg+xml;charset=utf-8," + encodeURIComponent(svgStr);
  };

  return (
    <div style={{ background: "var(--inset)", border: "1px solid var(--border)" }}>
      {/* Snapshot toolbar */}
      <div
        style={{
          display: "flex", gap: 6, padding: "6px 8px", borderBottom: "1px solid var(--border)",
          background: "var(--bg)", alignItems: "center",
        }}
      >
        <span className="mono" style={{ fontSize: 9, color: "var(--text-mute)", letterSpacing: "0.18em", marginRight: "auto" }}>
          SNAPSHOT ▸
        </span>
        <button className="nvx-btn sm ghost" onClick={downloadPng} data-testid="btn-attack-graph-png">
          <Camera size={11} /> PNG
        </button>
        <button className="nvx-btn sm ghost" onClick={downloadSvg} data-testid="btn-attack-graph-svg">
          <Download size={11} /> SVG
        </button>
      </div>
      <div style={{ overflow: "auto" }}>
      <svg ref={svgRef} width={width} height={height} style={{ display: "block", minWidth: "100%" }} data-testid="attack-graph-svg" xmlns="http://www.w3.org/2000/svg">
        {/* Lane backgrounds + headers (clickable) */}
        {laneMeta.map((L, i) => {
          const isSelected = selectedTactic === L.tactic;
          const isDim = dimLane(L.tactic);
          return (
            <g
              key={L.tactic}
              data-testid={`ag-lane-${L.tactic.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`}
              style={{ cursor: onTacticClick ? "pointer" : "default", opacity: isDim ? 0.28 : 1, transition: "opacity 160ms" }}
              onClick={() => onTacticClick?.(L.tactic)}
            >
              {i % 2 === 0 && (
                <rect x={L.x - 90} y={0} width={180} height={height} fill="#0a0a0c" opacity={0.35} />
              )}
              {isSelected && (
                <rect x={L.x - 90} y={0} width={180} height={height} fill={L.color} opacity={0.08} />
              )}
              <line x1={L.x - 90} y1={0} x2={L.x - 90} y2={height} stroke="#2d3135" strokeDasharray="3 3" />
              <rect x={L.x - 85} y={12} width={170} height={26}
                fill={L.color}
                opacity={isSelected ? 0.35 : 0.15}
                stroke={L.color} strokeWidth={isSelected ? 2 : 1} />
              <text x={L.x} y={30} fontSize={11} fontFamily="'Chivo',sans-serif" fill={L.color} textAnchor="middle" fontWeight={700} style={{ letterSpacing: "0.14em", textTransform: "uppercase" }}>
                {L.tactic.length > 22 ? L.tactic.slice(0, 20) + "…" : L.tactic}
              </text>
              <text x={L.x} y={48} fontSize={9} fontFamily="'JetBrains Mono',monospace" fill="#8b949e" textAnchor="middle">
                {L.nodeCount} node{L.nodeCount > 1 ? "s" : ""}{isSelected ? " · FILTERED" : ""}
              </text>
            </g>
          );
        })}
        {/* right terminator line */}
        {laneMeta.length > 0 && (
          <line
            x1={laneMeta[laneMeta.length - 1].x + 90} y1={0}
            x2={laneMeta[laneMeta.length - 1].x + 90} y2={height}
            stroke="#2d3135" strokeDasharray="3 3"
          />
        )}

        {/* Arrow defs */}
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#4aa890" />
          </marker>
          <marker id="arrow-red" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#d96c6c" />
          </marker>
        </defs>

        {/* Edges */}
        {edges.map((e, i) => {
          const a = positions[e.from]; const b = positions[e.to];
          if (!a || !b) return null;
          const from = nodes.find((n) => n.id === e.from);
          const to = nodes.find((n) => n.id === e.to);
          const stroke = (from?.malicious || to?.malicious) ? "#d96c6c" : "#4aa890";
          const marker = stroke === "#d96c6c" ? "arrow-red" : "arrow";
          const edgeDim = selectedTactic && !(from && to && (from.tactic === selectedTactic || to.tactic === selectedTactic));
          // Bezier curve for cross-lane clarity
          const dx = b.x - a.x;
          const cx1 = a.x + dx * 0.4, cy1 = a.y;
          const cx2 = b.x - dx * 0.4, cy2 = b.y;
          const midX = (a.x + b.x) / 2;
          const midY = (a.y + b.y) / 2;
          return (
            <g key={i} style={{ opacity: edgeDim ? 0.15 : 0.9, transition: "opacity 160ms" }}>
              <path d={`M ${a.x} ${a.y} C ${cx1} ${cy1}, ${cx2} ${cy2}, ${b.x} ${b.y}`}
                    stroke={stroke} strokeWidth={1.6} fill="none" markerEnd={`url(#${marker})`} />
              {e.label && (
                <g>
                  <rect x={midX - (e.label.length * 3.2)} y={midY - 9} width={e.label.length * 6.4} height={14} fill="#101112" opacity={0.9} rx={2} />
                  <text x={midX} y={midY + 2} fontSize={10} fontFamily="'JetBrains Mono',monospace" fill="#e5e7eb" textAnchor="middle">
                    {e.label.length > 26 ? e.label.slice(0, 24) + "…" : e.label}
                  </text>
                </g>
              )}
            </g>
          );
        })}

        {/* Nodes */}
        {nodes.map((n) => {
          const p = positions[n.id];
          if (!p) return null;
          const Icon = TYPE_ICON[n.type] || Cog;
          const color = n.malicious ? "#d96c6c" : (TACTIC_COLOR[n.tactic] || "#4aa890");
          const nDim = dimNode(n);
          return (
            <g
              key={n.id}
              transform={`translate(${p.x}, ${p.y})`}
              data-testid={`ag-node-${n.id}`}
              style={{ opacity: nDim ? 0.22 : 1, transition: "opacity 160ms", cursor: onTacticClick && n.tactic ? "pointer" : "default" }}
              onClick={() => onTacticClick && n.tactic && onTacticClick(n.tactic)}
            >
              {n.malicious && (
                <circle r={28} fill="none" stroke={color} strokeWidth={1.5} strokeDasharray="4 3" opacity={0.7} />
              )}
              <circle r={22} fill="var(--bg)" stroke={color} strokeWidth={n.malicious ? 2 : 1.5} />
              <foreignObject x={-10} y={-10} width={20} height={20}>
                <div xmlns="http://www.w3.org/1999/xhtml" style={{ color, width: 20, height: 20 }}>
                  <Icon size={20} />
                </div>
              </foreignObject>
              {n.malicious && (
                <g transform="translate(15, -15)">
                  <circle r={7} fill="#101112" stroke={color} strokeWidth={1.5} />
                  <foreignObject x={-5} y={-5} width={10} height={10}>
                    <div xmlns="http://www.w3.org/1999/xhtml" style={{ color, width: 10, height: 10 }}>
                      <Skull size={10} />
                    </div>
                  </foreignObject>
                </g>
              )}
              {/* Wrapped label */}
              {wrapLabel(n.label || n.id, 22).map((line, li) => (
                <text
                  key={li}
                  x={0} y={38 + li * 12}
                  fontSize={10.5} fontFamily="'JetBrains Mono',monospace"
                  fill="#e5e7eb" textAnchor="middle" fontWeight={700}
                >
                  {line}
                </text>
              ))}
              <text
                x={0} y={38 + wrapLabel(n.label || n.id, 22).length * 12 + 2}
                fontSize={9} fontFamily="'JetBrains Mono',monospace"
                fill="#8b949e" textAnchor="middle"
                style={{ textTransform: "uppercase", letterSpacing: "0.12em" }}
              >
                {n.type}
              </text>
            </g>
          );
        })}
      </svg>
      </div>
    </div>
  );
}

function wrapLabel(text, maxChars) {
  const words = String(text || "").split(" ");
  const lines = [];
  let line = "";
  for (const w of words) {
    const t = line ? line + " " + w : w;
    if (t.length > maxChars && line) { lines.push(line); line = w; }
    else line = t;
  }
  if (line) lines.push(line);
  return lines.slice(0, 2).map((l, i) => (i === 1 && lines.length > 2 ? l.slice(0, maxChars - 1) + "…" : l));
}

function layout(nodes, edges) {
  // Group nodes by tactic in MITRE kill-chain order
  const nodeByTactic = {};
  for (const n of nodes) {
    const t = n.tactic || "Execution";
    (nodeByTactic[t] ||= []).push(n);
  }
  // Determine present tactics in MITRE order
  const orderedTactics = TACTICS_ORDER.map(([t]) => t).filter((t) => nodeByTactic[t]);
  // Also include any AI-invented tactic not in our list, at the end
  Object.keys(nodeByTactic).forEach((t) => { if (!orderedTactics.includes(t)) orderedTactics.push(t); });

  const LANE_W = 200, ROW_H = 130, PAD_TOP = 70, PAD_BOTTOM = 30, PAD_X = 30;
  const positions = {};
  const laneMeta = [];
  let x = PAD_X + 90;
  const maxRows = Math.max(...orderedTactics.map((t) => nodeByTactic[t].length), 1);
  for (const tactic of orderedTactics) {
    const list = nodeByTactic[tactic];
    laneMeta.push({
      tactic, x, color: TACTIC_COLOR[tactic] || "#8b949e", nodeCount: list.length,
    });
    list.forEach((n, i) => {
      positions[n.id] = { x, y: PAD_TOP + i * ROW_H + (maxRows - list.length) * ROW_H / 2 };
    });
    x += LANE_W;
  }
  const width = Math.max(x + PAD_X, 900);
  const height = PAD_TOP + maxRows * ROW_H + PAD_BOTTOM;
  return { positions, laneMeta, width, height };
}
