import { useEffect, useRef } from "react";

/**
 * Behavior flow graph — canvas-based custom renderer.
 * Nodes are arranged in a top-to-bottom vertical flow with slight lateral offset.
 * Colored by `kind`. Edges drawn as arrows with optional labels.
 */
const KIND_COLORS = {
  start: "#4AA890",
  end: "#4AA890",
  filesystem: "#E27E5D",
  network: "#7fb9ff",
  crypto: "#c0ca33",
  execution: "#d96c6c",
  persistence: "#e27e5d",
  discovery: "#8b949e",
  c2: "#d96c6c",
  impact: "#d96c6c",
  default: "#8b949e",
};

export default function FlowGraph({ nodes = [], edges = [] }) {
  const canvasRef = useRef(null);
  const wrapRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    const wrap = wrapRef.current;
    if (!canvas || !wrap || !nodes.length) return;

    // layout
    const positions = layoutNodes(nodes, edges);
    const bounds = getBounds(positions);
    const pad = 40;
    const width = Math.max(600, bounds.maxX - bounds.minX + pad * 2);
    const height = Math.max(400, bounds.maxY - bounds.minY + pad * 2);

    const dpi = window.devicePixelRatio || 1;
    canvas.width = width * dpi;
    canvas.height = height * dpi;
    canvas.style.width = width + "px";
    canvas.style.height = height + "px";
    const ctx = canvas.getContext("2d");
    ctx.scale(dpi, dpi);
    ctx.textBaseline = "middle";
    ctx.font = "11px 'JetBrains Mono', monospace";

    // shift positions into canvas
    const offset = { x: pad - bounds.minX, y: pad - bounds.minY };
    const pos = {};
    for (const [id, p] of Object.entries(positions)) pos[id] = { x: p.x + offset.x, y: p.y + offset.y };

    // background grid
    ctx.strokeStyle = "#2d3135";
    ctx.lineWidth = 1;
    for (let x = 0; x < width; x += 40) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, height);
      ctx.stroke();
    }
    for (let y = 0; y < height; y += 40) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(width, y);
      ctx.stroke();
    }

    // edges
    ctx.strokeStyle = "#4AA890";
    ctx.fillStyle = "#4AA890";
    ctx.lineWidth = 1.4;
    for (const e of edges) {
      const a = pos[e.from];
      const b = pos[e.to];
      if (!a || !b) continue;
      drawArrow(ctx, a, b);
      if (e.label) drawEdgeLabel(ctx, a, b, e.label);
    }

    // nodes
    for (const n of nodes) {
      const p = pos[n.id];
      if (!p) continue;
      drawNode(ctx, p, n);
    }
  }, [nodes, edges]);

  if (!nodes.length) return null;
  return (
    <div ref={wrapRef} style={{ overflow: "auto", border: "1px solid var(--border)", background: "var(--inset)" }}>
      <canvas ref={canvasRef} data-testid="flow-graph-canvas" />
    </div>
  );
}

// ============ layout ============
function layoutNodes(nodes, edges) {
  // topological levels (best-effort). Fallback: single column top-to-bottom.
  const incoming = Object.fromEntries(nodes.map((n) => [n.id, 0]));
  for (const e of edges) if (incoming[e.to] !== undefined) incoming[e.to] += 1;

  const level = {};
  const queue = nodes.filter((n) => incoming[n.id] === 0).map((n) => n.id);
  for (const id of queue) level[id] = 0;
  const outMap = {};
  for (const e of edges) (outMap[e.from] ||= []).push(e.to);
  const q = [...queue];
  while (q.length) {
    const id = q.shift();
    const lvl = level[id];
    for (const to of outMap[id] || []) {
      if (level[to] === undefined || level[to] < lvl + 1) {
        level[to] = lvl + 1;
        q.push(to);
      }
    }
  }
  // any missing → tack on at end
  let fallback = Math.max(0, ...Object.values(level)) + 1;
  for (const n of nodes) if (level[n.id] === undefined) level[n.id] = fallback++;

  // group nodes per level → assign x within level
  const byLevel = {};
  for (const n of nodes) (byLevel[level[n.id]] ||= []).push(n.id);
  const positions = {};
  const NODE_H = 80;
  const NODE_W = 180;
  Object.entries(byLevel).forEach(([lvl, ids]) => {
    ids.forEach((id, i) => {
      const totalW = ids.length * NODE_W + (ids.length - 1) * 30;
      const startX = -totalW / 2 + NODE_W / 2;
      positions[id] = {
        x: startX + i * (NODE_W + 30),
        y: parseInt(lvl, 10) * (NODE_H + 40),
      };
    });
  });
  return positions;
}

function getBounds(pos) {
  const xs = Object.values(pos).map((p) => p.x);
  const ys = Object.values(pos).map((p) => p.y);
  const NODE_W = 180, NODE_H = 80;
  return {
    minX: Math.min(...xs) - NODE_W / 2,
    maxX: Math.max(...xs) + NODE_W / 2,
    minY: Math.min(...ys) - NODE_H / 2,
    maxY: Math.max(...ys) + NODE_H / 2,
  };
}

// ============ drawing ============
function drawNode(ctx, p, n) {
  const W = 180, H = 60;
  const x = p.x - W / 2, y = p.y - H / 2;
  const color = KIND_COLORS[n.kind] || KIND_COLORS.default;

  // panel
  ctx.fillStyle = "#18191b";
  ctx.strokeStyle = color;
  ctx.lineWidth = 1.5;
  ctx.fillRect(x, y, W, H);
  ctx.strokeRect(x + 0.5, y + 0.5, W - 1, H - 1);

  // left accent stripe
  ctx.fillStyle = color;
  ctx.fillRect(x, y, 4, H);

  // kind tag
  ctx.fillStyle = color;
  ctx.font = "700 9px 'JetBrains Mono', monospace";
  ctx.fillText((n.kind || "step").toUpperCase(), x + 12, y + 12);

  // label
  ctx.fillStyle = "#e5e7eb";
  ctx.font = "500 11px 'JetBrains Mono', monospace";
  wrapText(ctx, n.label || n.id, x + 12, y + 30, W - 20, 14);
}

function wrapText(ctx, text, x, y, maxW, lh) {
  const words = String(text || "").split(" ");
  let line = "";
  let yy = y;
  const lines = [];
  for (const w of words) {
    const testLine = line ? line + " " + w : w;
    if (ctx.measureText(testLine).width > maxW && line) {
      lines.push(line);
      line = w;
    } else line = testLine;
  }
  if (line) lines.push(line);
  for (let i = 0; i < Math.min(lines.length, 2); i++) {
    let ln = lines[i];
    if (i === 1 && lines.length > 2) ln = ln.slice(0, -1) + "…";
    ctx.fillText(ln, x, yy + i * lh);
  }
}

function drawArrow(ctx, a, b) {
  const NODE_H = 60;
  const from = { x: a.x, y: a.y + NODE_H / 2 };
  const to = { x: b.x, y: b.y - NODE_H / 2 };

  ctx.beginPath();
  // vertical → horizontal → vertical elbow
  if (Math.abs(a.x - b.x) < 4) {
    ctx.moveTo(from.x, from.y);
    ctx.lineTo(to.x, to.y);
  } else {
    const midY = (from.y + to.y) / 2;
    ctx.moveTo(from.x, from.y);
    ctx.lineTo(from.x, midY);
    ctx.lineTo(to.x, midY);
    ctx.lineTo(to.x, to.y);
  }
  ctx.stroke();
  // arrowhead
  const size = 5;
  ctx.beginPath();
  ctx.moveTo(to.x, to.y);
  ctx.lineTo(to.x - size, to.y - size);
  ctx.lineTo(to.x + size, to.y - size);
  ctx.closePath();
  ctx.fill();
}

function drawEdgeLabel(ctx, a, b, label) {
  ctx.fillStyle = "#8b949e";
  ctx.font = "9px 'JetBrains Mono', monospace";
  const mx = (a.x + b.x) / 2;
  const my = (a.y + b.y) / 2;
  const truncated = label.length > 26 ? label.slice(0, 24) + "…" : label;
  ctx.fillText(truncated, mx + 8, my);
}
