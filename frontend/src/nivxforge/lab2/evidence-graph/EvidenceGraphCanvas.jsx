import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ReactFlow, Background, Controls, MiniMap, ReactFlowProvider,
  useReactFlow, ConnectionMode
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import {
  Maximize2, Minimize2, Download, ArrowLeftRight, ArrowDownUp, Info, ExternalLink
} from "lucide-react";

import { StageNode } from "./nodes/StageNode";
import { layoutGraph } from "./layouts/dagreLayout";
import { PROJECTIONS } from "./projections";
import { NodeInspector } from "./NodeInspector";
import { RecursionBadge } from "./RecursionBadge";
import "./evidence-graph.css";

const NODE_TYPES = { stage: StageNode };

/**
 * EvidenceGraphCanvas — the canonical CIO-driven graph renderer for X-Lab.
 *
 * ONE renderer, MULTIPLE projections. Every attack chain, decode ladder,
 * MITRE map, timeline, and (future) process tree passes through this
 * component. The projector emits nodes/edges from `cio`, dagre lays them
 * out, React Flow renders them, and NodeInspector projects the selected
 * node's downstream truths.
 *
 * Props:
 *   cio      — full CIO object (single source of truth)
 *   onEvClick(node_id) — optional bridge to sync evidence chip across lenses
 *   defaultView — one of PROJECTIONS keys (default "investigation")
 */
export function EvidenceGraphCanvas({ cio, onEvClick, defaultView = "investigation" }) {
  return (
    <ReactFlowProvider>
      <Canvas cio={cio} onEvClick={onEvClick} defaultView={defaultView} />
    </ReactFlowProvider>
  );
}

function Canvas({ cio, onEvClick, defaultView }) {
  const wrapRef = useRef(null);
  const rf = useReactFlow();

  const [view, setView] = useState(defaultView);
  const [direction, setDirection] = useState(PROJECTIONS[defaultView]?.direction || "LR");
  const [selectedNodeId, setSelectedNodeId] = useState(null);
  const [fullscreen, setFullscreen] = useState(false);

  // Reset direction when switching views so each projection picks its default.
  const changeView = useCallback((next) => {
    setView(next);
    setDirection(PROJECTIONS[next]?.direction || "LR");
    setSelectedNodeId(null);
  }, []);

  // Project + layout every time cio, view, or direction changes.
  const { nodes, edges, empty, note } = useMemo(() => {
    const proj = PROJECTIONS[view]?.fn;
    const p = proj ? proj(cio || {}) : { nodes: [], edges: [], empty: true, note: "no projection" };
    if (p.empty) return p;
    const laid = layoutGraph({ nodes: p.nodes, edges: p.edges, direction });
    return { nodes: laid.nodes, edges: laid.edges, empty: false, note: "" };
  }, [cio, view, direction]);

  // Refit view whenever the projected graph changes.
  useEffect(() => {
    if (!empty && rf) {
      const t = setTimeout(() => rf.fitView({ padding: 0.15, duration: 350 }), 60);
      return () => clearTimeout(t);
    }
  }, [nodes.length, edges.length, view, direction, empty, rf]);

  const onNodeClick = useCallback((_, node) => {
    setSelectedNodeId(node.id);
    if (onEvClick) onEvClick(node.data?.id || node.id);
  }, [onEvClick]);

  const onPaneClick = useCallback(() => setSelectedNodeId(null), []);

  // Exports.
  const exportJson = useCallback(() => {
    const payload = { view, direction, nodes, edges, cio_snapshot_id: cio?.snapshot_hash || null };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `xlab-graph-${view}.json`; a.click();
    URL.revokeObjectURL(url);
  }, [view, direction, nodes, edges, cio]);

  const exportPng = useCallback(async () => {
    // Native SVG-to-PNG so we don't add another dependency. Serialize the
    // rendered React Flow SVG viewport and rasterise via canvas.
    const svgEl = wrapRef.current?.querySelector(".react-flow__viewport");
    const rf__renderer = wrapRef.current?.querySelector(".react-flow__renderer");
    if (!rf__renderer) return;
    const svgNS = "http://www.w3.org/2000/svg";
    // Fallback strategy: use the browser's built-in canvas from a data:image/svg+xml
    // via serializing the whole react-flow pane as html.
    // Simpler: use dom-to-image via inline canvas rasterization of the flow area.
    try {
      const rect = wrapRef.current.getBoundingClientRect();
      const foreignSvg = document.createElementNS(svgNS, "svg");
      foreignSvg.setAttribute("xmlns", svgNS);
      foreignSvg.setAttribute("width", rect.width);
      foreignSvg.setAttribute("height", rect.height);
      const fo = document.createElementNS(svgNS, "foreignObject");
      fo.setAttribute("width", "100%");
      fo.setAttribute("height", "100%");
      const html = rf__renderer.cloneNode(true);
      const div = document.createElement("div");
      div.setAttribute("xmlns", "http://www.w3.org/1999/xhtml");
      div.style.background = "var(--bg, #0b0e14)";
      div.appendChild(html);
      fo.appendChild(div);
      foreignSvg.appendChild(fo);
      const xml = new XMLSerializer().serializeToString(foreignSvg);
      const svg64 = btoa(unescape(encodeURIComponent(xml)));
      const img = new Image();
      img.crossOrigin = "anonymous";
      img.onload = () => {
        const canvas = document.createElement("canvas");
        canvas.width = rect.width * 2;
        canvas.height = rect.height * 2;
        const ctx = canvas.getContext("2d");
        ctx.fillStyle = "#0b0e14";
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
        canvas.toBlob((blob) => {
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a");
          a.href = url; a.download = `xlab-graph-${view}.png`; a.click();
          URL.revokeObjectURL(url);
        }, "image/png");
      };
      img.onerror = () => { /* silently ignore — user still has JSON export */ };
      img.src = `data:image/svg+xml;base64,${svg64}`;
    } catch (_e) { /* silent */ }
  }, [view]);

  const exportSvg = useCallback(() => {
    // Simple SVG re-render of just the node/edge geometry.
    const w = 1400, h = 800;
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("xmlns", "http://www.w3.org/2000/svg");
    svg.setAttribute("width", w); svg.setAttribute("height", h);
    // (Minimal geometry export — the JSON export contains the full data;
    // this SVG is for quick share/preview.)
    const bg = document.createElementNS("http://www.w3.org/2000/svg", "rect");
    bg.setAttribute("width", w); bg.setAttribute("height", h); bg.setAttribute("fill", "#0b0e14");
    svg.appendChild(bg);
    nodes.forEach((n) => {
      const g = document.createElementNS("http://www.w3.org/2000/svg", "g");
      g.setAttribute("transform", `translate(${n.position.x},${n.position.y})`);
      const rect = document.createElementNS("http://www.w3.org/2000/svg", "rect");
      rect.setAttribute("width", 220); rect.setAttribute("height", 92);
      rect.setAttribute("rx", 10); rect.setAttribute("fill", "#141922"); rect.setAttribute("stroke", "#2a3140");
      g.appendChild(rect);
      const t = document.createElementNS("http://www.w3.org/2000/svg", "text");
      t.setAttribute("x", 16); t.setAttribute("y", 28); t.setAttribute("fill", "#e6ebf5"); t.setAttribute("font-size", 13); t.setAttribute("font-family", "monospace");
      t.textContent = (n.data.title || "").slice(0, 30);
      g.appendChild(t);
      const s = document.createElementNS("http://www.w3.org/2000/svg", "text");
      s.setAttribute("x", 16); s.setAttribute("y", 52); s.setAttribute("fill", "#7c8494"); s.setAttribute("font-size", 11); s.setAttribute("font-family", "monospace");
      s.textContent = (n.data.subtitle || "").slice(0, 34);
      g.appendChild(s);
      svg.appendChild(g);
    });
    const xml = new XMLSerializer().serializeToString(svg);
    const blob = new Blob([xml], { type: "image/svg+xml" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `xlab-graph-${view}.svg`; a.click();
    URL.revokeObjectURL(url);
  }, [nodes, view]);

  // Fullscreen — CSS-based so we don't fight browser fullscreen APIs.
  const toggleFullscreen = useCallback(() => setFullscreen((v) => !v), []);

  // Broadcast the current CIO + view to any open popout window so it can
  // live-update when the analyst re-investigates.
  const popoutRef = useRef(null);
  const bcastRef = useRef(null);
  useEffect(() => {
    try {
      if (!bcastRef.current && typeof BroadcastChannel !== "undefined") {
        bcastRef.current = new BroadcastChannel("xlab-graph-popout");
      }
    } catch (_e) { /* noop */ }
    return () => {
      try { if (bcastRef.current) bcastRef.current.close(); } catch (_e) { /* noop */ }
      bcastRef.current = null;
    };
  }, []);

  // Whenever cio or view changes, mirror into localStorage + broadcast so
  // any open popout window refreshes automatically.
  useEffect(() => {
    if (!cio) return;
    try {
      localStorage.setItem("xlab.graph.popout.cio", JSON.stringify(cio));
      localStorage.setItem("xlab.graph.popout.view", view);
      if (bcastRef.current) {
        bcastRef.current.postMessage({ type: "cio", cio });
        bcastRef.current.postMessage({ type: "view", view });
      }
    } catch (_e) { /* localStorage quota or JSON error — skip silently */ }
  }, [cio, view]);

  const openPopout = useCallback(() => {
    try {
      // Persist snapshot immediately so the child window has data on load.
      localStorage.setItem("xlab.graph.popout.cio", JSON.stringify(cio || {}));
      localStorage.setItem("xlab.graph.popout.view", view);
    } catch (_e) { /* noop */ }
    const w = Math.min(1600, Math.round(window.screen.availWidth * 0.85));
    const h = Math.min(1000, Math.round(window.screen.availHeight * 0.85));
    const features = `popup=yes,width=${w},height=${h},left=${Math.max(0, (window.screen.availWidth - w) / 2)},top=${Math.max(0, (window.screen.availHeight - h) / 2)},resizable=yes,scrollbars=yes,noopener=no,noreferrer=no`;
    const win = window.open("/nivxforge/x-lab/graph", "xlab-graph-popout", features);
    if (win) {
      popoutRef.current = win;
      try { win.focus(); } catch (_e) { /* noop */ }
    }
  }, [cio, view]);

  // Keyboard shortcuts.
  useEffect(() => {
    const handler = (e) => {
      if (e.target?.tagName === "INPUT" || e.target?.tagName === "TEXTAREA") return;
      if (e.key === "f" && (e.shiftKey || e.metaKey)) { toggleFullscreen(); e.preventDefault(); }
      else if (e.key === "0") { rf.fitView({ padding: 0.15, duration: 300 }); }
      else if (e.key === "+" || e.key === "=") { rf.zoomIn(); }
      else if (e.key === "-" || e.key === "_") { rf.zoomOut(); }
      else if (e.key === "d") { setDirection((d) => d === "LR" ? "TB" : "LR"); }
      else if (e.key === "Escape" && fullscreen) { setFullscreen(false); }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [rf, toggleFullscreen, fullscreen]);

  const recursionReport = cio?.metadata?.recursion_report || null;

  return (
    <div
      ref={wrapRef}
      className={`eg-canvas-wrap${fullscreen ? " eg-fullscreen" : ""}`}
      data-testid="eg-canvas"
    >
      <div className="eg-toolbar" data-testid="eg-toolbar">
        <div className="eg-view-tabs" data-testid="eg-view-tabs">
          {Object.entries(PROJECTIONS).map(([key, cfg]) => (
            <button
              key={key}
              type="button"
              className={`eg-view-tab${view === key ? " on" : ""}`}
              onClick={() => changeView(key)}
              data-testid={`eg-view-${key}`}
            >
              {cfg.label}
            </button>
          ))}
        </div>
        <div className="eg-toolbar-spacer" />
        <RecursionBadge report={recursionReport} />
        <div className="eg-toolbar-actions">
          <button
            type="button"
            className="eg-tool"
            title={`Layout: ${direction === "LR" ? "Left→Right" : "Top→Bottom"} (press D to toggle)`}
            onClick={() => setDirection((d) => d === "LR" ? "TB" : "LR")}
            data-testid="eg-toggle-direction"
          >
            {direction === "LR" ? <ArrowLeftRight size={14} /> : <ArrowDownUp size={14} />}
          </button>
          <button type="button" className="eg-tool" title="Export PNG" onClick={exportPng} data-testid="eg-export-png">
            <Download size={14} /><span className="eg-tool-lbl">PNG</span>
          </button>
          <button type="button" className="eg-tool" title="Export SVG" onClick={exportSvg} data-testid="eg-export-svg">
            <Download size={14} /><span className="eg-tool-lbl">SVG</span>
          </button>
          <button type="button" className="eg-tool" title="Export JSON" onClick={exportJson} data-testid="eg-export-json">
            <Download size={14} /><span className="eg-tool-lbl">JSON</span>
          </button>
          <button
            type="button"
            className="eg-tool eg-tool-popout"
            title="Pop out to new window"
            onClick={openPopout}
            data-testid="eg-popout"
          >
            <ExternalLink size={14} /><span className="eg-tool-lbl">POP OUT</span>
          </button>
          <button
            type="button"
            className="eg-tool"
            title={fullscreen ? "Exit fullscreen (Esc)" : "Fullscreen (Shift+F)"}
            onClick={toggleFullscreen}
            data-testid="eg-toggle-fullscreen"
          >
            {fullscreen ? <Minimize2 size={14} /> : <Maximize2 size={14} />}
          </button>
        </div>
      </div>

      <div className="eg-canvas-body">
        {empty ? (
          <div className="eg-empty" data-testid="eg-empty">
            <Info size={16} style={{ marginRight: 8, verticalAlign: "text-bottom" }} />
            {note || "This projection is empty for the current investigation."}
          </div>
        ) : (
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={NODE_TYPES}
            onNodeClick={onNodeClick}
            onPaneClick={onPaneClick}
            connectionMode={ConnectionMode.Loose}
            fitView
            fitViewOptions={{ padding: 0.15 }}
            proOptions={{ hideAttribution: true }}
            panOnDrag
            panOnScroll={false}
            zoomOnScroll
            zoomOnPinch
            selectNodesOnDrag={false}
            nodesDraggable={false}
            nodesConnectable={false}
            elementsSelectable
          >
            <Background gap={20} size={1.2} color="rgba(200,210,235,0.06)" />
            <MiniMap
              pannable
              zoomable
              nodeStrokeWidth={2}
              nodeColor={(n) => {
                const c = n.data?.class || "context";
                if (c === "critical") return "#ff5c5c";
                if (c === "high") return "#f5a623";
                if (c === "medium") return "#f5c451";
                if (c === "low") return "#55e6b8";
                if (c === "mitigating") return "#4dabf7";
                return "#4b525f";
              }}
              maskColor="rgba(11,14,20,0.7)"
              style={{ background: "rgba(20,25,34,0.9)" }}
            />
            <Controls showInteractive={false} />
          </ReactFlow>
        )}

        {selectedNodeId && !empty ? (
          <NodeInspector nodeId={selectedNodeId} cio={cio} onClose={() => setSelectedNodeId(null)} />
        ) : null}
      </div>
    </div>
  );
}
