/**
 * NivXRay · Investigation Canvas Engine
 * ─────────────────────────────────────────────────────────────────────
 * Reusable interactive canvas foundation. Every investigation view
 * (Device Trajectory, Process Ancestry, File / Network / Registry /
 * Identity timelines, Attack Chain, Investigation Graph) plugs into
 * this engine to inherit:
 *
 *   • pan (click-and-drag empty space)
 *   • zoom (mouse wheel · Ctrl+wheel · pinch)
 *   • click-and-drag scrolling
 *   • auto-center on selected item (gentle — only if off-screen)
 *   • selection glow + connected-lifeline brightening
 *   • synchronised right-panel updates via `onSelect`
 *   • horizontal + vertical scrollbars
 *   • minimap (top-right, viewport rectangle overlay)
 *   • viewport virtualisation (only paint visible rows / events)
 *   • keyboard navigation (arrow keys, `f` = fit, `+`/`-` = zoom)
 *
 * Rendered with react-konva → Konva → native HTML5 canvas, so it
 * scales to tens of thousands of events without breaking a sweat.
 *
 * Public API:
 *
 *   <InvestigationCanvas
 *      rows={[{ key, label, band, worstVerdict, firstTs, lastTs, ... }]}
 *      events={[{ id, rowKey, ts, kind, verdict, mitre, label, ... }]}
 *      edges={[{ from, to, kind }]}
 *      selected={id | null}
 *      onSelect={(event) => …}
 *      tokens={NX_TOKENS}
 *      pxPerMs={0.02}                // initial time scale
 *      xForTs / tsForX (optional)    // custom time mapping
 *      onViewportChange={(vp) => …}  // for scrubber sync
 *      minimap={true}
 *   />
 */
import { useEffect, useMemo, useRef, useState, useCallback } from "react";
import { Stage, Layer, Line, Rect, Circle, Text, Group, Path } from "react-konva";
import Konva from "konva";
import {
  clampOffset as coreClampOffset,
  zoomAround as coreZoomAround,
  fit as coreFit,
} from "./core/viewport";

// ─── Defaults ────────────────────────────────────────────────────────
const DEFAULT_TOKENS = {
  bg:          "#24282F",
  grid:        "#3A404A",
  gridDim:     "#3A404A55",
  band:        "#262B33",
  band2:       "#2D333D",
  border:      "#4B5563",
  text:        "#F3F4F6",
  textDim:     "#A8B3C2",
  textMute:    "#646C76",
  link:        "#5FA8FF",
  success:     "#55C271",
  warning:     "#F5C542",
  critical:    "#F04B4B",
  lifeline:    "#4A8B47",
  lifelineDim: "#545C66",
  selectGlow:  "#4A90FF",
};

const ROW_H  = 24;
const BAND_H = 20;
const GLYPH  = 11;

// ═══════════════════════════════════════════════════════════════════
// Public component
// ═══════════════════════════════════════════════════════════════════
export default function InvestigationCanvas({
  rows = [],
  events = [],
  edges = [],
  selected = null,
  onSelect = () => {},
  onViewportChange = () => {},
  tokens = DEFAULT_TOKENS,
  minimap = true,
  emptyMessage = "No investigation data.",
  testId = "investigation-canvas",
}) {
  const T = { ...DEFAULT_TOKENS, ...tokens };
  const wrapperRef = useRef(null);
  const stageRef   = useRef(null);
  const [size, setSize]     = useState({ w: 1200, h: 600 });
  const [scale, setScale]   = useState(1);
  const [offset, setOffset] = useState({ x: 0, y: 0 });

  // Row + band layout
  const { rowY, canvasH, bands } = useMemo(() => {
    let y = 0;
    const rY = [];
    const bs = [];
    let curBand = null, curGroup = null;
    rows.forEach((r) => {
      if (r.band !== curBand) {
        y += BAND_H;
        curBand = r.band;
        curGroup = { label: r.band, top: y, rows: [] };
        bs.push(curGroup);
      }
      rY.push(y);
      curGroup.rows.push(r);
      y += ROW_H;
    });
    return { rowY: rY, canvasH: y + 16, bands: bs };
  }, [rows]);

  const rowIndex = useMemo(() => {
    const m = new Map();
    rows.forEach((r, i) => m.set(r.key, i));
    return m;
  }, [rows]);

  // Time bounds → x mapping.
  // Content width is fixed at 3000 CSS px at scale 1 — panning + zoom
  // in the stage stretch it. This is virtualisation-friendly because we
  // know deterministic content extents.
  const CONTENT_W = 3000;
  const { minTs, maxTs, xForTs } = useMemo(() => {
    if (!events.length) return { minTs: 0, maxTs: 0, xForTs: () => 0 };
    const ts = events.map(e => new Date(e.ts).getTime());
    let lo = Math.min(...ts), hi = Math.max(...ts);
    if (hi === lo) hi = lo + 1000;
    const usable = CONTENT_W - 48;
    return {
      minTs: lo, maxTs: hi,
      xForTs: (t) => 24 + ((new Date(t).getTime() - lo) / (hi - lo)) * usable,
    };
  }, [events]);

  // Resize observer
  useEffect(() => {
    if (!wrapperRef.current) return;
    const ro = new ResizeObserver(() => {
      const el = wrapperRef.current;
      if (el) setSize({ w: el.clientWidth, h: el.clientHeight });
    });
    ro.observe(wrapperRef.current);
    return () => ro.disconnect();
  }, []);

  // Report viewport upstream (for scrubber sync)
  useEffect(() => {
    onViewportChange({ scale, offset, size, contentW: CONTENT_W, contentH: canvasH });
  }, [scale, offset, size, canvasH, onViewportChange]);

  // ── Interaction · wheel zoom (Ctrl / Cmd = zoom, otherwise vertical scroll) ──
  const handleWheel = useCallback((e) => {
    e.evt.preventDefault();
    const stage = stageRef.current;
    if (!stage) return;

    if (e.evt.ctrlKey || e.evt.metaKey || e.evt.altKey) {
      // Anchor-preserving zoom (delegated to core/viewport for determinism)
      const pointer  = stage.getPointerPosition();
      const factor   = e.evt.deltaY > 0 ? 0.92 : 1.08;
      const next = coreZoomAround(
        { offset, scale, size },
        factor,
        pointer,
      );
      setScale(next.scale);
      setOffset(next.offset);
    } else {
      // Regular scroll — horizontal if shift held, else vertical
      const dx = e.evt.shiftKey ? e.evt.deltaY : e.evt.deltaX;
      const dy = e.evt.shiftKey ? 0 : e.evt.deltaY;
      setOffset(o => clampOffset({ x: o.x - dx, y: o.y - dy }, scale, size, canvasH, CONTENT_W));
    }
  }, [scale, size, canvasH]);

  function clampOffset(o, s, sz, cH, cW) {
    return coreClampOffset(o, s, sz, cH, cW);
  }

  // ── Interaction · click-and-drag pan (default Konva draggable=true on Stage) ──
  const handleDragEnd = () => {
    const stage = stageRef.current;
    if (!stage) return;
    setOffset(clampOffset({ x: stage.x(), y: stage.y() }, scale, size, canvasH, CONTENT_W));
  };

  // ── Auto-center gently on selection ──
  useEffect(() => {
    if (!selected || !stageRef.current) return;
    const ev = events.find(e => e.id === selected);
    if (!ev) return;
    const i = rowIndex.get(ev.rowKey);
    if (i == null) return;
    const evX = xForTs(ev.ts) * scale + offset.x;
    const evY = (rowY[i] + ROW_H / 2) * scale + offset.y;
    const margin = 60;
    const outHoriz = evX < margin || evX > size.w - margin;
    const outVert  = evY < margin || evY > size.h - margin;
    if (!outHoriz && !outVert) return; // Already visible — do not move (spec)

    const targetX = size.w / 2 - xForTs(ev.ts) * scale;
    const targetY = size.h / 2 - (rowY[i] + ROW_H / 2) * scale;
    const clamped = clampOffset({ x: targetX, y: targetY }, scale, size, canvasH, CONTENT_W);
    const stage = stageRef.current;
    new Konva.Tween({
      node: stage,
      duration: 0.3,
      easing: Konva.Easings.EaseInOut,
      x: clamped.x, y: clamped.y,
      onFinish: () => setOffset(clamped),
    }).play();
  }, [selected, events, rowIndex, rowY, xForTs, scale, size, canvasH]);

  // ── Keyboard: f = fit, +/- = zoom, arrows = pan ──
  useEffect(() => {
    const h = (e) => {
      if (document.activeElement?.tagName === "INPUT") return;
      if (e.key === "f" || e.key === "F") { fitToContent(); }
      else if (e.key === "+" || e.key === "=") { zoomBy(1.15); }
      else if (e.key === "-" || e.key === "_") { zoomBy(1/1.15); }
      else if (e.key === "ArrowLeft")  setOffset(o => clampOffset({ x: o.x + 80, y: o.y }, scale, size, canvasH, CONTENT_W));
      else if (e.key === "ArrowRight") setOffset(o => clampOffset({ x: o.x - 80, y: o.y }, scale, size, canvasH, CONTENT_W));
      else if (e.key === "ArrowUp")    setOffset(o => clampOffset({ x: o.x, y: o.y + 60 }, scale, size, canvasH, CONTENT_W));
      else if (e.key === "ArrowDown")  setOffset(o => clampOffset({ x: o.x, y: o.y - 60 }, scale, size, canvasH, CONTENT_W));
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [scale, size, canvasH]);

  const fitToContent = useCallback(() => {
    if (!size.w || !canvasH) return;
    const sX = (size.w - 20) / CONTENT_W;
    const sY = (size.h - 40) / Math.max(canvasH, 1);
    const s = Math.max(0.15, Math.min(sX, sY, 1));
    setScale(s);
    setOffset({ x: 0, y: 0 });
  }, [size, canvasH]);

  const zoomBy = useCallback((f) => {
    setScale(s => Math.max(0.15, Math.min(6, s * f)));
  }, []);

  // ── Virtualisation window (spec: only draw items in viewport + margin) ──
  const view = useMemo(() => {
    const marginPx = 200;
    const vx0 = (-offset.x - marginPx) / scale;
    const vx1 = (-offset.x + size.w + marginPx) / scale;
    const vy0 = (-offset.y - marginPx) / scale;
    const vy1 = (-offset.y + size.h + marginPx) / scale;
    return { vx0, vx1, vy0, vy1 };
  }, [offset, scale, size]);

  const visibleRows = useMemo(() => {
    return rows.filter((_, i) => {
      const y = rowY[i];
      return y + ROW_H > view.vy0 && y < view.vy1;
    });
  }, [rows, rowY, view]);

  const visibleEvents = useMemo(() => {
    return events.filter(ev => {
      const i = rowIndex.get(ev.rowKey);
      if (i == null) return false;
      const y = rowY[i] + ROW_H / 2;
      if (y < view.vy0 || y > view.vy1) return false;
      const x = xForTs(ev.ts);
      return x > view.vx0 && x < view.vx1;
    });
  }, [events, rowIndex, rowY, view, xForTs]);

  // ── Marquee selection (Shift+drag on empty canvas, per M1 locked spec Q1) ──
  // MUST be declared BEFORE any conditional early return (rules-of-hooks).
  const [marquee, setMarquee] = useState(null); // { x0, y0, x1, y1 } in world coords
  const marqueeStart = useRef(null);

  const beginMarquee = useCallback((pointer) => {
    const wx = (pointer.x - offset.x) / scale;
    const wy = (pointer.y - offset.y) / scale;
    marqueeStart.current = { x: wx, y: wy };
    setMarquee({ x0: wx, y0: wy, x1: wx, y1: wy });
  }, [offset, scale]);

  const updateMarquee = useCallback((pointer) => {
    if (!marqueeStart.current) return;
    const wx = (pointer.x - offset.x) / scale;
    const wy = (pointer.y - offset.y) / scale;
    setMarquee({
      x0: marqueeStart.current.x, y0: marqueeStart.current.y,
      x1: wx, y1: wy,
    });
  }, [offset, scale]);

  const commitMarquee = useCallback(() => {
    if (!marquee) return;
    const x0 = Math.min(marquee.x0, marquee.x1);
    const x1 = Math.max(marquee.x0, marquee.x1);
    const y0 = Math.min(marquee.y0, marquee.y1);
    const y1 = Math.max(marquee.y0, marquee.y1);
    const hits = events.filter(ev => {
      const i = rowIndex.get(ev.rowKey);
      if (i == null) return false;
      const evX = xForTs(ev.ts);
      const evY = (rowY[i] || 0) + ROW_H / 2;
      return evX >= x0 && evX <= x1 && evY >= y0 && evY <= y1;
    });
    setMarquee(null);
    marqueeStart.current = null;
    if (hits.length) {
      onSelect({ ...hits[0], _marquee_multi: hits.map(h => h.id) });
    }
  }, [marquee, events, rowIndex, rowY, xForTs, onSelect]);

  // ── Empty state ──
  if (!rows.length) {
    return (
      <div ref={wrapperRef} data-testid={testId}
           className="w-full h-full flex items-center justify-center text-[11px]"
           style={{ background: T.bg, color: T.textMute }}>
        {emptyMessage}
      </div>
    );
  }

  // ─── Render ────────────────────────────────────────────────────────
  return (
    <div ref={wrapperRef} data-testid={testId}
         className="relative w-full h-full overflow-hidden"
         style={{ background: T.bg, cursor: "grab" }}>
      <Stage
        ref={stageRef}
        width={size.w}
        height={size.h}
        draggable={!marqueeStart.current}
        x={offset.x}
        y={offset.y}
        scaleX={scale}
        scaleY={scale}
        onDragEnd={handleDragEnd}
        onWheel={handleWheel}
        onMouseDown={(e) => {
          const stage = e.target.getStage();
          const pointer = stage.getPointerPosition();
          if (e.target === stage) {
            if (e.evt.shiftKey) {
              beginMarquee(pointer);
              e.evt.preventDefault();
            } else {
              stage.container().style.cursor = "grabbing";
            }
          }
        }}
        onMouseMove={(e) => {
          if (marqueeStart.current) {
            const pointer = e.target.getStage().getPointerPosition();
            updateMarquee(pointer);
          }
        }}
        onMouseUp={(e) => {
          const stage = e.target.getStage();
          if (marqueeStart.current) {
            commitMarquee();
          }
          stage.container().style.cursor = "grab";
        }}
      >
        {/* Grid background layer */}
        <Layer listening={false}>
          <GridBackground contentW={CONTENT_W} contentH={canvasH} tokens={T} />
        </Layer>

        {/* Band header stripes */}
        <Layer listening={false}>
          {bands.map((b, i) => (
            <Group key={b.label + i}>
              <Rect x={0} y={b.top - BAND_H} width={CONTENT_W} height={BAND_H}
                    fill={T.band} />
              <Line points={[0, b.top, CONTENT_W, b.top]} stroke={T.border} strokeWidth={0.5} />
              <Text x={12} y={b.top - BAND_H + 5} text={b.label.toUpperCase()}
                    fontFamily="Inter, sans-serif" fontStyle="600"
                    fontSize={9} letterSpacing={1.5} fill={T.textDim} />
              <Text x={CONTENT_W - 40} y={b.top - BAND_H + 5} text={String(b.rows.length)}
                    fontFamily="'IBM Plex Mono', monospace"
                    fontSize={9} fill={T.textMute} align="right" width={30} />
            </Group>
          ))}
        </Layer>

        {/* Lifelines */}
        <Layer listening={false}>
          {visibleRows.map((r) => {
            const i = rowIndex.get(r.key);
            const y = rowY[i] + ROW_H / 2;
            const x1 = xForTs(r.firstTs) - 4;
            const x2 = xForTs(r.lastTs)  + 4;
            const sel = selected != null && events.some(ev => ev.id === selected && ev.rowKey === r.key);
            const stroke = r.worstVerdict === "malicious" ? T.critical
                         : r.worstVerdict === "suspicious" ? T.warning
                         : sel ? T.lifeline : T.lifelineDim;
            return (
              <Line key={r.key}
                    points={[x1, y, x2, y]}
                    stroke={stroke}
                    strokeWidth={sel ? 1.6 : 0.8}
                    dash={[2, 3]}
                    opacity={sel ? 0.95 : 0.42}
                    shadowColor={sel ? T.selectGlow : undefined}
                    shadowBlur={sel ? 6 : 0}
                    shadowOpacity={sel ? 0.8 : 0} />
            );
          })}
        </Layer>

        {/* Spawn / parent-child edges */}
        <Layer listening={false}>
          {edges.map((edge, i) => {
            const fromRow = rowIndex.get(edge.from);
            const toRow   = rowIndex.get(edge.to);
            if (fromRow == null || toRow == null) return null;
            const y1 = rowY[fromRow] + ROW_H / 2;
            const y2 = rowY[toRow]   + ROW_H / 2;
            const toRowObj = rows[toRow];
            const x = xForTs(toRowObj.firstTs);
            return (
              <Line key={i}
                    points={[x, y1, x, y2 - 5]}
                    stroke={T.border}
                    strokeWidth={0.8}
                    dash={[3, 3]}
                    opacity={0.6} />
            );
          })}
        </Layer>

        {/* Event glyphs */}
        <Layer>
          {visibleEvents.map((ev) => {
            const i = rowIndex.get(ev.rowKey);
            const x = xForTs(ev.ts);
            const y = rowY[i] + ROW_H / 2;
            const sel = ev.id === selected;
            return (
              <EventGlyph key={ev.id}
                          ev={ev} x={x} y={y}
                          selected={sel}
                          tokens={T}
                          onSelect={onSelect} />
            );
          })}
        </Layer>

        {/* Marquee selection rectangle (Shift+drag on empty canvas) */}
        {marquee && (
          <Layer listening={false}>
            <Rect
              x={Math.min(marquee.x0, marquee.x1)}
              y={Math.min(marquee.y0, marquee.y1)}
              width={Math.abs(marquee.x1 - marquee.x0)}
              height={Math.abs(marquee.y1 - marquee.y0)}
              stroke={T.selectGlow}
              strokeWidth={1 / scale}
              dash={[4 / scale, 3 / scale]}
              fill={`${T.selectGlow}18`}
            />
          </Layer>
        )}
      </Stage>

      {/* Overlay controls */}
      <CanvasControls scale={scale} onFit={fitToContent}
                      onZoomIn={() => zoomBy(1.15)} onZoomOut={() => zoomBy(1/1.15)}
                      tokens={T} />

      {/* Minimap */}
      {minimap && rows.length > 0 && (
        <Minimap
          rows={rows} rowY={rowY} events={events} rowIndex={rowIndex}
          xForTs={xForTs} contentW={CONTENT_W} contentH={canvasH}
          scale={scale} offset={offset} size={size}
          setOffset={(o) => setOffset(clampOffset(o, scale, size, canvasH, CONTENT_W))}
          tokens={T} />
      )}

      {/* Scrollbars — synthetic, driven by offset state */}
      <ScrollBars
        offset={offset} scale={scale} size={size}
        contentW={CONTENT_W} contentH={canvasH}
        onScroll={(o) => setOffset(clampOffset(o, scale, size, canvasH, CONTENT_W))}
        tokens={T} />
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// GridBackground — very subtle vertical hour columns
// ═══════════════════════════════════════════════════════════════════
function GridBackground({ contentW, contentH, tokens }) {
  const lines = [];
  const step = 48;
  for (let x = step; x < contentW; x += step) {
    lines.push(
      <Line key={x} points={[x, 0, x, contentH]}
            stroke={tokens.grid} strokeWidth={0.4} opacity={0.35} />
    );
  }
  return <>{lines}</>;
}

// ═══════════════════════════════════════════════════════════════════
// EventGlyph — tiny circle + verdict ring + activity mark inside
// ═══════════════════════════════════════════════════════════════════
function EventGlyph({ ev, x, y, selected, tokens: T, onSelect }) {
  const isMal = ev.verdict === "malicious";
  const ring = isMal ? T.critical
             : ev.verdict === "suspicious" ? T.warning
             : T.textDim;
  const mark = isMal ? "#FCA5A5" : "#FFFFFF";
  const [hovered, setHovered] = useState(false);
  const r = GLYPH / 2;

  return (
    <Group x={x} y={y}
           onClick={() => onSelect(ev)}
           onTap={() => onSelect(ev)}
           onMouseEnter={(e) => { setHovered(true); e.target.getStage().container().style.cursor = "pointer"; }}
           onMouseLeave={(e) => { setHovered(false); e.target.getStage().container().style.cursor = "grab"; }}
           scaleX={hovered ? 1.3 : 1} scaleY={hovered ? 1.3 : 1}
           shadowColor={selected ? T.selectGlow : (isMal ? T.critical : undefined)}
           shadowBlur={selected ? 10 : (isMal ? 3 : 0)}
           shadowOpacity={selected ? 0.9 : (isMal ? 0.6 : 0)}>
      <Circle radius={r}
              fill={isMal ? "#3B0F14" : T.bg}
              stroke={selected ? T.selectGlow : ring}
              strokeWidth={selected ? 1.5 : 1.1} />
      <ActivityMark kind={ev.kind} color={mark} />
    </Group>
  );
}

function ActivityMark({ kind, color }) {
  const w = 1.4;
  switch (kind) {
    case "execute":
      return <Line points={[-2.2, -3, -2.2, 3, 3, 0]} closed fill={color} />;
    case "create":
      return (
        <>
          <Line points={[-3, 0, 3, 0]} stroke={color} strokeWidth={w} />
          <Line points={[0, -3, 0, 3]} stroke={color} strokeWidth={w} />
        </>
      );
    case "delete":
      return (
        <>
          <Line points={[-3, -3, 3, 3]} stroke={color} strokeWidth={w} />
          <Line points={[-3, 3, 3, -3]} stroke={color} strokeWidth={w} />
        </>
      );
    case "network":
      return (
        <>
          <Line points={[-3, -1.5, 3, -1.5]} stroke={color} strokeWidth={w} />
          <Line points={[1.5, -3, 3, -1.5, 1.5, 0]} stroke={color} strokeWidth={w} />
          <Line points={[-3, 1.5, 3, 1.5]} stroke={color} strokeWidth={w} />
          <Line points={[-1.5, 3, -3, 1.5, -1.5, 0]} stroke={color} strokeWidth={w} />
        </>
      );
    case "registry":
      return <Rect x={-3} y={-3} width={6} height={6} stroke={color} strokeWidth={w} />;
    case "file":
      return <Path data="M -2.5 -3.5 L 1.5 -3.5 L 2.5 -2.5 L 2.5 3.5 L -2.5 3.5 Z"
                   stroke={color} strokeWidth={w} />;
    case "compromise":
      return <Text x={-3} y={-4} text="!" fontSize={9} fontStyle="900" fill={color}
                   fontFamily="Inter, sans-serif" align="center" width={6} />;
    case "detect":
      return <Circle radius={2} fill={color} />;
    default:
      return <Circle radius={1.8} fill={color} />;
  }
}

// ═══════════════════════════════════════════════════════════════════
// Minimap — bottom-right, live viewport rectangle
// ═══════════════════════════════════════════════════════════════════
function Minimap({
  rows, rowY, events, rowIndex, xForTs,
  contentW, contentH, scale, offset, size, setOffset, tokens: T,
}) {
  const W = 168, H = 96;
  const sX = W / contentW;
  const sY = H / Math.max(contentH, 1);

  const vpW = size.w / scale * sX;
  const vpH = size.h / scale * sY;
  const vpX = -offset.x / scale * sX;
  const vpY = -offset.y / scale * sY;

  const onDown = (e) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const relX = e.clientX - rect.left;
    const relY = e.clientY - rect.top;
    const newX = -(relX / sX - size.w / scale / 2) * scale;
    const newY = -(relY / sY - size.h / scale / 2) * scale;
    setOffset({ x: newX, y: newY });
  };

  return (
    <div className="absolute bottom-3 right-3 pointer-events-auto"
         style={{
           width: W, height: H,
           background: T.band, border: `1px solid ${T.border}`,
           borderRadius: 3, overflow: "hidden",
           boxShadow: "0 8px 20px -6px rgba(0,0,0,0.7)",
         }}
         onMouseDown={onDown}
         data-testid="canvas-minimap">
      {/* Event dots */}
      <svg width={W} height={H} style={{ position: "absolute", inset: 0 }}>
        {events.slice(0, 3000).map(ev => {
          const i = rowIndex.get(ev.rowKey);
          if (i == null) return null;
          const c = ev.verdict === "malicious" ? T.critical
                  : ev.verdict === "suspicious" ? T.warning
                  : T.lifelineDim;
          return (
            <circle key={ev.id}
                    cx={xForTs(ev.ts) * sX}
                    cy={(rowY[i] + ROW_H / 2) * sY}
                    r={0.9}
                    fill={c} />
          );
        })}
        {/* Viewport rectangle */}
        <rect x={vpX} y={vpY} width={vpW} height={vpH}
              fill="none" stroke={T.selectGlow} strokeWidth={1} />
      </svg>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// Canvas Controls (top-right FIT / zoom in / out / percent)
// ═══════════════════════════════════════════════════════════════════
function CanvasControls({ scale, onFit, onZoomIn, onZoomOut, tokens: T }) {
  const btn = {
    background: T.band2, color: T.text,
    border: `1px solid ${T.border}`, borderRadius: 3,
    fontFamily: "'IBM Plex Mono', ui-monospace, monospace",
    fontSize: 10, padding: "3px 6px", cursor: "pointer",
  };
  return (
    <div className="absolute top-3 right-3 flex items-center gap-1 pointer-events-auto"
         data-testid="canvas-controls">
      <button data-testid="canvas-zoom-out" onClick={onZoomOut} style={btn}>−</button>
      <button data-testid="canvas-fit" onClick={onFit} style={btn}>FIT</button>
      <button data-testid="canvas-zoom-in" onClick={onZoomIn} style={btn}>+</button>
      <span style={{
        ...btn, color: T.textDim, cursor: "default", minWidth: 42, textAlign: "center",
      }}>
        {Math.round(scale * 100)}%
      </span>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// ScrollBars — synthetic, driven by offset/scale state
// ═══════════════════════════════════════════════════════════════════
function ScrollBars({ offset, scale, size, contentW, contentH, onScroll, tokens: T }) {
  const trackStyle = { background: `${T.border}33`, borderRadius: 2 };
  const thumbStyle = { background: T.textMute, borderRadius: 2, opacity: 0.7 };

  // Horizontal
  const cW = contentW * scale;
  const hLen = Math.max(30, (size.w / cW) * (size.w - 24));
  const hMax = size.w - 24 - hLen;
  const hPos = cW <= size.w ? 0 : (-offset.x / (cW - size.w)) * hMax;

  const cH = contentH * scale;
  const vLen = Math.max(30, (size.h / cH) * (size.h - 40));
  const vMax = size.h - 40 - vLen;
  const vPos = cH <= size.h ? 0 : (-offset.y / (cH - size.h)) * vMax;

  const dragRef = useRef(null);
  const onHDown = (e) => {
    const startX = e.clientX;
    const startOff = offset.x;
    const onMove = (m) => {
      const dx = m.clientX - startX;
      const nOff = startOff - (dx / hMax) * (cW - size.w);
      onScroll({ x: nOff, y: offset.y });
    };
    const onUp = () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  };
  const onVDown = (e) => {
    const startY = e.clientY;
    const startOff = offset.y;
    const onMove = (m) => {
      const dy = m.clientY - startY;
      const nOff = startOff - (dy / vMax) * (cH - size.h);
      onScroll({ x: offset.x, y: nOff });
    };
    const onUp = () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  };

  return (
    <>
      {/* Horizontal */}
      {cW > size.w && (
        <div className="absolute pointer-events-auto"
             style={{ ...trackStyle, left: 0, right: 16, bottom: 4, height: 6 }}
             data-testid="canvas-hscroll">
          <div style={{ ...thumbStyle, position: "absolute", top: 0, height: 6,
                        left: hPos, width: hLen, cursor: "grab" }}
               onMouseDown={onHDown} />
        </div>
      )}
      {/* Vertical */}
      {cH > size.h && (
        <div className="absolute pointer-events-auto"
             style={{ ...trackStyle, top: 0, bottom: 16, right: 4, width: 6 }}
             data-testid="canvas-vscroll">
          <div style={{ ...thumbStyle, position: "absolute", left: 0, width: 6,
                        top: vPos, height: vLen, cursor: "grab" }}
               onMouseDown={onVDown} />
        </div>
      )}
    </>
  );
}
