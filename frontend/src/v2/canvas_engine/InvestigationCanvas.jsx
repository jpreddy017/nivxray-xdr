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

// ─── Defaults (Light · glassy-white analyst theme) ────────────────────
const DEFAULT_TOKENS = {
  bg:          "#F5F7FA",   // page canvas
  bg2:         "#FFFFFF",   // pure card white
  grid:        "#D9DEE5",
  gridDim:     "#E4E7ED",
  band:        "#EEF1F5",   // band header stripe
  band2:       "#F7F9FC",
  border:      "#C7CED8",
  text:        "#0F172A",
  textDim:     "#475569",
  textMute:    "#94A3B8",
  link:        "#2563EB",
  success:     "#059669",   // green (create)
  warning:     "#B7791F",   // amber (suspicious)
  critical:    "#DC2626",   // red (malicious)
  lifeline:    "#94A3B8",
  lifelineDim: "#D1D5DB",
  selectGlow:  "#2563EB",
};

const ROW_H  = 32;
const BAND_H = 24;
const AXIS_H = 22;   // time axis strip at top
const GLYPH  = 12;   // glyph diameter — SOC-analyst dense but readable
const LIFELINE_PAD = 20;

// Format a timestamp for time-axis labels.
function fmtTick(ms, span) {
  const d = new Date(ms);
  const pad = (n) => (n < 10 ? "0" + n : "" + n);
  if (span > 24 * 3600 * 1000)  return `${pad(d.getUTCMonth() + 1)}·${pad(d.getUTCDate())}`;
  if (span > 3600 * 1000)       return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
  return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
}

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

  // Row + band layout (rows start below the top time axis strip)
  const { rowY, canvasH, bands } = useMemo(() => {
    let y = AXIS_H + 4;
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
  // Content width sizes to the current viewport so at scale=1 the timeline
  // fills the visible area without wasted whitespace. Users zoom above 1
  // to expand a busy region.
  const CONTENT_W = Math.max(size.w - 24, 1000);
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

  // ── Hover state (screen-space tooltip position + event snapshot) ──
  const [hover, setHover] = useState(null);           // { ev, x, y } in screen coords
  const [hoverRow, setHoverRow] = useState(null);     // row.key (for row-band highlight)
  // ── Right-click context menu ──
  const [ctxMenu, setCtxMenu] = useState(null);       // { x, y, ev }

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
         style={{ background: T.bg2 || "#FFFFFF", cursor: "grab" }}
         onClick={() => setCtxMenu(null)}>
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
          <GridBackground contentW={CONTENT_W} contentH={canvasH} tokens={T}
                          minTs={minTs} maxTs={maxTs} xForTs={xForTs} />
        </Layer>

        {/* Row hover highlight — subtle full-width band, below everything else */}
        {hoverRow != null && rowIndex.get(hoverRow) != null && (
          <Layer listening={false}>
            <Rect x={0} y={rowY[rowIndex.get(hoverRow)]}
                  width={CONTENT_W} height={ROW_H}
                  fill={`${T.selectGlow}0F`} />
          </Layer>
        )}

        {/* Band header stripes with left-edge accent + count pill */}
        <Layer listening={false}>
          {bands.map((b, i) => {
            const evCount = b.rows.reduce((acc, r) => {
              return acc + events.filter(e => e.rowKey === r.key).length;
            }, 0);
            const accent = b.rows.some(r => r.worstVerdict === "malicious") ? T.critical
                         : b.rows.some(r => r.worstVerdict === "suspicious") ? T.warning
                         : T.selectGlow;
            return (
              <Group key={b.label + i}>
                <Rect x={0} y={b.top - BAND_H} width={CONTENT_W} height={BAND_H}
                      fill={T.band} />
                {/* Left accent stripe */}
                <Rect x={0} y={b.top - BAND_H} width={3} height={BAND_H}
                      fill={accent} opacity={0.85} />
                {/* Bottom hairline */}
                <Line points={[0, b.top, CONTENT_W, b.top]} stroke={T.border} strokeWidth={0.5} />
                {/* Band label */}
                <Text x={14} y={b.top - BAND_H + 6} text={b.label.toUpperCase()}
                      fontFamily="Inter, sans-serif" fontStyle="700"
                      fontSize={10} letterSpacing={1.8} fill={T.text} />
                {/* Row count */}
                <Text x={130} y={b.top - BAND_H + 6}
                      text={`${b.rows.length} ROW${b.rows.length === 1 ? "" : "S"}`}
                      fontFamily="'IBM Plex Mono', monospace"
                      fontSize={9} fill={T.textMute} letterSpacing={1} />
                {/* Event count pill (right side) */}
                <Text x={CONTENT_W - 60} y={b.top - BAND_H + 6}
                      text={`${evCount} EV`}
                      fontFamily="'IBM Plex Mono', monospace"
                      fontSize={9} fill={T.textDim} letterSpacing={1} />
              </Group>
            );
          })}
        </Layer>

        {/* Lifelines — SOLID ENTITY-LIFETIME BARS with inline label · verdict-colored */}
        <Layer>
          {visibleRows.map((r) => {
            const i = rowIndex.get(r.key);
            const y = rowY[i] + ROW_H / 2;
            const sel = selected != null && events.some(ev => ev.id === selected && ev.rowKey === r.key);
            const hov = hoverRow === r.key;
            const isMal = r.worstVerdict === "malicious";
            const isSus = r.worstVerdict === "suspicious";

            // Bar colors — bar body is subtle tint; stroke is verdict color.
            const stroke = isMal ? T.critical
                         : isSus ? T.warning
                         : (sel || hov) ? T.selectGlow : T.lifeline;
            const fill = isMal ? "#FEE2E2"
                       : isSus ? "#FEF3C7"
                       : "#EEF2F7";
            const barX0 = xForTs(r.firstTs) - 12;
            const barX1 = xForTs(r.lastTs)  + 12;
            const barY0 = y - ROW_H / 2 + 3;
            const barH  = ROW_H - 6;
            const barW  = Math.max(60, barX1 - barX0);

            return (
              <Group key={r.key}
                     onMouseEnter={() => setHoverRow(r.key)}
                     onMouseLeave={() => setHoverRow(null)}>
                {/* Faint full-row dashed baseline behind the bar (for empty ends) */}
                <Line points={[LIFELINE_PAD, y, CONTENT_W - LIFELINE_PAD, y]}
                      stroke={T.lifelineDim} strokeWidth={0.5}
                      dash={[1, 4]} opacity={0.25} listening={false} />
                {/* Entity-lifetime bar */}
                <Rect x={barX0} y={barY0}
                      width={barW} height={barH}
                      fill={fill}
                      stroke={stroke}
                      strokeWidth={sel || hov ? 1.4 : 1}
                      cornerRadius={barH / 2}
                      opacity={sel || hov ? 1 : 0.92}
                      shadowColor={sel ? T.selectGlow : (isMal ? T.critical : undefined)}
                      shadowBlur={sel ? 10 : (isMal ? 5 : 0)}
                      shadowOpacity={sel ? 0.7 : (isMal ? 0.3 : 0)} />
                {/* Inline entity label — small tag ABOVE the bar so events stay clean */}
                <Text x={barX0 + 2} y={barY0 - 10}
                      text={r.label || r.key}
                      fontFamily="Inter, -apple-system, BlinkMacSystemFont, sans-serif"
                      fontStyle="600"
                      fontSize={10}
                      fill={isMal ? T.critical : isSus ? T.warning : T.text}
                      listening={false} />
                {/* Event-count pill on the right side of the bar */}
                {r.events != null && (
                  <Text x={barX1 + 6} y={barY0 + 4}
                        text={""}
                        fontSize={9}
                        listening={false} />
                )}
              </Group>
            );
          })}
        </Layer>

        {/* Spawn / parent-child edges · right-angle L-shape with arrow */}
        <Layer listening={false}>
          {edges.map((edge, i) => {
            const fromIdx = rowIndex.get(edge.from);
            const toIdx   = rowIndex.get(edge.to);
            if (fromIdx == null || toIdx == null) return null;
            const y1 = rowY[fromIdx] + ROW_H / 2;
            const y2 = rowY[toIdx]   + ROW_H / 2;
            const toRowObj = rows[toIdx];
            const x = xForTs(toRowObj.firstTs);
            const going = y2 > y1;
            const arrowY = going ? y2 - 8 : y2 + 8;
            return (
              <Group key={i}>
                {/* Vertical connector */}
                <Line points={[x, y1, x, arrowY]}
                      stroke={T.selectGlow}
                      strokeWidth={1.4}
                      opacity={0.55} />
                {/* Arrowhead at child */}
                <Line points={[x - 3, arrowY, x, y2, x + 3, arrowY]}
                      stroke={T.selectGlow} strokeWidth={1.4}
                      opacity={0.7} lineCap="round" lineJoin="round" />
              </Group>
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
                          scale={scale}
                          onSelect={onSelect}
                          onHover={(scrPos) => { setHover({ ev, ...scrPos }); setHoverRow(ev.rowKey); }}
                          onLeave={() => { setHover(null); setHoverRow(null); }}
                          onContext={(scrPos) => setCtxMenu({ ev, ...scrPos })} />
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

      {/* Hover tooltip — floating card near the cursor */}
      {hover && !ctxMenu && (
        <HoverTooltip hover={hover} tokens={T} />
      )}

      {/* Right-click context menu */}
      {ctxMenu && (
        <ContextMenu
          ctx={ctxMenu} tokens={T}
          onSelect={onSelect}
          onClose={() => setCtxMenu(null)} />
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// GridBackground — hourly vertical rules + optional labeled ticks
// ═══════════════════════════════════════════════════════════════════
function GridBackground({ contentW, contentH, tokens, minTs, maxTs, xForTs }) {
  const lines = [];
  const step = 64;
  for (let x = step; x < contentW; x += step) {
    lines.push(
      <Line key={x} points={[x, 0, x, contentH]}
            stroke={tokens.grid} strokeWidth={0.5} opacity={0.5} />
    );
  }
  // Time axis strip at top
  const axis = [];
  if (minTs && maxTs && xForTs) {
    const span = maxTs - minTs;
    const ticks = 12;
    for (let i = 0; i <= ticks; i++) {
      const t = minTs + (span * i) / ticks;
      const x = xForTs(t);
      axis.push(
        <Group key={`ax-${i}`}>
          <Line points={[x, 0, x, 6]} stroke={tokens.textDim} strokeWidth={0.8} />
          <Text x={x - 24} y={7} width={48} align="center"
                text={fmtTick(t, span)}
                fontFamily="'IBM Plex Mono', ui-monospace, monospace"
                fontSize={9} fill={tokens.textDim} />
        </Group>
      );
    }
  }
  return (
    <>
      <Rect x={0} y={0} width={contentW} height={contentH} fill={tokens.bg2 || "#FFFFFF"} />
      {lines}
      {/* Axis strip background */}
      <Rect x={0} y={0} width={contentW} height={AXIS_H} fill={tokens.band} opacity={0.7} />
      <Line points={[0, AXIS_H, contentW, AXIS_H]} stroke={tokens.border} strokeWidth={0.5} />
      {axis}
    </>
  );
}

// ═══════════════════════════════════════════════════════════════════
// EventGlyph — activity-colored symbol (▶ red = malicious exec · + green = create · ✕ red = delete · ...)
// ═══════════════════════════════════════════════════════════════════
function EventGlyph({ ev, x, y, selected, tokens: T, scale = 1, onSelect,
                     onHover = () => {}, onLeave = () => {}, onContext = () => {} }) {
  const isMal = ev.verdict === "malicious";
  const isSus = ev.verdict === "suspicious";
  const [hovered, setHovered] = useState(false);
  const hasMitre = ev.mitre && ev.mitre.length > 0;

  // Per-activity color palette (verdict-aware where it makes sense).
  const activityColor = (() => {
    switch (ev.kind) {
      case "execute":    return isMal ? T.critical : (isSus ? T.warning : T.textDim);
      case "create":     return T.success;                // + is always green
      case "delete":     return T.critical;               // ✕ is always red
      case "network":    return isMal ? T.critical : T.link;
      case "registry":   return isSus ? T.warning : T.textDim;
      case "file":       return isMal ? T.critical : T.link;
      case "detect":     return T.warning;
      case "compromise": return T.critical;
      case "exploit":    return T.critical;
      case "scan":       return T.link;
      case "restore":    return T.success;
      default:           return isMal ? T.critical : (isSus ? T.warning : T.textDim);
    }
  })();
  const r = GLYPH / 2;
  // Soft tinted disc behind the mark — improves contrast on white bg.
  const discFill = isMal ? "#FEE2E2"
                 : isSus ? "#FEF3C7"
                 : ev.kind === "create" ? "#DCFCE7"
                 : "#F1F5F9";

  return (
    <Group x={x} y={y}
           onClick={() => onSelect(ev)}
           onTap={() => onSelect(ev)}
           onContextMenu={(e) => {
             e.evt.preventDefault();
             const stage = e.target.getStage();
             const pos = stage.getPointerPosition();
             const container = stage.container().getBoundingClientRect();
             onContext({ x: pos.x + container.left, y: pos.y + container.top });
           }}
           onMouseEnter={(e) => {
             setHovered(true);
             const stage = e.target.getStage();
             stage.container().style.cursor = "pointer";
             const pos = stage.getPointerPosition();
             const container = stage.container().getBoundingClientRect();
             onHover({ x: pos.x + container.left, y: pos.y + container.top });
           }}
           onMouseLeave={(e) => {
             setHovered(false);
             e.target.getStage().container().style.cursor = "grab";
             onLeave();
           }}
           scaleX={hovered ? 1.4 : 1} scaleY={hovered ? 1.4 : 1}
           shadowColor={selected ? T.selectGlow : (isMal ? T.critical : undefined)}
           shadowBlur={selected ? 14 : (isMal ? 5 : 0)}
           shadowOpacity={selected ? 0.85 : (isMal ? 0.35 : 0)}>
      {/* Selection halo */}
      {selected && (
        <Circle radius={r + 5}
                stroke={T.selectGlow} strokeWidth={1.2}
                opacity={0.6} />
      )}
      {/* Tinted disc for contrast on white */}
      <Circle radius={r}
              fill={discFill}
              stroke={selected ? T.selectGlow : activityColor}
              strokeWidth={selected ? 1.6 : 1.1}
              opacity={0.95} />
      <ActivityMark kind={ev.kind} color={activityColor} />
      {/* MITRE indicator — small red tick above the glyph */}
      {hasMitre && (
        <Rect x={-1} y={-r - 5} width={2} height={4} fill={T.critical} opacity={0.9} />
      )}
    </Group>
  );
}

function ActivityMark({ kind, color }) {
  const w = 1.6;
  switch (kind) {
    case "execute":
      // Right-facing filled triangle ▶
      return <Line points={[-2.5, -3, -2.5, 3, 3, 0]} closed fill={color} />;
    case "create":
      // Green + (bold plus sign)
      return (
        <>
          <Line points={[-3.2, 0, 3.2, 0]} stroke={color} strokeWidth={w + 0.2} lineCap="round" />
          <Line points={[0, -3.2, 0, 3.2]} stroke={color} strokeWidth={w + 0.2} lineCap="round" />
        </>
      );
    case "delete":
      // Bold red ✕
      return (
        <>
          <Line points={[-3, -3, 3, 3]} stroke={color} strokeWidth={w + 0.2} lineCap="round" />
          <Line points={[-3, 3, 3, -3]} stroke={color} strokeWidth={w + 0.2} lineCap="round" />
        </>
      );
    case "network":
      return (
        <>
          <Line points={[-3, -1.5, 3, -1.5]} stroke={color} strokeWidth={w} lineCap="round" />
          <Line points={[1.5, -3, 3, -1.5, 1.5, 0]} stroke={color} strokeWidth={w} lineCap="round" />
          <Line points={[-3, 1.5, 3, 1.5]} stroke={color} strokeWidth={w} lineCap="round" />
          <Line points={[-1.5, 3, -3, 1.5, -1.5, 0]} stroke={color} strokeWidth={w} lineCap="round" />
        </>
      );
    case "registry":
      return <Rect x={-3} y={-3} width={6} height={6} stroke={color} strokeWidth={w} cornerRadius={0.6} />;
    case "file":
      return <Path data="M -2.5 -3.5 L 1.5 -3.5 L 2.5 -2.5 L 2.5 3.5 L -2.5 3.5 Z"
                   stroke={color} strokeWidth={w} />;
    case "compromise":
      return <Text x={-3} y={-4} text="!" fontSize={10} fontStyle="900" fill={color}
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


// ═══════════════════════════════════════════════════════════════════
// HoverTooltip — floating card next to the hovered event glyph
// ═══════════════════════════════════════════════════════════════════
function HoverTooltip({ hover, tokens: T }) {
  const { ev, x, y } = hover;
  const isMal = ev.verdict === "malicious";
  const isSus = ev.verdict === "suspicious";
  const verdictPill = { background: isMal ? "#FEE2E2" : isSus ? "#FEF3C7" : "#F1F5F9",
                        color:      isMal ? T.critical : isSus ? T.warning  : T.textDim };
  const ts = new Date(ev.ts);
  const pad = (n) => (n < 10 ? "0" + n : "" + n);
  const tsStr = `${ts.getUTCFullYear()}-${pad(ts.getUTCMonth() + 1)}-${pad(ts.getUTCDate())} `
              + `${pad(ts.getUTCHours())}:${pad(ts.getUTCMinutes())}:${pad(ts.getUTCSeconds())} UTC`;
  return (
    <div className="fixed pointer-events-none z-50"
         style={{
           left: x + 14, top: y + 14,
           background: T.bg2 || "#FFFFFF",
           border: `1px solid ${T.border}`,
           borderRadius: 6,
           boxShadow: "0 12px 32px -8px rgba(15,23,42,0.25), 0 4px 12px -2px rgba(15,23,42,0.12)",
           padding: "10px 12px",
           minWidth: 240, maxWidth: 360,
           fontFamily: "Inter, -apple-system, BlinkMacSystemFont, sans-serif",
         }}
         data-testid="canvas-hover-tooltip">
      <div className="flex items-center gap-2 mb-1.5">
        <span className="text-[9px] px-1.5 py-0.5 rounded uppercase font-bold tracking-wider"
              style={verdictPill}>
          {ev.verdict}
        </span>
        <span className="text-[10px] font-semibold uppercase tracking-wider"
              style={{ color: T.textDim }}>
          {ev.kind}
        </span>
      </div>
      <div className="text-[13px] font-semibold leading-tight mb-1"
           style={{ color: T.text }}>
        {ev.label || "—"}
      </div>
      <div className="text-[10px] tabular-nums"
           style={{ color: T.textMute, fontFamily: "'IBM Plex Mono', ui-monospace, monospace" }}>
        {tsStr}
      </div>
      {ev.mitre && ev.mitre.length > 0 && (
        <div className="flex flex-wrap gap-1 mt-2">
          {ev.mitre.slice(0, 6).map(t => (
            <span key={t} className="text-[9px] px-1.5 py-0.5 rounded font-semibold tabular-nums"
                  style={{
                    background: `${T.critical}18`, color: T.critical,
                    fontFamily: "'IBM Plex Mono', ui-monospace, monospace",
                  }}>{t}</span>
          ))}
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// ContextMenu — right-click actions for an event
// ═══════════════════════════════════════════════════════════════════
function ContextMenu({ ctx, tokens: T, onSelect, onClose }) {
  const { ev, x, y } = ctx;
  const items = [
    { label: "Focus this event", act: () => { onSelect(ev); onClose(); } },
    { label: "Copy event IID",   act: () => { navigator.clipboard?.writeText(ev.id || ""); onClose(); } },
    { label: "Copy timestamp",   act: () => { navigator.clipboard?.writeText(new Date(ev.ts).toISOString()); onClose(); } },
    { label: "Copy label",       act: () => { navigator.clipboard?.writeText(ev.label || ""); onClose(); } },
  ];
  return (
    <div className="fixed z-50 rounded-md py-1"
         style={{
           left: x, top: y,
           background: T.bg2 || "#FFFFFF",
           border: `1px solid ${T.border}`,
           boxShadow: "0 12px 32px -8px rgba(15,23,42,0.28), 0 4px 12px -2px rgba(15,23,42,0.14)",
           minWidth: 200,
           fontFamily: "Inter, -apple-system, BlinkMacSystemFont, sans-serif",
         }}
         data-testid="canvas-context-menu"
         onClick={(e) => e.stopPropagation()}>
      {items.map((it, i) => (
        <button key={i}
                onClick={it.act}
                className="w-full text-left px-3 py-1.5 text-[12px]"
                style={{ color: T.text, background: "transparent" }}
                onMouseEnter={(e) => e.currentTarget.style.background = `${T.selectGlow}15`}
                onMouseLeave={(e) => e.currentTarget.style.background = "transparent"}>
          {it.label}
        </button>
      ))}
    </div>
  );
}
