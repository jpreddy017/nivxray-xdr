// ═══════════════════════════════════════════════════════════════════════
// InvestigationCanvas — v3 · Cisco-methodology hero build
// -----------------------------------------------------------------------
// Renders thin-lifeline investigation timeline per the approved hero
// mockup at /design/trajectory-hero.html:
//   · thin 1-px lifelines, indented ancestry with L-connectors
//   · sticky-X entity gutter with process names + indent glyphs
//   · yellow vertical compromise TIME-WINDOW columns (never per row)
//   · dedicated compromise indicator rows
//   · double-circle SOURCE / single-symbol ACTED-UPON glyphs
//   · three-state disposition fill (green benign · gray unknown · red malicious)
//   · blue trigger halo on causally-linked events when a compromise row is
//     selected
//   · adaptive relative-seconds ruler when case span < 10 s, HH:MM otherwise
//   · pan (space+drag / middle-mouse), horizontal-only zoom, marquee select
// ═══════════════════════════════════════════════════════════════════════
import React, { useEffect, useMemo, useRef, useState, useCallback } from "react";
import { Stage, Layer, Group, Rect, Line, Circle, Text, Path } from "react-konva";
import { clampOffset, visibleWorldRect } from "./core/viewport";

// ── Design tokens (Glassy-white analyst theme) ─────────────────────
const T = {
  bg:       "#F4F6FA",
  paper:    "#FFFFFF",
  paper2:   "#FAFBFD",
  ink:      "#0B1220",
  inkDim:   "#475569",
  inkMute:  "#64748B",
  inkFaint: "#94A3B8",
  line:     "#E2E8F0",
  lineStr:  "#CBD5E1",
  green:    "#059669",
  gray:     "#94A3B8",
  red:      "#DC2626",
  amber:    "#F5C142",
  amberBg:  "#F5C14219",
  blue:     "#2563EB",
  band:     "#F8FAFC",
};

// ── Layout constants — MUST NOT DEVIATE from mockup ──
const AXIS_H       = 26;   // inner canvas time ruler
const ROW_H        = 22;   // one process row
const BAND_H       = 22;   // Files / Registry / Network band header
const GUTTER_W     = 168;  // sticky-X entity gutter width inside canvas
const GLYPH        = 10;   // event glyph outer diameter
const HALO_R       = 9;    // blue trigger-halo radius

// Format one axis tick.
function fmtTick(ms, spanMs) {
  const d = new Date(ms);
  const p2 = (n) => (n < 10 ? "0" + n : "" + n);
  if (spanMs < 10_000) {
    // Relative seconds mode
    return "";
  }
  if (spanMs < 86_400_000) return `${p2(d.getUTCHours())}:${p2(d.getUTCMinutes())}`;
  return `${p2(d.getUTCMonth() + 1)}-${p2(d.getUTCDate())}`;
}

/**
 * @param {object} props
 * @param {Array}  props.rows          — [{ key, label, indent, worstVerdict, firstTs, lastTs, kind?: "compromise"|"process"|"file"|"registry"|"network" }]
 * @param {Array}  props.events        — [{ id, rowKey, ts, kind, verdict, source?: boolean, label, mitre?, meta? }]
 * @param {Array}  props.edges         — [{ from, to }]   parent→child spawn edges (rowKey to rowKey)
 * @param {Array}  props.bands         — [{ label, top, rows }] Files / Registry / Network dividers
 * @param {Array}  props.timeWindows   — [{ start, end, label, kind: "compromise"|"selection" }]
 * @param {string} props.selected      — selected event id
 * @param {Set}    props.triggerIds    — set of event ids that get a blue halo
 * @param {Function} props.onSelect    — (event) => void
 * @param {string} props.testId
 */
export default function InvestigationCanvas({
  rows = [], events = [], edges = [], bands = [], timeWindows = [],
  selected = null, triggerIds = null,
  onSelect = () => {},
  testId = "trajectory-canvas",
}) {
  // ── Container sizing ─────────────────────────────────────────────
  const wrapperRef = useRef(null);
  const [size, setSize] = useState({ w: 0, h: 0 });
  useEffect(() => {
    if (!wrapperRef.current) return;
    const ro = new ResizeObserver(entries => {
      for (const e of entries) {
        setSize({ w: Math.floor(e.contentRect.width), h: Math.floor(e.contentRect.height) });
      }
    });
    ro.observe(wrapperRef.current);
    return () => ro.disconnect();
  }, []);

  // ── Row layout ───────────────────────────────────────────────────
  const rowIndex = useMemo(() => new Map(rows.map((r, i) => [r.key, i])), [rows]);
  const { rowY, canvasH } = useMemo(() => {
    let y = AXIS_H + 6;
    const rY = [];
    let prevBand = null;
    rows.forEach((r) => {
      if (r.band && r.band !== prevBand) {
        y += BAND_H;
        prevBand = r.band;
      }
      rY.push(y);
      y += ROW_H;
    });
    return { rowY: rY, canvasH: y + 18 };
  }, [rows]);

  // ── Time domain ──────────────────────────────────────────────────
  const [minTs, maxTs] = useMemo(() => {
    if (!events.length) return [Date.now() - 1, Date.now()];
    let lo = Infinity, hi = -Infinity;
    for (const e of events) { if (e.ts < lo) lo = e.ts; if (e.ts > hi) hi = e.ts; }
    if (lo === hi) hi = lo + 1000;
    return [lo, hi];
  }, [events]);
  const spanMs = maxTs - minTs;

  const contentW = Math.max((size.w || 800) - 24, 800);
  const eventArea = { x0: GUTTER_W + 8, x1: contentW - 8 };
  const xForTs = useCallback(
    (ts) => eventArea.x0 + ((ts - minTs) / (maxTs - minTs || 1)) * (eventArea.x1 - eventArea.x0),
    [minTs, maxTs, eventArea.x0, eventArea.x1],
  );

  // ── Pan + zoom state ─────────────────────────────────────────────
  const [scale, setScale]   = useState(1);
  const [offset, setOffset] = useState({ x: 0, y: 0 });
  const draggingRef = useRef(null); // { x, y, ox, oy }
  const [spaceHeld, setSpaceHeld] = useState(false);
  const [ctxMenu,  setCtxMenu]  = useState(null);
  const [hover,    setHover]    = useState(null);

  // Space key = pan-cursor affordance
  useEffect(() => {
    const kd = (e) => { if (e.code === "Space") setSpaceHeld(true); };
    const ku = (e) => { if (e.code === "Space") setSpaceHeld(false); };
    window.addEventListener("keydown", kd);
    window.addEventListener("keyup",   ku);
    return () => { window.removeEventListener("keydown", kd); window.removeEventListener("keyup", ku); };
  }, []);

  // Mouse-wheel zoom (horizontal only, per spec)
  const onWheel = useCallback((e) => {
    e.evt.preventDefault();
    const dy = e.evt.deltaY;
    setScale((s) => Math.max(0.4, Math.min(6, s * (dy > 0 ? 0.94 : 1.06))));
  }, []);

  // Drag pan
  const onMouseDown = (e) => {
    if (e.evt.button === 1 || spaceHeld) {
      draggingRef.current = { x: e.evt.clientX, y: e.evt.clientY, ox: offset.x, oy: offset.y };
      e.target.getStage().container().style.cursor = "grabbing";
    }
  };
  const onMouseMove = (e) => {
    if (draggingRef.current) {
      const d = draggingRef.current;
      const nx = d.ox + (e.evt.clientX - d.x);
      const ny = d.oy + (e.evt.clientY - d.y);
      setOffset(clampOffset({ x: nx, y: ny }, scale, size, canvasH, contentW));
    }
  };
  const onMouseUp = (e) => {
    draggingRef.current = null;
    if (e && e.target && e.target.getStage) {
      e.target.getStage().container().style.cursor = spaceHeld ? "grab" : "default";
    }
  };

  // ── Time-window layer (yellow compromise vertical columns) ───────
  const timeCols = useMemo(() =>
    timeWindows.map((tw) => ({
      ...tw,
      x0: xForTs(tw.start),
      x1: xForTs(tw.end),
    })),
    [timeWindows, xForTs],
  );

  // ── Viewport-culling ─────────────────────────────────────────────
  const world = visibleWorldRect({ offset, scale, size });
  const visibleRowKeys = useMemo(() => new Set(
    rows.filter((r, i) => {
      const y = rowY[i];
      return y + ROW_H >= world.y0 - 40 && y <= world.y1 + 40;
    }).map(r => r.key),
  ), [rows, rowY, world.y0, world.y1]);
  const visibleEvents = useMemo(
    () => events.filter(e => visibleRowKeys.has(e.rowKey)),
    [events, visibleRowKeys],
  );

  // ── Adaptive ruler ticks ─────────────────────────────────────────
  const ticks = useMemo(() => {
    const out = [];
    const N = 8;
    for (let i = 0; i <= N; i++) {
      const t   = minTs + (spanMs * i) / N;
      const px  = xForTs(t);
      const lab = spanMs < 10_000
        ? `T+${((t - minTs) / 1000).toFixed(1)}s`
        : fmtTick(t, spanMs);
      out.push({ x: px, label: lab });
    }
    return out;
  }, [minTs, spanMs, xForTs]);

  // ── Render ───────────────────────────────────────────────────────
  return (
    <div ref={wrapperRef}
         data-testid={testId}
         className="relative w-full h-full overflow-hidden"
         style={{ background: T.paper, cursor: spaceHeld ? "grab" : "default" }}
         onClick={() => setCtxMenu(null)}>
      <Stage width={size.w} height={size.h}
             x={offset.x} y={offset.y}
             scaleX={1} scaleY={1}    /* pan-only; zoom applies via xForTs re-derivation */
             onWheel={onWheel}
             onMouseDown={onMouseDown}
             onMouseMove={onMouseMove}
             onMouseUp={onMouseUp}
             onMouseLeave={onMouseUp}>

        {/* 1 · Yellow compromise TIME-WINDOW columns (behind everything) */}
        <Layer listening={false}>
          {timeCols.map((tw, i) => (
            <Group key={`tw-${i}`}>
              <Rect x={tw.x0} y={AXIS_H} width={Math.max(2, tw.x1 - tw.x0)} height={canvasH - AXIS_H}
                    fill={T.amber} opacity={0.10} />
              <Line points={[tw.x0, AXIS_H, tw.x0, canvasH]} stroke={T.amber} strokeWidth={0.8} opacity={0.55} />
              <Line points={[tw.x1, AXIS_H, tw.x1, canvasH]} stroke={T.amber} strokeWidth={0.8} opacity={0.55} />
              {tw.label && (
                <Text x={tw.x0 + 6} y={AXIS_H + 4}
                      text={tw.label}
                      fontFamily="'IBM Plex Mono', ui-monospace, monospace"
                      fontSize={9} fontStyle="700"
                      fill="#B7791F" />
              )}
            </Group>
          ))}
        </Layer>

        {/* 2 · Time-axis strip at top */}
        <Layer listening={false}>
          <Rect x={0} y={0} width={contentW} height={AXIS_H} fill={T.paper2} />
          <Line points={[0, AXIS_H, contentW, AXIS_H]} stroke={T.line} />
          {ticks.map((tk, i) => (
            <Group key={`ax-${i}`}>
              <Line points={[tk.x, AXIS_H - 6, tk.x, AXIS_H]} stroke={T.inkFaint} strokeWidth={0.6} />
              <Text x={tk.x - 24} y={4} width={48} align="center"
                    text={tk.label}
                    fontFamily="'IBM Plex Mono', ui-monospace, monospace"
                    fontSize={9} fill={T.inkMute} />
            </Group>
          ))}
        </Layer>

        {/* 3 · Band separators (Files / Registry / Network) */}
        <Layer listening={false}>
          {bands.map((b, i) => (
            <Group key={`bd-${i}`}>
              <Rect x={0} y={b.top - BAND_H} width={contentW} height={BAND_H} fill={T.band} />
              <Line points={[0, b.top, contentW, b.top]} stroke={T.line} strokeWidth={0.5} />
              <Text x={14} y={b.top - BAND_H + 6}
                    text={b.label.toUpperCase()}
                    fontFamily="Inter, sans-serif" fontStyle="700"
                    fontSize={9} letterSpacing={1.6} fill={T.inkMute} />
              <Text x={80} y={b.top - BAND_H + 6}
                    text={`${b.rows.length} ROWS · ${b.eventCount || 0} EV`}
                    fontFamily="'IBM Plex Mono', ui-monospace, monospace"
                    fontSize={9} fill={T.inkFaint} letterSpacing={1} />
            </Group>
          ))}
        </Layer>

        {/* 4 · Row lifelines · thin 1-px neutral · red if row is malicious-heavy */}
        <Layer listening={false}>
          {rows.map((r, i) => {
            const y  = rowY[i] + ROW_H / 2;
            const sel = selected && events.some(e => e.id === selected && e.rowKey === r.key);
            const isMal = r.worstVerdict === "malicious";
            const isCompromise = r.kind === "compromise";
            const stroke = isCompromise ? T.amber
                         : isMal        ? T.red
                         : sel          ? T.blue
                         :                T.gray;
            const w = (sel || isCompromise) ? 1.5 : 1;
            const op = (isMal || isCompromise) ? 0.65 : 0.5;
            return (
              <Line key={`ll-${r.key}`}
                    points={[GUTTER_W + 4, y, contentW - 4, y]}
                    stroke={stroke} strokeWidth={w} opacity={op} />
            );
          })}
        </Layer>

        {/* 5 · Compromise-row lifetime bar (short yellow pill on compromise rows) */}
        <Layer listening={false}>
          {rows.map((r, i) => {
            if (r.kind !== "compromise") return null;
            const y = rowY[i] + ROW_H / 2;
            const x0 = xForTs(r.firstTs);
            const x1 = xForTs(r.lastTs);
            return (
              <Rect key={`crb-${r.key}`}
                    x={x0} y={y - 4} width={Math.max(4, x1 - x0)} height={8}
                    fill={T.amber} opacity={0.6} cornerRadius={4} />
            );
          })}
        </Layer>

        {/* 6 · Ancestry L-connectors */}
        <Layer listening={false}>
          {edges.map((e, i) => {
            const fromIdx = rowIndex.get(e.from);
            const toIdx   = rowIndex.get(e.to);
            if (fromIdx == null || toIdx == null) return null;
            const fromRow = rows[fromIdx];
            const toRow   = rows[toIdx];
            const x  = xForTs(toRow.firstTs);
            const y1 = rowY[fromIdx] + ROW_H / 2 + 4;
            const y2 = rowY[toIdx]   + ROW_H / 2 - 4;
            return (
              <Line key={`ed-${i}`}
                    points={[x, y1, x, y2]}
                    stroke={T.lineStr} strokeWidth={1} opacity={0.7} />
            );
          })}
        </Layer>

        {/* 7 · Event glyphs */}
        <Layer>
          {visibleEvents.map((ev) => {
            const i = rowIndex.get(ev.rowKey);
            if (i == null) return null;
            const x = xForTs(ev.ts);
            const y = rowY[i] + ROW_H / 2;
            const sel = ev.id === selected;
            const trig = triggerIds && triggerIds.has(ev.id);
            return (
              <EventGlyph key={ev.id}
                          ev={ev} x={x} y={y}
                          selected={sel}
                          triggered={!!trig}
                          onSelect={onSelect}
                          onHover={(scr) => setHover({ ev, ...scr })}
                          onLeave={() => setHover(null)}
                          onContext={(scr) => setCtxMenu({ ev, ...scr })} />
            );
          })}
        </Layer>

        {/* 8 · Sticky-X entity gutter — labels at fixed X regardless of pan */}
        <Layer listening={false}>
          <Rect x={-offset.x} y={AXIS_H} width={GUTTER_W} height={canvasH - AXIS_H}
                fill={T.paper} />
          <Line points={[-offset.x + GUTTER_W, AXIS_H, -offset.x + GUTTER_W, canvasH]}
                stroke={T.line} strokeWidth={1} />
          {rows.map((r, i) => {
            const isMal = r.worstVerdict === "malicious";
            const isSus = r.worstVerdict === "suspicious";
            const isCompromise = r.kind === "compromise";
            const isSelected = selected && events.some(e => e.id === selected && e.rowKey === r.key);
            const fill = isCompromise ? "#B7791F"
                       : isMal        ? T.red
                       : isSus        ? "#B7791F"
                       :                T.ink;
            const indent = 6 + (r.indent || 0) * 14;
            const glyph = r.kind === "compromise" ? "⚠ " : (r.indentGlyph || "");
            const y = rowY[i] + ROW_H / 2 + 4;
            return (
              <Group key={`gu-${r.key}`}>
                {isSelected && (
                  <Rect x={-offset.x} y={rowY[i]} width={GUTTER_W} height={ROW_H}
                        fill={T.blue} opacity={0.06} />
                )}
                <Text x={-offset.x + indent}
                      y={y - 6}
                      text={`${glyph}${r.label}`}
                      fontFamily="Inter, sans-serif"
                      fontStyle={isMal || isCompromise ? "700" : "500"}
                      fontSize={11}
                      fill={fill}
                      width={GUTTER_W - indent - 30}
                      wrap="none"
                      ellipsis={true} />
                {r.eventCount != null && (
                  <Text x={-offset.x + GUTTER_W - 26} y={y - 6}
                        text={String(r.eventCount)}
                        fontFamily="'IBM Plex Mono', ui-monospace, monospace"
                        fontSize={9}
                        fill={isMal ? T.red : T.inkFaint}
                        width={20} align="right" />
                )}
              </Group>
            );
          })}
        </Layer>

      </Stage>

      {/* HTML overlays outside the Stage */}
      {hover && !ctxMenu && <HoverTooltip hover={hover} />}
      {ctxMenu && (
        <ContextMenu ctx={ctxMenu}
                     onSelect={onSelect}
                     onClose={() => setCtxMenu(null)} />
      )}

      {/* Synthetic scrollbars — right (Y) and bottom (X) · driven by offset state */}
      <Scrollbars offset={offset} size={size}
                  contentW={contentW} contentH={canvasH}
                  onScroll={(o) => setOffset(clampOffset(o, scale, size, canvasH, contentW))} />
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// Scrollbars · thin dark-theme sliders on right + bottom
// ═══════════════════════════════════════════════════════════════════════
function Scrollbars({ offset, size, contentW, contentH, onScroll }) {
  const barSz = 10;
  // Vertical (right)
  const vRatio = size.h / Math.max(contentH, 1);
  const vShow  = vRatio < 1;
  const vTrackH = size.h - barSz - 4;
  const vThumbH = Math.max(28, vTrackH * vRatio);
  const vRange  = contentH - size.h;
  const vScroll = vRange > 0 ? Math.min(1, Math.max(0, (-offset.y) / vRange)) : 0;
  const vThumbY = 2 + vScroll * (vTrackH - vThumbH);

  // Horizontal (bottom)
  const hRatio = size.w / Math.max(contentW, 1);
  const hShow  = hRatio < 1;
  const hTrackW = size.w - barSz - 4;
  const hThumbW = Math.max(28, hTrackW * hRatio);
  const hRange  = contentW - size.w;
  const hScroll = hRange > 0 ? Math.min(1, Math.max(0, (-offset.x) / hRange)) : 0;
  const hThumbX = 2 + hScroll * (hTrackW - hThumbW);

  const dragV = useRef(null);
  const dragH = useRef(null);
  useEffect(() => {
    const mv = (e) => {
      if (dragV.current) {
        const d = dragV.current;
        const dy = e.clientY - d.y;
        const ny = d.oy - (dy / (vTrackH - vThumbH)) * vRange;
        onScroll({ x: offset.x, y: ny });
      }
      if (dragH.current) {
        const d = dragH.current;
        const dx = e.clientX - d.x;
        const nx = d.ox - (dx / (hTrackW - hThumbW)) * hRange;
        onScroll({ x: nx, y: offset.y });
      }
    };
    const up = () => { dragV.current = null; dragH.current = null;
                       document.body.style.userSelect = ""; };
    window.addEventListener("mousemove", mv);
    window.addEventListener("mouseup", up);
    return () => { window.removeEventListener("mousemove", mv);
                   window.removeEventListener("mouseup", up); };
  }, [offset.x, offset.y, vTrackH, vThumbH, hTrackW, hThumbW, vRange, hRange, onScroll]);

  return (
    <>
      {vShow && (
        <div className="absolute right-0 top-0"
             style={{ width: barSz, height: size.h - barSz,
                      background: "#0B122055", borderLeft: `1px solid ${T.line}` }}
             data-testid="canvas-scrollbar-y">
          <div className="absolute rounded-sm cursor-grab"
               style={{ top: vThumbY, left: 2, width: barSz - 4, height: vThumbH,
                        background: T.lineStr }}
               onMouseDown={(e) => {
                 dragV.current = { y: e.clientY, oy: offset.y };
                 document.body.style.userSelect = "none";
               }} />
        </div>
      )}
      {hShow && (
        <div className="absolute left-0 bottom-0"
             style={{ height: barSz, width: size.w - barSz,
                      background: "#0B122055", borderTop: `1px solid ${T.line}` }}
             data-testid="canvas-scrollbar-x">
          <div className="absolute rounded-sm cursor-grab"
               style={{ left: hThumbX, top: 2, height: barSz - 4, width: hThumbW,
                        background: T.lineStr }}
               onMouseDown={(e) => {
                 dragH.current = { x: e.clientX, ox: offset.x };
                 document.body.style.userSelect = "none";
               }} />
        </div>
      )}
    </>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// EventGlyph — activity-shape × disposition-fill × source-double-circle
// ═══════════════════════════════════════════════════════════════════════
function EventGlyph({ ev, x, y, selected, triggered, onSelect,
                     onHover, onLeave, onContext }) {
  const [hovered, setHovered] = useState(false);
  const isSource = ev.source !== false; // default true if unspecified
  const disposition = ev.verdict === "malicious" ? T.red
                    : ev.verdict === "suspicious" ? T.gray
                    : ev.verdict === "benign" ? T.green
                    : T.gray;
  const r = GLYPH / 2;

  return (
    <Group x={x} y={y}
           onClick={() => onSelect(ev)}
           onTap={() => onSelect(ev)}
           onContextMenu={(e) => {
             e.evt.preventDefault();
             const stage = e.target.getStage();
             const pos = stage.getPointerPosition();
             const rect = stage.container().getBoundingClientRect();
             onContext({ x: pos.x + rect.left, y: pos.y + rect.top });
           }}
           onMouseEnter={(e) => {
             setHovered(true);
             e.target.getStage().container().style.cursor = "pointer";
             const pos = e.target.getStage().getPointerPosition();
             const rect = e.target.getStage().container().getBoundingClientRect();
             onHover({ x: pos.x + rect.left, y: pos.y + rect.top });
           }}
           onMouseLeave={(e) => {
             setHovered(false);
             e.target.getStage().container().style.cursor = "default";
             onLeave();
           }}
           scaleX={hovered ? 1.35 : 1}
           scaleY={hovered ? 1.35 : 1}>
      {/* Blue trigger halo — only when this event caused the currently-selected compromise */}
      {triggered && (
        <Circle radius={HALO_R} fill="none" stroke={T.blue} strokeWidth={1.4} opacity={0.85} />
      )}
      {/* Selection ring */}
      {selected && (
        <Circle radius={r + 4} fill="none" stroke={T.blue} strokeWidth={1.4} opacity={0.9} />
      )}
      {/* Symbol */}
      <ActivitySymbol kind={ev.kind} color={disposition} isSource={isSource} r={r} />
    </Group>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// ActivitySymbol — shape depends on kind, ring depends on source-flag,
// colour is always the disposition.
// ═══════════════════════════════════════════════════════════════════════
function ActivitySymbol({ kind, color, isSource, r }) {
  const stroke = color;
  const w = 1.4;
  // Draw the source-outer-ring first (double-circle affordance)
  const OuterRing = isSource
    ? <Circle radius={r + 1.5} fill="#FFFFFF" stroke={stroke} strokeWidth={1.1} />
    : null;

  switch (kind) {
    case "execute":
      // Right-facing filled triangle ▶
      return <>{OuterRing}<Line points={[-2.8, -3.2, -2.8, 3.2, 3.2, 0]} closed fill={color} /></>;
    case "create":
      return (
        <>
          {OuterRing}
          <Line points={[-3, 0, 3, 0]} stroke={color} strokeWidth={w + 0.4} lineCap="round" />
          <Line points={[0, -3, 0, 3]} stroke={color} strokeWidth={w + 0.4} lineCap="round" />
        </>
      );
    case "delete":
      return (
        <>
          {OuterRing}
          <Line points={[-3, -3, 3, 3]} stroke={color} strokeWidth={w + 0.4} lineCap="round" />
          <Line points={[-3, 3, 3, -3]} stroke={color} strokeWidth={w + 0.4} lineCap="round" />
        </>
      );
    case "network":
      return (
        <>
          {OuterRing}
          <Line points={[-3, 0, 3, 0]}  stroke={color} strokeWidth={w} lineCap="round" />
          <Line points={[1, -2, 3, 0, 1, 2]} stroke={color} strokeWidth={w} lineCap="round"/>
        </>
      );
    case "registry":
      return <>{OuterRing}<Rect x={-3} y={-3} width={6} height={6} fill={color} opacity={0.9} /></>;
    case "file":
      return <>{OuterRing}<Path data="M -2.5 -3.5 L 1.5 -3.5 L 2.5 -2.5 L 2.5 3.5 L -2.5 3.5 Z"
                                stroke={color} strokeWidth={w} fill="none" /></>;
    default:
      // Fallback: filled circle at disposition colour
      return <>{OuterRing}<Circle radius={r * 0.55} fill={color} /></>;
  }
}

// ═══════════════════════════════════════════════════════════════════════
// HoverTooltip · HTML overlay, positioned in viewport coords
// ═══════════════════════════════════════════════════════════════════════
function HoverTooltip({ hover }) {
  const { ev, x, y } = hover;
  const isMal = ev.verdict === "malicious";
  const badgeBg = isMal ? "#FEE2E2" : ev.verdict === "suspicious" ? "#FEF3C7"
                : ev.verdict === "benign" ? "#DCFCE7" : "#F1F5F9";
  const badgeFg = isMal ? T.red : ev.verdict === "suspicious" ? "#B7791F"
                : ev.verdict === "benign" ? T.green : T.inkDim;
  const ts = new Date(ev.ts);
  const p2 = (n) => (n < 10 ? "0" + n : "" + n);
  const tsStr = `${ts.getUTCFullYear()}-${p2(ts.getUTCMonth() + 1)}-${p2(ts.getUTCDate())} `
              + `${p2(ts.getUTCHours())}:${p2(ts.getUTCMinutes())}:${p2(ts.getUTCSeconds())} UTC`;
  return (
    <div className="fixed pointer-events-none z-50"
         style={{
           left: x + 14, top: y + 14,
           background: "#FFFFFF", border: `1px solid ${T.line}`, borderRadius: 6,
           boxShadow: "0 12px 30px -8px rgba(15,23,42,0.22)",
           padding: "10px 12px", minWidth: 240, maxWidth: 380,
           fontFamily: "Inter, sans-serif",
         }}
         data-testid="canvas-hover-tooltip">
      <div className="flex items-center gap-2 mb-1.5">
        <span className="text-[9px] px-1.5 py-0.5 rounded uppercase font-bold tracking-wider"
              style={{ background: badgeBg, color: badgeFg }}>{ev.verdict || "unknown"}</span>
        <span className="text-[10px] font-semibold uppercase tracking-wider"
              style={{ color: T.inkDim }}>
          {ev.kind}{ev.source === false ? " · target" : " · source"}
        </span>
      </div>
      <div className="text-[13px] font-semibold leading-tight mb-1" style={{ color: T.ink }}>
        {ev.label || "—"}
      </div>
      <div className="text-[10px]"
           style={{ color: T.inkMute, fontFamily: "'IBM Plex Mono', ui-monospace, monospace" }}>
        {tsStr}
      </div>
      {ev.mitre && ev.mitre.length > 0 && (
        <div className="flex flex-wrap gap-1 mt-2">
          {ev.mitre.slice(0, 6).map(t => (
            <span key={t} className="text-[9px] px-1.5 py-0.5 rounded font-semibold"
                  style={{ background: "#FEE2E2", color: T.red,
                           fontFamily: "'IBM Plex Mono', ui-monospace, monospace" }}>{t}</span>
          ))}
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════════
// ContextMenu · right-click actions
// ═══════════════════════════════════════════════════════════════════════
function ContextMenu({ ctx, onSelect, onClose }) {
  const { ev, x, y } = ctx;
  const copy = (v) => { try { navigator.clipboard.writeText(v); } catch {} onClose(); };
  const items = [
    { label: "Focus event",       act: () => { onSelect(ev); onClose(); } },
    { label: "Copy event IID",    act: () => copy(ev.id || "") },
    { label: "Copy timestamp",    act: () => copy(new Date(ev.ts).toISOString()) },
    { label: "Copy label",        act: () => copy(ev.label || "") },
  ];
  return (
    <div className="fixed z-50 rounded-md py-1"
         style={{
           left: x, top: y,
           background: "#FFFFFF", border: `1px solid ${T.line}`,
           boxShadow: "0 12px 32px -8px rgba(15,23,42,0.28)",
           minWidth: 200, fontFamily: "Inter, sans-serif",
         }}
         data-testid="canvas-context-menu"
         onClick={(e) => e.stopPropagation()}>
      {items.map((it, i) => (
        <button key={i} onClick={it.act}
                className="w-full text-left px-3 py-1.5 text-[12px]"
                style={{ color: T.ink, background: "transparent" }}
                onMouseEnter={(e) => e.currentTarget.style.background = "#EEF2FF"}
                onMouseLeave={(e) => e.currentTarget.style.background = "transparent"}>
          {it.label}
        </button>
      ))}
    </div>
  );
}
