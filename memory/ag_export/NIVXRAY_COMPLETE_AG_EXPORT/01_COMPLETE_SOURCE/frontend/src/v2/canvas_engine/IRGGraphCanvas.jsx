/*
 * IRGGraphCanvas — hierarchical node-and-edge graph rendered on Konva.
 *
 * X axis: case-time (shared viewport, in sync with TimeRangeBox / Device
 *   Trajectory).
 * Y axis: execution depth from the synthetic explorer.exe root.
 * Nodes:   entities (process / file / registry / network) drawn as pills.
 * Edges:   parent → child relationships (SPAWNED, WROTE, CONNECTED, …).
 */
import { useEffect, useMemo, useRef, useState, useCallback } from "react";
import { Stage, Layer, Line, Circle, Rect, Text, Group } from "react-konva";
import { T } from "../theme";

const NODE_H     = 22;
const NODE_MIN_W = 92;
const AXIS_H     = 26;
const ROW_GAP    = 60;
// Left/right gutter must reserve at least half a node width plus a
// small margin so the first / last node on any depth row is fully
// visible instead of being clipped by the Stage edge.
const PAD_X      = NODE_MIN_W / 2 + 14;   // 60px — was 24 (clipped nodes)

const TYPE_COLOR = {
  process:  T.ink,
  file:     T.blue,
  registry: "#B7791F",
  network:  "#0E7C61",
  unknown:  T.inkMute,
};

const REL_LABEL = {
  SPAWNED: "spawned", WROTE: "wrote", READ: "read",
  DELETED: "deleted", MODIFIED: "modified", RENAMED: "renamed",
  CONNECTED: "connected", REGISTRY_WRITE: "reg-write",
  LOADED: "loaded", INJECTED: "injected", THREAD_CREATE: "thread",
};

function tsMs(ts) {
  if (ts == null) return null;
  if (typeof ts === "number") return ts > 1e12 ? ts : ts * 1000;
  const s = String(ts).endsWith("Z") ? ts : ts + "Z";
  const t = Date.parse(s);
  return Number.isFinite(t) ? t : null;
}

export default function IRGGraphCanvas({
  nodes = [], edges = [],
  selected = null,
  focusRange = null,
  onViewportChange = () => {},
  onSelect = () => {},
}) {
  const wrapRef = useRef(null);
  const [size, setSize] = useState({ w: 800, h: 400 });
  useEffect(() => {
    if (!wrapRef.current) return;
    const el = wrapRef.current;
    const update = () => setSize({ w: el.clientWidth, h: el.clientHeight });
    update();
    const ro = new ResizeObserver(update);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // Compute case time bounds from all nodes' first_seen / last_seen.
  const bounds = useMemo(() => {
    let lo = Infinity, hi = -Infinity;
    for (const n of nodes) {
      const a = tsMs(n.first_seen), b = tsMs(n.last_seen);
      if (a != null && a < lo) lo = a;
      if (b != null && b > hi) hi = b;
    }
    if (!Number.isFinite(lo)) lo = 0;
    if (!Number.isFinite(hi)) hi = lo + 1;
    if (lo === hi) hi = lo + 1;
    return { start: lo, end: hi };
  }, [nodes]);

  // Depth buckets — spread nodes vertically by depth level.
  const maxDepth = useMemo(
    () => nodes.reduce((m, n) => Math.max(m, n.depth || 0), 0),
    [nodes],
  );

  // Viewport (case-time window we render).
  const [hZoom, setHZoom] = useState(1);
  const [hPan,  setHPan]  = useState(0);
  const contentW = size.w;
  const worldW   = Math.max(1, (contentW - PAD_X * 2) * hZoom);
  const minTs    = bounds.start;
  const maxTs    = bounds.end;
  const viewMinTs = minTs + (hPan / worldW) * (maxTs - minTs);
  const viewMaxTs = viewMinTs + ((contentW - PAD_X * 2) / worldW) * (maxTs - minTs);

  // Sync focusRange (from parent) → hZoom / hPan.
  useEffect(() => {
    if (!focusRange) return;
    const spn = Math.max(1, maxTs - minTs);
    const winSpn = Math.max(1, focusRange.end - focusRange.start);
    const nz = Math.max(1, Math.min(500, spn / winSpn));
    const nWorldW = (contentW - PAD_X * 2) * nz;
    const np = Math.max(0, Math.min(Math.max(0, nWorldW - (contentW - PAD_X * 2)),
                                    ((focusRange.start - minTs) / spn) * nWorldW));
    setHZoom(nz); setHPan(np);
  }, [focusRange, minTs, maxTs, contentW]);

  // Emit viewport upstream.
  const lastRef = useRef({ s: 0, e: 0 });
  useEffect(() => {
    const s = Math.round(viewMinTs), e = Math.round(viewMaxTs);
    if (lastRef.current.s === s && lastRef.current.e === e) return;
    lastRef.current = { s, e };
    onViewportChange({ start: viewMinTs, end: viewMaxTs });
  }, [viewMinTs, viewMaxTs, onViewportChange]);

  // Positions
  const rowY = useMemo(() => {
    const arr = [];
    for (let d = 0; d <= maxDepth; d++) {
      arr.push(AXIS_H + 22 + d * ROW_GAP);
    }
    return arr;
  }, [maxDepth]);
  const canvasH = AXIS_H + 40 + (maxDepth + 1) * ROW_GAP;

  const xForTs = useCallback((ts) => {
    const t = tsMs(ts);
    if (t == null) return PAD_X;
    return PAD_X + ((t - minTs) / (maxTs - minTs || 1)) * worldW - hPan;
  }, [minTs, maxTs, worldW, hPan]);

  // Layout: place each node at (xForTs(first_seen), rowY[depth]).
  // When nodes at the same depth collide (data is sub-second dense), stagger
  // them horizontally so every node is visible instead of being stacked.
  const laid = useMemo(() => {
    const out = new Map();
    const perDepth = new Map();
    nodes.forEach(n => {
      const d = n.depth || 0;
      const list = perDepth.get(d) || [];
      list.push(n); perDepth.set(d, list);
    });
    const STEP = NODE_MIN_W + 22;
    for (const [d, list] of perDepth.entries()) {
      list.sort((a, b) => {
        const ta = tsMs(a.first_seen) || 0, tb = tsMs(b.first_seen) || 0;
        return ta - tb || (a.name || "").localeCompare(b.name || "");
      });
      let lastX = -Infinity;
      list.forEach((n) => {
        let x = xForTs(n.first_seen);
        if (x - lastX < STEP) x = lastX + STEP;   // avoid overlap
        lastX = x;
        out.set(n.iid, { x, y: rowY[d] || 40, node: n });
      });
    }
    return out;
  }, [nodes, xForTs, rowY]);

  // Wheel : Ctrl+wheel = zoom, Shift+wheel = hpan.
  const onWheel = (e) => {
    e.evt.preventDefault();
    const dy = e.evt.deltaY;
    if (e.evt.ctrlKey || e.evt.metaKey) {
      const stg = e.target.getStage();
      const pos = stg.getPointerPosition();
      const cx = pos ? pos.x : contentW / 2;
      const localX = cx - PAD_X;
      const cursorTs = minTs + ((localX + hPan) / worldW) * (maxTs - minTs);
      const factor = dy > 0 ? 0.9 : 1.1;
      setHZoom(z => {
        const next = Math.max(1, Math.min(500, z * factor));
        const nWorldW = (contentW - PAD_X * 2) * next;
        const nCursorWorldX = ((cursorTs - minTs) / (maxTs - minTs || 1)) * nWorldW;
        setHPan(Math.max(0, Math.min(Math.max(0, nWorldW - (contentW - PAD_X * 2)),
                                     nCursorWorldX - localX)));
        return next;
      });
      return;
    }
    // Plain wheel or Shift+wheel = horizontal pan.
    const delta = dy * 0.6;
    setHPan(p => Math.max(0, Math.min(Math.max(0, worldW - (contentW - PAD_X * 2)), p + delta)));
  };

  const dragRef = useRef(null);
  const onMouseDown = (e) => {
    const isBg = e.target === e.target.getStage() ||
                 (e.target.getAttr && !e.target.getAttr("name"));
    if (isBg || e.evt.button === 1) {
      dragRef.current = { x: e.evt.clientX, ohp: hPan };
      e.target.getStage().container().style.cursor = "grabbing";
    }
  };
  const onMouseMove = (e) => {
    if (!dragRef.current) return;
    const dxScreen = e.evt.clientX - dragRef.current.x;
    const maxP = Math.max(0, worldW - (contentW - PAD_X * 2));
    setHPan(Math.max(0, Math.min(maxP, dragRef.current.ohp - dxScreen)));
  };
  const onMouseUp = (e) => {
    dragRef.current = null;
    if (e && e.target && e.target.getStage) {
      e.target.getStage().container().style.cursor = "default";
    }
  };

  // Time ruler ticks — same logic as Device Trajectory.
  const ticks = useMemo(() => {
    const span = viewMaxTs - viewMinTs;
    const step = niceStep(span / 8);
    const arr = [];
    const first = Math.ceil(viewMinTs / step) * step;
    for (let t = first; t <= viewMaxTs; t += step) {
      const x = xForTs(t);
      if (x < PAD_X - 30 || x > contentW - PAD_X + 30) continue;
      arr.push({ x, label: fmtTs(t - viewMinTs, step) });
    }
    return arr;
  }, [viewMinTs, viewMaxTs, xForTs, contentW]);

  return (
    <div ref={wrapRef} className="relative w-full h-full overflow-hidden"
         data-testid="irg-graph-canvas">
      <Stage width={size.w} height={Math.max(size.h, canvasH)}
             onWheel={onWheel}
             onMouseDown={onMouseDown}
             onMouseMove={onMouseMove}
             onMouseUp={onMouseUp}
             onTouchStart={onMouseDown}
             onTouchMove={onMouseMove}
             onTouchEnd={onMouseUp}>
        {/* Time ruler */}
        <Layer listening={false}>
          <Rect x={0} y={0} width={size.w} height={AXIS_H} fill={T.paper} />
          <Line points={[0, AXIS_H, size.w, AXIS_H]} stroke={T.line} strokeWidth={1} />
          {ticks.map((t, i) => (
            <Group key={`tk-${i}`}>
              <Line points={[t.x, AXIS_H - 6, t.x, AXIS_H]}
                    stroke={T.inkFaint} strokeWidth={1} />
              <Text x={t.x - 30} y={4} width={60} align="center"
                    text={t.label} fontSize={10}
                    fontFamily="'IBM Plex Mono', ui-monospace, monospace"
                    fill={T.inkMute} />
            </Group>
          ))}
        </Layer>

        {/* Depth rails · one horizontal line per depth level */}
        <Layer listening={false}>
          {rowY.map((y, d) => (
            <Group key={`dp-${d}`}>
              <Line points={[PAD_X, y + NODE_H / 2, size.w - PAD_X, y + NODE_H / 2]}
                    stroke={T.line} strokeWidth={1} dash={[2, 4]} opacity={0.5} />
              <Text x={4} y={y + 6} text={`d${d}`} fontSize={9}
                    fontFamily="'IBM Plex Mono', ui-monospace, monospace"
                    fill={T.inkFaint} />
            </Group>
          ))}
        </Layer>

        {/* Edges */}
        <Layer listening={false}>
          {edges.map((e, i) => {
            const a = laid.get(e.source);
            const b = laid.get(e.target);
            if (!a || !b) return null;
            const ax = a.x + NODE_MIN_W / 2;
            const ay = a.y + NODE_H / 2;
            const bx = b.x - NODE_MIN_W / 2 + 6;
            const by = b.y + NODE_H / 2;
            const mid = (ax + bx) / 2;
            const isSel = selected &&
              (selected === e.source || selected === e.target);
            return (
              <Line key={`ed-${i}`}
                    points={[ax, ay, mid, ay, mid, by, bx, by]}
                    stroke={isSel ? T.blue : T.gray}
                    strokeWidth={isSel ? 1.6 : 1}
                    opacity={isSel ? 0.9 : 0.5}
                    lineJoin="round" />
            );
          })}
        </Layer>

        {/* Nodes */}
        <Layer>
          {[...laid.values()].map(({ x, y, node }) => {
            const isSel = selected === node.iid;
            const stroke = node.malicious ? T.red : (TYPE_COLOR[node.type] || T.ink);
            const bg = isSel ? T.blueT : T.paper2;
            const label = node.name.length > 22 ? node.name.slice(0, 20) + "…" : node.name;
            return (
              <Group key={node.iid} x={x - NODE_MIN_W / 2} y={y}
                     onClick={() => onSelect(node)}
                     onTap={() => onSelect(node)}
                     onMouseEnter={(e) => e.target.getStage().container().style.cursor = "pointer"}
                     onMouseLeave={(e) => e.target.getStage().container().style.cursor = "default"}>
                <Rect x={0} y={0} width={NODE_MIN_W} height={NODE_H}
                      name="irg-node"
                      cornerRadius={NODE_H / 2}
                      fill={bg}
                      stroke={stroke}
                      strokeWidth={isSel ? 2 : 1}
                      shadowColor={isSel ? T.blue : "rgba(15,23,42,0.08)"}
                      shadowBlur={isSel ? 8 : 3}
                      shadowOffset={{ x: 0, y: 1 }}
                      shadowOpacity={isSel ? 0.35 : 0.6} />
                {/* Type dot */}
                <Circle x={10} y={NODE_H / 2} radius={3}
                        fill={TYPE_COLOR[node.type] || T.ink}
                        listening={false} />
                <Text x={18} y={5}
                      text={label}
                      fontFamily="Inter, sans-serif"
                      fontSize={11}
                      fontStyle={node.malicious ? "700" : "500"}
                      fill={node.malicious ? T.red : T.ink}
                      width={NODE_MIN_W - 30}
                      wrap="none"
                      ellipsis={true}
                      listening={false} />
                {node.event_count > 1 && (
                  <Text x={NODE_MIN_W - 22} y={5}
                        text={String(node.event_count)}
                        fontFamily="'IBM Plex Mono', ui-monospace, monospace"
                        fontSize={9}
                        fill={node.malicious ? T.red : T.inkFaint}
                        width={18} align="right"
                        listening={false} />
                )}
              </Group>
            );
          })}
        </Layer>
      </Stage>

      {/* Horizontal scrollbar overlay — always visible when the graph is
          wider than the viewport. Provides an obvious affordance that the
          canvas is pannable and lets the user click / drag to pan the
          shared viewport. */}
      <HScrollbar
        contentW={contentW}
        worldW={worldW}
        hPan={hPan}
        onPan={(next) => {
          const maxP = Math.max(0, worldW - (contentW - PAD_X * 2));
          setHPan(Math.max(0, Math.min(maxP, next)));
        }}
      />
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════════
// HScrollbar — thin, always-visible scrollbar pinned to the bottom of
// the IRG canvas. Behaves like a native scrollbar (click-jump + drag)
// and only renders when the underlying content overflows.
// ═══════════════════════════════════════════════════════════════════
function HScrollbar({ contentW, worldW, hPan, onPan }) {
  const viewportW = Math.max(1, contentW - PAD_X * 2);
  const overflow  = worldW - viewportW;
  const trackRef  = useRef(null);
  const dragRef   = useRef(null);

  const trackW  = Math.max(0, contentW - 24);
  const thumbW  = Math.max(28, (viewportW / worldW) * trackW);
  const thumbX  = (hPan / Math.max(1, overflow)) * (trackW - thumbW);

  const onMove = useCallback((e) => {
    if (!dragRef.current) return;
    const dx = e.clientX - dragRef.current.startX;
    const dPan = (dx / Math.max(1, trackW - thumbW)) * overflow;
    onPan(dragRef.current.startPan + dPan);
  }, [trackW, thumbW, overflow, onPan]);
  const onUp = useCallback(() => { dragRef.current = null; }, []);
  useEffect(() => {
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
    return () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
  }, [onMove, onUp]);

  if (overflow <= 1) return null;  // no scroll needed

  const onTrackMouseDown = (e) => {
    const r = trackRef.current?.getBoundingClientRect();
    if (!r) return;
    const clickX = e.clientX - r.left;
    // If clicked outside the thumb, jump the thumb to that spot.
    if (clickX < thumbX || clickX > thumbX + thumbW) {
      const targetX = Math.max(0, Math.min(trackW - thumbW, clickX - thumbW / 2));
      const frac = targetX / Math.max(1, trackW - thumbW);
      onPan(frac * overflow);
    }
    dragRef.current = { startX: e.clientX, startPan: hPan };
    e.preventDefault();
  };

  return (
    <div
      ref={trackRef}
      data-testid="irg-hscroll"
      onMouseDown={onTrackMouseDown}
      style={{
        position: "absolute",
        left: 12, right: 12, bottom: 6,
        height: 10,
        background: "rgba(148,163,184,0.08)",
        border: "1px solid rgba(148,163,184,0.15)",
        borderRadius: 5,
        cursor: "pointer",
        zIndex: 5,
      }}
      title="Scroll IRG timeline"
    >
      <div
        data-testid="irg-hscroll-thumb"
        style={{
          position: "absolute",
          left: thumbX,
          top: 1,
          bottom: 1,
          width: thumbW,
          background: dragRef.current ? T.amber : "rgba(203,213,225,0.55)",
          borderRadius: 4,
          transition: dragRef.current ? "none" : "background 120ms ease",
        }}
      />
    </div>
  );
}

function niceStep(rough) {
  const pow = Math.pow(10, Math.floor(Math.log10(Math.max(rough, 1))));
  const n = rough / pow;
  const step = n < 1.5 ? 1 : n < 3.5 ? 2 : n < 7.5 ? 5 : 10;
  return step * pow;
}
function fmtTs(deltaMs, step) {
  if (step < 100) return `+${deltaMs.toFixed(0)}ms`;
  if (step < 1000) return `+${(deltaMs / 1000).toFixed(3)}s`;
  if (step < 60_000) return `+${(deltaMs / 1000).toFixed(1)}s`;
  return `+${(deltaMs / 60_000).toFixed(1)}m`;
}
