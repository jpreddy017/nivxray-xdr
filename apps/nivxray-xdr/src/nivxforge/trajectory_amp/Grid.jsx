import React, { useEffect, useMemo, useRef, useState } from "react";
import { PAL, basename, connectorSource, connectorStyle, fmtInstant, fmtShort, groupMarkers, ticks, xOf } from "./model";
import { Glyph } from "./Glyphs";
import { useDrag, useWidth } from "./hooks";
import { MONO } from "./ui";

export const GUTTER = 300;
const ROW_H = 26, AXIS_H = 28, BODY_H = 520;
const fmtCount = (n) => (n >= 10000 ? `${Math.round(n / 1000)}k` : n >= 1000 ? `${(n / 1000).toFixed(1)}k` : String(n));

function rowLabel(l) {
  if (l.lane_type === "PROCESS") return `${basename(l.image || l.label)}${l.pid != null ? ` · ${l.pid}` : ""}`;
  if (l.lane_type === "FILE") return basename(l.label);
  if (l.lane_type === "UNATTRIBUTED_NETWORK") return "Unattributed network activity";
  return l.label;
}

function Marker({ g, i, j, det, selected, onPick, onExpand, onCtx }) {
  if (g.group) {
    const w = Math.max(18, fmtCount(g.count).length * 6 + 10);
    return (
      <g data-testid={`marker-group-${i}-${j}`} data-count={g.count} transform={`translate(${GUTTER + g.x},${ROW_H / 2})`}
        style={{ cursor: "zoom-in" }} onClick={(e) => { e.stopPropagation(); onExpand(g); }}>
        <rect x={-w / 2} y={-7} width={w} height={14} rx={7} fill="#173640" stroke={PAL.accent} strokeWidth={1} />
        <text y={3.5} fontSize={9.5} textAnchor="middle" fill={PAL.text} fontFamily={MONO}>{fmtCount(g.count)}</text>
        <title>{g.count} events grouped · click or zoom to expand</title>
      </g>
    );
  }
  return (
    <g data-testid={`marker-${g.event_id}`} data-kind={g.kind} data-detection={det ? "MATCH" : "NONE"}
      transform={`translate(${GUTTER + g.x},${ROW_H / 2})`} style={{ cursor: "pointer" }}
      onClick={(e) => { e.stopPropagation(); onPick(g); }} onContextMenu={(e) => { e.preventDefault(); e.stopPropagation(); onCtx(e, g); }}>
      {selected && <circle r={9} fill="none" stroke={PAL.accent} strokeWidth={1.5} />}
      <Glyph kind={g.kind} color={det ? PAL.amber : PAL.neutral} />
      {det && <g transform="translate(0,-9) scale(.62)"><Glyph kind="MATCH" /></g>}
      {g.late && <g data-testid={`late-badge-${g.event_id}`} transform="translate(8,-6) scale(.85)"><Glyph kind="LATE" /></g>}
    </g>
  );
}

function Connectors({ rows, idx, first, last, X, t0, t1 }) {
  return rows.map((l, i) => {
    const src = connectorSource(l);
    if (!src || !idx.has(src)) return null;
    const p = idx.get(src);
    if (Math.max(p, i) < first || Math.min(p, i) > last) return null;
    const st = connectorStyle(l.causal_state);
    const x = X(Math.min(t1, Math.max(t0, l.span?.from_ms ?? t0)));
    const ys = p * ROW_H + ROW_H / 2 + (p < i ? 5 : -5), yc = i * ROW_H + ROW_H / 2;
    return (
      <g key={l.lane_id} data-testid={`connector-${i}`} data-causal={l.causal_state || "UNRESOLVED"} pointerEvents="none">
        <path d={`M${x},${ys} V${yc} H${x + 7}`} fill="none" stroke={PAL.accent} strokeOpacity={0.85} strokeWidth={1.4}
          strokeDasharray={st.dash || undefined} />
        {st.mark && <text x={x + 4} y={(ys + yc) / 2 + 3} fontSize={10} fontWeight={700} fill={PAL.amber}>{st.mark}</text>}
      </g>
    );
  });
}

export default function Grid({ lanes, vp, view, kinds, keep, hideOthers, coverage, sel, eventsById, retro, approvals,
                               tzMode, onSelect, onContext, onView, onWidth }) {
  const [wrap, W] = useWidth(1100);
  const plotW = Math.max(200, W - GUTTER - 14);
  useEffect(() => { onWidth(plotW); }, [plotW, onWidth]);
  const [scrollTop, setScrollTop] = useState(0);
  const body = useRef(null);
  const { t0, t1 } = view;
  const X = (t) => GUTTER + xOf(t, t0, t1, plotW);
  const rows = useMemo(() => (hideOthers && keep ? lanes.filter((l) => keep.has(l.lane_id)) : lanes), [lanes, keep, hideOthers]);
  const idx = useMemo(() => new Map(rows.map((l, i) => [l.lane_id, i])), [rows]);
  const vpBy = useMemo(() => new Map((vp?.lanes || []).map((l) => [l.lane_id, l])), [vp]);
  const first = Math.max(0, Math.floor(scrollTop / ROW_H) - 4);
  const last = Math.min(rows.length, first + Math.ceil(BODY_H / ROW_H) + 8);
  const groups = useMemo(() => new Map(rows.slice(first, last).map((l) => {
    const v = vpBy.get(l.lane_id);
    return [l.lane_id, v ? groupMarkers(v, t0, t1, plotW, kinds) : []];
  })), [rows, first, last, vpBy, t0, t1, plotW, kinds]);
  const span = t1 - t0;
  const drag = useDrag((dx) => onView((v) => ({ t0: v.t0 - (dx * (v.t1 - v.t0)) / plotW, t1: v.t1 - (dx * (v.t1 - v.t0)) / plotW })));

  useEffect(() => {
    const el = body.current;
    if (!el) return undefined;
    const h = (e) => {
      const r = el.getBoundingClientRect();
      if (e.ctrlKey || e.metaKey) {
        e.preventDefault();
        const f = Math.exp(e.deltaY * 0.0022);
        onView((v) => {
          const c = v.t0 + ((e.clientX - r.left - GUTTER) / plotW) * (v.t1 - v.t0);
          const s = Math.min(90 * 86_400_000, Math.max(5000, (v.t1 - v.t0) * f));
          const k = (c - v.t0) / (v.t1 - v.t0);
          return { t0: c - k * s, t1: c - k * s + s };
        });
      } else if (e.shiftKey || Math.abs(e.deltaX) > Math.abs(e.deltaY)) {
        e.preventDefault();
        const d = e.deltaX || e.deltaY;
        onView((v) => ({ t0: v.t0 + (d * (v.t1 - v.t0)) / plotW, t1: v.t1 + (d * (v.t1 - v.t0)) / plotW }));
      }
    };
    el.addEventListener("wheel", h, { passive: false });
    return () => el.removeEventListener("wheel", h);
  }, [onView, plotW]);

  const expand = (g) => {
    const pad = Math.max((g.t_end - g.t_ms) * 0.15, 1500);
    onView({ t0: g.t_ms - pad, t1: Math.max(g.t_end + pad, g.t_ms - pad + 5000) });
  };
  const tk = ticks(t0, t1, Math.max(4, Math.floor(plotW / 110)));
  const gaps = (coverage?.intervals || []).filter((g) => g.to_ms > t0 && g.from_ms < t1);
  const H = Math.max(rows.length * ROW_H, 60);

  return (
    <section data-testid="trajectory-grid" ref={wrap} style={{ background: PAL.panel, border: `1px solid ${PAL.grid}`, borderRadius: 6, overflow: "hidden" }}>
      <svg width={W} height={AXIS_H} style={{ display: "block", borderBottom: `1px solid ${PAL.gridStrong}` }}>
        <text x={12} y={18} fontSize={11} fill={PAL.muted} letterSpacing={1}>PROCESS / FILE ROWS · {rows.length}</text>
        {tk.ticks.map((t) => (
          <g key={t}><line x1={X(t)} x2={X(t)} y1={AXIS_H - 6} y2={AXIS_H} stroke={PAL.faint} />
            <text x={X(t) + 3} y={13} fontSize={10} fill={PAL.muted} fontFamily={MONO}>{tk.step < 60_000 ? fmtInstant(t, tzMode).slice(11, 19) : fmtShort(t, tzMode)}</text></g>
        ))}
        {gaps.map((g, k) => {
          const x1 = X(Math.max(g.from_ms, t0)), x2 = X(Math.min(g.to_ms, t1));
          return x2 - x1 > 90 && <text key={k} x={x1 + 4} y={25} fontSize={9} fill="#C9A15A">{g.state === "NO_TELEMETRY_RECEIVED" ? "No telemetry received" : g.state === "SENSOR_OFFLINE" ? "Sensor offline" : "Sensor declared gap"}</text>;
        })}
      </svg>
      <div ref={body} data-testid="grid-body" onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)}
        style={{ height: BODY_H, overflowY: "auto", overflowX: "hidden", position: "relative" }}>
        <svg width={W} height={H} onMouseDown={(e) => { if (e.clientX - e.currentTarget.getBoundingClientRect().left > GUTTER) drag(e); }}
          style={{ display: "block", cursor: "grab", userSelect: "none" }}>
          <defs>
            <pattern id="grid-hatch" width="7" height="7" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
              <rect width="7" height="7" fill="rgba(58,46,26,.10)" /><rect width="1.2" height="7" fill="rgba(183,138,58,.16)" /></pattern>
            <clipPath id="gutter-clip"><rect x={0} y={0} width={GUTTER - 10} height={ROW_H} /></clipPath>
          </defs>
          {rows.slice(first, last).map((l, n) => {
            const i = first + n;
            const dim = keep && !keep.has(l.lane_id);
            const isSel = sel?.laneId === l.lane_id;
            const from = l.span?.from_ms ?? null, to = l.span?.to_ms ?? null;
            const before = l.lane_type !== "FILE" && l.lane_type !== "UNATTRIBUTED_NETWORK" && (l.continues_before || (from != null && from < t0));
            const after = l.lane_type !== "FILE" && l.lane_type !== "UNATTRIBUTED_NETWORK" && (to == null || to > t1);
            return (
              <g key={l.lane_id} data-testid={`grid-row-${i}`} data-lane-id={l.lane_id} data-lane-type={l.lane_type}
                data-isolated={keep ? String(!dim) : undefined} opacity={dim ? 0.18 : 1} transform={`translate(0,${i * ROW_H})`}
                onClick={() => onSelect({ laneId: l.lane_id })} onContextMenu={(e) => { e.preventDefault(); onContext(e, { lane: l }); }}>
                <rect width={W} height={ROW_H} fill={isSel ? "#132A33" : i % 2 ? PAL.bg : "#0C1218"} />
                <g clipPath="url(#gutter-clip)">
                  <text x={12 + (l.depth || 0) * 14} y={17} fontSize={12} fontFamily={l.lane_type === "FILE" ? MONO : undefined}
                    fill={l.lane_type === "PROCESS" ? PAL.text : PAL.muted} fontStyle={l.lane_type === "UNRESOLVED_PARENT" ? "italic" : "normal"}>
                    {l.lane_type === "FILE" ? "▤ " : l.lane_type === "UNATTRIBUTED_NETWORK" ? "◇ " : l.lane_type === "UNRESOLVED_PARENT" ? "? " : ""}{rowLabel(l)}
                  </text>
                </g>
                {l.lane_type === "PROCESS" && !(to != null && to < t0) && !(from != null && from > t1) && (
                  <line x1={X(Math.max(from ?? t0, t0))} x2={X(Math.min(to ?? t1, t1))} y1={ROW_H / 2} y2={ROW_H / 2} stroke="#33475A" strokeWidth={2} />)}
                {l.lane_type === "UNRESOLVED_PARENT" && <line x1={GUTTER} x2={GUTTER + plotW} y1={ROW_H / 2} y2={ROW_H / 2} stroke={PAL.faint} strokeDasharray="1.5 5" />}
                {before && <text data-testid={`chevron-before-${i}`} x={GUTTER + 2} y={17} fontSize={13} fill={PAL.accent}>‹</text>}
                {after && <text data-testid={`chevron-after-${i}`} x={GUTTER + plotW - 8} y={17} fontSize={13} fill={PAL.accent}>›</text>}
                {(groups.get(l.lane_id) || []).map((g, j) => (
                  <Marker key={j} g={g} i={i} j={j} det={!g.group && !!eventsById.get(g.event_id)?.detection}
                    selected={sel?.eventId === g.event_id} onExpand={expand}
                    onPick={(m) => onSelect({ laneId: l.lane_id, eventId: m.event_id })}
                    onCtx={(e, m) => onContext(e, { lane: l, eventId: m.event_id, t_ms: m.t_ms })} />
                ))}
              </g>
            );
          })}
          <Connectors rows={rows} idx={idx} first={first} last={last} X={X} t0={t0} t1={t1} />
          {gaps.map((g, k) => (
            <rect key={k} data-testid={`coverage-gap-${k}`} data-state={g.state} x={X(Math.max(g.from_ms, t0))} y={0} height={H} pointerEvents="none"
              width={Math.max(1, X(Math.min(g.to_ms, t1)) - X(Math.max(g.from_ms, t0)))} fill="url(#grid-hatch)" />
          ))}
          {retro.filter((r) => idx.has(r.lane_id) && r.t_ms >= t0 && r.t_ms <= t1).map((r, k) => (
            <g key={`r${k}`} data-testid={`retro-marker-${k}`} transform={`translate(${X(r.t_ms)},${idx.get(r.lane_id) * ROW_H + ROW_H / 2})`}
              style={{ cursor: "pointer" }} onClick={() => onSelect({ laneId: r.lane_id })}>
              <Glyph kind="RETRO" /><title>Retrospective {r.status.kind} · {r.status.state} · added later at {r.status.recorded_at}; original event unchanged</title></g>
          ))}
          {approvals.filter((a) => idx.has(a.lane_id)).map((a, k) => (
            <g key={`a${k}`} data-testid={`approval-marker-${k}`} transform={`translate(${X(Math.min(t1, Math.max(t0, a.t_ms))) + 11},${idx.get(a.lane_id) * ROW_H + ROW_H / 2})`}
              style={{ cursor: "pointer" }} onClick={() => onSelect({ laneId: a.lane_id })}>
              <Glyph kind="APPROVAL" /><title>{a.request.action} · APPROVAL_REQUESTED · not executed</title></g>
          ))}
        </svg>
      </div>
      <div style={{ fontSize: 11, color: PAL.faint, padding: "5px 12px", borderTop: `1px solid ${PAL.grid}` }}>
        X = observed_at only · drag to pan · Ctrl/⌘ + wheel to zoom · Shift + wheel to scroll time · span {Math.round(span / 60000)} min
      </div>
    </section>
  );
}
