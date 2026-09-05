/**
 * TrajectoryLifelineCanvas · Cisco Secure Endpoint (AMP) lifeline
 * paradigm, NivXForge-native.
 *
 * D3 owns the temporal scale, the tick generator and the brush.  React
 * owns state and every rendered node, so selection / context menus /
 * test IDs behave like ordinary DOM.
 *
 * Rows are continuous lifelines, not disconnected dots:
 *   PROCESSES            one row per observed process name
 *   ARTIFACTS & NETWORK  one row per recorded target (file, key, socket)
 *
 * Overlap discipline (AMP behaviour):
 *   1. Per-process swimlanes — concurrent processes separate vertically.
 *   2. Horizontal jitter — markers on one lifeline keep a 14 px minimum
 *      spacing while preserving true chronological order; a drop-tick
 *      marks the real instant so the offset never lies about time.
 *   3. Severity z-ordering — malicious floats above attributed above
 *      benign, so a detection is never buried in a cluster.
 *   4. Double-click a cluster → the shared window zooms to the exact
 *      millisecond span of that cluster.
 *
 * Connectors are drawn ONLY between the actor and the target of the
 * SAME observation document — that is evidence, not inference.  Process
 * → process lineage is drawn only for a `parent_iid` that resolves to an
 * observed `process_iid`; when none resolve the gutter states
 * `[ROOT / PARENT NOT OBSERVED]` and nothing is joined.
 */
import React, { useEffect, useMemo, useRef, useState } from "react";
import { scaleTime } from "d3-scale";
import { brushX } from "d3-brush";
import { select } from "d3-selection";
import { timeFormat } from "d3-time-format";

import {
  glyphFor, tsOf, buildSwimlanes, lineageStats, compromiseSpans,
  severityTier, TIER_COLOR, TIER_MALICIOUS, TIER_ATTRIBUTED,
  IOC_RED, TELEMETRY_CYAN, IOC_BAND_FILL, IOC_BAND_EDGE, shortHash,
} from "@/xdr/lib/trajectoryModel";

const GUTTER      = 220;
const ROW_H       = 28;
const HEADER_H    = 20;
const AXIS_H      = 54;
const BRUSH_H     = 18;
const RIGHT_PAD   = 18;
const MIN_SPACING = 14;   // px · AMP-style micro-step offset
const CLUSTER_PX  = 60;   // px · what counts as "the same cluster"

const fmtTick = (span) => {
  if (span <= 5 * 60 * 1000)        return timeFormat("%H:%M:%S");
  if (span <= 36 * 60 * 60 * 1000)  return timeFormat("%H:%M");
  return timeFormat("%m-%d %Hh");
};

export default function TrajectoryLifelineCanvas({
  events,
  viewStart,
  viewEnd,
  onWindowChange,
  selectedId,
  onSelect,
  onContextMenu,
  haloIds,
  matchedIds,
  focusLabel,
  cursorTs,
  hoverId,
  onHover,
}) {
  const wrapRef  = useRef(null);
  const brushRef = useRef(null);
  const [width, setWidth] = useState(980);

  useEffect(() => {
    if (!wrapRef.current) return;
    const ro = new ResizeObserver((en) => {
      const w = en[0]?.contentRect?.width;
      if (w) setWidth(Math.max(680, Math.floor(w)));
    });
    ro.observe(wrapRef.current);
    return () => ro.disconnect();
  }, []);

  const plotW = Math.max(120, width - GUTTER - RIGHT_PAD);
  const x = useMemo(
    () => scaleTime().domain([new Date(viewStart), new Date(viewEnd)])
                     .range([GUTTER, GUTTER + plotW]),
    [viewStart, viewEnd, plotW],
  );

  const { processRows, artifactRows, anchors } = useMemo(
    () => buildSwimlanes(events), [events]);
  const lineage = useMemo(() => lineageStats(events), [events]);
  const spans   = useMemo(() => compromiseSpans(events), [events]);

  // Row geometry: two labelled groups, fixed-height rows.
  const layout = useMemo(() => {
    const rows = [];
    let y = AXIS_H;
    if (processRows.length) {
      rows.push({ type: "header", label: "PROCESSES", y, h: HEADER_H,
                  note: `${processRows.length} lifeline${processRows.length === 1 ? "" : "s"}` });
      y += HEADER_H;
      for (const r of processRows) { rows.push({ type: "row", row: r, y, h: ROW_H }); y += ROW_H; }
    }
    if (artifactRows.length) {
      rows.push({ type: "header", label: "ARTIFACTS & NETWORK", y, h: HEADER_H,
                  note: `${artifactRows.length} lifeline${artifactRows.length === 1 ? "" : "s"}` });
      y += HEADER_H;
      for (const r of artifactRows) { rows.push({ type: "row", row: r, y, h: ROW_H }); y += ROW_H; }
    }
    return { rows, bodyEnd: y };
  }, [processRows, artifactRows]);

  const rowY = useMemo(() => {
    const m = new Map();
    for (const item of layout.rows) {
      if (item.type === "row") m.set(item.row.key, item.y + ROW_H / 2);
    }
    return m;
  }, [layout]);

  /**
   * Collision layout — per lifeline, chronological, minimum 14 px apart.
   * `trueX` is the honest instant; `renderX` is the de-overlapped slot.
   */
  const placement = useMemo(() => {
    const byRow = new Map();
    const push = (rowKey, item) => {
      if (!rowKey) return;
      if (!byRow.has(rowKey)) byRow.set(rowKey, []);
      byRow.get(rowKey).push(item);
    };
    for (const a of anchors) {
      push(a.actorRowKey, { evt: a.evt, t: a.t, role: "actor",
                            rowKey: a.actorRowKey, partner: a.targetRowKey });
      if (a.targetRowKey) {
        push(a.targetRowKey, { evt: a.evt, t: a.t, role: "target",
                               rowKey: a.targetRowKey, partner: a.actorRowKey });
      }
    }
    const index = new Map();
    for (const [rowKey, items] of byRow) {
      items.sort((p, q) => p.t - q.t);
      let prev = -Infinity;
      for (const it of items) {
        it.trueX = x(new Date(it.t));
        it.renderX = Math.max(it.trueX, prev + MIN_SPACING);
        prev = it.renderX;
        index.set(`${it.evt.id}:${it.role}:${rowKey}`, it);
      }
    }
    return { byRow, index };
  }, [anchors, x]);

  const height = layout.bodyEnd + BRUSH_H + 12;
  const span = Math.max(1, viewEnd - viewStart);
  const ticks = useMemo(() => x.ticks(Math.max(4, Math.floor(plotW / 78))), [x, plotW]);
  const tickFmt = fmtTick(span);

  // ── d3 brush over the strip → shared temporal selection ─────────
  useEffect(() => {
    if (!brushRef.current) return;
    const g = select(brushRef.current);
    const brush = brushX()
      .extent([[GUTTER, 0], [GUTTER + plotW, BRUSH_H]])
      .on("end", (ev) => {
        if (!ev.selection || !ev.sourceEvent) return;
        const [a, b] = ev.selection;
        if (Math.abs(b - a) < 4) { g.call(brush.move, null); return; }
        onWindowChange?.(x.invert(a).getTime(), x.invert(b).getTime());
        g.call(brush.move, null);
      });
    g.call(brush);
    return () => { g.on(".brush", null); g.selectAll("*").remove(); };
  }, [plotW, x, onWindowChange]);

  const haloActive = haloIds && haloIds.size > 0;

  /** Double-click → zoom the shared window to this cluster's real span. */
  const zoomCluster = (item) => {
    const siblings = (placement.byRow.get(item.rowKey) || [])
      .filter((s) => Math.abs(s.renderX - item.renderX) <= CLUSTER_PX);
    const ts = siblings.map((s) => s.t);
    let lo = Math.min(...ts), hi = Math.max(...ts);
    if (hi - lo < 1000) { lo -= 1000; hi += 1000; }
    else { const pad = (hi - lo) * 0.08; lo -= pad; hi += pad; }
    onWindowChange?.(lo, hi);
  };

  /** Draw order: benign → attributed → malicious (z-index by severity). */
  const drawItems = useMemo(() => {
    const all = [];
    for (const [, items] of placement.byRow) all.push(...items);
    return all.sort((a, b) => severityTier(a.evt) - severityTier(b.evt));
  }, [placement]);

  return (
    <div ref={wrapRef} style={{ position: "relative", width: "100%" }}
         data-testid="edr-lifeline-canvas">
      {/* Lineage + overlap honesty banner. */}
      <div style={{ display: "flex", gap: 10, alignItems: "center",
                    padding: "5px 8px", background: "#11161D",
                    border: "1px solid #212B36", borderRadius: 4,
                    marginBottom: 6, flexWrap: "wrap" }}
           data-testid="edr-lifeline-lineage-banner">
        <span className="nx-ep"
              data-ep={lineage.resolved.length ? "evidence_present" : "unknown"}
              data-known="true">
          {lineage.resolved.length
            ? `◆ ${lineage.resolved.length} LINEAGE EDGE${lineage.resolved.length === 1 ? "" : "S"} RESOLVED`
            : "? NO PROCESS→PROCESS LINEAGE RESOLVABLE"}
        </span>
        <span className="mono" style={{ fontSize: 9.8, color: "var(--faint)" }}>
          {lineage.declaredCount} declared <code>parent_iid</code> reference
          {lineage.declaredCount === 1 ? "" : "s"} ·{" "}
          {lineage.resolved.length} resolve to an observed{" "}
          <code>process_iid</code> · {lineage.unresolvedParents.length} unresolved
          {lineage.unresolvedParents.length > 0
            && " → those lifelines carry a dashed ghost-root marker instead of an invented ancestor"}
        </span>
        <div style={{ flex: 1 }} />
        <span className="mono" style={{ fontSize: 9.8, color: TELEMETRY_CYAN }}>
          {anchors.length} observation{anchors.length === 1 ? "" : "s"} ·{" "}
          {processRows.length + artifactRows.length} lifelines · 14px jitter ·
          dbl-click a cluster to zoom
        </span>
      </div>

      <svg width={width} height={height} style={{ display: "block", background: "#0B0F14" }}
           data-testid="edr-lifeline-svg">
        <defs>
          <clipPath id="edr-plot-clip">
            <rect x={GUTTER} y={0} width={plotW} height={height} />
          </clipPath>
        </defs>

        {/* IOC correlation bands, spanning every lifeline. */}
        <g clipPath="url(#edr-plot-clip)">
          {spans.map((s) => {
            const xa = x(new Date(s.start));
            const xb = Math.max(x(new Date(s.end)), xa + 3);
            return (
              <g key={s.id} data-testid={`edr-lifeline-ioc-band-${s.id}`}>
                <rect x={xa} y={AXIS_H - 8} width={xb - xa}
                      height={layout.bodyEnd - AXIS_H + 8}
                      fill={IOC_BAND_FILL} stroke={IOC_BAND_EDGE} strokeWidth={0.6}>
                  <title>
                    {`IOC correlation window · ${s.events.length} attributed observation(s)`
                      + (s.mitre.length ? ` · ${s.mitre.join(", ")}` : "")}
                  </title>
                </rect>
                <text x={xa + 3} y={AXIS_H - 11} fill={IOC_BAND_EDGE}
                      fontSize={8.5} fontFamily="'IBM Plex Mono', monospace">
                  IOC
                </text>
              </g>
            );
          })}
        </g>

        {/* Time axis — vertical tick labels survive dense clusters. */}
        <g data-testid="edr-lifeline-axis">
          <line x1={GUTTER} y1={AXIS_H - 4} x2={GUTTER + plotW} y2={AXIS_H - 4}
                stroke="#212B36" />
          {ticks.map((d, i) => {
            const tx = x(d);
            return (
              <g key={i}>
                <line x1={tx} y1={AXIS_H - 8} x2={tx} y2={layout.bodyEnd}
                      stroke="#161C24" strokeDasharray="2 4" />
                <text x={tx} y={AXIS_H - 12} fill="#7A8797" fontSize={9.5}
                      fontFamily="'IBM Plex Mono', monospace"
                      transform={`rotate(-90 ${tx} ${AXIS_H - 12})`}
                      textAnchor="start">
                  {tickFmt(d)}
                </text>
              </g>
            );
          })}
        </g>

        {/* Rows: gutter label + continuous lifeline. */}
        {layout.rows.map((item, idx) => {
          if (item.type === "header") {
            return (
              <g key={`h-${idx}`}>
                <rect x={0} y={item.y} width={width} height={HEADER_H} fill="#0E141B" />
                <text x={8} y={item.y + 14} fill="#8895A6" fontSize={9.5}
                      fontWeight={800} letterSpacing="0.6"
                      fontFamily="'IBM Plex Mono', monospace">
                  {item.label}
                </text>
                <text x={GUTTER - 12} y={item.y + 14} textAnchor="end" fill="#59636F"
                      fontSize={8.5} fontFamily="'IBM Plex Mono', monospace">
                  {item.note}
                </text>
              </g>
            );
          }
          const r = item.row;
          const cy = item.y + ROW_H / 2;
          const isFocus = focusLabel
            && r.label.toLowerCase().includes(String(focusLabel).toLowerCase());
          const malicious = r.maliciousCount > 0;
          const attributed = !malicious && r.attributedCount > 0;
          const x0 = x(new Date(Math.max(r.first, viewStart)));
          const x1 = x(new Date(Math.min(r.last, viewEnd)));
          const labelText = r.label.length > 26
            ? `${r.label.slice(0, 12)}…${r.label.slice(-11)}` : r.label;
          return (
            <g key={r.key} data-testid={`edr-lifeline-row-${r.key}`}>
              <rect x={0} y={item.y} width={width} height={ROW_H}
                    fill={idx % 2 === 0 ? "#0B0F14" : "#0D1218"} />
              {/* Gutter label — solid crimson only for a real detection. */}
              <rect x={0} y={item.y + 2} width={GUTTER - 6} height={ROW_H - 4}
                    fill={malicious ? IOC_RED : "transparent"}
                    stroke={isFocus ? TELEMETRY_CYAN : "transparent"} strokeWidth={1} />
              {attributed && (
                <rect x={0} y={item.y + 2} width={3} height={ROW_H - 4}
                      fill={TIER_COLOR[TIER_ATTRIBUTED]} />
              )}
              <text x={8} y={cy + 3.5}
                    fill={malicious ? "#FFFFFF" : "#C7D0DB"}
                    fontSize={10.5} fontWeight={isFocus || malicious ? 800 : 600}
                    fontFamily="'IBM Plex Mono', monospace">
                {labelText}
                <title>{`${r.label}  ${r.tag}`}</title>
              </text>
              <text x={GUTTER - 12} y={cy + 3.5} textAnchor="end"
                    fill={malicious ? "#FFE3E3" : "#6B7686"} fontSize={9}
                    fontFamily="'IBM Plex Mono', monospace">
                {r.tag}
              </text>
              <g clipPath="url(#edr-plot-clip)">
                {/* Continuous execution track across the visible window —
                    the substrate records instants, not exit times, so the
                    track is drawn quiet (#30363D) and the OBSERVED span is
                    overdrawn brighter on top of it. */}
                <line x1={GUTTER} y1={cy} x2={GUTTER + plotW} y2={cy}
                      stroke="#30363D" strokeWidth={1.5} />
                <line x1={Math.min(x0, x1)} y1={cy} x2={Math.max(x0, x1)} y2={cy}
                      stroke={malicious ? "rgba(255,56,56,0.75)" : "rgba(143,166,200,0.75)"}
                      strokeWidth={2} />
                {r.parentClaims.length > 0 && lineage.resolved.length === 0 && (
                  <g data-testid={`edr-lifeline-ghost-root-${r.key}`}>
                    <circle cx={GUTTER + 6} cy={cy} r={3.4} fill="none"
                            stroke="#4B5563" strokeWidth={1}
                            strokeDasharray="1.6 1.6" />
                    <title>
                      {`Ghost root · this process declares a parent`
                       + (r.parentClaims[0].name ? ` "${r.parentClaims[0].name}"` : "")
                       + ` (${r.parentClaims[0].iid}) that was never itself observed.`
                       + ` No lineage edge is drawn and no ancestor is synthesised.`}
                    </title>
                  </g>
                )}
              </g>
            </g>
          );
        })}

        {/* actor → target orthogonal connectors (single observation record). */}
        <g clipPath="url(#edr-plot-clip)">
          {anchors.map((a, i) => {
            if (!a.targetRowKey) return null;
            const A = placement.index.get(`${a.evt.id}:actor:${a.actorRowKey}`);
            const B = placement.index.get(`${a.evt.id}:target:${a.targetRowKey}`);
            const ay = rowY.get(a.actorRowKey);
            const by = rowY.get(a.targetRowKey);
            if (!A || !B || ay === undefined || by === undefined) return null;
            const dim = haloActive && !haloIds.has(a.evt.id);
            const mid = (ay + by) / 2;
            return (
              <path key={`lnk-${a.evt.id}-${i}`}
                    d={`M ${A.renderX} ${ay} V ${mid} H ${B.renderX} V ${by}`}
                    fill="none"
                    stroke={hoverId === a.evt.id ? TELEMETRY_CYAN : "rgba(0,210,211,0.38)"}
                    strokeWidth={hoverId === a.evt.id ? 1.6 : 1}
                    opacity={dim ? 0.18 : 1} />
            );
          })}

          {/* Drop-ticks: the honest instant behind every jittered marker. */}
          {drawItems.map((it, i) => {
            const cy = rowY.get(it.rowKey);
            if (cy === undefined) return null;
            const offset = it.renderX - it.trueX;
            if (offset < 1.5) return null;
            const dim = haloActive && !haloIds.has(it.evt.id);
            return (
              <g key={`tick-${it.evt.id}-${it.role}-${i}`} opacity={dim ? 0.18 : 0.8}>
                <line x1={it.trueX} y1={cy - 8} x2={it.trueX} y2={cy + 8}
                      stroke="#3A4653" strokeWidth={0.8} />
                <line x1={it.trueX} y1={cy - 8} x2={it.renderX} y2={cy - 8}
                      stroke="#3A4653" strokeWidth={0.8} strokeDasharray="1 2" />
              </g>
            );
          })}

          {/* Glyphs, drawn benign → attributed → malicious. */}
          {drawItems.map((it, i) => {
            const cy = rowY.get(it.rowKey);
            if (cy === undefined) return null;
            const evt = it.evt;
            const g = glyphFor(evt);
            const tier = severityTier(evt);
            const dim = haloActive && !haloIds.has(evt.id);
            const halo = haloActive && haloIds.has(evt.id);
            const sel = selectedId === evt.id;
            const hov = hoverId === evt.id;
            const matched = matchedIds && matchedIds.has(evt.id);
            const cx = it.renderX;
            return (
              <g key={`gl-${evt.id}-${it.role}-${i}`}
                 style={{ cursor: "pointer" }}
                 opacity={dim ? 0.22 : 1}
                 onMouseEnter={() => onHover?.(evt.id)}
                 onMouseLeave={() => onHover?.(null)}
                 onClick={() => onSelect?.(evt)}
                 onDoubleClick={(e) => { e.stopPropagation(); zoomCluster(it); }}
                 onContextMenu={(e) => {
                   e.preventDefault();
                   onContextMenu?.(evt, { x: e.clientX, y: e.clientY });
                 }}
                 data-testid={`edr-lifeline-glyph-${evt.id}-${it.role}`}>
                {halo && (
                  <circle cx={cx} cy={cy} r={9.5} fill="none"
                          stroke={TELEMETRY_CYAN} strokeWidth={1.8} opacity={0.95} />
                )}
                {(hov || sel) && (
                  <circle cx={cx} cy={cy} r={8.5} fill="none"
                          stroke={sel ? "#FFFFFF" : TELEMETRY_CYAN} strokeWidth={1.2} />
                )}
                {matched && (
                  <circle cx={cx} cy={cy} r={7.5} fill="none"
                          stroke={TELEMETRY_CYAN} strokeDasharray="2 2" strokeWidth={1} />
                )}
                <circle cx={cx} cy={cy} r={sel ? 6.4 : hov ? 5.8 : 5}
                        fill={tier === TIER_MALICIOUS ? IOC_RED
                              : tier === TIER_ATTRIBUTED ? TIER_COLOR[TIER_ATTRIBUTED]
                              : g.color}
                        stroke="#0A0D12" strokeWidth={1.2} />
                <text x={cx} y={cy + 2.6} textAnchor="middle" fontSize={6.5}
                      fill="#080B10" fontWeight={800} pointerEvents="none"
                      fontFamily="'IBM Plex Mono', monospace">
                  {g.sym}
                </text>
                <title>
                  {`${g.label} · ${new Date(it.t).toISOString()}\n`
                   + `${it.role === "actor" ? "actor lifeline" : "target lifeline"}\n`
                   + `${evt.process || "◇ no actor recorded"}`
                   + (evt.file ? ` → ${evt.file}` : "")
                   + (evt.file_sha256 ? `\nfile sha256 ${shortHash(evt.file_sha256)}` : "")
                   + (evt.mitre?.length ? `\nATT&CK ${evt.mitre.join(", ")}` : "")
                   + (evt.occurrences > 1 ? `\n${evt.occurrences} case references` : "")
                   + (it.renderX - it.trueX >= 1.5
                      ? "\n(offset for legibility · drop-tick marks the true instant)" : "")}
                </title>
              </g>
            );
          })}

          {/* Ledger / band cursor. */}
          {cursorTs != null && cursorTs >= viewStart && cursorTs <= viewEnd && (
            <line x1={x(new Date(cursorTs))} y1={AXIS_H - 8}
                  x2={x(new Date(cursorTs))} y2={layout.bodyEnd}
                  stroke="#FFFFFF" strokeWidth={1} opacity={0.6}
                  data-testid="edr-lifeline-cursor" />
          )}
        </g>

        {/* Brush strip — drag to scope the shared temporal window. */}
        <g transform={`translate(0,${layout.bodyEnd + 4})`}>
          <rect x={GUTTER} y={0} width={plotW} height={BRUSH_H} fill="#0E141B"
                stroke="#212B36" strokeWidth={0.6} />
          <text x={8} y={13} fill="#6B7686" fontSize={9}
                fontFamily="'IBM Plex Mono', monospace">
            DRAG TO SCOPE WINDOW
          </text>
          <g ref={brushRef} data-testid="edr-lifeline-brush" />
        </g>
      </svg>
    </div>
  );
}
