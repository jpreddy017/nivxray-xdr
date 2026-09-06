/**
 * Device Trajectory · Stage 1 backbone (endpoint-centric, windowed).
 *
 * Ships ALONGSIDE the proven /edr/trajectory page — nothing there is
 * changed. What is different here is the mechanism, not the styling:
 *
 *   viewport state {t0,t1,laneStart}  →  windowed API request
 *                                     →  bounded merge cache
 *                                     →  virtualized rows
 *
 * Only the lanes and time slice in view are rendered, only the window
 * needed is fetched (with a prefetch margin), events are de-duplicated
 * on `event_iid`, and loading never moves the viewport. It needs no
 * case, incident or verdict: `?device=<device_iid|hostname>` is the only
 * required state.
 */
import React, { useCallback, useEffect, useMemo, useRef,
                useState } from "react";
import { useSearchParams } from "react-router-dom";

import NivXForgeConsole from "@/nivxforge/NivXForgeConsole";
import api from "@/lib/api";

const ROW_H = 22;
const GUTTER = 240;
const LANE_PREFETCH = 12;
const TIME_PREFETCH = 0.35;
const CACHE_MAX = 24;
const MS = { s: 1000, m: 60000, h: 3600000, d: 86400000 };

const iso = (ms) => new Date(ms).toISOString();
const fmtSpan = (ms) => ms < 90 * MS.s ? `${(ms / MS.s).toFixed(1)} s`
  : ms < 90 * MS.m ? `${(ms / MS.m).toFixed(1)} min`
    : ms < 48 * MS.h ? `${(ms / MS.h).toFixed(1)} h`
      : `${(ms / MS.d).toFixed(1)} d`;
const GROUP_COLOR = { PROCESS: "#7FB3FF", FILE: "#FFB454",
                      NETWORK: "#5FD4A0", OTHER: "#8A93A0" };

export default function EdrDeviceTrajectoryPage() {
  const [params] = useSearchParams();
  const device = params.get("device") || "";

  const [axis, setAxis] = useState(null);        // lane axis + extent
  const [view, setView] = useState(null);        // {t0, t1}
  const [laneStart, setLaneStart] = useState(0);
  const [rows, setRows] = useState(24);
  const [events, setEvents] = useState(new Map());
  const [lanes, setLanes] = useState(new Map());
  const [selected, setSelected] = useState(null);
  const [state, setState] = useState({ loading: true, err: null,
                                       epistemic: null });
  const [stats, setStats] = useState({ requests: 0, merged: 0, dupes: 0,
                                       lastWindow: null, cache: 0 });

  const cache = useRef(new Map());
  const plotRef = useRef(null);
  const vScroll = useRef(null);
  const hScroll = useRef(null);
  const pan = useRef(null);
  const [plotW, setPlotW] = useState(900);

  useEffect(() => {
    const el = plotRef.current;
    if (!el) return;
    const ro = new ResizeObserver((en) => {
      const w = en[0]?.contentRect?.width;
      const h = en[0]?.contentRect?.height;
      if (w) setPlotW(Math.max(400, Math.floor(w - GUTTER)));
      if (h) setRows(Math.max(6, Math.floor(h / ROW_H)));
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  /** One windowed request, merged into the cache. Never resets view. */
  const fetchWindow = useCallback(async (t0, t1, l0, l1) => {
    const key = `${Math.round(t0)}|${Math.round(t1)}|${l0}|${l1}`;
    if (cache.current.has(key)) return;
    cache.current.set(key, true);
    if (cache.current.size > CACHE_MAX) {
      // Bounded: evict the oldest window, keep the newest.
      const first = cache.current.keys().next().value;
      cache.current.delete(first);
    }
    setStats((s) => ({ ...s, requests: s.requests + 1,
                       cache: cache.current.size,
                       lastWindow: `${fmtSpan(t1 - t0)} · lanes ${l0}-${l1}` }));
    const { data } = await api.get(
      `/edr/endpoints/${encodeURIComponent(device)}/trajectory`,
      { params: { time_start: iso(t0), time_end: iso(t1), lane_start: l0,
                  lane_end: l1, limit: 1500 } });
    setState((s) => ({ ...s, loading: false, epistemic: data.epistemic_state,
                       err: null }));
    if (data.lane_axis) {
      setAxis((a) => ({
        total_lanes: data.lane_axis.total_lanes,
        lane_axis_version: data.lane_axis.lane_axis_version,
        group_counts: data.lane_axis.group_counts,
        observed_start: data.time_range?.observed_start || a?.observed_start,
        observed_end: data.time_range?.observed_end || a?.observed_end,
        total: data.total_or_estimate }));
      setLanes((prev) => {
        const m = new Map(prev);
        for (const ln of data.lane_axis.lanes || []) m.set(ln.lane_index, ln);
        return m;
      });
    }
    setEvents((prev) => {
      const m = new Map(prev);
      let dup = 0, add = 0;
      for (const e of data.events || []) {
        if (m.has(e.event_iid)) dup += 1; else add += 1;
        m.set(e.event_iid, e);           // stable identity → no doubles
      }
      setStats((s) => ({ ...s, merged: s.merged + add, dupes: s.dupes + dup }));
      return m;
    });
  }, [device]);

  /** First load: resolve the observed extent, then open on it. */
  useEffect(() => {
    if (!device) { setState({ loading: false, err: null, epistemic: null });
                   return; }
    let dead = false;
    (async () => {
      try {
        const { data } = await api.get(
          `/edr/endpoints/${encodeURIComponent(device)}/trajectory`,
          { params: { lane_start: 0, lane_end: 1, limit: 1 } });
        if (dead) return;
        const s = data.time_range?.observed_start;
        const e = data.time_range?.observed_end;
        setState((st) => ({ ...st, loading: false,
                            epistemic: data.epistemic_state }));
        setAxis({ total_lanes: data.lane_axis?.total_lanes || 0,
                  lane_axis_version: data.lane_axis?.lane_axis_version,
                  group_counts: data.lane_axis?.group_counts,
                  observed_start: s, observed_end: e,
                  total: data.total_or_estimate });
        if (s && e) {
          const a = Date.parse(s), b = Date.parse(e);
          const pad = Math.max((b - a) * 0.02, MS.s);
          setView({ t0: a - pad, t1: b + pad });
        }
      } catch (x) {
        if (!dead) setState({ loading: false, epistemic: null,
                              err: x?.response?.data?.detail?.reason
                                   || x?.message || String(x) });
      }
    })();
    return () => { dead = true; };
  }, [device]);

  /** Windowed loading with a prefetch margin around the viewport. */
  useEffect(() => {
    if (!device || !view) return;
    const span = view.t1 - view.t0;
    const t0 = view.t0 - span * TIME_PREFETCH;
    const t1 = view.t1 + span * TIME_PREFETCH;
    const l0 = Math.max(0, laneStart - LANE_PREFETCH);
    const l1 = laneStart + rows + LANE_PREFETCH;
    fetchWindow(t0, t1, l0, l1).catch((x) =>
      setState((s) => ({ ...s, err: x?.message || String(x) })));
  }, [device, view, laneStart, rows, fetchWindow]);

  const total = axis?.total_lanes || 0;
  const obsStart = axis?.observed_start ? Date.parse(axis.observed_start)
                                        : null;
  const obsEnd = axis?.observed_end ? Date.parse(axis.observed_end) : null;
  const span = view ? view.t1 - view.t0 : 0;
  const x = useCallback((ts) => {
    const t = Date.parse(ts);
    return ((t - view.t0) / Math.max(1, span)) * plotW;
  }, [view, span, plotW]);

  /** Only the lanes in view are rendered. */
  const visible = useMemo(() => {
    const out = [];
    for (let i = laneStart; i < laneStart + rows; i += 1) {
      const ln = lanes.get(i);
      if (ln) out.push(ln);
    }
    return out;
  }, [lanes, laneStart, rows]);

  const byLane = useMemo(() => {
    const m = new Map();
    if (!view) return m;
    for (const e of events.values()) {
      if (e.lane_index < laneStart || e.lane_index >= laneStart + rows)
        continue;
      const t = Date.parse(e.timestamp);
      if (!(t >= view.t0 && t <= view.t1)) continue;
      const arr = m.get(e.lane_index) || [];
      arr.push(e);
      m.set(e.lane_index, arr);
    }
    return m;
  }, [events, view, laneStart, rows]);

  const renderedGlyphs = [...byLane.values()].reduce((n, a) => n + a.length,
                                                     0);

  const moveTime = (dt) => setView((v) => {
    if (!v) return v;
    return { t0: v.t0 + dt, t1: v.t1 + dt };
  });
  const zoom = (f) => setView((v) => {
    if (!v) return v;
    const c = (v.t0 + v.t1) / 2, s = Math.max(1000, (v.t1 - v.t0) * f);
    return { t0: c - s / 2, t1: c + s / 2 };
  });
  const fit = () => obsStart && setView({ t0: obsStart, t1: obsEnd });

  const onMouseDown = (ev) => {
    if (ev.button !== 0) return;
    pan.current = { x0: ev.clientX, y0: ev.clientY, t0: view.t0,
                    t1: view.t1, lane0: laneStart, moved: false };
    const onMove = (e2) => {
      const p = pan.current;
      if (!p) return;
      const dx = e2.clientX - p.x0, dy = e2.clientY - p.y0;
      if (!p.moved && Math.abs(dx) < 4 && Math.abs(dy) < 4) return;
      p.moved = true;
      const dt = -(dx / Math.max(1, plotW)) * (p.t1 - p.t0);
      setView({ t0: p.t0 + dt, t1: p.t1 + dt });
      const dl = Math.round(-dy / ROW_H);
      const next = Math.max(0, Math.min(Math.max(0, total - 1),
                                        p.lane0 + dl));
      setLaneStart(next);
      if (vScroll.current) vScroll.current.scrollTop = next * ROW_H;
    };
    const onUp = () => {
      pan.current = null;
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
  };

  const epi = state.epistemic;
  const honest = epi && epi.state !== "OBSERVED";

  return (
    <NivXForgeConsole activeTab="device-trajectory">
      <h1 className="page-h1" data-testid="dt-heading">Device Trajectory</h1>
      <div className="page-sub">
        Endpoint-centric and windowed · Stage 1. Needs no case, incident or
        verdict: only the lanes and time slice in view are rendered, and
        only the window needed is fetched. A projection over the existing
        canonical evidence — it stores nothing of its own.
      </div>

      {!device && (
        <div className="x-empty" data-testid="dt-no-endpoint">
          Select an endpoint to view operational Device Trajectory —
          add <b>?device=&lt;device_iid&gt;</b>
        </div>
      )}
      {state.err && (
        <div className="x-empty" style={{ color: "#ff9494" }}
             data-testid="dt-error">{String(state.err)}</div>
      )}
      {honest && (
        <div className="x-empty" data-testid="dt-epistemic">
          <b>{epi.state}</b> — {epi.message}
        </div>
      )}

      {device && view && (
        <>
          <div style={{ display: "flex", gap: 8, alignItems: "center",
                        flexWrap: "wrap", margin: "10px 0 6px" }}
               data-testid="dt-controls">
            <button className="btn" onClick={() => zoom(0.5)}
                    data-testid="dt-zoom-in">Zoom +</button>
            <button className="btn" onClick={() => zoom(2)}
                    data-testid="dt-zoom-out">Zoom −</button>
            <button className="btn" onClick={fit}
                    data-testid="dt-fit">Fit</button>
            <button className="btn" onClick={() => moveTime(-span / 2)}
                    data-testid="dt-step-back">◀</button>
            <button className="btn" onClick={() => moveTime(span / 2)}
                    data-testid="dt-step-fwd">▶</button>
            <span className="mono" data-testid="dt-window"
                  style={{ fontSize: 10, color: "var(--cyan)" }}>
              window {fmtSpan(span)} · lanes {laneStart}–
              {Math.min(total, laneStart + rows)} of {total} ·{" "}
              {axis?.total?.value ?? "?"} observations in range
            </span>
            <span className="mono" data-testid="dt-loadstats"
                  style={{ fontSize: 9.5, color: "var(--faint)" }}>
              {stats.requests} window request(s) · {stats.merged} merged ·{" "}
              {stats.dupes} duplicate(s) suppressed · cache {stats.cache}/
              {CACHE_MAX} · rendering {renderedGlyphs} glyph(s) of{" "}
              {events.size} cached
            </span>
          </div>

          <div style={{ display: "flex", gap: 0 }}>
            <div ref={plotRef} onMouseDown={onMouseDown}
                 data-testid="dt-plot"
                 style={{ flex: 1, height: "52vh", overflow: "hidden",
                          background: "#0B0F14",
                          border: "1px solid #212B36", cursor: "grab",
                          position: "relative", userSelect: "none" }}>
              <svg width={GUTTER + plotW} height={rows * ROW_H}
                   data-testid="dt-svg">
                {visible.map((ln, i) => (
                  <g key={ln.lane_id}
                     data-testid={`dt-lane-${ln.lane_index}`}>
                    <rect x={0} y={i * ROW_H} width={GUTTER + plotW}
                          height={ROW_H}
                          fill={i % 2 ? "#0D1319" : "#0B0F14"} />
                    <text x={6 + Math.min(ln.depth, 6) * 8}
                          y={i * ROW_H + 14} fontSize={9.5}
                          fill={GROUP_COLOR[ln.group]} className="mono">
                      {ln.group === "PROCESS" && ln.depth > 0
                        ? "└ " : ""}{String(ln.label).slice(0, 34)}
                    </text>
                    <text x={GUTTER - 46} y={i * ROW_H + 14} fontSize={8.5}
                          fill="var(--faint)" className="mono">
                      {ln.count}
                    </text>
                    <line x1={GUTTER} y1={i * ROW_H + ROW_H / 2}
                          x2={GUTTER + plotW} y2={i * ROW_H + ROW_H / 2}
                          stroke="#161C24" />
                    {(byLane.get(ln.lane_index) || []).map((e) => (
                      <circle key={e.event_iid}
                              cx={GUTTER + x(e.timestamp)}
                              cy={i * ROW_H + ROW_H / 2} r={3.4}
                              fill={selected?.event_iid === e.event_iid
                                ? "#fff" : GROUP_COLOR[e.lane_group]}
                              stroke="#0B0F14"
                              onClick={() => setSelected(e)}
                              data-testid={`dt-glyph-${e.event_iid}`}
                              style={{ cursor: "pointer" }} />
                    ))}
                  </g>
                ))}
              </svg>
            </div>

            {/* Vertical scrollbar over the FULL lane axis. */}
            <div ref={vScroll} data-testid="dt-vscroll"
                 onScroll={(e) => setLaneStart(
                   Math.max(0, Math.min(Math.max(0, total - 1),
                                        Math.floor(e.target.scrollTop
                                                   / ROW_H))))}
                 style={{ width: 14, height: "52vh", overflowY: "scroll",
                          borderTop: "1px solid #212B36",
                          borderBottom: "1px solid #212B36",
                          borderRight: "1px solid #212B36" }}>
              <div style={{ height: Math.max(1, total) * ROW_H, width: 1 }} />
            </div>
          </div>

          {/* Horizontal scrollbar over the FULL observed time extent. */}
          <div ref={hScroll} data-testid="dt-hscroll"
               onScroll={(e) => {
                 if (!obsStart || !obsEnd) return;
                 const totalMs = Math.max(1, obsEnd - obsStart);
                 const w = e.target.scrollWidth - e.target.clientWidth;
                 const frac = w > 0 ? e.target.scrollLeft / w : 0;
                 const t0 = obsStart + frac * Math.max(0, totalMs - span);
                 setView({ t0, t1: t0 + span });
               }}
               style={{ overflowX: "scroll", height: 14,
                        border: "1px solid #212B36", borderTop: "none" }}>
            <div style={{ width: obsStart && obsEnd && span > 0
              ? `${Math.max(100, ((obsEnd - obsStart) / span) * 100)}%`
              : "100%", height: 1 }} />
          </div>

          <div className="mono" data-testid="dt-help"
               style={{ fontSize: 9, color: "var(--faint)", marginTop: 5 }}>
            drag ← → to move through time · drag ↑ ↓ to move through lanes ·
            or use the scrollbars · lanes are ordered processes (by lineage
            depth) → files → network, deterministically · lane axis
            version {axis?.lane_axis_version}
          </div>

          {selected && (
            <div data-testid="dt-details"
                 style={{ marginTop: 12, border: "1px solid #17202A",
                          borderRadius: 4, padding: "8px 10px",
                          background: "#080C10" }}>
              <div style={{ fontSize: 9, fontWeight: 800,
                            letterSpacing: ".6px", color: "var(--cyan)",
                            textTransform: "uppercase" }}>
                Activity details
              </div>
              <div style={{ display: "flex", gap: 16, flexWrap: "wrap",
                            marginTop: 8 }}>
                {[["timestamp", selected.timestamp],
                  ["event type", selected.event_type],
                  ["lane", `${selected.lane_group} #${selected.lane_index}`],
                  ["process", selected.process],
                  ["process state", selected.process_state],
                  ["process_iid", selected.process_iid],
                  ["parent_process_iid", selected.parent_process_iid],
                  ["pid", selected.pid], ["ppid", selected.ppid],
                  ["image", selected.image],
                  ["command line", selected.command_line],
                  ["user", selected.user], ["file", selected.file],
                  ["network", selected.network],
                  ["rule id", selected.rule_id],
                  ["raw_event_id", selected.provenance?.raw_event_id],
                  ["canonical_event_id",
                   selected.provenance?.canonical_event_id],
                  ["evidence_id", selected.provenance?.evidence_id],
                  ["adapter", selected.provenance?.adapter]].map(
                  ([k, v]) => (
                    <div key={k} style={{ minWidth: 170, maxWidth: 520 }}
                         data-testid={`dt-detail-${k.replace(/[ _]/g, "-")}`}>
                      <div style={{ color: "var(--faint)", fontSize: 8.5,
                                    fontWeight: 800,
                                    textTransform: "uppercase" }}>{k}</div>
                      <div className="mono"
                           style={{ fontSize: 10, marginTop: 2,
                                    wordBreak: "break-all",
                                    color: v ? "var(--text)"
                                             : "var(--faint)" }}>
                        {v === null || v === undefined || v === ""
                          ? "◇ not reported" : String(v)}
                      </div>
                    </div>
                  ))}
              </div>
            </div>
          )}
        </>
      )}
    </NivXForgeConsole>
  );
}
