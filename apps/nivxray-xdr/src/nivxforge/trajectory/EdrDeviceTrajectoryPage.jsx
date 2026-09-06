/**
 * Device Trajectory — Cisco Secure Endpoint (AMP) observable clone,
 * driven exclusively by NivXForge's authoritative endpoint evidence.
 *
 * Layout, as in the Cisco reference:
 *   Device Trajectory                       [Legacy Device Trajectory] [⤢]
 *   ┌ computer card ───────────┐ ┌ Navigator: filters · search ──────┐
 *   │ hostname · attributes    │ │ sparkline · 30-day · 24-hour      │
 *   └──────────────────────────┘ └───────────────────────────────────┘
 *   ┌ trajectory: rows × time ─────────────────────┐┌ Events ────────┐
 *
 * Mechanism:
 *   viewport {t0,t1,laneStart}  →  windowed projection request
 *                               →  bounded merge cache (event_iid)
 *                               →  virtualized rows
 *
 * The activity axis is ENDPOINT-WIDE and invariant to the viewport, so
 * row 300 is the same process at every zoom level; that is what makes
 * deep activity slices render real events instead of empty rows.
 *
 * There is no mock data path in this page. Every row, mark, day cell
 * and detail field comes from `GET /api/edr/endpoints/{id}/trajectory`.
 */
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { Maximize2, Minimize2, Moon, Sun } from "lucide-react";

import NivXForgeConsole from "@/nivxforge/NivXForgeConsole";
import api from "@/lib/api";

import { C, GUTTER, ROW_H, AXIS_H, MS, DAY_MS, iso, dayKeyOf, setTheme,
         startOfDayUTC } from "./ampModel";
import AmpComputerHeader from "./AmpComputerHeader";
import AmpFilterBar from "./AmpFilterBar";
import AmpCanvas from "./AmpCanvas";
import AmpNavigator from "./AmpNavigator";
import AmpActivityPanel from "./AmpActivityPanel";

const LANE_PREFETCH = 14;
const TIME_PREFETCH = 0.3;
const CACHE_MAX = 28;
const DETAILS_W = 348;

export default function EdrDeviceTrajectoryPage() {
  const [params, setParams] = useSearchParams();
  const device = params.get("device") || "";

  /** Cisco ships both a dark and a light console; the analyst picks.
   *  Applied before children render so one palette drives every part. */
  const [theme, setThemeState] = useState(
    () => window.localStorage.getItem("nvf-amp-theme") || "dark");
  setTheme(theme);

  const [meta, setMeta] = useState(null);
  const [view, setView] = useState(null);
  const [laneStart, setLaneStart] = useState(0);
  const [rows, setRows] = useState(26);
  const [events, setEvents] = useState(new Map());
  const [lanes, setLanes] = useState(new Map());
  const [selected, setSelected] = useState(null);
  const [selectedDay, setSelectedDay] = useState(null);
  const [preset, setPreset] = useState("all");
  const [kinds, setKinds] = useState([]);
  const [dispositions, setDispositions] = useState([]);
  const [query, setQuery] = useState("");
  const [debounced, setDebounced] = useState("");
  const [navCollapsed, setNavCollapsed] = useState(false);
  const [fullscreen, setFullscreen] = useState(false);
  const [status, setStatus] = useState({ loading: true, err: null });
  const [locating, setLocating] = useState(false);
  const [endpoints, setEndpoints] = useState([]);

  const cache = useRef(new Map());
  const plotRef = useRef(null);
  const vScroll = useRef(null);
  const [plotW, setPlotW] = useState(760);

  useEffect(() => {
    const t = setTimeout(() => setDebounced(query.trim()), 350);
    return () => clearTimeout(t);
  }, [query]);

  const filterKey = useMemo(
    () => `${kinds.slice().sort().join(",")}|${dispositions.slice().sort()
      .join(",")}|${debounced}`, [kinds, dispositions, debounced]);

  const filterParams = useMemo(() => {
    const p = {};
    if (kinds.length) p.kinds = kinds.join(",");
    if (dispositions.length) p.dispositions = dispositions.join(",");
    if (debounced) p.q = debounced;
    return p;
  }, [kinds, dispositions, debounced]);

  /** Filters change the population AND re-index the activity axis
   *  (a filtered axis only contains rows with matching activity), so
   *  the merge cache, the row cache and the row offset are all reset —
   *  keeping them would draw row 0's evidence on row 300. */
  useEffect(() => {
    cache.current.clear();
    setEvents(new Map());
    setLanes(new Map());
    setLaneStart(0);
    if (vScroll.current) vScroll.current.scrollTop = 0;
  }, [filterKey]);

  useEffect(() => {
    const el = plotRef.current;
    if (!el) return;
    const ro = new ResizeObserver((en) => {
      const w = en[0]?.contentRect?.width;
      if (w) setPlotW(Math.max(300, Math.floor(w - GUTTER - 13)));
    });
    ro.observe(el);
    return () => ro.disconnect();
  }, [fullscreen, navCollapsed, device, view]);

  /** The trajectory fills whatever the header leaves — measured, not
   *  assumed, so collapsing the Navigator really does give the plot the
   *  space back. */
  useEffect(() => {
    const h = () => {
      const top = plotRef.current?.getBoundingClientRect()?.top ?? 300;
      const avail = window.innerHeight - top - 92;
      setRows(Math.max(24, Math.floor(Math.max(180, avail) / ROW_H)));
    };
    const t = setTimeout(h, 120);
    window.addEventListener("resize", h);
    return () => { clearTimeout(t); window.removeEventListener("resize", h); };
  }, [fullscreen, navCollapsed, meta, view]);

  useEffect(() => {
    if (device) return;
    api.get("/edr/endpoints").then(({ data }) =>
      setEndpoints((data.endpoints || []).filter((e) => e.device_iid)))
      .catch(() => {});
  }, [device]);

  /** Meta pass: computer card, activity bands, type counts, extent.
   *  lane 0-1 / limit 1 keeps it off the event path. */
  const loadMeta = useCallback(async (day) => {
    const { data } = await api.get(
      `/edr/endpoints/${encodeURIComponent(device)}/trajectory`,
      { params: { lane_start: 0, lane_end: 1, limit: 1,
                  hist_day: day || undefined, ...filterParams } });
    setMeta(data);
    return data;
  }, [device, filterParams]);

  useEffect(() => {
    if (!device) { setStatus({ loading: false, err: null }); return; }
    let dead = false;
    setStatus((s) => ({ ...s, loading: true }));
    (async () => {
      try {
        const data = await loadMeta(selectedDay != null
          ? dayKeyOf(selectedDay) : null);
        if (dead) return;
        setStatus({ loading: false, err: null });
        const s = data.time_range?.observed_start;
        const e = data.time_range?.observed_end;
        if (s && e) {
          const a = Date.parse(s), b = Date.parse(e);
          setSelectedDay((d) => d ?? startOfDayUTC(b));
          setView((v) => v ?? { t0: startOfDayUTC(b), t1: startOfDayUTC(b)
            + DAY_MS });
          if (preset === "all") setPreset("1d");
        }
      } catch (x) {
        if (!dead) setStatus({ loading: false,
                               err: x?.response?.data?.detail?.reason
                                 || x?.message || String(x) });
      }
    })();
    return () => { dead = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [device, filterKey]);

  /** The 24-hour band needs the selected day's bins. */
  useEffect(() => {
    if (!device || selectedDay == null || status.loading) return;
    loadMeta(dayKeyOf(selectedDay)).catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [device, selectedDay]);

  const fetchWindow = useCallback(async (t0, t1, l0, l1) => {
    const key = `${Math.round(t0)}|${Math.round(t1)}|${l0}|${l1}|${filterKey}`;
    if (cache.current.has(key)) return;
    cache.current.set(key, true);
    if (cache.current.size > CACHE_MAX) {
      cache.current.delete(cache.current.keys().next().value);
    }
    const { data } = await api.get(
      `/edr/endpoints/${encodeURIComponent(device)}/trajectory`,
      { params: { time_start: iso(t0), time_end: iso(t1), lane_start: l0,
                  lane_end: l1, limit: 2500, ...filterParams } });
    if (data.lane_axis) {
      setLanes((prev) => {
        const m = new Map(prev);
        for (const ln of data.lane_axis.lanes || []) m.set(ln.lane_index, ln);
        return m;
      });
    }
    setEvents((prev) => {
      const m = new Map(prev);
      for (const e of data.events || []) m.set(e.event_iid, e);
      return m;
    });
  }, [device, filterKey, filterParams]);

  useEffect(() => {
    if (!device || !view) return;
    const span = view.t1 - view.t0;
    const l0 = Math.max(0, laneStart - LANE_PREFETCH);
    const l1 = laneStart + rows + LANE_PREFETCH;
    fetchWindow(view.t0 - span * TIME_PREFETCH,
                view.t1 + span * TIME_PREFETCH, l0, l1)
      .catch((x) => setStatus((s) => ({ ...s,
        err: x?.message || String(x) })));
  }, [device, view, laneStart, rows, fetchWindow]);

  const total = meta?.lane_axis?.total_lanes || 0;
  const obsStart = meta?.time_range?.observed_start
    ? Date.parse(meta.time_range.observed_start) : null;
  const obsEnd = meta?.time_range?.observed_end
    ? Date.parse(meta.time_range.observed_end) : null;
  const span = view ? view.t1 - view.t0 : 0;

  const visibleLanes = useMemo(() => {
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
    for (const arr of m.values()) {
      arr.sort((a, b) => (a.timestamp < b.timestamp ? -1 : 1));
    }
    return m;
  }, [events, view, laneStart, rows]);

  /** The Events panel lists the window's observations chronologically,
   *  across every row in view. */
  const windowEvents = useMemo(() => {
    const out = [];
    for (const arr of byLane.values()) out.push(...arr);
    out.sort((a, b) => (a.timestamp < b.timestamp ? -1 : 1));
    return out;
  }, [byLane]);

  /** Selecting an observation brings it into view on BOTH axes — a
   *  selection the analyst cannot see is not a selection. */
  const focusEvent = useCallback((e) => {
    if (!e) { setSelected(null); return; }
    setSelected(e);
    const t = Date.parse(e.timestamp);
    setView((v) => {
      if (!v) return v;
      const s = v.t1 - v.t0;
      if (t >= v.t0 + s * 0.06 && t <= v.t1 - s * 0.06) return v;
      return { t0: t - s / 2, t1: t + s / 2 };
    });
    setSelectedDay((d) => (d === startOfDayUTC(t) ? d : startOfDayUTC(t)));
    if (e.lane_index < laneStart || e.lane_index >= laneStart + rows) {
      const n = Math.max(0, Math.min(Math.max(0, total - 1),
                                     e.lane_index - Math.floor(rows / 3)));
      setLaneStart(n);
      if (vScroll.current) vScroll.current.scrollTop = n * ROW_H;
    }
    const next = new URLSearchParams(params);
    next.set("event", e.event_iid);
    setParams(next, { replace: true });
  }, [laneStart, rows, total, params, setParams]);

  const deepLink = params.get("event");
  const locate = useCallback(async (iid) => {
    if (!device) return;
    setLocating(true);
    try {
      let cursor = null;
      for (let page = 0; page < 6; page += 1) {
        const { data } = await api.get(
          `/edr/endpoints/${encodeURIComponent(device)}/trajectory`,
          { params: { lane_start: 0, lane_end: Math.max(1, total),
                      limit: 2500, cursor: cursor || undefined,
                      ...filterParams } });
        setEvents((prev) => {
          const m = new Map(prev);
          for (const e of data.events || []) m.set(e.event_iid, e);
          return m;
        });
        setLanes((prev) => {
          const m = new Map(prev);
          for (const ln of data.lane_axis?.lanes || []) {
            m.set(ln.lane_index, ln);
          }
          return m;
        });
        const hit = (data.events || []).find((e) => e.event_iid === iid);
        if (hit) { focusEvent(hit); break; }
        if (!data.next_cursor) break;
        cursor = data.next_cursor;
      }
    } finally {
      setLocating(false);
    }
  }, [device, total, filterParams, focusEvent]);

  useEffect(() => {
    if (!deepLink || selected?.event_iid === deepLink) return;
    const hit = events.get(deepLink);
    if (hit) focusEvent(hit);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [deepLink, events]);

  const onPreset = (key, days) => {
    setPreset(key);
    if (obsEnd == null) return;
    if (!days) {
      if (obsStart != null) setView({ t0: obsStart, t1: obsEnd });
      return;
    }
    setView({ t0: obsEnd - days * DAY_MS, t1: obsEnd });
    setSelectedDay(startOfDayUTC(obsEnd));
  };

  const openTab = (path, extra) => {
    const p = new URLSearchParams();
    if (device) p.set("device", device);
    Object.entries(extra || {}).forEach(([k, v]) => v && p.set(k, v));
    window.open(`${path}?${p.toString()}`, "_blank", "noopener");
  };

  const onPivot = (kind, e) => {
    if (kind === "process-tree") {
      openTab("/edr/process-tree", { process_iid: e?.process_iid });
    } else if (kind === "campaign-story") {
      openTab("/edr/campaign-story",
              { incident_id: e?.provenance?.incident_id });
    } else if (kind === "file-trajectory") {
      openTab("/xdr/fleet-file-trajectory",
              { key: e?.file || e?.process,
                key_type: e?.file ? "path" : "name" });
    } else if (kind === "filter-indicator") {
      setQuery(e?.file || e?.network || e?.process || e?.rule_id || "");
    } else if (kind === "focus" && e?.timestamp) {
      const t = Date.parse(e.timestamp);
      setView({ t0: t - 15 * MS.m, t1: t + 15 * MS.m });
      setSelectedDay(startOfDayUTC(t));
    } else if (kind === "copy-digest") {
      navigator.clipboard?.writeText(e?.event_content_digest || "");
    } else if (kind === "forensics") openTab("/edr/forensics");
    else if (kind === "live-query") openTab("/edr/live-query");
    else if (kind === "detections") openTab("/edr/detections");
    else if (kind === "isolation") openTab("/edr/response");
  };

  const epi = meta?.epistemic_state;
  const canvasH = AXIS_H + rows * ROW_H;
  const malicious = (meta?.activity?.days || [])
    .reduce((n, d) => n + (d.malicious || 0), 0);
  const detections = (meta?.activity?.days || [])
    .reduce((n, d) => n + (d.detections || 0), 0);

  const filterStrip = (
    <div style={{ background: C.paper,
                  border: `1px solid ${C.gridStrong}`, borderRadius: 6,
                  height: "fit-content" }}>
      <AmpFilterBar
        typeCounts={meta?.event_type_counts || []}
        kinds={kinds} onKinds={setKinds}
        dispositions={dispositions} onDispositions={setDispositions}
        query={query} onQuery={setQuery}
        preset={preset} onPreset={onPreset}
        matched={meta?.matched_after_filters ?? 0}
        total={meta?.observations_all_time ?? 0}
        collapsed={navCollapsed} onCollapsed={setNavCollapsed}
        onZoom={(f) => setView((v) => {
          if (!v) return v;
          const c = (v.t0 + v.t1) / 2;
          const sp = Math.max(1000, (v.t1 - v.t0) * f);
          return { t0: c - sp / 2, t1: c + sp / 2 };
        })}
        onPan={(frac) => setView((v) => {
          if (!v) return v;
          const sp = v.t1 - v.t0;
          return { t0: v.t0 + sp * frac, t1: v.t1 + sp * frac };
        })}
        onFitDay={() => selectedDay != null
          && setView({ t0: selectedDay, t1: selectedDay + DAY_MS })} />
    </div>
  );

  const navigator_ = view && (
    <AmpNavigator
      days={meta?.activity?.days || []}
      dayBins={meta?.activity?.day_bins || []}
      selectedDay={selectedDay} onSelectDay={setSelectedDay}
      view={view} onView={setView}
      observedEnd={meta?.time_range?.observed_end}
      cursorTs={selected?.timestamp ? Date.parse(selected.timestamp) : null}
      collapsed={navCollapsed}
      onFocusTime={(t, iid) => {
        setView({ t0: t - 15 * MS.m, t1: t + 15 * MS.m });
        const hit = iid ? events.get(iid) : null;
        if (hit) setSelected(hit);
      }} />
  );

  const body = (
    <>
      <div style={{ display: "flex", alignItems: "center", gap: 10,
                    marginBottom: 8 }}>
        <span style={{ fontSize: 15, fontWeight: 700, color: C.ink }}
              data-testid="dt-heading">
          Device Trajectory
        </span>
        <span style={{ flex: 1 }} />
        <button onClick={() => {
                  const next = theme === "dark" ? "light" : "dark";
                  window.localStorage.setItem("nvf-amp-theme", next);
                  setThemeState(next);
                }}
                data-testid="amp-theme-toggle"
                data-theme={theme}
                title={theme === "dark" ? "Switch to the light console"
                  : "Switch to the dark console"}
                style={{ fontSize: 10.6, color: C.link, cursor: "pointer",
                         background: C.paper, padding: "4px 8px",
                         borderRadius: 2,
                         border: `1px solid ${C.gridStrong}`,
                         display: "flex", alignItems: "center", gap: 5 }}>
          {theme === "dark" ? <Sun size={11} /> : <Moon size={11} />}
          {theme === "dark" ? "Light" : "Dark"}
        </button>
        <a href="/edr/trajectory" target="_blank" rel="noreferrer"
           data-testid="amp-legacy-link"
           style={{ fontSize: 10.6, color: C.link, textDecoration: "none",
                    background: C.paper, padding: "4px 9px", borderRadius: 2,
                    border: `1px solid ${C.gridStrong}` }}>
          Use Legacy Device Trajectory
        </a>
        <button onClick={() => setFullscreen((v) => !v)}
                data-testid="amp-fullscreen-toggle"
                title={fullscreen ? "Exit fullscreen" : "Fullscreen"}
                style={{ fontSize: 10.6, color: C.link, cursor: "pointer",
                         background: C.paper, padding: "4px 8px",
                         borderRadius: 2,
                         border: `1px solid ${C.gridStrong}`,
                         display: "flex", alignItems: "center" }}>
          {fullscreen ? <Minimize2 size={11} /> : <Maximize2 size={11} />}
        </button>
      </div>

      {!device && (
        <div data-testid="amp-no-endpoint"
             style={{ background: C.paper, border: `1px solid ${C.grid}`,
                      padding: 16, color: C.ink, fontSize: 11.5 }}>
          <b>Select an endpoint</b> to open its Device Trajectory.
          <div style={{ marginTop: 10, display: "flex", gap: 8,
                        flexWrap: "wrap" }}>
            {endpoints.map((e) => (
              <button key={e.device_iid}
                      data-testid={`amp-pick-${e.device_iid}`}
                      onClick={() => setParams({ device: e.device_iid })}
                      style={{ fontSize: 10.5, padding: "5px 9px",
                               cursor: "pointer", background: C.paperAlt,
                               border: `1px solid ${C.gridStrong}`,
                               color: C.ink }}>
                {e.hostname || e.device_iid}
                <span className="mono" style={{ color: C.inkFaint,
                                                marginLeft: 6 }}>
                  {e.observation_count} obs
                </span>
              </button>
            ))}
          </div>
        </div>
      )}

      {status.err && (
        <div data-testid="amp-error"
             style={{ background: "#FDECEC", border: "1px solid #F3C2C2",
                      color: "#8E1E23", padding: "8px 12px", fontSize: 11,
                      marginBottom: 8 }}>{String(status.err)}</div>
      )}

      {device && (
        <>
          <div style={{ display: "flex", gap: 10, alignItems: "flex-start",
                        marginBottom: 8 }}>
            <div style={{ flex: "1 1 50%", minWidth: 320, display: "flex" }}>
              {meta && (
                <AmpComputerHeader computer={meta.computer} epistemic={epi}
                                   malicious={malicious}
                                   detections={detections}
                                   onAction={(k) => onPivot(k, selected)} />
              )}
            </div>
            <div style={{ flex: "1 1 50%", minWidth: 360 }}>
              {filterStrip}
            </div>
          </div>
          <div style={{ marginBottom: 8 }}>{navigator_}</div>
        </>
      )}

      {device && status.loading && !meta && (
        <div data-testid="amp-loading"
             style={{ background: C.paper, border: `1px solid ${C.grid}`,
                      padding: 14, fontSize: 11, color: C.inkDim }}>
          Loading endpoint evidence…
        </div>
      )}

      {locating && (
        <div data-testid="amp-locating"
             style={{ background: C.paper, border: `1px solid ${C.grid}`,
                      padding: "6px 12px", fontSize: 10.5,
                      color: C.inkDim }}>
          Searching the retained period for the deep-linked observation…
        </div>
      )}

      {device && meta && !view && !status.loading && (
        <div data-testid="amp-no-activity"
             style={{ background: C.paper, border: `1px solid ${C.grid}`,
                      padding: 14, fontSize: 11, color: C.inkDim }}>
          {epi?.message || "No observed activity for this endpoint."}
        </div>
      )}

      {device && deepLink && !events.get(deepLink) && !locating && (
        <div style={{ background: C.paper, border: `1px solid ${C.grid}`,
                      padding: "7px 12px", fontSize: 10.5, color: C.inkDim,
                      marginBottom: 8 }}>
          Deep-linked observation <span className="mono">{deepLink}</span> is
          not in the loaded window.{" "}
          <button onClick={() => locate(deepLink)}
                  data-testid="amp-locate-deeplink"
                  style={{ fontSize: 10.5, cursor: "pointer",
                           background: C.paperAlt, color: C.link,
                           border: `1px solid ${C.gridStrong}`,
                           padding: "2px 7px" }}>
            Search the retained period
          </button>
        </div>
      )}

      {device && view && (
        <>
          <div style={{ display: "flex", alignItems: "stretch",
                        border: `1px solid ${C.gridStrong}`,
                        borderRadius: 6, overflow: "hidden",
                        background: C.paper }}
               data-testid="amp-workspace">
            <div ref={plotRef} style={{ flex: 1, minWidth: 0,
                                        display: "flex",
                                        flexDirection: "column" }}>
              <div style={{ display: "flex" }}>
                <AmpCanvas
                  lanes={visibleLanes} laneStart={laneStart} rows={rows}
                  totalLanes={total} view={view} plotW={plotW}
                  height={canvasH} byLane={byLane} selected={selected}
                  onSelect={focusEvent} onView={setView}
                  onLaneStart={(n) => {
                    setLaneStart(n);
                    if (vScroll.current) vScroll.current.scrollTop = n * ROW_H;
                  }}
                  onPivot={onPivot} />
                <div ref={vScroll} data-testid="amp-vscroll"
                     onScroll={(e) => setLaneStart(Math.max(0, Math.min(
                       Math.max(0, total - 1),
                       Math.floor(e.target.scrollTop / ROW_H))))}
                     style={{ width: 13, height: canvasH,
                              overflowY: "scroll", flexShrink: 0,
                              background: C.paperAlt,
                              borderLeft: `1px solid ${C.grid}` }}>
                  <div style={{ height: Math.max(1, total) * ROW_H,
                                width: 1 }} />
                </div>
              </div>

              {/* time-axis scrollbar over the whole retained period */}
              <div data-testid="amp-hscroll"
                   onScroll={(e) => {
                     if (obsStart == null || obsEnd == null) return;
                     const totalMs = Math.max(1, obsEnd - obsStart);
                     const w = e.target.scrollWidth - e.target.clientWidth;
                     const frac = w > 0 ? e.target.scrollLeft / w : 0;
                     const t0 = obsStart + frac * Math.max(0, totalMs - span);
                     setView({ t0, t1: t0 + span });
                   }}
                   style={{ overflowX: "scroll", height: 13,
                            background: C.paperAlt,
                            borderTop: `1px solid ${C.grid}` }}>
                <div style={{ width: obsStart != null && obsEnd != null
                  && span > 0
                  ? `${Math.max(100, ((obsEnd - obsStart) / span) * 100)}%`
                  : "100%", height: 1 }} />
              </div>
            </div>

            {/* Cisco's right-hand pane: Activity master list, drilling
                in to Activity Details in place, with a back arrow. */}
            <AmpActivityPanel events={windowEvents} lanes={lanes}
                              selected={selected} onSelect={focusEvent}
                              onPivot={onPivot} width={DETAILS_W}
                              height={canvasH + 13} />
          </div>

          <div className="mono" data-testid="amp-status"
               style={{ fontSize: 9, color: C.inkFaint,
                        padding: "5px 2px" }}>
            rows {laneStart}–{Math.min(total, laneStart + rows)} of {total} ·{" "}
            {windowEvents.length} observation(s) in the window from{" "}
            {events.size} cached · activity axis{" "}
            {meta?.lane_axis?.lane_axis_version}{" "}
            ({meta?.lane_axis?.axis_scope}) · navigate with the two
            scrollbars, by dragging the trajectory, or from the Navigator
            bands and search · the mouse wheel is intentionally inert
            here, as in the Cisco console
          </div>
        </>
      )}
    </>
  );

  if (fullscreen) {
    return (
      <div data-testid="amp-fullscreen"
           style={{ position: "fixed", inset: 0, zIndex: 2000,
                    background: C.shell, overflow: "auto",
                    padding: "12px 16px" }}>
        {body}
      </div>
    );
  }

  return (
    <NivXForgeConsole activeTab="device-trajectory">
      <div data-testid="amp-page-surface"
           style={{ background: C.page,
                    border: `1px solid ${C.gridStrong}`, borderRadius: 6,
                    padding: "12px 14px 14px", margin: "-4px -8px 0" }}>
        {body}
      </div>
    </NivXForgeConsole>
  );
}
