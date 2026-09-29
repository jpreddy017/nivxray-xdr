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
import { Maximize2, Minimize2, Share2 } from "lucide-react";

import NivXForgeConsole from "@/nivxforge/NivXForgeConsole";
import { buildFileTrajectoryPivot, buildIncidentPivot,
         buildSightingsPivot } from "@/xdr/lib/pivots";
import { getSessionContext } from "@/nivxforge/edrApi";
import api from "@/lib/api";

import { C, GUTTER, ROW_H, AXIS_H, MS, DAY_MS, iso, dayKeyOf, setTheme,
         startOfDayUTC } from "./ampModel";
import { HISTORY, REQ, WINDOW_STATE, bucketsOf, centreOn, clampLaneStart,
         evidenceWindow,
         createCoordinator, emptinessMeaning, historyMode, laneWindow,
         levelOf, panByFraction, prefetchTargets, requestKey, restore,
         retentionBounds, selectionState, serialize, spikes, stepDetection,
         stepObservation, windowForBucket, windowStateOf,
         zoomBySteps } from "./dt2";
import AmpComputerHeader from "./AmpComputerHeader";
import AmpFilterBar from "./AmpFilterBar";
import AmpCanvas from "./AmpCanvas";
import RelationshipCanvas from "./RelationshipCanvas";
import { msUTC } from "./dt2/instant";
import { CISCO_DISPLAYED, fileTypeOf } from "./dt2/fileType";
import { attachContributors, indexCompromise } from "./dt2/compromise";
import { GRAPH_READY, focusOf, graphBoundsOf, graphOf, graphStateOf,
         neighbourStep, parentOf } from "./dt2/graphModel";
import AmpNavigator from "./AmpNavigator";
import AmpCompromisePanel from "./AmpCompromisePanel";
import AmpActivityPanel from "./AmpActivityPanel";

const LANE_PREFETCH = 14;
const TIME_PREFETCH = 0.3;
const CACHE_MAX = 28;
const DETAILS_W = 394;

/** Phase-2 gate. `false` = the AMP-parity presentation. NivXForge's own
 *  trajectory surfaces (handoff/projection/request banners, the temporal
 *  toolbar, the endpoint-wide EVENT LANES canvas, the relationship-basis
 *  rail) stay compiled and wired behind this flag; none of them appears
 *  in the Cisco reference, so none of them is presented. */
const PARKED_NIVXFORGE_UI = false;

const navBtn = { fontSize: 10.4, cursor: "pointer", background: C.paperAlt,
                 color: C.link, border: `1px solid ${C.gridStrong}`,
                 borderRadius: 2, padding: "3px 7px" };

/** Cisco's two square, blue-outlined icon buttons at the top right. */
const iconBtn = { width: 34, height: 32, cursor: "pointer",
                  background: C.paper, color: C.link, borderRadius: 4,
                  border: `1px solid ${C.link}`, display: "flex",
                  alignItems: "center", justifyContent: "center",
                  flexShrink: 0 };

export default function EdrDeviceTrajectoryPage({ embedded = false,
                                                 device: deviceProp = null }) {
  const [params, setParams] = useSearchParams();
  const device = deviceProp || params.get("device") || "";

  /** The Cisco Device Trajectory is ONE investigation surface. The
   *  reference defines it, so this page offers no theme choice; the
   *  surrounding NivXForge console chrome keeps its own. */
  setTheme("light");

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
  //: Cisco's documented displayed file types (User Guide p.401) are the
  //: default File Type selection; `OTHER` is offered but not displayed
  //: by default, exactly as Cisco's set implies.
  const [fileTypes, setFileTypes] = useState(CISCO_DISPLAYED);
  //: Cisco's Filters de-select individual process trajectories to de-noise
  //: the graph. Presentation only — nothing is removed from the evidence.
  const [hiddenProcs, setHiddenProcs] = useState([]);
  const [query, setQuery] = useState("");
  const [debounced, setDebounced] = useState("");
  const [navCollapsed, setNavCollapsed] = useState(false);
  const [fullscreen, setFullscreen] = useState(false);
  const [status, setStatus] = useState({ loading: true, err: null });
  const [locating, setLocating] = useState(false);
  const [endpoints, setEndpoints] = useState([]);
  const [sessCtx, setSessCtx] = useState(null);

  const cache = useRef(new Map());
  const plotRef = useRef(null);
  const vScroll = useRef(null);
  const [plotW, setPlotW] = useState(760);

  /** DT2-1 · navigation engine state.
   *  `coord` owns request generations and AbortControllers; `boundsRef`
   *  carries the retention/evidence bounds into callbacks that are
   *  created before the meta pass has resolved them. */
  const coord = useRef(null);
  if (!coord.current) coord.current = createCoordinator();
  const boundsRef = useRef({ min: null, max: null });
  const tenantRef = useRef(null);
  const urlWriteRef = useRef("");
  const [dt2, setDt2] = useState(null);
  /* DT2-3c · the AUTHORITATIVE compromise layer, straight from the
     server contract. `observed === false` means no authoritative
     compromise exists for this endpoint — a real answer, and not a
     clean claim. The client never derives one. */
  const compromise = useMemo(() => indexCompromise(meta), [meta]);
  /** DT2-3 · the process/relationship/time view over the server graph. The
   *  event canvas stays one click away; neither view infers relationships. */
  const [mode, setMode] = useState("RELATIONSHIPS");
  const [selectedNode, setSelectedNode] = useState(null);
  const [selectedCompromise, setSelectedCompromise] = useState(null);
  const [stepCtx, setStepCtx] = useState(null);
  const [req, setReq] = useState({ loading: false, prefetching: false,
                                   canceled: false, staleDiscarded: false,
                                   err: null });

  useEffect(() => {
    const t = setTimeout(() => setDebounced(query.trim()), 350);
    return () => clearTimeout(t);
  }, [query]);

  const filterKey = useMemo(
    () => `${kinds.slice().sort().join(",")}|${dispositions.slice().sort()
      .join(",")}|${debounced}`, [kinds, dispositions, debounced]);

  /** Real counts per Cisco file class, from the observed paths the
   *  graph already carries. Nothing is counted that was not observed. */
  const fileTypeCounts = useMemo(() => {
    const n = new Map();
    for (const a of (dt2?.graph?.activity_nodes || [])) {
      if (a.family !== "FILE" || !a.label) continue;
      const k = fileTypeOf(a.label);
      n.set(k, (n.get(k) || 0) + 1);
    }
    return n;
  }, [dt2]);

  /** The process trajectories the analyst may de-select, from the graph. */
  const processChoices = useMemo(
    () => (dt2?.graph?.process_nodes || []).map((n) => ({
      nodeId: n.node_id, label: n.label || n.image || n.node_id,
      pid: n.pid })), [dt2]);



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
      const avail = window.innerHeight - top - 150;
      setRows(Math.max(14, Math.floor(Math.max(180, avail) / ROW_H)));
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
    getSessionContext().then(setSessCtx).catch(() => {});
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
          const b = msUTC(e);
          // Detection → Trajectory: land on the detection's own moment,
          // not on "now" and not on the endpoint's last day.
          const at = params.get("at") ? msUTC(params.get("at")) : null;
          const anchor = Number.isFinite(at) && at ? at : b;
          setSelectedDay((d) => d ?? startOfDayUTC(anchor));
          /** Cisco's trajectory axis is the SELECTED DAY: the date
           *  header names the day(s), the time scale carries the hour
           *  reference marks, and the 24-hour navigator band above it
           *  describes the same interval. No timestamp is moved,
           *  spread or collapsed to fill it. */
          setView((v) => {
            if (v) return v;
            const day = startOfDayUTC(Number.isFinite(at) && at ? at : b);
            return { t0: day, t1: day + DAY_MS };
          });
          if (preset === "all") setPreset("1d");
        }
        // Progressive completion: the first paint is a BOUNDED projection
        // of the most recent observations. The complete, viewport-invariant
        // axis is being built server-side, so re-read once it is ready
        // instead of making the analyst wait for it up front.
        if (data.projection?.state === "BOUNDED_RECENT") {
          for (let i = 0; i < 12 && !dead; i += 1) {
            // eslint-disable-next-line no-await-in-loop
            await new Promise((r) => window.setTimeout(r, 2500));
            if (dead) return;
            // eslint-disable-next-line no-await-in-loop
            const next = await loadMeta(selectedDay != null
              ? dayKeyOf(selectedDay) : null);
            if (next?.projection?.state === "COMPLETE") break;
          }
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

  /** DT2-3a.2 · the PRIMARY VIEWPORT opens on the evidence-bearing
   *  interval of the selected day, not on the whole day. The day stays
   *  the navigator's domain; the trajectory is the focused window. Runs
   *  once per device+day, so an analyst's own pan/zoom always wins. */
  const autoFocusRef = useRef(null);
  useEffect(() => {
    const g = graphOf(dt2);
    if (!g || selectedDay == null) return;
    const key = `${device}|${selectedDay}|${filterKey}`;
    if (autoFocusRef.current === key) return;
    const b = graphBoundsOf(g);
    if (b.min == null) return;
    const w = evidenceWindow(b.min, b.max, { dayStart: selectedDay });
    if (!w) return;
    autoFocusRef.current = key;
    setView((v) => (v && v.t0 === w.t0 && v.t1 === w.t1 ? v : w));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dt2, device, selectedDay, filterKey]);

  /** The 24-hour band needs the selected day's bins. */
  useEffect(() => {
    if (!device || selectedDay == null || status.loading) return;
    loadMeta(dayKeyOf(selectedDay)).catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [device, selectedDay]);

  /** DT2-1 · one windowed request, protected against races.
   *
   *  A generation token is minted per viewport change and the previous
   *  in-flight request is aborted. A response whose generation is no
   *  longer current is DISCARDED — window A completing after window C
   *  can never reposition the viewport or replace the selection.
   */
  const fetchWindow = useCallback(async (t0, t1, l0, l1) => {
    const key = requestKey({ tenantId: tenantRef.current, endpointId: device,
                             t0, t1, laneStart: l0, laneEnd: l1, filterKey });
    if (cache.current.has(key)) return;
    const begun = coord.current.begin(key);
    if (begun.deduped) return;
    cache.current.set(key, true);
    if (cache.current.size > CACHE_MAX) {
      cache.current.delete(cache.current.keys().next().value);
    }
    setReq((s) => ({ ...s, loading: true, err: null, canceled: false,
                     staleDiscarded: false }));
    try {
      const { data } = await api.get(
        `/edr/endpoints/${encodeURIComponent(device)}/trajectory`,
        { params: { time_start: iso(t0), time_end: iso(t1), lane_start: l0,
                    lane_end: l1, limit: 2500, ...filterParams },
          signal: begun.signal });
      if (coord.current.commit(begun.generation) !== REQ.COMMITTED) {
        /** A stale success is not evidence about the current window. */
        setReq((s) => ({ ...s, loading: false, staleDiscarded: true }));
        return;
      }
      if (data.dt2) setDt2(data.dt2);
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
      setReq((s) => ({ ...s, loading: false }));
    } catch (x) {
      coord.current.commit(begun.generation);
      /** A window that was never delivered must be retryable. */
      cache.current.delete(key);
      const aborted = x?.code === "ERR_CANCELED" || x?.name === "CanceledError"
        || x?.name === "AbortError" || begun.signal?.aborted;
      setReq((s) => ({ ...s, loading: false, canceled: !!aborted,
                       err: aborted ? null : (x?.message || String(x)) }));
    }
  }, [device, filterKey, filterParams]);

  useEffect(() => {
    if (!device || !view) return;
    const span = view.t1 - view.t0;
    const lw = laneWindow(laneStart, rows, total || (laneStart + rows),
                          LANE_PREFETCH);
    fetchWindow(view.t0 - span * TIME_PREFETCH,
                view.t1 + span * TIME_PREFETCH, lw.from, lw.to)
      .catch((x) => setReq((s) => ({ ...s,
        err: x?.message || String(x) })));
  }, [device, view, laneStart, rows, fetchWindow]);

  const total = meta?.lane_axis?.total_lanes || 0;
  const obsStart = meta?.time_range?.observed_start
    ? msUTC(meta.time_range.observed_start) : null;
  const obsEnd = meta?.time_range?.observed_end
    ? msUTC(meta.time_range.observed_end) : null;
  const span = view ? view.t1 - view.t0 : 0;

  /** DT2-1 · retention truth. The bounds that clamp pan/zoom come from
   *  the DT2-0 contract when it is present and from the V1 observed
   *  extent otherwise. An unprovable bound stays null and clamps
   *  nothing — we never invent a retention edge. */
  const retention = useMemo(
    () => retentionBounds(dt2, { min: obsStart, max: obsEnd }),
    [dt2, obsStart, obsEnd]);
  boundsRef.current = { min: retention.min ?? obsStart,
                        max: retention.max ?? obsEnd };
  tenantRef.current = sessCtx?.active_customer?.value
    || meta?.computer?.tenant_id || null;

  /** Density is NAVIGATION QUANTITY from the DT2-0 contract. It is not
   *  severity, and a spike is not a threat claim. */
  const density = useMemo(() => bucketsOf(dt2, "events"), [dt2]);
  const densitySpikes = useMemo(() => spikes(density, { count: 5 }),
                                [density]);

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
      const t = msUTC(e.timestamp);
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

  /** DT2-1 · window state truth. A failed or superseded request is
   *  never rendered as "no activity". */
  const windowState = useMemo(() => windowStateOf({
    hasMeta: !!meta, initial: !meta, loading: status.loading || req.loading,
    prefetching: req.prefetching, focusResolving: locating,
    error: status.err || req.err, canceled: req.canceled,
    staleDiscarded: req.staleDiscarded,
    observationCount: windowEvents.length,
  }), [meta, status, req, locating, windowEvents.length]);
  const emptiness = useMemo(() => emptinessMeaning(windowState),
                            [windowState]);

  /** Selection is reported, never silently replaced. */
  const selState = useMemo(
    () => selectionState(selected,
                         { view, loadedIds: new Set(events.keys()),
                           retention: boundsRef.current }),
    [selected, view, events]);

  /** Selecting an observation brings it into view on BOTH axes — a
   *  selection the analyst cannot see is not a selection. */
  const focusEvent = useCallback((e) => {
    if (!e) { setSelected(null); return; }
    setSelected(e);
    const t = msUTC(e.timestamp);
    setView((v) => {
      if (!v) return v;
      const s = v.t1 - v.t0;
      if (t >= v.t0 + s * 0.06 && t <= v.t1 - s * 0.06) return v;
      return centreOn(v, t, boundsRef.current).view;
    });
    setSelectedDay((d) => (d === startOfDayUTC(t) ? d : startOfDayUTC(t)));
    if (e.lane_index < laneStart || e.lane_index >= laneStart + rows) {
      const n = clampLaneStart(e.lane_index - Math.floor(rows / 3), rows,
                               total);
      setLaneStart(n);
      if (vScroll.current) vScroll.current.scrollTop = n * ROW_H;
    }
    /** DT2-1 · selecting a different observation IS a materially
     *  different investigation, so it gets a history entry. V1 replaced
     *  unconditionally, which is why Back did not step. */
    const next = new URLSearchParams(params);
    next.set("event", e.event_iid);
    if (e.process_iid) next.set("process_iid", e.process_iid);
    const mode = historyMode(
      { event: params.get("event"), process_iid: params.get("process_iid") },
      { event: e.event_iid, process_iid: e.process_iid || null });
    urlWriteRef.current = next.toString();
    setParams(next, { replace: mode !== HISTORY.PUSH });
  }, [laneStart, rows, total, params, setParams]);

  const deepLink = params.get("event");

  /** P0-F.13.5 · detection handoff.
   *
   *  A detection names itself with a stable identifier; the server turns
   *  that into the exact observation. If it cannot, we say so — we never
   *  drop the analyst on the right machine at the wrong moment and let
   *  them hunt for it. */
  const [handoff, setHandoff] = useState(null);
  const handoffKey = `${params.get("detection") || ""}|`
    + `${params.get("raw_event_id") || ""}|`
    + `${params.get("canonical_event_id") || ""}`;
  useEffect(() => {
    if (!device || handoffKey === "||" || deepLink) return undefined;
    let live = true;
    api.get(`/edr/endpoints/${encodeURIComponent(device)}/trajectory/focus`,
            { params: {
              detection_id: params.get("detection") || undefined,
              raw_event_id: params.get("raw_event_id") || undefined,
              canonical_event_id: params.get("canonical_event_id")
                || undefined,
              incident_id: params.get("incident")
                || params.get("incident_id") || undefined } })
      .then(({ data }) => {
        if (!live) return;
        setHandoff(data);
        if (data.state !== "FOCUS_RESOLVED" || !data.focus) return;
        const w = data.focus.window;
        if (w) {
          setPreset("custom");
          setView({ t0: msUTC(w.time_start),
                    t1: msUTC(w.time_end) });
          setSelectedDay(startOfDayUTC(msUTC(data.focus.timestamp)));
        }
        /** The resolver returns the observation's ROW as well as its
         *  moment. Without moving the row viewport the windowed request
         *  never asks for that row, so the exact observation would be
         *  resolved by the server and still be absent from the canvas. */
        const li = data.focus.lane_index;
        if (Number.isInteger(li)) {
          const n = Math.max(0, li - 6);
          setLaneStart(n);
          if (vScroll.current) vScroll.current.scrollTop = n * ROW_H;
        }
        const next = new URLSearchParams(params);
        next.set("event", data.focus.event_iid);
        setParams(next, { replace: true });
      })
      .catch(() => { if (live) setHandoff({ state: "FOCUS_UNAVAILABLE" }); });
    return () => { live = false; };
  }, [device, handoffKey, deepLink]);   // eslint-disable-line

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

  /** P0-F.13.5 · the handoff completes itself.
   *
   *  The resolver has already named the exact observation, so the
   *  analyst must never be asked to press "search" to see the event
   *  they clicked a detection to reach. If the windowed fetch has not
   *  produced it, the retained period is searched once, automatically. */
  const autoLocatedRef = useRef(false);
  useEffect(() => {
    if (handoff?.state !== "FOCUS_RESOLVED" || !deepLink) return undefined;
    if (autoLocatedRef.current || selected?.event_iid === deepLink) {
      return undefined;
    }
    if (events.get(deepLink) || locating || !total) return undefined;
    const t = setTimeout(() => {
      autoLocatedRef.current = true;
      locate(deepLink);
    }, 900);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [handoff, deepLink, events, locating, total, selected]);

  /** Detection → Trajectory, when the caller knows the instant but not
   *  the observation id: select the observation nearest that instant
   *  (optionally constrained to a process), once only, so the analyst's
   *  own later selections are never overridden. */
  const anchoredRef = useRef(false);
  useEffect(() => {
    const atRaw = params.get("at");
    if (!atRaw || deepLink || anchoredRef.current || selected) return;
    const at = msUTC(atRaw);
    if (!Number.isFinite(at) || events.size === 0) return;
    const wantProc = params.get("process_iid");
    let best = null;
    let bestD = Infinity;
    for (const e of events.values()) {
      if (wantProc && e.process_iid !== wantProc) continue;
      const d = Math.abs(msUTC(e.timestamp) - at);
      if (d < bestD) { bestD = d; best = e; }
    }
    if (best) {
      anchoredRef.current = true;
      focusEvent(best);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [events, params, deepLink, selected]);

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

  /** DT2-1 · Previous / Next observation and Previous / Next detection.
   *  Ordering is deterministic (timestamp, event_iid) and comes from the
   *  evidence, never from DOM order. When the next object is outside the
   *  loaded window the containing window is resolved instead of the
   *  control silently doing nothing. */
  const stepTo = useCallback((dir, detectionsOnly) => {
    const next = detectionsOnly
      ? stepDetection(windowEvents, selected, dir)
      : stepObservation(windowEvents, selected, dir);
    if (next) { focusEvent(next); return; }
    if (!view) return;
    const moved = panByFraction(view, dir * 0.9, boundsRef.current);
    if (moved.view.t0 !== view.t0) {
      setView(moved.view);
      setSelectedDay(startOfDayUTC(moved.view.t0));
    }
  }, [windowEvents, selected, view, focusEvent]);

  /** Density spike navigation. A spike is activity VOLUME. */
  const goToSpike = useCallback((bucket) => {
    const w = windowForBucket(bucket);
    if (!w) return;
    setView(w);
    setSelectedDay(startOfDayUTC(w.t0));
  }, []);

  /** DT2-1 · viewport → URL. Transient geometry REPLACES and is
   *  debounced, so a wheel burst can never flood browser history. */
  useEffect(() => {
    if (embedded || !device || !view) return undefined;
    const t = setTimeout(() => {
      const next = new URLSearchParams(params);
      next.set("device", device);
      next.set("from", iso(view.t0));
      next.set("to", iso(view.t1));
      next.set("zoom", String(levelOf(view.t1 - view.t0)));
      const s = next.toString();
      if (s === urlWriteRef.current) return;
      urlWriteRef.current = s;
      setParams(next, { replace: true });
    }, 260);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [device, view, embedded]);

  /** DT2-1 · URL → viewport. Back/Forward restore the investigation
   *  window; an entry we wrote ourselves is ignored to avoid a loop. */
  const paramKey = params.toString();
  useEffect(() => {
    if (embedded || paramKey === urlWriteRef.current) return;
    const r = restore(params);
    if (!r.view) return;
    if (!view || r.view.t0 !== view.t0 || r.view.t1 !== view.t1) {
      urlWriteRef.current = paramKey;
      setView(r.view);
      setSelectedDay(startOfDayUTC(r.view.t0));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [paramKey, embedded]);

  /** Bounded adjacent-window prefetch: at most two, cancelable,
   *  never recursive, and it never commits the viewport. */
  useEffect(() => {
    if (!device || !view || req.loading) return undefined;
    const t = setTimeout(() => {
      const lw = laneWindow(laneStart, rows, total || (laneStart + rows),
                            LANE_PREFETCH);
      for (const w of prefetchTargets(view, boundsRef.current)) {
        const key = requestKey({ tenantId: tenantRef.current,
                                 endpointId: device, t0: w.t0, t1: w.t1,
                                 laneStart: lw.from, laneEnd: lw.to,
                                 filterKey });
        if (cache.current.has(key)) continue;
        const slot = coord.current.beginPrefetch(key);
        if (!slot.accepted) continue;
        cache.current.set(key, true);
        setReq((s) => ({ ...s, prefetching: true }));
        api.get(`/edr/endpoints/${encodeURIComponent(device)}/trajectory`,
                { params: { time_start: iso(w.t0), time_end: iso(w.t1),
                            lane_start: lw.from, lane_end: lw.to,
                            limit: 2500, ...filterParams },
                  signal: slot.signal })
          .then(({ data }) => setEvents((prev) => {
            const m = new Map(prev);
            for (const e of data.events || []) m.set(e.event_iid, e);
            return m;
          }))
          .catch(() => cache.current.delete(key))
          .finally(() => {
            slot.done();
            setReq((s) => ({ ...s,
              prefetching: coord.current.prefetchCount() > 0 }));
          });
      }
    }, 400);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [device, view, laneStart, rows, total, filterKey, req.loading]);

  useEffect(() => () => coord.current.abortAll(), []);

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
      // `/xdr/fleet-file-trajectory` is not a route — this pivot has been
      // opening a tab that the SPA catch-all bounced to /xdr. The real
      // surface is keyed in the path.
      const key = e?.file ? `name:${String(e.file).split(/[\\/]/).pop()}`
        : e?.process ? `name:${e.process}` : null;
      if (key) window.open(buildFileTrajectoryPivot(key), "_blank",
                           "noopener");
    } else if (kind === "sightings") {
      // OBSERVE · where else has the platform seen this observable.
      const v = e?.file_sha256 || e?.file || e?.network || e?.process
        || e?.rule_id;
      if (v) window.open(buildSightingsPivot(v), "_blank", "noopener");
    } else if (kind === "investigate-xdr") {
      // EDR → XDR product pivot on the observable's incident, when the
      // evidence records one; otherwise the XDR search for its value.
      const inc = e?.provenance?.incident_id
        || (e?.detection?.incident_ids || [])[0];
      window.open(inc ? buildIncidentPivot(inc)
        : buildSightingsPivot(e?.file_sha256 || e?.file || e?.process || ""),
        "_blank", "noopener");
    } else if (kind === "filter-indicator") {
      setQuery(e?.file || e?.network || e?.process || e?.rule_id || "");
    } else if (kind === "focus" && e?.timestamp) {
      const t = msUTC(e.timestamp);
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

  /** DT2-3a.1 · Cisco's documented time-start filter: `at:<timestamp>`
   *  starts the trajectory view at that moment, and `<term> at:<ts>` is
   *  a logical AND of the term and the start time (User Guide p.409). */
  const onSearch = (raw) => {
    const text = String(raw || "");
    const m = text.match(/(?:^|\s)at:(\S+)/i);
    if (m) {
      const lit = m[1];
      const t = msUTC(lit.length <= 10 ? `${lit}T00:00:00Z` : lit);
      if (Number.isFinite(t)) {
        // a bare date starts at midnight and shows the day; a full
        // timestamp starts there and keeps at least an hour of context
        const span = lit.length <= 10 ? DAY_MS
          : Math.max(MS.h, view ? view.t1 - view.t0 : MS.h);
        setSelectedDay(startOfDayUTC(t));
        setView({ t0: t, t1: t + span });
      }
    }
    setQuery(text.replace(/(?:^|\s)at:\S+/i, "").trim());
  };
  const malicious = (meta?.activity?.days || [])
    .reduce((n, d) => n + (d.malicious || 0), 0);
  const detections = (meta?.activity?.days || [])
    .reduce((n, d) => n + (d.detections || 0), 0);

  const filterStrip = (
    <AmpFilterBar
      typeCounts={meta?.event_type_counts || []}
      kinds={kinds} onKinds={setKinds}
      dispositions={dispositions} onDispositions={setDispositions}
      fileTypes={fileTypes} onFileTypes={setFileTypes}
      fileTypeCounts={fileTypeCounts}
      processes={processChoices}
      hiddenProcesses={hiddenProcs} onHiddenProcesses={setHiddenProcs}
      query={query} onQuery={onSearch} />
  );

  const navigator_ = view && (
    <AmpNavigator
      days={meta?.activity?.days || []}
      dayBins={meta?.activity?.day_bins || []}
      selectedDay={selectedDay} onSelectDay={setSelectedDay}
      view={view} onView={setView}
      bounds={boundsRef.current}
      observedEnd={meta?.time_range?.observed_end}
      searchActive={Boolean(query)}
      collapsed={navCollapsed} onCollapsed={setNavCollapsed}
      onFocusTime={(t, iid) => {
        setView(centreOn(view, t, boundsRef.current).view);
        const hit = iid ? events.get(iid) : null;
        if (hit) setSelected(hit);
      }} />
  );

  /** DT2-1 · temporal navigation controls.
   *
   *  PARKED — NOT PART OF THE AMP-PARITY PRESENTATION (DT2-3a).
   *  Cisco's Device Trajectory has no trajectory toolbar: none of these
   *  controls appears in the reference figure, so the strip is not
   *  rendered. The engines behind it (evidence-ordered stepping,
   *  detection stepping, the zoom ladder, density buckets, window state)
   *  are deliberately left intact and wired for the NivXForge
   *  enhancement phase. */
  const navBarParked = view && (
    <div data-testid="dt2-navbar"
         data-dt2-scroll-domain="controls"
         data-window-state={windowState}
         data-selection-state={selState || "NONE"}
         data-zoom-level={levelOf(span)}
         data-window-from={iso(view.t0)}
         data-window-to={iso(view.t1)}
         data-retention-state={retention.retentionState}
         data-density-buckets={density.length}
         style={{ display: "flex", alignItems: "center", gap: 6,
                  flexWrap: "wrap", background: C.paper,
                  border: `1px solid ${C.gridStrong}`, borderRadius: 6,
                  padding: "6px 9px", marginBottom: 8, fontSize: 10.4,
                  color: C.inkDim, position: "sticky", top: 0,
                  zIndex: 30 }}>
      <button data-testid="dt2-prev-event" onClick={() => stepTo(-1, false)}
              title="Previous observation"
              style={navBtn}>◀ Event</button>
      <button data-testid="dt2-next-event" onClick={() => stepTo(1, false)}
              title="Next observation"
              style={navBtn}>Event ▶</button>
      <button data-testid="dt2-prev-detection"
              onClick={() => stepTo(-1, true)}
              title="Previous detection"
              style={navBtn}>◀ Detection</button>
      <button data-testid="dt2-next-detection"
              onClick={() => stepTo(1, true)}
              title="Next detection"
              style={navBtn}>Detection ▶</button>
      <span style={{ width: 1, height: 16, background: C.grid }} />
      <button data-testid="dt2-zoom-in"
              onClick={() => setView(zoomBySteps(view, -1,
                (view.t0 + view.t1) / 2, boundsRef.current).view)}
              style={navBtn}>Zoom in</button>
      <button data-testid="dt2-zoom-out"
              onClick={() => setView(zoomBySteps(view, 1,
                (view.t0 + view.t1) / 2, boundsRef.current).view)}
              style={navBtn}>Zoom out</button>
      <span className="mono" data-testid="dt2-window-label"
            style={{ color: C.inkFaint }}>
        {iso(view.t0).slice(0, 19)}Z → {iso(view.t1).slice(0, 19)}Z
      </span>
      {densitySpikes.length > 0 && (
        <>
          <span style={{ width: 1, height: 16, background: C.grid }} />
          <span style={{ color: C.inkFaint }}>Activity volume:</span>
          {densitySpikes.map((b) => (
            <button key={`${b.t0}-${b.count}`}
                    data-testid={`dt2-spike-${b.t0}`}
                    data-count={b.count}
                    data-semantics={b.semantics}
                    onClick={() => goToSpike(b)}
                    title={`${b.count} observations — activity volume, `
                      + "not a severity or threat claim"}
                    style={navBtn}>
              {b.count.toLocaleString()}
            </button>
          ))}
        </>
      )}
      <span style={{ flex: 1 }} />
      <span data-testid="dt2-window-state" style={{ color: C.inkFaint }}>
        {windowState}
      </span>
    </div>
  );

  const body = (
    <>
      {/* Cisco titles the page with the DEVICE NAME, followed by
          Show details and Actions (User Guide p.402 figure). */}
      <div style={{ display: "flex", alignItems: "center", gap: 12,
                    marginBottom: 16 }}
           data-testid="dt-heading">
        {device && meta && (
          <AmpComputerHeader computer={meta.computer}
                             malicious={malicious}
                             detections={detections}
                             onAction={(k) => onPivot(k, selected)} />
        )}
        <span style={{ flex: 1 }} />
        {/* Cisco's share control · Share > Copy URL (p.404) */}
        <button onClick={() => navigator.clipboard
                  ?.writeText(window.location.href)}
                data-testid="amp-share-url" title="Copy URL"
                style={iconBtn}>
          <Share2 size={15} />
        </button>
        <button onClick={() => setFullscreen((v) => !v)}
                data-testid="amp-fullscreen-toggle"
                title={fullscreen ? "Exit fullscreen" : "Fullscreen"}
                style={iconBtn}>
          {fullscreen ? <Minimize2 size={15} /> : <Maximize2 size={15} />}
        </button>
      </div>

      {/* DT2-3a · the AMP-parity presentation carries no handoff,
          projection or request-state banners: none appears in the Cisco
          reference. The handoff resolver, its diagnostics and the
          epistemic states remain intact server- and client-side. */}

      {/* Only ONE handoff state is ever shown. When the endpoint itself
          did not resolve, the focus resolver's echo of the same outcome
          is redundant noise, so it is suppressed. */}
      {PARKED_NIVXFORGE_UI && device && handoff && handoff.state !== "FOCUS_RESOLVED"
        && epi?.state !== "ENDPOINT_NOT_RESOLVED" && (
        <div data-testid="amp-handoff-state"
             data-state={handoff.state}
             data-observations-searched={handoff.search?.observations_examined
               ?? handoff.observations_searched}
             data-pages-searched={handoff.search?.pages_searched}
             data-cursor-state={handoff.search?.cursor_state}
             style={{ background: C.paper, padding: "8px 10px",
                      marginBottom: 8, fontSize: 11, color: C.ink,
                      borderLeft: `3px solid ${C.suspicious}`,
                      border: `1px solid ${C.grid}` }}>
          <b>◇ AMP HANDOFF — {handoff.state}</b>{" "}
          {handoff.missing_link || handoff.reason
            || "the originating observation could not be resolved"}
          <div className="mono" style={{ marginTop: 5, color: C.inkDim,
                                         lineHeight: 1.7, fontSize: 10.2 }}>
            <div>
              Search scope: endpoint{" "}
              {handoff.endpoint?.device_iid || device}
              {handoff.endpoint?.hostname
                ? ` · ${handoff.endpoint.hostname}` : ""}
            </div>
            {handoff.search && (
              <>
                <div data-testid="amp-handoff-observations-searched">
                  Observations searched:{" "}
                  {Number(handoff.search.observations_examined || 0)
                    .toLocaleString()}
                  {" "}· pages searched: {handoff.search.pages_searched}
                  {" "}(page size {handoff.search.page_size})
                </div>
                <div>Search state: {handoff.search.cursor_state}</div>
                <div>
                  Identity searched:{" "}
                  {[handoff.search.identities_searched?.raw_event_ids?.length
                    ? `raw_event_id ${handoff.search.identities_searched
                      .raw_event_ids.join(", ")}` : null,
                    handoff.search.identities_searched?.canonical_event_ids
                      ?.length
                      ? `canonical_event_id ${handoff.search
                        .identities_searched.canonical_event_ids.join(", ")}`
                      : null,
                    handoff.search.identities_searched?.event_iid
                      ? `event_iid ${handoff.search.identities_searched
                        .event_iid}` : null,
                  ].filter(Boolean).join(" · ") || "none supplied"}
                </div>
              </>
            )}
            <div>Result: {handoff.state}</div>
            <div style={{ color: C.inkFaint }}>
              Diagnostic information — not evidence that the event exists.
            </div>
          </div>
        </div>
      )}

      {PARKED_NIVXFORGE_UI && device && handoff?.state === "FOCUS_RESOLVED"
        && handoff.focus && (
        <div data-testid="amp-handoff-resolved"
             data-event-iid={handoff.focus.event_iid}
             data-lane-index={handoff.focus.lane_index}
             data-incident-id={handoff.context?.incident_id || ""}
             data-tenant-id={handoff.context?.tenant_id || ""}
             style={{ background: C.paper, padding: "6px 10px",
                      marginBottom: 8, fontSize: 10.4, color: C.inkDim,
                      borderLeft: `3px solid ${C.link}`,
                      border: `1px solid ${C.grid}` }}>
          <b style={{ color: C.ink }}>OPENED FROM DETECTION</b>{" "}
          <span className="mono">
            {handoff.context?.detection_id
              || handoff.focus.provenance?.raw_event_id}
          </span>{" "}
          → observation{" "}
          <span className="mono">{handoff.focus.event_iid}</span> @{" "}
          <span className="mono">{handoff.focus.timestamp}</span> · row{" "}
          {handoff.focus.lane_index}
          {(handoff.focus.detection?.rule_ids || []).length
            ? ` · rule ${handoff.focus.detection.rule_ids.join(", ")}` : ""}
          {handoff.focus.detection?.verdict
            ? ` · verdict ${handoff.focus.detection.verdict}` : ""}
          {handoff.context?.incident_id
            ? ` · incident ${handoff.context.incident_id}` : ""}
          {handoff.context?.tenant_id
            ? ` · customer ${handoff.context.tenant_id}` : ""}
          <span style={{ color: C.inkFaint }}>
            {" "}· exact identifier match, no timestamp inference
          </span>
        </div>
      )}

      {!device && (
        <div data-testid="amp-no-endpoint"
             style={{ background: C.paper, border: `1px solid ${C.grid}`,
                      padding: 16, color: C.ink, fontSize: 11.5 }}>
          <b>Select an endpoint</b>
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
              </button>
            ))}
          </div>
        </div>
      )}

      {(status.err || req.err) && (
        <div data-testid="amp-error"
             data-window-state={windowState}
             style={{ background: "#FDECEC", border: "1px solid #F3C2C2",
                      color: "#8E1E23", padding: "8px 12px", fontSize: 11,
                      marginBottom: 8 }}>
          {String(status.err || req.err)}
        </div>
      )}

      {device && (
        <>
          {PARKED_NIVXFORGE_UI && navBarParked}
          {/* Cisco: ONE card carries the search row and, beneath it, the
              day and 24-hour navigator. */}
          <div data-testid="amp-control-card"
               style={{ marginBottom: 16, background: C.paper,
                        border: `1px solid ${C.gridStrong}`,
                        borderRadius: 4, padding: "16px 18px 10px" }}>
            {filterStrip}
            {navigator_}
          </div>
        </>
      )}

      {device && status.loading && !meta && (
        <div data-testid="amp-loading"
             style={{ background: C.paper, border: `1px solid ${C.grid}`,
                      padding: 14, fontSize: 11, color: C.inkDim }}>
          Loading…
        </div>
      )}

      {PARKED_NIVXFORGE_UI && locating && (
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
          {"No activity to display."}
        </div>
      )}

      {PARKED_NIVXFORGE_UI && device && deepLink && !events.get(deepLink) && !locating && (
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
                        borderRadius: 4, overflow: "hidden",
                        background: C.paper }}
               data-testid="amp-workspace"
               data-row-start={laneStart}
               data-row-end={Math.min(total, laneStart + rows)}
               data-row-total={total}
               data-window-observations={windowEvents.length}
               data-cached-observations={events.size}
               data-lane-axis-version={meta?.lane_axis?.lane_axis_version}
               data-axis-scope={meta?.lane_axis?.axis_scope}
               data-dt2-engine="dt2.1"
               data-dt2-window-state={windowState}
               data-dt2-generation={coord.current.generation()}
               data-dt2-selection-state={selState || "NONE"}
               data-dt2-zoom-level={levelOf(span)}
               data-dt2-process-iid={selected?.process_iid || ""}
               data-wheel-navigation="rows|shift-time|ctrl-zoom">
            <div ref={plotRef} style={{ flex: 1, minWidth: 0,
                                        display: "flex",
                                        flexDirection: "column" }}>
              {PARKED_NIVXFORGE_UI && (
              <div style={{ display: "flex", alignItems: "center", gap: 6,
                            padding: "4px 8px",
                            borderBottom: `1px solid ${C.grid}`,
                            background: C.paperAlt }}
                   data-testid="dt2-view-modes"
                   data-dt2-graph-state={graphStateOf(dt2)}>
                {["RELATIONSHIPS", "EVENTS"].map((m) => (
                  <button key={m} onClick={() => setMode(m)}
                          data-testid={`dt2-mode-${m.toLowerCase()}`}
                          data-active={String(mode === m)}
                          style={{ ...navBtn,
                                   color: mode === m ? C.text : C.link,
                                   background: mode === m ? C.paper
                                                          : C.paperAlt }}>
                    {m === "RELATIONSHIPS" ? "PROCESS / RELATIONSHIP / TIME"
                                           : "EVENT LANES"}
                  </button>
                ))}
                <span style={{ fontSize: 9.6, color: C.faint,
                               fontFamily: "var(--mono)" }}>
                  {mode === "RELATIONSHIPS"
                    ? "server-derived edges only · dashed span = observed evidence, not a process exit"
                    : "endpoint-wide activity lanes"}
                </span>
              </div>
              )}
              <AmpCompromisePanel
                compromise={compromise}
                selectedId={selectedCompromise}
                onSelect={(c) => {
                  setSelectedCompromise(c.compromise_event_id);
                  if (c?.observedMs != null) {
                    setView(centreOn(view, c.observedMs,
                                     boundsRef.current).view);
                  }
                }} />
              {mode === "RELATIONSHIPS" && !PARKED_NIVXFORGE_UI ? (
                <div data-testid="dt2-graph"
                     data-dt2-graph-state={graphStateOf(dt2)}>
                  <RelationshipCanvas
                    graph={attachContributors(graphOf(dt2), compromise)}
                    compromise={compromise}
                    onCompromise={(c) => {
                      if (c?.observedMs == null) return;
                      setView(centreOn(view, c.observedMs,
                                       boundsRef.current).view);
                      setSelectedCompromise(c.compromise_event_id);
                    }}
                    view={view}
                    plotW={plotW + GUTTER} rows={rows}
                    laneOffset={laneStart}
                    bounds={boundsRef.current}
                    selectedNodeId={selectedNode}
                    selectedEventMs={selected?.timestamp
                      ? msUTC(selected.timestamp) : null}
                    fileTypes={fileTypes}
                    hiddenProcesses={hiddenProcs}
                    theme={C}
                    onView={setView}
                    onLaneOffset={(n) => {
                      setLaneStart(n);
                      if (vScroll.current) {
                        vScroll.current.scrollTop = n * ROW_H;
                      }
                    }}
                    onReturnToEvent={() => {
                      if (!selected?.timestamp) return;
                      const t = msUTC(selected.timestamp);
                      setView(centreOn(view, t, boundsRef.current).view);
                    }}
                    onSelect={(lane) => {
                      setSelectedNode(lane.nodeId);
                      setStepCtx(null);
                    }} />
                </div>
              ) : (
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
                  onPivot={onPivot}
                  compromise={compromise}
                  onCompromise={(c) => {
                    setSelectedCompromise(c.compromise_event_id);
                    if (c?.observedMs != null) {
                      setView(centreOn(view, c.observedMs,
                                       boundsRef.current).view);
                    }
                  }}
                  observedStart={obsStart} observedEnd={obsEnd} />
                <div ref={vScroll} data-testid="amp-vscroll"
                     onScroll={(e) => setLaneStart(Math.max(0, Math.min(
                       Math.max(0, total - rows),
                       Math.floor(e.target.scrollTop / ROW_H))))}
                     style={{ width: 13, height: canvasH,
                              overflowY: "scroll", flexShrink: 0,
                              background: C.paperAlt,
                              borderLeft: `1px solid ${C.grid}` }}>
                  <div style={{ height: Math.max(1, total) * ROW_H,
                                width: 1 }} />
                </div>
              </div>
              )}

              {/* time-axis scrollbar over the whole retained period.
                  PARKED: the Cisco reference carries ONE bottom time
                  scroll, which the trajectory itself renders with ◀ ▶. */}
              {PARKED_NIVXFORGE_UI && (
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
              )}
            </div>

            {/* Cisco's right-hand pane: Activity master list, drilling
                in to Activity Details in place, with a back arrow. */}
            <AmpActivityPanel events={windowEvents} lanes={lanes}
                              selected={selected} onSelect={focusEvent}
                              onPivot={onPivot} width={DETAILS_W}
                              windowState={windowState}
                              emptiness={emptiness}
                              compromise={compromise}
                              height="auto" />
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

  if (embedded) {
    // Rendered inside the device workspace: the console chrome and the
    // page header belong to the parent, so only the canvas is returned.
    return (
      <div data-testid="amp-page-surface" data-embedded="true"
           style={{ background: C.page,
                    border: `1px solid ${C.gridStrong}`, borderRadius: 6,
                    padding: "12px 14px 14px" }}>
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
