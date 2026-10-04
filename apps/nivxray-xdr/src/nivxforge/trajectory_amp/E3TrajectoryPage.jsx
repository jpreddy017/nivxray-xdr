import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { PAL, basename, approvalMarkers, filterSummary, fmtInstant, isolateRows, retroMarkers } from "./model";
import { e3 } from "./e3Api";
import Navigator from "./Navigator";
import Toolbar from "./Toolbar";
import Legend from "./Legend";
import Grid from "./Grid";
import DetailsPane from "./DetailsPane";
import { ApprovalDialog, ContextMenu } from "./ContextMenu";
import { FONT, ui } from "./ui";

const DAY = 86_400_000;
const iso = (ms) => new Date(Math.round(ms)).toISOString();
const isPrimary = (meta) => !(meta?.lane_type === "FILE" && (meta.touched_by || []).length);

function Banner({ s }) {
  const shape = s.label !== "SYNTHETIC";
  return (
    <div data-testid="data-banner" data-label={s.label} style={{ position: "sticky", top: 0, zIndex: 40, background: shape ? "#7A3E0B" : "#5B4508",
      color: "#FFF6E0", fontWeight: 600, fontSize: 13, padding: "7px 14px", letterSpacing: 0.3, borderRadius: 4 }}>
      {shape ? "SHAPE-FAITHFUL / NOT PRODUCTION DATA" : "SYNTHETIC"} · E3 contract preview (/api/e3/trajectory) · not live evidence · scenario {s.scenario_id}
    </div>
  );
}

function useStatic(s, REF) {
  const [st, setSt] = useState({ density: null, cov30: null, events: new Map(), paging: null, statusEvents: [], approvals: [], err: null });
  useEffect(() => {
    const a = (Math.floor(REF / DAY) + 1) * DAY - 30 * DAY;
    Promise.all([e3.dev(s, "density", { days: 30 }), e3.dev(s, "coverage", { t0: iso(a), t1: iso(REF) }),
      e3.dev(s, "events", { page_size: 500 }), e3.statusEvents(s), e3.approvals(s)])
      .then(([density, cov30, ev, se, ap]) => setSt({ density, cov30, events: new Map(ev.items.map((x) => [x.event_id, x])), paging: ev,
        statusEvents: se.events, approvals: ap.requests, err: null }))
      .catch((e) => setSt((o) => ({ ...o, err: e.message })));
  }, [s, REF]);
  return [st, setSt];
}

function useWindowed(s, REF, view, plotW) {
  const [w, setW] = useState({ lanes: [], vp: null, coverage: null });
  useEffect(() => {
    const ac = new AbortController();
    const t = setTimeout(() => {
      const q = { t0: iso(view.t0), t1: iso(view.t1) };
      const c1 = Math.max(view.t0 + 1000, Math.min(view.t1, REF));
      Promise.all([e3.dev(s, "lanes", q, ac.signal), e3.dev(s, "viewport", { ...q, width: Math.round(plotW), rows: 200 }, ac.signal),
        e3.dev(s, "coverage", { t0: q.t0, t1: iso(c1) }, ac.signal)])
        .then(([l, vp, coverage]) => setW({ lanes: l.lanes, vp, coverage })).catch(() => {});
    }, 140);
    return () => { clearTimeout(t); ac.abort(); };
  }, [s, REF, view.t0, view.t1, plotW]);
  return w;
}

function useHourly(s, day0, meta) {
  const [hv, setHv] = useState(null);
  useEffect(() => {
    e3.dev(s, "viewport", { t0: iso(day0), t1: iso(day0 + DAY), width: 192, bucket_px: 8, rows: 200 }).then(setHv).catch(() => {});
  }, [s, day0]);
  return useMemo(() => {
    const h = new Array(24).fill(0);
    for (const l of hv?.lanes || []) {
      if (!isPrimary(meta.get(l.lane_id))) continue;
      if (l.mode === "BUCKETS") for (const b of l.buckets) h[Math.min(23, b.i)] += b.count;
      else for (const m of l.markers) h[Math.min(23, Math.max(0, Math.floor((m.t_ms - day0) / 3_600_000)))] += 1;
    }
    return h;
  }, [hv, meta, day0]);
}

function usePerf(vp) {
  const start = useRef(typeof performance !== "undefined" ? performance.now() : 0);
  useEffect(() => {
    if (!vp || typeof window === "undefined") return;
    requestAnimationFrame(() => requestAnimationFrame(() => {
      const p = window.__e3dtPerf || {};
      const ms = Math.round(performance.now() - start.current);
      window.__e3dtPerf = { ...p, initialRenderMs: p.initialRenderMs ?? ms, renders: (p.renders || 0) + 1 };
    }));
  }, [vp]);
}

export default function E3TrajectoryPage({ scenario: s }) {
  const REF = Date.parse(s.reference_at);
  const [view, setViewRaw] = useState({ t0: REF - DAY, t1: REF });
  const onView = useCallback((v) => setViewRaw((cur) => (typeof v === "function" ? v(cur) : { t0: v.t0, t1: v.t1 })), []);
  const [plotW, setPlotW] = useState(900);
  const [st, setSt] = useStatic(s, REF);
  const { lanes, vp, coverage } = useWindowed(s, REF, view, plotW);
  const meta = useMemo(() => new Map(lanes.map((l) => [l.lane_id, l])), [lanes]);
  const hourly = useHourly(s, Math.floor((view.t1 - 1) / DAY) * DAY, meta);
  usePerf(vp);
  const [sel, setSel] = useState(null);
  const [kinds, setKinds] = useState(new Set());
  const [query, setQuery] = useState("");
  const [isolation, setIsolation] = useState(null);
  const [hideOthers, setHideOthers] = useState(false);
  const [tzMode, setTzMode] = useState("UTC");
  const [legendOpen, setLegendOpen] = useState(false);
  const [menu, setMenu] = useState(null);
  const [dialog, setDialog] = useState(null);
  const [notice, setNotice] = useState(null);
  const [fileStatus, setFileStatus] = useState(null);

  const present = useMemo(() => {
    const m = new Map();
    const add = (k, n) => m.set(k, (m.get(k) || 0) + n);
    for (const l of vp?.lanes || []) {
      if (!isPrimary(meta.get(l.lane_id))) continue;
      if (l.mode === "BUCKETS") for (const b of l.buckets) for (const [k, n] of Object.entries(b.kinds)) add(k, n);
      else for (const x of l.markers) add(x.kind, 1);
    }
    return m;
  }, [vp, meta]);
  const summary = useMemo(() => filterSummary(vp?.lanes, Object.fromEntries(meta), kinds), [vp, meta, kinds]);
  const keep = useMemo(() => (isolation ? isolateRows(lanes, isolation.ids) : null), [isolation, lanes]);
  const retro = useMemo(() => retroMarkers(st.statusEvents, lanes), [st.statusEvents, lanes]);
  const apprM = useMemo(() => approvalMarkers(st.approvals, lanes, view.t0), [st.approvals, lanes, view.t0]);
  const lane = sel ? meta.get(sel.laneId) : null;
  const event = sel?.eventId ? st.events.get(sel.eventId) : null;
  const sha = event?.process?.sha256 || event?.file?.sha256 || lane?.sha256 || null;

  useEffect(() => {
    setFileStatus(null);
    if (sha) e3.fileStatus(s, sha).then(setFileStatus).catch(() => {});
  }, [s, sha]);
  useEffect(() => {
    if (!menu) return undefined;
    const close = () => setMenu(null);
    window.addEventListener("click", close);
    return () => window.removeEventListener("click", close);
  }, [menu]);

  const runIsolation = async (q) => {
    const v = (q || "").trim();
    if (!v) return;
    const isHash = /^[a-f0-9]{64}$/i.test(v);
    try {
      const r = await e3.dev(s, "lineage", isHash ? { sha256: v.toLowerCase() } : { filename: basename(v) });
      const ids = r.lane_ids || [];
      setIsolation({ label: isHash ? `${v.slice(0, 12)}…` : basename(v), ids, count: isolateRows(lanes, ids).size });
    } catch (e) { setNotice(`Isolation failed: ${e.message}`); }
  };
  const openCtx = (e, { lane: l, eventId, t_ms }) => {
    const ev = eventId ? st.events.get(eventId) : null;
    const t = { device_id: s.device_id, lane_id: l.lane_id, event_id: eventId || null, t_ms: ev?.observed_ms ?? t_ms ?? null,
      sha256: ev?.process?.sha256 || ev?.file?.sha256 || l.sha256 || null,
      path: ev?.file?.path || (l.lane_type === "FILE" ? l.label : null), image: ev?.process?.image || l.image || null };
    t.name = basename(t.path || t.image || "");
    setSel({ laneId: l.lane_id, eventId: eventId || null });
    setMenu({ x: Math.min(e.clientX, window.innerWidth - 270), y: Math.min(e.clientY, window.innerHeight - 340), target: t });
  };
  const onPivot = async (kind) => {
    const t = menu.target;
    setMenu(null);
    const value = kind === "SEARCH_FILENAME" ? t.name : t.sha256 || t.name;
    try {
      const p = await e3.pivot(kind, value);
      if (kind === "COPY_HASH") { try { await navigator.clipboard.writeText(value); } catch { /* clipboard may be blocked */ } setNotice(`Copied ${value} · read-only pivot`); }
      else if (kind === "OPEN_FILE_TRAJECTORY") setNotice(`File Trajectory is not yet built (deferred). Reserved read-only route: ${p.route}`);
      else { setQuery(value); runIsolation(value); setNotice(`Read-only pivot ${kind} → ${p.route} (search surface owned by E1). Lineage isolated here.`); }
    } catch (e) { setNotice(`Pivot failed: ${e.message}`); }
  };
  const confirm = async (reason) => {
    const d = dialog;
    setDialog({ ...d, phase: "pending" });
    try {
      const r = await e3.requestApproval({ tenant_id: s.tenant_id, action: d.action, target: d.target, requested_by: "e3-preview-analyst",
        idempotency_key: `${s.scenario_id}:${d.action}:${d.target.lane_id}:${d.target.event_id || ""}`, reason });
      setDialog({ ...d, phase: "result", result: r });
      e3.approvals(s).then((a) => setSt((o) => ({ ...o, approvals: a.requests }))).catch(() => {});
    } catch (e) { setDialog({ ...d, phase: "result", error: e.message }); }
  };
  const loadOlder = async () => {
    const r = await e3.dev(s, "events", { page_size: 500, cursor: st.paging.next_cursor });
    setSt((o) => { const m = new Map(o.events); for (const x of r.items) m.set(x.event_id, x); return { ...o, events: m, paging: r }; });
  };
  const zoom = (f) => onView((v) => { const c = (v.t0 + v.t1) / 2, h = Math.max(2500, ((v.t1 - v.t0) * f) / 2); return { t0: c - h, t1: c + h }; });
  const total = st.events.size + (st.paging?.remaining_older || 0);

  return (
    <div data-testid="e3-trajectory-page" style={{ fontFamily: FONT, color: PAL.text, background: PAL.bg, padding: 12, display: "grid", gap: 10 }}>
      <Banner s={s} />
      <header style={{ display: "flex", gap: 16, alignItems: "baseline", flexWrap: "wrap" }}>
        <h1 style={{ margin: 0, fontSize: 22, fontWeight: 600 }}>Device Trajectory</h1>
        <span data-testid="device-id" style={ui.mono}>{s.device_id}</span>
        <span style={{ color: PAL.muted, fontSize: 12 }}>tenant {s.tenant_id} · reference {fmtInstant(REF, tzMode)} · stores {(vp?.provenance?.stores || []).join(" + ")} · authority {vp?.provenance?.authority || "—"}</span>
        <span style={{ color: PAL.muted, fontSize: 12, flexBasis: "100%" }}>{s.description}</span>
      </header>
      {st.err && <div data-testid="e3-error" style={{ color: PAL.amber }}>E3 contract read failed: {st.err}</div>}
      <Navigator density={st.density} cov30={st.cov30} hourly={hourly} view={view} refMs={REF} tzMode={tzMode} onView={onView} />
      <Toolbar present={present} kinds={kinds} setKinds={setKinds} summary={summary} query={query} setQuery={setQuery} onSearch={runIsolation}
        isolation={isolation} onClearIsolation={() => { setIsolation(null); setHideOthers(false); }} hideOthers={hideOthers} setHideOthers={setHideOthers}
        tzMode={tzMode} setTzMode={setTzMode} legendOpen={legendOpen} setLegendOpen={setLegendOpen} onZoom={zoom} />
      {legendOpen && <Legend present={present} />}
      {notice && <div data-testid="pivot-notice" style={{ ...ui.panel, padding: "7px 12px", fontSize: 12.5, display: "flex", gap: 10 }}>
        <span style={{ flex: 1 }}>{notice}</span><button data-testid="pivot-notice-close" style={ui.btn} onClick={() => setNotice(null)}>Dismiss</button></div>}
      <div style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) 420px", gap: 10, alignItems: "start" }}>
        <div style={{ display: "grid", gap: 8 }}>
          <Grid lanes={lanes} vp={vp} view={view} kinds={kinds} keep={keep} hideOthers={hideOthers} coverage={coverage} sel={sel}
            eventsById={st.events} retro={retro} approvals={apprM} tzMode={tzMode} onSelect={setSel} onContext={openCtx} onView={onView} onWidth={setPlotW} />
          <div data-testid="paging-state" style={{ ...ui.panel, padding: "7px 12px", fontSize: 12, display: "flex", gap: 10, alignItems: "center" }}>
            <span>Event details loaded newest-first: <b>{st.events.size}</b> of {total} · {st.paging?.remaining_older ?? 0} older remaining
              {st.paging?.as_of != null && <span style={{ color: PAL.muted }}> · session frozen as of ingest {fmtInstant(st.paging.as_of, tzMode)}</span>}</span>
            {st.paging?.has_more && <span data-testid="partial-disclosure" style={{ color: PAL.amber }}>Partially loaded: grid markers are complete (server viewport); full evidence for older events needs Load older.</span>}
            <span style={{ flex: 1 }} />
            <button data-testid="load-older" style={ui.btn} disabled={!st.paging?.has_more} onClick={loadOlder}>Load older</button>
          </div>
        </div>
        <DetailsPane lane={lane} event={event} eventId={sel?.eventId} fileStatus={fileStatus} sha={sha} statusEvents={st.statusEvents} approvals={st.approvals} />
      </div>
      {menu && <ContextMenu menu={menu} onPivot={onPivot} onAction={(action) => { setDialog({ action, target: menu.target, phase: "confirm" }); setMenu(null); }} />}
      {dialog && <ApprovalDialog dialog={dialog} onConfirm={confirm} onClose={() => setDialog(null)} />}
    </div>
  );
}
