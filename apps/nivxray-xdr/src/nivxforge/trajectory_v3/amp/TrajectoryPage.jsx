import { ChevronDown, ChevronLeft, ChevronRight, Info, X } from "lucide-react";
import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import api from "@/lib/api";
import { ActivityDetails, ActivityList } from "./Activity";
import { NetworkSummary } from "./Artifacts";
import { AttackPanel } from "./AttackStrip";
import { hasTechnique } from "./attack";
import { FiltersPanel } from "./Filters";
import Grid from "./Grid";
import Header from "./Header";
import { Legend } from "./Glyphs";
import { ApprovalDialog, ContextMenu } from "./Menu";
import { buildModel, DEFAULT_ON, lineage, matches, passes, presentKinds } from "./model";
import Navigator from "./Navigator";
import { perfEvents } from "./perf";
import { C, CSS, DAY } from "./theme";
import { readCollapsed, setCollapsedGlobal } from "../../EdrSidebar";

const PANEL_KEY = "nvx.dt.panelW", PANEL_MIN = 320, PANEL_DEFAULT = 336;

const iso = (ms) => new Date(ms).toISOString();

function useUrlState() {
  const [params, setParams] = useSearchParams();
  const upd = useCallback((patch, replace = false) => setParams((p) => {
    const n = new URLSearchParams(p);
    for (const [k, v] of Object.entries(patch)) (v == null || v === "") ? n.delete(k) : n.set(k, String(v));
    return n;
  }, { replace }), [setParams]);
  return [params, upd];
}

function Debug({ data, timing, deep, onLegacy }) {
  const p = data?.e3_preview || {};
  return (
    <div data-testid="v3-debug-drawer" style={{ position: "fixed", right: 0, top: 0, bottom: 0, width: 420, zIndex: 70, background: C.tip, borderLeft: `1px solid ${C.line}`,
      padding: 16, fontSize: 12, color: C.text, overflowY: "auto", boxShadow: "-10px 0 40px rgba(0,0,0,.5)" }}>
      <b style={{ fontSize: 14 }}>Debug (preview only)</b>
      {[["engine", data?.engine_id], ["adapter", p.engine], ["data label", p.data_label], ["source", p.source || p.source_origin], ["window rows", p.window_rows],
        ["remaining older", p.remaining_older], ["returned", data?.returned], ["timing ms", JSON.stringify(timing)], ["deep link", JSON.stringify(deep)],
        ["detections basis", p.detections_basis]].map(([k, v]) => <div key={k} style={{ display: "grid", gridTemplateColumns: "120px 1fr", padding: "3px 0" }}>
        <span style={{ color: C.muted }}>{k}</span><span style={{ wordBreak: "break-all" }}>{v ?? "—"}</span></div>)}
      <button className="v3-btn" data-testid="v3-use-legacy" style={{ marginTop: 12 }} onClick={onLegacy}>Use Legacy Device Trajectory</button>
    </div>
  );
}

export default function TrajectoryPage({ device, onLegacy }) {
  const [params, upd] = useUrlState();
  const now = useRef(Date.now()).current;
  const perf = Number(params.get("perf") || 0);
  const t0 = Number(params.get("t0")) || now - DAY, t1 = Number(params.get("t1")) || now;
  const view = useMemo(() => ({ t0, t1 }), [t0, t1]);
  const q = params.get("q") || "", fp = params.get("f"), isoId = params.get("iso"), wanted = params.get("event"), att = params.get("att");
  const sev = params.get("sev"), ioc = params.get("ioc"), scenario = params.get("scenario") || undefined;
  const [present, setPresent] = useState(() => new Set());
  const filters = useMemo(() => new Set(fp ? fp.split(",") : [...DEFAULT_ON, ...present]), [fp, present]);
  const [data, setData] = useState(null);
  const [older, setOlder] = useState({ events: [], cursor: null });
  const [loading, setLoading] = useState(false);
  const [details, setDetails] = useState(false);
  const [hover, setHover] = useState(null);
  const [showF, setShowF] = useState(false);
  const [menu, setMenu] = useState(null);
  const [approval, setApproval] = useState(null);
  const [notice, setNotice] = useState(null);
  const [deep, setDeep] = useState(null);
  const [dbg, setDbg] = useState(false);
  const [legend, setLegend] = useState(false);
  const [netSum, setNetSum] = useState(false);
  const [approvals, setApprovals] = useState({});
  const [colW, setColW] = useState(24);
  const [expanded, setExpanded] = useState(() => new Set());
  const [hitIdx, setHitIdx] = useState(-1);
  const returnTo = useRef(false), req = useRef(0), timing = useRef({});
  const wsRef = useRef(null);
  const [railed, setRailed] = useState(readCollapsed);
  useEffect(() => { const on = (e) => setRailed(!!e.detail); window.addEventListener("nvx-sidebar", on); return () => window.removeEventListener("nvx-sidebar", on); }, []);
  const panelMax = useCallback(() => Math.max(PANEL_MIN, Math.floor((wsRef.current?.clientWidth || 1600) * 0.4)), []);
  const [panelW, setPanelW] = useState(() => { const v = Number(sessionStorage.getItem(PANEL_KEY)); return v >= PANEL_MIN ? v : PANEL_DEFAULT; });
  const setPanel = useCallback((w) => {
    const v = Math.round(Math.min(panelMax(), Math.max(PANEL_MIN, w)));
    setPanelW(v);
    try { sessionStorage.setItem(PANEL_KEY, String(v)); } catch { /* ok */ }
  }, [panelMax]);
  useEffect(() => {
    const o = new ResizeObserver(() => setPanelW((w) => Math.min(panelMax(), Math.max(PANEL_MIN, w))));
    wsRef.current && o.observe(wsRef.current);
    return () => o.disconnect();
  }, [panelMax]);
  const dragPanel = (e) => {
    e.preventDefault();
    const right = wsRef.current.getBoundingClientRect().right;
    const mv = (ev) => setPanel(right - ev.clientX);
    const up = () => { window.removeEventListener("mousemove", mv); window.removeEventListener("mouseup", up); document.body.style.cursor = ""; };
    document.body.style.cursor = "col-resize";
    window.addEventListener("mousemove", mv); window.addEventListener("mouseup", up);
  };
  const gridH = useRef(Math.max(420, (typeof window !== "undefined" ? window.innerHeight : 1000) - 470)).current;
  const say = useCallback((m) => { setNotice(m); setTimeout(() => setNotice((n) => (n === m ? null : n)), 4500); }, []);
  const url = `/edr/endpoints/${encodeURIComponent(device)}/trajectory`;

  useEffect(() => {
    if (perf) {
      const t = performance.now();
      setData({ events: perfEvents(perf, now), lane_axis: { lanes: [] }, computer: { hostname: `PERF-${perf}` }, activity: { days: [] },
        e3_preview: { window_rows: perf, data_label: "PERF FIXTURE (client-side rows, not evidence)", detections_all: [] } });
      timing.current.gen = Math.round(performance.now() - t);
      return undefined;
    }
    const ac = new AbortController(), id = ++req.current, t = performance.now();
    setLoading(true);
    api.get(url, { params: { time_start: iso(t0), time_end: iso(t1), lane_start: 0, lane_end: 100000, limit: 500, scenario }, signal: ac.signal })
      .then(({ data: d }) => { if (id !== req.current) return; timing.current.fetch = Math.round(performance.now() - t); setData(d); setOlder({ events: [], cursor: d?.e3_preview?.older_cursor || null }); })
      .catch((e) => { if (id === req.current && e?.name !== "CanceledError") say(`Trajectory read failed: ${e.message}`); })
      .finally(() => { if (id === req.current) setLoading(false); });
    return () => ac.abort();
  }, [url, t0, t1, perf, scenario]); // eslint-disable-line

  const fetchHours = useCallback((day) => (perf ? Promise.resolve(null) : api.get(`${url}/hours`, { params: { day } }).then(({ data: d }) => d.hours)), [url, perf]);
  const loadOlder = async () => {
    const id = req.current;
    setLoading(true);
    try {
      const { data: d } = await api.get(url, { params: { time_start: iso(t0), time_end: iso(t1), lane_start: 0, lane_end: 100000, limit: 500, before: older.cursor, scenario } });
      if (id === req.current) setOlder((o) => ({ events: [...(d.events || []), ...o.events], cursor: d?.e3_preview?.older_cursor || null }));
    } catch (e) { say(`Older events read failed: ${e.message}`); } finally { setLoading(false); }
  };

  const os = String(data?.computer?.platform || JSON.stringify(data?.computer?.operating_system || "")).toLowerCase();
  const platform = /mac/.test(os) ? "macos" : /linux|ubuntu|debian|rhel/.test(os) ? "linux" : "windows";
  const model = useMemo(() => {
    const t = performance.now();
    const m = buildModel([...older.events, ...(data?.events || [])], data?.lane_axis?.lanes || [], platform);
    timing.current.model = Math.round(performance.now() - t);
    return m;
  }, [data, older.events, platform]);
  const isoItem = isoId ? model.items.find((it) => it.ev.event_iid === isoId) : null;
  useEffect(() => { setPresent(presentKinds(model.items)); }, [model]);
  useEffect(() => { window.__v3perf = { ...timing.current, n: model.total, cols: model.ncol, rows: model.rows.length }; }, [model]);
  const lin = useMemo(() => (isoItem ? lineage(model, isoItem) : null), [model, isoItem]);
  const shown = useMemo(() => model.items.filter((it) => passes(it, filters) && matches(it, q) && (!lin || lin.has(it.actorIid) || lin.has(it.targetIid))
    && (!att || hasTechnique(it, att)) && (!sev || it.ev.e3_detection?.severity === sev)
    && (!ioc || (it.ev.e3_detection && (it.ev.e3_detection.rule_id || it.ev.e3_detection.name) === ioc))), [model, filters, q, lin, att, sev, ioc]);
  useEffect(() => {
    const k = (e) => { if (e.key === "Escape" && (att || sev || ioc)) upd({ att: null, sev: null, ioc: null }); };
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }); // eslint-disable-line
  const vmodel = useMemo(() => {
    if (shown.length === model.items.length) return model;
    const keep = new Set(shown.flatMap((it) => [it.target?.key, it.actor?.key]));
    return { ...model, rows: model.rows.filter((r) => keep.has(r.key)) };
  }, [model, shown]);
  const hits = useMemo(() => {
    if (!q) return null;
    const n = q.toLowerCase();
    return new Set(vmodel.rows.filter((r) => [r.label, r.path, r.hash].some((v) => v && String(v).toLowerCase().includes(n))).map((r) => r.key));
  }, [vmodel, q]);
  const sel = wanted ? model.items.find((it) => it.ev.event_iid === wanted) || null : null;
  const dets = (data?.e3_preview?.detections_all || []).map((d) => ({ ...d, ms: d.ms || Date.parse(d.at) }));

  const select = useCallback((it, center = false) => {
    if (center) returnTo.current = true;
    setDeep({ state: "FOCUSED", id: it.ev.event_iid });
    setDetails(true);
    setNetSum(false);
    upd({ event: it.ev.event_iid });
  }, [upd]);

  useEffect(() => {
    if (!data || !wanted || perf) return;
    if (model.items.some((it) => it.ev.event_iid === wanted)) {
      if (deep?.id !== wanted || deep.state !== "FOCUSED") { setDeep({ state: "FOCUSED", id: wanted }); setDetails(true); returnTo.current = true; }
      return;
    }
    if (deep?.id === wanted) return;
    setDeep({ state: "LOCATING", id: wanted });
    api.get(`${url}/focus`, { params: { event_iid: wanted } }).then(({ data: f }) => {
      if (f.state !== "FOCUS_RESOLVED") { setDeep({ state: "NOT_FOUND", id: wanted }); return; }
      setDeep({ state: "FOCUSING", id: wanted });
      upd({ t0: Date.parse(f.focus.window.time_start), t1: Date.parse(f.focus.window.time_end) }, true);
    }).catch(() => setDeep({ state: "NOT_FOUND", id: wanted }));
  }, [data, wanted, model]); // eslint-disable-line

  const jump = async (d) => {
    let id = d.event_iid, f = null;
    if (!id) { ({ data: f } = await api.get(`${url}/focus`, { params: { observation_id: d.observation_id } })); id = f?.focus?.event_iid; }
    if (!id) { say("That event could not be resolved in retained evidence."); return; }
    setDeep(null);
    upd({ event: id, ...(f ? { t0: Date.parse(f.focus.window.time_start), t1: Date.parse(f.focus.window.time_end) } : {}) });
  };

  const span = t1 - t0;
  const setView = (v) => upd({ t0: Math.round(v.t0), t1: Math.round(Math.min(v.t1, now)) });
  const nav = (k) => () => ({
    last24: () => upd({ t0: null, t1: null }), now: () => setView({ t0: now - span, t1: now }), prev: () => setView({ t0: t0 - span, t1: t1 - span }),
    next: () => setView({ t0: Math.min(t0 + span, now - span), t1: Math.min(t1 + span, now) }),
    fit: () => { const g = document.querySelector('[data-testid="v3-grid"]'); setColW(Math.max(1.5, Math.min(48, ((g?.clientWidth || 1200) - 300) / Math.max(1, vmodel.ncol)))); },
    reset: () => { upd({ t0: null, t1: null, q: null, f: null, iso: null, event: null, att: null }); setColW(24); setExpanded(new Set()); setDetails(false); },
    zin: () => setColW((w) => Math.min(48, w * 1.25)), zout: () => setColW((w) => Math.max(1.5, w * 0.8)),
  })[k]();
  const step = (d) => { if (!shown.length) return; const i = (hitIdx + d + shown.length) % shown.length; setHitIdx(i); select(shown[i], true); };
  const copy = (v) => { navigator.clipboard?.writeText(v || "").catch(() => {}); say("Copied to clipboard"); };
  const onAction = (a, v) => {
    const it = menu?.it;
    setMenu(null);
    if (a === "copy-hash" || a === "copy-path") copy(v);
    else if (a === "search") { upd({ q: v }); setHitIdx(-1); }
    else if (a === "isolate") upd({ iso: v.ev.event_iid });
    else if (a === "nyb") say(`${v} is not yet built`);
    else if (a === "approve") setApproval({ action: v, it, target: v === "ISOLATE_DEVICE" ? data?.computer?.hostname || device : it?.target?.path || it?.target?.label });
  };
  const confirmApproval = async () => {
    const { action, it } = approval;
    setApproval(null);
    try {
      const { data: r } = await api.post("/e3/trajectory/approvals", { tenant_id: data?.identity?.tenant_id, action, requested_by: "preview-analyst",
        target: { device_id: device, event_iid: it?.ev.event_iid, path: it?.target?.path }, idempotency_key: `${action}:${it?.ev.event_iid || device}`, reason: "trajectory" });
      say(`Approval Requested — not executed. (${r.request?.state || "REQUESTED"})`);
      if (it) setApprovals((a) => ({ ...a, [it.ev.event_iid]: [...(a[it.ev.event_iid] || []), { action, state: r.request?.state || "APPROVAL_REQUESTED" }] }));
    } catch (e) { say(`Approval request not recorded: ${e.message}`); }
  };
  const filtered = shown.length !== model.items.length;

  return (
    <div className="v3amp" data-testid="v3-page" style={{ color: C.text, padding: "20px 24px", background: C.page, minHeight: "100%" }} onClick={() => { setMenu(null); setShowF(false); }}>
      <style>{CSS}</style>
      <Header data={data} device={device} dets={dets} onShare={() => copy(window.location.href)}
        onActions={(e) => setMenu({ x: e.clientX - 200, y: e.clientY + 16, deviceOnly: true, device })} />
      <div style={{ background: C.panel, borderRadius: 12, padding: 16, border: `1px solid ${C.line}` }}>
        <div style={{ display: "flex", gap: 14, alignItems: "center", marginBottom: 14, position: "relative" }} onClick={(e) => e.stopPropagation()}>
          <div style={{ flex: 1, display: "flex", alignItems: "center", gap: 8, background: C.page, border: `1px solid ${C.line}`, borderRadius: 20, padding: "0 8px 0 16px", height: 38 }}>
            <input data-testid="v3-search" defaultValue={q} key={q} placeholder="Search Device Trajectory"
              onKeyDown={(e) => { if (e.key === "Enter") { upd({ q: e.currentTarget.value.trim() }); setHitIdx(-1); } }}
              style={{ flex: 1, background: "transparent", border: 0, outline: "none", color: C.text, fontSize: 14 }} />
            {q && <>
              <span data-testid="v3-search-count" style={{ fontSize: 13, color: C.label, whiteSpace: "nowrap" }}>{shown.length} results</span>
              <button className="v3-link" data-testid="v3-search-prev" onClick={() => step(-1)} title="Previous result"><ChevronLeft size={16} /></button>
              <button className="v3-link" data-testid="v3-search-next" onClick={() => step(1)} title="Next result"><ChevronRight size={16} /></button>
              <button className="v3-link" data-testid="v3-search-clear" onClick={() => upd({ q: null })} title="Clear"><X size={16} color="currentColor" /></button></>}
            <span title="Searches SHA-256, filename, process, command line, IP, domain and user" style={{ color: C.muted, display: "flex" }}><Info size={16} /></span>
          </div>
          {filtered && <span data-testid="v3-filter-indicator" style={{ fontSize: 13, color: C.amber, whiteSpace: "nowrap" }}>{shown.length} of {model.items.length}
            <button className="v3-link" data-testid="v3-filter-reset" style={{ marginLeft: 8, fontSize: 13 }} onClick={() => upd({ f: null, q: null, iso: null, att: null, sev: null, ioc: null })}>Reset</button></span>}
          <button className="v3-link" data-testid="v3-filters" onClick={() => setShowF(!showF)} style={{ display: "flex", alignItems: "center", gap: 2 }}>Filters <ChevronDown size={15} /></button>
          {showF && <FiltersPanel present={present} applied={filters} onCancel={() => setShowF(false)} onApply={(s) => { setShowF(false); upd({ f: [...s].sort().join(",") === [...DEFAULT_ON].sort().join(",") ? null : [...s].join(",") }); }} />}
        </div>
        {deep && !["FOCUSED"].includes(deep.state) && <div data-testid="v3-deeplink-state" style={{ fontSize: 13, color: deep.state === "NOT_FOUND" ? C.amber : C.muted, marginBottom: 8 }}>
          {deep.state === "NOT_FOUND" ? `Observation ${deep.id} was not found in retained evidence for this device.` : `Locating observation ${deep.id} in history…`}</div>}
        {isoItem && <div data-testid="v3-isolate-banner" style={{ fontSize: 13, marginBottom: 8, color: C.accent }}>Isolated lineage of {isoItem.target?.label} · {shown.length} events
          <button className="v3-link" data-testid="v3-isolate-restore" style={{ marginLeft: 10, fontSize: 13 }} onClick={() => upd({ iso: null })}>Restore</button></div>}
        {notice && <div data-testid={/Approval/.test(notice) ? "dt-approval-result" : "v3-notice"} onClick={() => setNotice(null)} style={{ position: "fixed", bottom: 24, left: "50%", transform: "translateX(-50%)", zIndex: 90, background: C.tip,
          border: `1px solid ${C.line}`, borderRadius: 8, padding: "10px 18px", fontSize: 13.5, boxShadow: "0 10px 30px rgba(0,0,0,.5)", animation: "v3in .15s ease-out" }}>{notice}</div>}
        <div style={{ border: `1px solid ${C.line}`, borderRadius: 10, overflow: "visible" }}>
          <Navigator days={data?.activity?.days} dets={dets} view={view} now={now} onView={setView} onJump={jump} fetchHours={fetchHours} />
          {!perf && <AttackPanel url={url} device={device} t0={t0} t1={t1} active={att} dets={dets} onJump={jump} onPick={(v) => upd({ att: v })}
            sev={sev} onSev={(v) => upd({ sev: v })} ioc={ioc} onIoc={(v, d) => (d?.event_iid ? upd({ ioc: v, event: d.event_iid }) : (upd({ ioc: v }), d && setTimeout(() => jump(d), 0)))} scenario={scenario} />}
          {att && <div data-testid="dt-attack-filter-banner" style={{ fontSize: 13, padding: "6px 12px", color: C.accent, background: C.panel, borderBottom: `1px solid ${C.line}` }}>
            ATT&amp;CK {att} · {shown.length} mapped events in the loaded window (observed technique, not a confirmed attack)
            <button className="v3-link" data-testid="dt-attack-filter-clear" style={{ marginLeft: 10, fontSize: 13 }} onClick={() => upd({ att: null })}>Clear</button></div>}
          <div data-testid="v3-toolbar" style={{ display: "flex", gap: 6, alignItems: "center", justifyContent: "flex-end", padding: "6px 10px", background: C.panel, borderBottom: `1px solid ${C.line}`, fontSize: 12 }}>
            <span style={{ color: C.muted, marginRight: "auto" }}>{new Date(t0).toISOString().slice(0, 16).replace("T", " ")} – {new Date(t1).toISOString().slice(0, 16).replace("T", " ")} UTC</span>
            {[["last24", "Last 24h"], ["now", "Now"], ["prev", "‹ Prev"], ["next", "Next ›"], ["fit", "Fit to evidence"], ["reset", "Reset"], ["zout", "−"], ["zin", "+"]].map(([k, l]) =>
              <button key={k} className="v3-btn" data-testid={`v3-${k}`} style={{ padding: "3px 10px", fontSize: 12 }} onClick={nav(k)}>{l}</button>)}
            <span style={{ position: "relative" }} onClick={(e) => e.stopPropagation()}>
              <button className="v3-btn" data-testid="v3-legend-toggle" style={{ padding: "3px 10px", fontSize: 12 }} onClick={() => setLegend(!legend)}>Legend</button>
              {legend && <Legend />}</span>
            <button className="v3-btn" data-testid="v3-workspace-mode" data-mode={railed ? "max" : "standard"} style={{ padding: "3px 10px", fontSize: 12 }}
              onClick={() => { setCollapsedGlobal(!railed); setPanel(railed ? PANEL_DEFAULT : PANEL_MIN); }}>{railed ? "Standard layout" : "Maximum workspace"}</button>
          </div>
          <div style={{ overflowX: "auto" }}><div ref={wsRef} data-testid="v3-workspace" style={{ display: "grid", gridTemplateColumns: `minmax(0,1fr) 6px ${panelW}px`, minWidth: 260 + 380 + 6 + PANEL_MIN }}>
            <div style={{ position: "relative", minWidth: 0 }}>
              <Grid model={vmodel} items={shown} sel={sel} onSelect={(it) => select(it)} hover={hover} setHover={setHover} colW={colW} setColW={setColW}
                returnTo={returnTo} expanded={expanded} toggle={(k) => setExpanded((s) => { const n = new Set(s); n.has(k) ? n.delete(k) : n.add(k); return n; })}
                hits={hits} height={gridH} onContext={(e, it) => { setHover(null); setMenu({ x: e.clientX, y: e.clientY, it }); }}
                onRowClick={(r) => { if (r.type === "Network") { setNetSum(true); setDetails(false); } }} />
              {loading && <div data-testid="v3-loading" style={{ position: "absolute", inset: 0, background: "rgba(16,18,22,.55)", display: "flex", alignItems: "center", justifyContent: "center", zIndex: 8 }}>
                <div style={{ width: 38, height: 38, borderRadius: 38, border: `3px solid ${C.line}`, borderTopColor: C.accent, animation: "v3spin .8s linear infinite" }} /></div>}
            </div>
            <div data-testid="v3-panel-divider" role="separator" aria-orientation="vertical" aria-label="Resize Activity panel" tabIndex={0}
              aria-valuemin={PANEL_MIN} aria-valuemax={panelMax()} aria-valuenow={panelW} onMouseDown={dragPanel}
              onKeyDown={(e) => { if (e.key === "ArrowLeft") setPanel(panelW + 16); if (e.key === "ArrowRight") setPanel(panelW - 16); }}
              style={{ cursor: "col-resize", background: C.line, opacity: 0.6, transition: "opacity .12s" }}
              onMouseEnter={(e) => { e.currentTarget.style.opacity = 1; }} onMouseLeave={(e) => { e.currentTarget.style.opacity = 0.6; }} />
            <div data-testid="v3-activity-panel" style={{ background: C.panel, minWidth: 0, overflow: "hidden" }}>
              <div style={{ height: 44, display: "flex", alignItems: "center", padding: "0 16px", fontWeight: 600, fontSize: 18, borderBottom: `1px solid ${C.line}` }}>{netSum ? "Network" : details && sel ? "Activity Details" : "Activity"}</div>
              <ActivityList items={shown} sel={sel} onSelect={(it) => select(it, true)} hidden={(details && !!sel) || netSum} height={gridH - 44} onCtx={(e, it) => setMenu({ x: e.clientX, y: e.clientY, it })} />
              {netSum && <NetworkSummary model={model} height={gridH - 44} onBack={() => setNetSum(false)} onFilter={(v) => { upd({ q: v }); setNetSum(false); }} />}
              {!netSum && details && sel && <ActivityDetails it={sel} height={gridH - 44} onBack={() => setDetails(false)} onCopy={copy} onCtx={(e) => setMenu({ x: e.clientX, y: e.clientY, it: sel })}
                model={model} computer={data?.computer} device={device} approvals={approvals[sel.ev.event_iid]} onSearch={(v) => upd({ q: v })} onJump={(x) => select(x, true)} range={view} />}
            </div>
          </div></div>
          <div data-testid="v3-status-bar" style={{ display: "flex", alignItems: "center", gap: 12, padding: "7px 12px", fontSize: 12, color: C.muted, borderTop: `1px solid ${C.line}` }}>
            <span data-testid="v3-loaded-count">Showing {model.items.length} of {data?.e3_preview?.window_rows ?? data?.matched_in_window ?? 0} events in range</span>
            {older.cursor && <button className="v3-btn" style={{ padding: "2px 10px", fontSize: 12 }} data-testid="v3-load-older" onClick={loadOlder}>Load older events</button>}
            <span style={{ flex: 1 }} />
            <span data-testid="v3-data-label" title={data?.e3_preview?.data_label}>{/KUSHU/.test(data?.e3_preview?.data_label || "") ? "Production export (read-only)"
              : /FIXTURE/.test(data?.e3_preview?.data_label || "") ? "Fixture data" : "Synthetic data"}</span>
            <button className="v3-link" data-testid="v3-debug-toggle" style={{ fontSize: 12, color: C.muted }} onClick={(e) => { e.stopPropagation(); setDbg(!dbg); }}>Debug</button>
          </div>
        </div>
      </div>
      {hover?.x != null && (hover.it || hover.text) && <div data-testid="v3-tooltip" style={{ position: "fixed", left: hover.x + 14, top: hover.y + 14, zIndex: 95, pointerEvents: "none", background: C.tip,
        border: `1px solid ${C.line}`, borderRadius: 6, padding: "7px 10px", fontSize: 12.5, maxWidth: 420, boxShadow: "0 8px 24px rgba(0,0,0,.5)" }}>
        {hover.it ? <><b>{hover.it.kind.label}</b> · {hover.it.target?.label}<br /><span style={{ color: C.muted }}>{hover.it.actor ? `by ${hover.it.actor.label}` : "actor not observed"} · {iso(hover.it.ev.timestamp_instant_ms).slice(0, 19).replace("T", " ")} UTC</span>
          {hover.it.ev.e3_detection && <div style={{ color: C.red }}>{hover.it.ev.e3_detection.name}</div>}</> : hover.text}
      </div>}
      {menu && <ContextMenu menu={menu} onAction={onAction} />}
      {approval && <ApprovalDialog req={approval} onCancel={() => setApproval(null)} onConfirm={confirmApproval} />}
      {dbg && <Debug data={data} timing={timing.current} deep={deep} onLegacy={onLegacy} />}
    </div>
  );
}
