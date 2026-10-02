import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import api from "@/lib/api";
import NivXForgeConsole from "@/nivxforge/NivXForgeConsole";
import EdrDeviceTrajectoryPage from "@/nivxforge/trajectory/EdrDeviceTrajectoryPage";
import Grid3, { C } from "./Grid3";
import { ActivityDetails, ActivityList, FiltersPanel } from "./Side3";
import { buildModel, matches } from "./model";

const DAY = 86_400_000;
const iso = (ms) => new Date(ms).toISOString();
const ACT = { create: "create", execute: "exec", network: "net", dns: "dns", registry: "reg" };
const DEFAULT_ON = ["create", "execute", "network", "dns", "registry", "match", "d_benign", "d_malicious", "d_unknown", "f_warning", "f_cmd",
  "f_none", "t_PE", "t_Document", "t_PDF", "t_Archive", "t_MSI", "t_Script", "t_Other"];

function Navigator({ activity, view, now, onView, dets }) {
  const [open, setOpen] = useState(true);
  const days = (activity?.days || []).slice(-30);
  const max = Math.max(1, ...days.map((d) => d.total));
  const day0 = Math.floor((view.t1 - 1) / DAY) * DAY;
  return (
    <div data-testid="v3-navigator" style={{ padding: "6px 12px", background: C.nav, borderBottom: `1px solid ${C.line}` }}>
      <button data-testid="v3-nav-collapse" onClick={() => setOpen(!open)} style={{ background: "none", border: 0, color: C.muted, cursor: "pointer" }}>{open ? "∨" : "›"}</button>
      {open && <>
        <div style={{ display: "flex", gap: 2, alignItems: "flex-end", height: 44 }}>
          {days.map((d) => {
            const t = Date.parse(`${d.day}T00:00:00Z`), det = dets.filter((x) => x.t >= t && x.t < t + DAY);
            const cur = t === day0;
            return (<div key={d.day} data-testid={`v3-day-cell-${d.day}`} onClick={() => onView({ t0: t, t1: Math.min(t + DAY, now) })}
              title={`${new Date(t).toUTCString().slice(5, 16)}\n${d.total} observations${det.length ? `\n● Compromise / detection events: ${det.map((x) => iso(x.t).slice(11, 16)).join(", ")}` : ""}`}
              style={{ flex: 1, cursor: "pointer", textAlign: "center", borderRadius: 3, background: cur ? "rgba(63,169,245,.18)" : C.panel, padding: "2px 0" }}>
              <div style={{ height: 14 }}>{det.length > 0 && <span style={{ display: "inline-block", width: 9, height: 9, borderRadius: 9, background: C.red }} />}
                {d.total > 0 && <span style={{ display: "inline-block", marginLeft: 2, width: 3 + 4 * (d.total / max), height: 3 + 4 * (d.total / max), borderRadius: 9, background: C.accent }} />}</div>
              <div style={{ fontSize: 10, color: cur ? C.text : C.muted }}>{d.day.slice(8)}</div>
            </div>);
          })}
        </div>
        <div data-testid="v3-hour-strip" style={{ position: "relative", height: 20, marginTop: 4, background: C.panel, borderRadius: 3 }}>
          {Array.from({ length: 25 }, (_, h) => <span key={h} style={{ position: "absolute", left: `${(h / 24) * 100}%`, fontSize: 9, color: C.muted, top: 4 }}>{h % 3 ? "" : h}</span>)}
          {now < day0 + DAY && <div title="Not yet occurred" style={{ position: "absolute", left: `${((now - day0) / DAY) * 100}%`, right: 0, top: 0, bottom: 0,
            background: "repeating-linear-gradient(135deg, rgba(132,148,166,.25) 0 2px, transparent 2px 6px)" }} />}
          <div data-testid="v3-hour-bracket" style={{ position: "absolute", left: `${Math.max(0, (view.t0 - day0) / DAY) * 100}%`,
            width: `${Math.max(1, ((view.t1 - Math.max(view.t0, day0)) / DAY) * 100)}%`, top: 0, bottom: 0, border: `2px solid ${C.accent}`, borderRadius: 3 }} />
          {dets.filter((x) => x.t >= day0 && x.t < day0 + DAY).map((x, i) => <span key={i} style={{ position: "absolute", left: `${((x.t - day0) / DAY) * 100}%`, top: 2, width: 3, height: 16, background: C.red }} />)}
        </div>
      </>}
    </div>
  );
}

function V3({ device, onLegacy }) {
  const [params, setParams] = useSearchParams();
  const now = useRef(Date.now()).current;
  const [view, setView] = useState({ t0: now - DAY, t1: now });
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [sel, setSel] = useState(null);
  const [details, setDetails] = useState(false);
  const [hover, setHover] = useState(null);
  const [filters, setFilters] = useState(() => new Set(params.get("f") ? params.get("f").split(",") : DEFAULT_ON));
  const [showF, setShowF] = useState(false);
  const [menu, setMenu] = useState(null);
  const [notice, setNotice] = useState(null);
  const [deep, setDeep] = useState(null);
  const returnTo = useRef(false);
  const q = params.get("q") || "";
  const setQ = (v) => { const n = new URLSearchParams(params); v ? n.set("q", v) : n.delete("q"); setParams(n, { replace: true }); };

  const load = useCallback(async (v, signal) => {
    setLoading(true);
    try {
      const { data: d } = await api.get(`/edr/endpoints/${encodeURIComponent(device)}/trajectory`,
        { params: { time_start: iso(v.t0), time_end: iso(v.t1), lane_start: 0, lane_end: 100000, limit: 500 }, signal });
      setData(d);
      setOlder({ events: [], cursor: d?.e3_preview?.older_cursor || null });
      return d;
    } catch (e) { if (e?.name !== "CanceledError") setNotice(`Trajectory read failed: ${e.message}`); return null; } finally { setLoading(false); }
  }, [device]);
  useEffect(() => { const ac = new AbortController(); load(view, ac.signal); return () => ac.abort(); }, [view, load]);
  const [older, setOlder] = useState({ events: [], cursor: null });
  const loadOlder = async () => {
    setLoading(true);
    try {
      const { data: d } = await api.get(`/edr/endpoints/${encodeURIComponent(device)}/trajectory`,
        { params: { time_start: iso(view.t0), time_end: iso(view.t1), lane_start: 0, lane_end: 100000, limit: 500, before: older.cursor } });
      setOlder((o) => ({ events: [...(d.events || []), ...o.events], cursor: d?.e3_preview?.older_cursor || null }));
    } catch (e) { setNotice(`Older events read failed: ${e.message}`); } finally { setLoading(false); }
  };

  const model = useMemo(() => buildModel([...older.events, ...(data?.events || [])], data?.lane_axis?.lanes || []), [data, older.events]);
  const pass = (it) => (ACT[Object.keys(ACT).find((k) => ACT[k] === it.kind.glyph)] ? filters.has(Object.keys(ACT).find((k) => ACT[k] === it.kind.glyph)) : true)
    && filters.has(`d_${it.shape === "hexagon" ? "malicious" : it.shape === "circle" ? "benign" : "unknown"}`);
  const shown = useMemo(() => model.items.filter((it) => pass(it) && matches(it, q)), [model, filters, q]); // eslint-disable-line
  const rowKeys = useMemo(() => new Set(shown.flatMap((it) => [it.target?.key, it.actor?.key])), [shown]);
  const vmodel = useMemo(() => (q || shown.length !== model.items.length ? { ...model, rows: model.rows.filter((r) => rowKeys.has(r.key)) } : model), [model, shown, rowKeys, q]);
  const filtered = shown.length !== model.items.length;
  const select = (it) => { setSel(it); setDetails(true); returnTo.current = true; const n = new URLSearchParams(params); n.set("event", it.ev.event_iid); setParams(n, { replace: true }); };

  const wanted = params.get("event");
  useEffect(() => {
    if (!data || !wanted || sel?.ev.event_iid === wanted) return;
    const hit = model.items.find((it) => it.ev.event_iid === wanted);
    if (hit) { setDeep({ state: "FOCUSED", id: wanted }); select(hit); return; }
    if (deep?.id === wanted) return;
    setDeep({ state: "LOCATING", id: wanted });
    api.get(`/edr/endpoints/${encodeURIComponent(device)}/trajectory/focus`, { params: { event_iid: wanted } }).then(({ data: f }) => {
      if (f.state !== "FOCUS_RESOLVED") { setDeep({ state: "NOT_FOUND", id: wanted }); return; }
      setDeep({ state: "FOCUSING", id: wanted });
      setView({ t0: Date.parse(f.focus.window.time_start), t1: Date.parse(f.focus.window.time_end) });
    }).catch(() => setDeep({ state: "NOT_FOUND", id: wanted }));
  }, [data, wanted]); // eslint-disable-line

  const dets = model.items.filter((it) => it.ev.e3_detection).map((it) => ({ t: it.ev.timestamp_instant_ms }));
  const detItems = model.items.filter((it) => it.ev.e3_detection);
  const host = data?.computer?.hostname || device;
  const approve = async (action) => {
    setMenu(null);
    if (!window.confirm(`${action}: record an APPROVAL REQUEST only? Nothing is executed.`)) return;
    try {
      const { data: r } = await api.post("/e3/trajectory/approvals", { tenant_id: data?.identity?.tenant_id, action, requested_by: "preview-analyst",
        target: { device_id: device, event_iid: menu?.it?.ev.event_iid, path: menu?.it?.target?.path }, idempotency_key: `${action}:${menu?.it?.ev.event_iid}`, reason: "preview" });
      setNotice(`${action}: Approval requested — not executed. Execution is owned by E1. (${r.request?.state})`);
    } catch (e) { setNotice(`Approval request not recorded: ${e.message}`); }
  };
  const B = { background: C.band, color: C.text, border: `1px solid ${C.line}`, borderRadius: 4, padding: "5px 10px", fontSize: 12, cursor: "pointer" };

  return (
    <div data-testid="v3-page" style={{ color: C.text, padding: 16, background: C.bg, fontFamily: "Inter, system-ui, sans-serif" }} onClick={() => menu && setMenu(null)}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 10, flexWrap: "wrap" }}>
        <h1 data-testid="v3-hostname" style={{ margin: 0, fontSize: 32, fontWeight: 700 }}>{host}</h1>
        <button style={{ ...B, background: "transparent", border: `1px solid ${C.accent}`, color: C.accent }} data-testid="v3-show-details" onClick={() => setNotice(`OS ${JSON.stringify(data?.computer?.operating_system)} · sensor ${JSON.stringify(data?.computer?.connector_version)} · device ${data?.computer?.device_iid}`)}>Show details</button>
        <button style={{ ...B, background: C.accent, color: "#0b1020", border: 0, fontWeight: 600 }} data-testid="v3-actions" onClick={(e) => { e.stopPropagation(); setMenu({ x: e.clientX, y: e.clientY + 10, it: sel, deviceOnly: true }); }}>Actions ▾</button>
        <span style={{ fontSize: 12, color: C.muted }}>Linked XDR Incidents: none</span>
        <span style={{ flex: 1 }} />
        <span data-testid="v3-data-label" title={data?.e3_preview?.data_label} style={{ fontSize: 11, color: C.muted }}>
          {/KUSHU/.test(data?.e3_preview?.data_label || "") ? "Production export (read-only)" : "Synthetic dataset"}</span>
        <button style={B} data-testid="v3-share" onClick={() => { navigator.clipboard?.writeText(window.location.href).catch(() => {}); setNotice("Deep link copied"); }}>Share</button>
        <button style={B} data-testid="v3-fullscreen" onClick={() => document.documentElement.requestFullscreen?.()}>⛶</button>
        <button style={B} data-testid="v3-use-legacy" onClick={onLegacy}>Use Legacy Device Trajectory</button>
      </div>
      <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 8, position: "relative" }}>
        <input data-testid="v3-search" defaultValue={q} key={q} placeholder="Search Device Trajectory (SHA-256, filename, process, command line, IP, domain, user)"
          onKeyDown={(e) => e.key === "Enter" && setQ(e.currentTarget.value.trim())} style={{ ...B, flex: 1, cursor: "text", background: C.bg }} />
        {q && <><span data-testid="v3-search-count" style={{ fontSize: 12 }}>{shown.length} results</span><button style={B} data-testid="v3-search-clear" onClick={() => setQ("")}>×</button></>}
        {filtered && <span data-testid="v3-filter-indicator" style={{ fontSize: 12, color: C.amber }}>Filtered trajectory · {shown.length} of {model.items.length}
          <button style={{ ...B, marginLeft: 6 }} data-testid="v3-filter-reset" onClick={() => { setFilters(new Set(DEFAULT_ON)); setQ(""); }}>Reset</button></span>}
        <button style={B} data-testid="v3-filters" onClick={() => setShowF(!showF)}>Filters ▾</button>
        <button style={B} data-testid="v3-zoom-out" onClick={() => setView((v) => ({ t0: v.t0 - (v.t1 - v.t0) / 2, t1: Math.min(now, v.t1 + (v.t1 - v.t0) / 2) }))}>−</button>
        <button style={B} data-testid="v3-zoom-in" onClick={() => setView((v) => ({ t0: v.t0 + (v.t1 - v.t0) / 4, t1: v.t1 - (v.t1 - v.t0) / 4 }))}>+</button>
        <button style={B} data-testid="v3-last24" onClick={() => setView({ t0: now - DAY, t1: now })}>Last 24h</button>
        {showF && <FiltersPanel applied={filters} onCancel={() => setShowF(false)} onApply={(s) => { setFilters(s); setShowF(false); const n = new URLSearchParams(params); n.set("f", [...s].join(",")); setParams(n, { replace: true }); }} />}
      </div>
      {deep && deep.state !== "FOCUSED" && <div data-testid="v3-deeplink-state" style={{ fontSize: 12, color: deep.state === "NOT_FOUND" ? C.amber : C.muted, marginBottom: 6 }}>
        {deep.state === "NOT_FOUND" ? `Observation ${deep.id} was not found in retained evidence for this device.` : `Locating observation ${deep.id}…`}</div>}
      {notice && <div data-testid="v3-notice" onClick={() => setNotice(null)} style={{ fontSize: 12, background: C.band, padding: "6px 10px", borderRadius: 4, marginBottom: 6 }}>{notice}</div>}
      <div style={{ border: `1px solid ${C.line}`, borderRadius: 12, overflow: "hidden", background: C.panel }}>
        <Navigator activity={data?.activity} view={view} now={now} onView={setView} dets={dets} />
        <div data-testid="v3-ioc-strip" style={{ padding: "8px 12px", fontSize: 12, color: C.muted, borderBottom: `1px solid ${C.line}`, display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <b style={{ color: C.text, fontWeight: 600 }}>Indications of Compromise</b>
          {detItems.length ? detItems.map((it) => (
            <button key={it.col} data-testid={`v3-ioc-chip-${it.col}`} onClick={() => select(it)} style={{ background: "rgba(229,83,75,.14)", color: "#FF8A84",
              border: `1px solid rgba(229,83,75,.5)`, borderRadius: 3, padding: "2px 8px", fontSize: 11.5, cursor: "pointer" }}>
              {it.ev.e3_detection.name} · {it.target?.label}</button>)) : <span>None in this range</span>}
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "minmax(0,1fr) 400px", position: "relative" }}>
          <div style={{ position: "relative", minWidth: 0 }}>
            <Grid3 model={vmodel} items={shown} sel={sel} onSelect={select} hover={hover} setHover={setHover} returnTo={returnTo}
              onContext={(e, it) => setMenu({ x: e.clientX, y: e.clientY, it })} />
            {loading && <div data-testid="v3-loading" style={{ position: "absolute", inset: 0, background: "rgba(11,16,22,.55)", display: "flex", alignItems: "center", justifyContent: "center" }}>
              <div style={{ width: 34, height: 34, borderRadius: 34, border: `3px solid ${C.line}`, borderTopColor: C.accent, animation: "v3spin 0.8s linear infinite" }} /></div>}
          </div>
          <div style={{ borderLeft: `1px solid ${C.line}` }}>
            <div style={{ padding: "8px 12px", fontWeight: 700, fontSize: 12.5, borderBottom: `1px solid ${C.line}` }}>{details && sel ? "Activity details" : "Activity"}</div>
            {details && sel ? <ActivityDetails it={sel} onBack={() => setDetails(false)} onCtx={(e) => setMenu({ x: e.clientX, y: e.clientY, it: sel })} />
              : <ActivityList items={shown} sel={sel} onSelect={select} />}
          </div>
        </div>
        <div data-testid="v3-status-bar" style={{ display: "flex", alignItems: "center", gap: 10, padding: "6px 12px", fontSize: 11.5, color: C.muted, borderTop: `1px solid ${C.line}` }}>
          <span data-testid="v3-loaded-count">Showing {model.items.length} of {data?.e3_preview?.window_rows ?? data?.matched_in_window ?? 0} events in range</span>
          {older.cursor && <button style={{ ...B, padding: "2px 8px", fontSize: 11.5 }} data-testid="v3-load-older" onClick={loadOlder}>Load older events</button>}
        </div>
      </div>
      {menu && <div data-testid="v3-context-menu" onClick={(e) => e.stopPropagation()} style={{ position: "fixed", left: menu.x, top: menu.y, zIndex: 50, background: C.panel,
        border: `1px solid ${C.line}`, borderRadius: 6, padding: "4px 0", minWidth: 240, fontSize: 12.5 }}>
        {[["Copy path", () => { navigator.clipboard?.writeText(menu.it?.target?.path || "").catch(() => {}); setNotice("Copied path"); }],
          ["Search trajectory", () => setQ(menu.it?.target?.label || "")], ["Isolate lineage", () => setQ(menu.it?.actor?.label || menu.it?.target?.label || "")],
          ["Open File Trajectory (not yet built)", () => setNotice("File Trajectory is not yet built")], ["File Analysis (not yet built)", () => setNotice("File Analysis is not yet built")]]
          .filter(() => !menu.deviceOnly).map(([l, f]) => <div key={l} data-testid={`v3-ctx-${l.split(" ")[0].toLowerCase()}-${l.split(" ")[1]?.toLowerCase()}`} onClick={() => { f(); setMenu(null); }} style={{ padding: "5px 12px", cursor: "pointer" }}>{l}</div>)}
        <div style={{ padding: "4px 12px", color: C.muted, fontSize: 10.5, borderTop: `1px solid ${C.line}` }}>APPROVAL REQUEST ONLY</div>
        {(menu.deviceOnly ? ["ISOLATE_DEVICE"] : ["ADD_HASH_TO_BLOCKLIST", "BLOCK_APPLICATION", "QUARANTINE_FILE", "ISOLATE_DEVICE"]).map((a) =>
          <div key={a} data-testid={`v3-ctx-${a}`} onClick={() => approve(a)} style={{ padding: "5px 12px", cursor: "pointer" }}>{a.replace(/_/g, " ").toLowerCase()}…</div>)}
      </div>}
      <style>{"@keyframes v3spin{to{transform:rotate(360deg)}}"}</style>
    </div>
  );
}

export default function DeviceTrajectoryV3Page() {
  const [params] = useSearchParams();
  const [legacy, setLegacy] = useState(params.get("legacy") === "1");
  const device = params.get("device");
  if (legacy) return <div><button data-testid="v3-back-to-new" onClick={() => setLegacy(false)} style={{ margin: 8 }}>Use new Device Trajectory</button><EdrDeviceTrajectoryPage /></div>;
  return <NivXForgeConsole activeTab="device-trajectory"><V3 device={device} onLegacy={() => setLegacy(true)} /></NivXForgeConsole>;
}
