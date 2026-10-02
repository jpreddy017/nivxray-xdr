import React, { useEffect, useLayoutEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import api from "@/lib/api";
import { layerFromStrip } from "@/xdr/mitre/navigatorLayer";
import { ATTACK_ATTRIBUTION, heatmapHref, sevTone } from "./attack";
import { C } from "./theme";

// IOC / ATT&CK STRIP AT SCALE: grouped, bounded (≤220px, virtualized), filterable, steppable.
const SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
const ROW_H = 30, MAX_H = 220, TOP = 5, KEY = "e3.dt.strip.collapsed";
const utc = (ms) => (ms ? `${new Date(ms).toISOString().slice(0, 19).replace("T", " ")} UTC` : "—");
const local = (ms) => (ms ? new Date(ms).toLocaleString() : "");
const T = ({ ms }) => <span title={`Local: ${local(ms)}`}>{utc(ms)}</span>;
const cap = (s) => (s ? s[0] + s.slice(1).toLowerCase() : "Unknown");
const tri = (sev) => <svg width={12} height={11} viewBox="0 0 13 12" style={{ flex: "none" }}><path d="M6.5,0.5 L12.5,11.5 L0.5,11.5 Z" fill={sevTone(sev, C)} /></svg>;

export function groupDetections(dets, t0, t1) {
  const g = new Map();
  for (const d of dets) {
    const k = d.rule_id || d.name, inR = d.ms >= t0 && d.ms <= t1;
    const x = g.get(k) || { key: k, name: d.name, rule_id: d.rule_id, severity: d.severity, total: 0, count: 0, items: [], rows: new Set(), first: Infinity, last: 0 };
    x.total += 1;
    if (inR) {
      x.count += 1; x.items.push(d); x.rows.add(d.observation_id);
      x.first = Math.min(x.first, d.ms); x.last = Math.max(x.last, d.ms);
    }
    if ((RANK[d.severity] || 0) > (RANK[x.severity] || 0)) x.severity = d.severity;
    g.set(k, x);
  }
  return [...g.values()].filter((x) => x.count).map((x) => ({ ...x, items: x.items.sort((a, b) => a.ms - b.ms), rows: x.rows.size }))
    .sort((a, b) => (RANK[b.severity] || 0) - (RANK[a.severity] || 0) || b.last - a.last);
}

function VList({ rows, render, testid }) {
  const [st, setSt] = useState(0);
  const h = Math.min(MAX_H, rows.length * ROW_H), r0 = Math.max(0, Math.floor(st / ROW_H) - 2), r1 = Math.min(rows.length, r0 + Math.ceil(MAX_H / ROW_H) + 4);
  return (
    <div data-testid={testid} className="v3-scroll" onScroll={(e) => setSt(e.currentTarget.scrollTop)} style={{ maxHeight: MAX_H, height: h, overflowY: "auto", position: "relative" }}>
      <div style={{ height: rows.length * ROW_H, position: "relative" }}>
        {rows.slice(r0, r1).map((x, i) => <div key={x.key || x.technique} style={{ position: "absolute", top: (r0 + i) * ROW_H, left: 0, right: 0, height: ROW_H }}>{render(x)}</div>)}
      </div>
    </div>
  );
}

function Stepper({ items, idx, setIdx, onJump, onClear }) {
  const go = (i) => { setIdx(i); onJump(items[i]); };
  return (
    <span data-testid="dt-strip-stepper" style={{ display: "inline-flex", gap: 6, alignItems: "center", fontSize: 12 }}>
      <button className="v3-link" data-testid="dt-strip-prev" disabled={idx <= 0} onClick={() => go(idx - 1)}>‹</button>
      <span data-testid="dt-strip-step-pos">{idx + 1} of {items.length}</span>
      <button className="v3-link" data-testid="dt-strip-next" disabled={idx >= items.length - 1} onClick={() => go(idx + 1)}>›</button>
      <button className="v3-link" data-testid="dt-strip-clear" onClick={onClear}>Clear</button>
    </span>
  );
}

function Iocs({ dets, t0, t1, sev, onSev, ioc, onIoc, onJump }) {
  const [all, setAll] = useState(false), [qf, setQf] = useState(""), [idx, setIdx] = useState(0);
  const groups = useMemo(() => groupDetections(dets, t0, t1), [dets, t0, t1]);
  const sevCount = useMemo(() => Object.fromEntries(SEVS.map((s) => [s, groups.filter((g) => g.severity === s).reduce((n, g) => n + g.count, 0)])), [groups]);
  const total = groups.reduce((n, g) => n + g.count, 0), total30 = dets.length;
  const q = qf.trim().toLowerCase();
  const list = groups.filter((g) => (!sev || g.severity === sev) && (!q || `${g.name} ${g.rule_id || ""}`.toLowerCase().includes(q)));
  const shown = all ? list : list.slice(0, TOP);
  const [stepItems, setStepItems] = useState(null);
  const cur = ioc && (stepItems?.key === ioc ? stepItems : groups.find((g) => g.key === ioc));
  return (
    <div data-testid="dt-ioc-list">
      <div data-testid="dt-ioc-summary" style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap", fontSize: 12, marginBottom: 6 }}>
        {SEVS.map((s) => <button key={s} type="button" data-testid={`dt-sev-pill-${s}`} data-active={sev === s ? "1" : "0"} onClick={() => onSev(sev === s ? null : s)}
          style={{ border: `1px solid ${sevTone(s, C)}`, background: sev === s ? sevTone(s, C) : "transparent", color: sev === s ? "#111" : C.text, borderRadius: 10, padding: "0 9px", cursor: "pointer", fontSize: 12 }}>
          {cap(s)} {sevCount[s]}</button>)}
        <span data-testid="dt-ioc-total" style={{ color: C.text }}>{total} detections · {groups.length} distinct <span style={{ color: C.muted }}>in selected range</span></span>
        <span style={{ color: C.muted }}>({total30} in last 30 days)</span>
        <input data-testid="dt-strip-quickfilter" placeholder="Filter name, rule ID" value={qf} onChange={(e) => setQf(e.target.value)}
          style={{ marginLeft: "auto", background: C.inset, border: `1px solid ${C.line}`, color: C.text, borderRadius: 4, padding: "2px 8px", fontSize: 12, width: 190 }} />
        {cur && <Stepper items={cur.items} idx={idx} setIdx={setIdx} onJump={onJump} onClear={() => onIoc(null)} />}
      </div>
      {!list.length ? <div style={{ color: C.muted, fontSize: 13 }}>No indications of compromise in the selected range.</div> : (
        <VList testid="dt-ioc-groups" rows={shown} render={(g) => (
          <button type="button" data-testid={`dt-ioc-group-${g.key}`} data-active={ioc === g.key ? "1" : "0"} title={`${g.name} · ${g.rule_id || "no rule id"}`}
            onClick={() => { const on = ioc === g.key; setIdx(0); setStepItems(on ? null : g); onIoc(on ? null : g.key, on ? null : g.items[0]); }}
            style={{ display: "grid", gridTemplateColumns: "14px minmax(0,1fr) 56px 90px 360px", gap: 8, alignItems: "center", width: "100%", height: ROW_H - 2, textAlign: "left",
              background: ioc === g.key ? "rgba(110,160,255,.18)" : "transparent", border: 0, borderBottom: `1px solid ${C.line}`, color: C.text, cursor: "pointer", fontSize: 12.5 }}>
            {tri(g.severity)}<b style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{g.name}</b>
            <span data-testid="dt-ioc-group-count">×{g.count}</span><span style={{ color: C.muted }}>{g.rows} row{g.rows === 1 ? "" : "s"}</span>
            <span style={{ color: C.muted }}><T ms={g.first} /> → <T ms={g.last} /></span>
          </button>)} />)}
      {list.length > TOP && <button className="v3-link" data-testid="dt-ioc-show-all" style={{ fontSize: 12, marginTop: 4 }} onClick={() => setAll(!all)}>{all ? "Show top 5" : `Show all (${list.length})`}</button>}
    </div>
  );
}

function Column({ t, active, onPick }) {
  const [more, setMore] = useState(false);
  const rows = [...t.techniques].sort((a, b) => b.count - a.count), vis = more ? rows : rows.slice(0, TOP), n = rows.reduce((s, x) => s + x.count, 0);
  return (
    <div data-testid={`dt-attack-tactic-${t.shortname}`} data-observed={t.observed ? "1" : "0"}
      style={{ background: C.inset, borderRadius: 4, padding: 6, opacity: t.observed ? 1 : 0.38, minWidth: 0, maxHeight: MAX_H, overflowY: "auto" }} className="v3-scroll">
      <a href={t.url} target="_blank" rel="noopener noreferrer" title={t.name} style={{ color: C.text, fontSize: 11.5, fontWeight: 700, textDecoration: "none", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis", display: "block" }}>
        {t.observed ? t.name : t.name.split(" ")[0]} <span data-testid="dt-attack-tactic-count" style={{ color: C.muted }}>{n}</span></a>
      {vis.map((x) => {
        const on = active === x.technique;
        return (
          <button key={x.technique} type="button" data-testid={`dt-attack-tech-${x.technique}`} data-active={on ? "1" : "0"} title={x.description}
            onClick={() => onPick(on ? null : x.technique)}
            style={{ display: "block", width: "100%", textAlign: "left", marginTop: 5, padding: "3px 6px", borderRadius: 4, cursor: "pointer", fontSize: 11.5,
              color: C.text, background: on ? "rgba(110,160,255,.22)" : C.panel, border: `1px solid ${on ? C.accent : sevTone(x.max_severity, C)}`, transition: "background-color .12s" }}>
            <b style={{ fontFamily: "ui-monospace, Menlo, monospace" }}>{x.technique}</b> {x.name}{x.status !== "active" ? ` (${x.status})` : ""}
            {x.types?.includes("Heuristic") && <span style={{ color: C.muted }}> · heuristic</span>}
            <div style={{ color: C.muted, fontSize: 10.5 }}>×{x.count} · <T ms={x.last_ms} /></div>
          </button>);
      })}
      {rows.length > TOP && <button className="v3-link" data-testid={`dt-attack-more-${t.shortname}`} style={{ fontSize: 11, marginTop: 4 }} onClick={() => setMore(!more)}>{more ? "less" : `+${rows.length - TOP} more`}</button>}
    </div>
  );
}

function Matrix({ data, active, onPick }) {
  const max = Math.max(1, ...data.tactics.flatMap((t) => t.techniques.map((x) => x.count)));
  return (
    <div data-testid="dt-attack-matrix" className="v3-scroll" style={{ display: "grid", gridTemplateColumns: `repeat(${data.tactics.length}, minmax(0,1fr))`, gap: 3, maxHeight: MAX_H, overflowY: "auto" }}>
      {data.tactics.map((t) => (
        <div key={t.shortname} style={{ minWidth: 0 }}>
          <div title={t.name} style={{ fontSize: 10, color: t.observed ? C.text : C.muted, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{t.name}</div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 2, marginTop: 2 }}>
            {t.techniques.map((x) => <button key={x.technique} type="button" data-testid="dt-attack-cell" title={`${x.technique} ${x.name} · ×${x.count}`} onClick={() => onPick(active === x.technique ? null : x.technique)}
              style={{ width: 12, height: 12, padding: 0, borderRadius: 2, cursor: "pointer", border: active === x.technique ? `1px solid ${C.text}` : 0,
                background: `rgba(102,177,255,${0.18 + 0.82 * (x.count / max)})` }} />)}
          </div>
        </div>))}
    </div>
  );
}

function download(name, obj) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([JSON.stringify(obj, null, 2)], { type: "application/json" }));
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

function Strip({ data, active, onPick, heat, heur, setHeur, onExport, onJump, focusTech }) {
  const [matrix, setMatrix] = useState(false), [idx, setIdx] = useState(0);
  const cur = active && data.tactics.flatMap((t) => t.techniques).find((x) => x.technique === active);
  const steps = (cur?.event_iids || []).map((event_iid) => ({ event_iid }));
  useEffect(() => setIdx(0), [active]);
  return (
    <div data-testid="dt-attack-strip">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 6, gap: 10 }}>
        <span data-testid="dt-attack-strip-label" style={{ color: C.muted, fontSize: 12 }}>{data.label} · Enterprise v{data.catalogue_version}</span>
        <span style={{ display: "flex", gap: 14, alignItems: "center", fontSize: 12 }}>
          {steps.length > 0 && <Stepper items={steps} idx={idx} setIdx={setIdx} onJump={focusTech} onClear={() => onPick(null)} />}
          <label style={{ color: C.muted, cursor: "pointer" }}><input type="checkbox" data-testid="dt-attack-matrix-toggle" checked={matrix} onChange={(e) => setMatrix(e.target.checked)} /> matrix</label>
          <label style={{ color: C.muted, cursor: "pointer" }}><input type="checkbox" data-testid="dt-attack-include-heuristic" checked={heur} onChange={(e) => setHeur(e.target.checked)} /> include heuristic ingest tags (not detections)</label>
          <button className="v3-link" data-testid="dt-attack-export-layer" style={{ fontSize: 12 }} onClick={onExport}>Export ATT&amp;CK Navigator layer</button>
          {active && <button className="v3-link" data-testid="dt-attack-strip-heatmap" style={{ fontSize: 12 }} onClick={() => heat(active)}>Open {active} in ATT&amp;CK HeatMap ↗</button>}
        </span>
      </div>
      {matrix ? <Matrix data={data} active={active} onPick={onPick} /> : (
        <div style={{ display: "grid", gridTemplateColumns: data.tactics.map((t) => (t.observed ? "minmax(0,2fr)" : "minmax(0,.5fr)")).join(" "), gap: 4 }}>
          {data.tactics.map((t) => <Column key={t.shortname} t={t} active={active} onPick={onPick} />)}
        </div>)}
      <div style={{ color: C.muted, fontSize: 11, marginTop: 6 }}>{data.semantics}</div>
      <div data-testid="dt-attack-attribution" style={{ color: C.muted, fontSize: 10.5, marginTop: 2 }}>ATT&amp;CK Enterprise v{data.catalogue_version} ({String(data.catalogue_modified || "").slice(0, 10)}) · {ATTACK_ATTRIBUTION}</div>
    </div>
  );
}

export function AttackPanel({ url, device, t0, t1, active, onPick, dets, onJump, sev, onSev, ioc, onIoc, scenario }) {
  const start = performance.now();
  const [tab, setTabS] = useState(() => { try { return sessionStorage.getItem(KEY + ".tab") || "attack"; } catch { return "attack"; } });
  const setTab = (k) => { setTabS(k); try { sessionStorage.setItem(KEY + ".tab", k); } catch { /* ok */ } };
  const [open, setOpen] = useState(() => { try { const v = sessionStorage.getItem(KEY); return v ? v !== "1" : window.innerHeight >= 1000; } catch { return true; } });
  const [data, setData] = useState(null);
  const [heur, setHeur] = useState(false);
  const navigate = useNavigate();
  useEffect(() => {
    const ac = new AbortController();
    api.get(`${url}/attack`, { params: { time_start: new Date(t0).toISOString(), time_end: new Date(t1).toISOString(), include_heuristic: heur, scenario }, signal: ac.signal })
      .then(({ data: d }) => setData(d)).catch(() => {});
    return () => ac.abort();
  }, [url, t0, t1, heur, scenario]);
  useLayoutEffect(() => { window.__e3StripMs = performance.now() - start; });
  const toggle = () => { setOpen(!open); try { sessionStorage.setItem(KEY, open ? "1" : "0"); } catch { /* ok */ } };
  const heat = (technique) => navigate(heatmapHref({ technique, device, t0, t1 }));
  const onExport = () => { const l = layerFromStrip(data, { device, t0, t1 }); window.__e3LastLayer = l; download(`nivxforge-dt-${device}-attack-layer.json`, l); };
  const inRange = dets.filter((d) => d.ms >= t0 && d.ms <= t1).length;
  const tabBtn = (k, l) => <button type="button" data-testid={`dt-tab-${k}`} aria-selected={tab === k} onClick={() => { setTab(k); if (!open) toggle(); }}
    style={{ background: "none", border: 0, borderBottom: `2px solid ${tab === k && open ? C.accent : "transparent"}`, color: tab === k ? C.text : C.muted, padding: "6px 2px", marginRight: 18, fontSize: 13.5, fontWeight: 600, cursor: "pointer" }}>{l}</button>;
  return (
    <div data-testid="dt-attack-panel" data-open={open ? "1" : "0"} style={{ background: C.panel, borderBottom: `1px solid ${C.line}`, padding: "4px 12px 8px", flex: "none", minWidth: 0, overflow: "hidden" }}>
      <div style={{ display: "flex", alignItems: "center" }}>
        <button type="button" data-testid="dt-strip-collapse" aria-expanded={open} onClick={toggle} style={{ background: "none", border: 0, color: C.muted, cursor: "pointer", fontSize: 14, marginRight: 8, transform: open ? "rotate(90deg)" : "none", transition: "transform .15s" }}>›</button>
        {tabBtn("ioc", `Indications of compromise (${inRange})`)}{tabBtn("attack", "ATT&CK")}
      </div>
      {open && (tab === "ioc" ? <Iocs dets={dets} t0={t0} t1={t1} sev={sev} onSev={onSev} ioc={ioc} onIoc={onIoc} onJump={onJump} />
        : data ? <Strip data={data} active={active} onPick={onPick} heat={heat} heur={heur} setHeur={setHeur} onExport={onExport} onJump={onJump}
            focusTech={(x) => onJump({ event_iid: x.event_iid })} />
          : <div style={{ color: C.muted, fontSize: 12 }}>Loading ATT&amp;CK mapping…</div>)}
    </div>
  );
}
