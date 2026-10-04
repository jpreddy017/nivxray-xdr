import React, { useEffect, useMemo, useRef, useState } from "react";
import { Mark } from "./Glyphs";
import { C, HDR_H, LABEL_W, ROW_H } from "./theme";

const lower = (arr, col) => { let lo = 0, hi = arr.length; while (lo < hi) { const m = (lo + hi) >> 1; if (arr[m].col < col) lo = m + 1; else hi = m; } return lo; };
const day = (ms) => new Date(ms).toISOString().slice(0, 10);

function buildLines(rows, expanded) {
  const out = [];
  for (const s of ["System", "Files & Network"]) {
    const rs = rows.filter((r) => r.section === s);
    if (!rs.length) continue;
    out.push({ hdr: s, key: `hdr:${s}` });
    for (const r of rs) {
      out.push({ row: r, key: r.key });
      if (expanded.has(r.key)) for (const inst of r.instances.values()) out.push({ row: r, inst, key: `${r.key}#${inst.iid}` });
    }
  }
  return out;
}

function Label({ l, y, sel, hover, hits, expanded, toggle, onRowCtx, onRowClick }) {
  if (l.hdr) return <div style={{ position: "absolute", top: y, left: 0, right: 0, height: ROW_H, background: C.band, display: "flex", alignItems: "center",
    justifyContent: "flex-end", padding: "0 12px", boxSizing: "border-box", fontWeight: 600, fontSize: 18, color: "#fff" }}>{l.hdr}</div>;
  const r = l.row, on = sel && (sel.target?.key === r.key || sel.actor?.key === r.key), hov = hover && (hover.a === r.key || hover.t === r.key);
  const hit = hits?.has(r.key);
  return (
    <div data-testid={l.inst ? `v3-subrow-${l.inst.pid || "x"}` : `v3-row-${r.key}`} data-row-type={r.type} title={r.path || r.label}
      onContextMenu={(e) => { e.preventDefault(); e.stopPropagation(); onRowCtx(e, r); }} onClick={() => onRowClick(r)}
      style={{ position: "absolute", top: y, left: 0, right: 0, height: ROW_H, display: "flex", alignItems: "center", justifyContent: "flex-end", gap: 4,
        padding: "0 12px", boxSizing: "border-box", fontSize: l.inst ? 12 : 14, whiteSpace: "nowrap", color: r.detection ? "#ff8a84" : C.label,
        fontWeight: on && !l.inst ? 700 : 400, background: hov ? "rgba(110,160,255,.14)" : on ? C.sel : "transparent", transition: "background-color .12s" }}>
      {!l.inst && r.instances.size > 1 && <button data-testid={`v3-expand-${r.key}`} onClick={() => toggle(r.key)} title={`${r.instances.size} instances`}
        style={{ background: "none", border: 0, color: C.muted, cursor: "pointer", fontSize: 11, padding: 0, marginRight: "auto" }}>{expanded.has(r.key) ? "▾" : "▸"} {r.instances.size}</button>}
      {l.inst ? <span style={{ color: C.muted }}>pid {l.inst.pid || "?"} · {String(l.inst.iid).slice(-6)}</span> : <>
        <span data-testid={hit ? "v3-search-hit-label" : "dt-row-label"} style={{ cursor: r.type === "Network" ? "pointer" : undefined, overflow: "hidden", textOverflow: "ellipsis", borderRadius: 3, padding: hit ? "0 4px" : 0,
          background: hit ? "rgba(229,83,75,.28)" : "transparent", color: hit ? "#ffb1ac" : undefined }}>{r.label}</span>
        <span style={{ color: C.muted, flex: "none" }}>[{r.type}]</span></>}
    </div>
  );
}

export default function Grid({ model, items, sel, onSelect, onContext, hover, setHover, colW, setColW, returnTo, expanded, toggle, hits, height, onRowClick }) {
  const box = useRef(null);
  const [vp, setVp] = useState({ sl: 0, st: 0, vw: 1000, vh: 600 });
  const lines = useMemo(() => buildLines(model.rows, expanded), [model.rows, expanded]);
  const yOf = useMemo(() => new Map(lines.map((l, i) => [l.key, i * ROW_H + ROW_H / 2])), [lines]);
  const rk = (r, iid) => (r && expanded.has(r.key) && iid && r.instances.has(iid) ? `${r.key}#${iid}` : r?.key);
  const W = Math.max(model.ncol * colW + 360, vp.vw), H = lines.length * ROW_H, x = (c) => c * colW + colW / 2;
  const sync = () => { const b = box.current; if (b) setVp({ sl: b.scrollLeft, st: b.scrollTop, vw: b.clientWidth - LABEL_W, vh: b.clientHeight - HDR_H }); };
  useEffect(() => { sync(); const o = new ResizeObserver(sync); box.current && o.observe(box.current); return () => o.disconnect(); }, []);
  useEffect(() => {
    if (!sel || !box.current || !returnTo.current) return;
    returnTo.current = false;
    box.current.scrollLeft = Math.max(0, sel.col * colW - vp.vw / 2);
    const y = yOf.get(rk(sel.target, sel.targetIid));
    if (y != null && (y < vp.st || y > vp.st + vp.vh)) box.current.scrollTop = Math.max(0, y - vp.vh / 2);
  });
  const firstCol = items[0]?.col, lastCol = items[items.length - 1]?.col;
  useEffect(() => {
    // Filtered/search view: bring the matched columns into view (AMP search shows the matched events, not empty space).
    const b = box.current;
    if (!b || sel || firstCol == null || items.length === model.items.length) return;
    if (firstCol * colW < b.scrollLeft || lastCol * colW > b.scrollLeft + vp.vw) b.scrollLeft = Math.max(0, firstCol * colW - 60);
  }, [firstCol, lastCol, items.length]); // eslint-disable-line

  const zoomRef = useRef({ colW, vp });
  zoomRef.current = { colW, vp };
  useEffect(() => {
    const b = box.current;
    const wheel = (e) => {
      const inHdr = e.clientY - b.getBoundingClientRect().top < HDR_H;
      if (!(e.ctrlKey || e.metaKey || e.altKey || inHdr)) return;
      e.preventDefault();
      const { colW: w } = zoomRef.current, px = e.clientX - b.getBoundingClientRect().left - LABEL_W;
      const nw = Math.min(48, Math.max(1.5, w * (e.deltaY < 0 ? 1.25 : 0.8))), c = (b.scrollLeft + px) / w;
      setColW(nw);
      requestAnimationFrame(() => { b.scrollLeft = c * nw - px; });
    };
    b.addEventListener("wheel", wheel, { passive: false });
    return () => b.removeEventListener("wheel", wheel);
  }, [setColW]);
  const downAt = useRef(null);
  const down = (e) => {
    downAt.current = { x: e.clientX, y: e.clientY };
    if (e.button !== 0 || e.target.closest("[data-mk]")) return;
    const b = box.current, s = { x: e.clientX, y: e.clientY, sl: b.scrollLeft, st: b.scrollTop };
    b.style.cursor = "grabbing";
    const mv = (ev) => { b.scrollLeft = s.sl - (ev.clientX - s.x); b.scrollTop = s.st - (ev.clientY - s.y); };
    const up = () => { b.style.cursor = ""; window.removeEventListener("mousemove", mv); window.removeEventListener("mouseup", up); };
    window.addEventListener("mousemove", mv); window.addEventListener("mouseup", up);
  };
  const nearest = (e) => {
    const rc = e.currentTarget.getBoundingClientRect(), c = (e.clientX - rc.left) / colW, y = e.clientY - rc.top;
    const dist = (it) => Math.abs(it.col + 0.5 - c) * colW + Math.abs((yOf.get(rk(it.target, it.targetIid)) ?? 1e9) - y);
    const it = vis.reduce((b, x) => (!b || dist(x) < dist(b) ? x : b), null);
    return it && { it, d: dist(it) };
  };
  const c0 = Math.max(0, Math.floor(vp.sl / colW) - 20), c1 = c0 + Math.ceil(vp.vw / colW) + 40;
  const r0 = Math.max(0, Math.floor(vp.st / ROW_H) - 4), r1 = r0 + Math.ceil(vp.vh / ROW_H) + 10;
  const vis = items.slice(lower(items, c0), lower(items, c1 + 1));
  const vlines = lines.slice(r0, r1);
  const small = colW < 10;
  const selOff = sel && (sel.col * colW < vp.sl || sel.col * colW > vp.sl + vp.vw);
  const secIdx = (() => { let s = 0; for (let i = 0; i <= Math.min(lines.length - 1, Math.floor(vp.st / ROW_H)); i++) if (lines[i].hdr) s = i; return s; })();
  const leads = [], last = new Map();
  for (const it of vis) {
    const k = `${rk(it.target, it.targetIid)}|${it.kind.glyph}`, p = last.get(k);
    if (p != null && it.col - p <= 6 && it.col - p > 1) leads.push([p, it.col, rk(it.target, it.targetIid)]);
    last.set(k, it.col);
  }
  const groups = new Map();
  if (small) for (const it of vis) { const k = `${rk(it.target, it.targetIid)}|${Math.floor((it.col * colW) / 14)}`; if (!groups.has(k)) groups.set(k, []); groups.get(k).push(it); }
  const marks = small ? [...groups.values()].map((g) => ({ it: g[0], n: g.length })) : vis.map((it) => ({ it, n: 1 }));
  const hdrLabels = [];
  let lastLbl = -1e9;
  vis.forEach((it) => {
    const i = lower(items, it.col), prev = items[i - 1], d = it.ev.timestamp_instant_ms;
    const newDay = !prev || day(prev.ev.timestamp_instant_ms) !== day(d);
    const newMin = !prev || Math.floor(prev.ev.timestamp_instant_ms / 60000) !== Math.floor(d / 60000);
    if (newDay) hdrLabels.push({ kind: "day", col: it.col, d });
    if (newMin && x(it.col) - lastLbl >= 15) { hdrLabels.push({ kind: "min", col: it.col, d }); lastLbl = x(it.col); }
  });
  const instLines = [];
  for (const l of vlines) {
    if (l.hdr) continue;
    const insts = l.inst ? [l.inst] : expanded.has(l.row.key) ? [] : [...l.row.instances.values()];
    for (const n of insts) if (n.to >= c0 && n.from <= c1) instLines.push({ l, n, glow: sel && [sel.targetIid, sel.actorIid].includes(n.iid) });
  }
  return (
    <div data-testid="v3-grid" data-colw={colW.toFixed(2)} ref={box} className="v3-scroll" onScroll={sync} onMouseDown={down}
      style={{ overflow: "auto", height, position: "relative", background: C.page, userSelect: "none" }}>
      <div style={{ width: LABEL_W + W, height: HDR_H + H, position: "relative" }}>
        <div style={{ position: "sticky", top: 0, zIndex: 6, display: "flex", width: LABEL_W + W, height: HDR_H, background: C.panel, borderBottom: `1px solid ${C.line}` }}>
          <div style={{ position: "sticky", left: 0, zIndex: 7, width: LABEL_W, flex: "none", background: C.panel, borderRight: `1px solid ${C.line}`,
            display: "flex", flexDirection: "column", alignItems: "flex-end", justifyContent: "flex-end", padding: "0 12px 8px", boxSizing: "border-box" }}>
            {selOff && <button className="v3-link" data-testid="v3-return-to-activity" onClick={() => { returnTo.current = true; sync(); }} style={{ fontSize: 13, marginBottom: 8 }}>↩ Return to activity</button>}
            <span style={{ fontSize: 18, fontWeight: 600, color: C.text }}>Timeline</span>
          </div>
          <svg data-testid="v3-time-header" width={W} height={HDR_H} style={{ flex: "none" }}>
            {hdrLabels.map((h, i) => h.kind === "day"
              ? <g key={i}><line x1={h.col * colW} x2={h.col * colW} y1={0} y2={HDR_H} stroke={C.muted} />
                <text data-testid={`v3-day-${day(h.d)}`} x={h.col * colW + 5} y={17} fill={C.text} fontSize={14} fontWeight={600}>
                  {new Date(h.d).toLocaleString("en-US", { month: "short", day: "numeric", timeZone: "UTC" })}</text></g>
              : <text key={i} x={x(h.col) + 4} y={HDR_H - 5} fill={C.label} fontSize={12} transform={`rotate(-90 ${x(h.col) + 4} ${HDR_H - 5})`}>{new Date(h.d).toISOString().slice(11, 16)}</text>)}
            {model.ticks.filter((t) => t.col >= c0 && t.col <= c1).map((t) => <text key={`t${t.col}`} data-testid="v3-gap-tick" x={x(t.col) + 4} y={HDR_H - 5} fill={C.muted}
              fontSize={11} fontStyle="italic" transform={`rotate(-90 ${x(t.col) + 4} ${HDR_H - 5})`}>{new Date(t.ms).toISOString().slice(11, 16)}</text>)}
          </svg>
        </div>
        {lines[secIdx]?.hdr && <div data-testid="v3-sticky-section" style={{ position: "sticky", top: HDR_H, left: 0, zIndex: 5, height: ROW_H, marginBottom: -ROW_H, width: LABEL_W + vp.vw,
          background: C.band, display: "flex", alignItems: "center", pointerEvents: "none" }}>
          <span style={{ width: LABEL_W, textAlign: "right", padding: "0 12px", boxSizing: "border-box", fontWeight: 600, fontSize: 18, color: "#fff" }}>{lines[secIdx].hdr}</span></div>}
        <div style={{ display: "flex" }}>
          <div style={{ position: "sticky", left: 0, zIndex: 4, width: LABEL_W, height: H, flex: "none", background: C.panel, borderRight: `1px solid ${C.line}` }}>
            {vlines.map((l, i) => <Label key={l.key} l={l} y={(r0 + i) * ROW_H} sel={sel} hover={hover} hits={hits} expanded={expanded} toggle={toggle} onRowClick={onRowClick}
              onRowCtx={(e, r) => { const it = [...items].reverse().find((x) => x.target?.key === r.key || x.actor?.key === r.key); if (it) onContext(e, it); }} />)}
          </div>
          <svg data-testid="v3-grid-body" width={W} height={H} style={{ display: "block", flex: "none" }} onContextMenu={(e) => {
            e.preventDefault();
            const near = nearest(e);
            if (near) onContext(e, near.it);
          }} onClick={(e) => {
            const d0 = downAt.current;
            if (e.target.closest("[data-mk]") || (d0 && Math.hypot(e.clientX - d0.x, e.clientY - d0.y) > 4)) return;
            const near = nearest(e);
            if (near && near.d <= 14) onSelect(near.it);
          }}>
            <defs>
              <pattern id="v3h" width="7" height="7" patternUnits="userSpaceOnUse" patternTransform="rotate(45)"><rect width="1.6" height="7" fill={C.hatch} /></pattern>
              <filter id="v3glow" x="-50%" y="-50%" width="200%" height="200%"><feGaussianBlur stdDeviation="2.2" result="b" /><feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge></filter>
            </defs>
            {vlines.map((l, i) => l.hdr ? <rect key={l.key} y={(r0 + i) * ROW_H} width={W} height={ROW_H} fill={C.band} />
              : <line key={l.key} x1={0} x2={W} y1={(r0 + i + 1) * ROW_H} y2={(r0 + i + 1) * ROW_H} stroke={C.line} strokeWidth={0.5} opacity={0.5} />)}
            {vlines.filter((l) => l.hdr).map((l) => <text key={`t${l.key}`} x={Math.max(8, vp.sl + 8)} y={yOf.get(l.key) + 5} fill={C.muted} fontSize={11}> </text>)}
            {sel?.target && yOf.has(rk(sel.target, sel.targetIid)) && <rect y={yOf.get(rk(sel.target, sel.targetIid)) - ROW_H / 2} width={W} height={ROW_H} fill={C.sel} />}
            {hover && hover.col != null && hover.col !== sel?.col && <rect x={hover.col * colW} width={colW} height={H} fill="rgba(110,160,255,.06)" />}
            {sel && <rect data-testid="v3-selected-column" x={sel.col * colW} width={colW} height={H} fill="rgba(110,160,255,.11)" />}
            {model.ticks.filter((t) => t.col >= c0 && t.col <= c1).map((t) => <line key={`g${t.col}`} x1={x(t.col)} x2={x(t.col)} y1={0} y2={H} stroke={C.line} strokeDasharray="2 4" />)}
            <rect x={model.ncol * colW} width={W - model.ncol * colW} height={H} fill="url(#v3h)" data-testid="v3-future-hatch"><title>After the last evidence / now</title></rect>
            {instLines.map(({ l, n, glow }) => {
              const y = yOf.get(l.key), x1 = x(n.from), x2 = x(n.to) + colW / 2;
              return (<g key={`${l.key}${n.iid}`}>
                {glow && <rect x={x1 - 4} y={y - 6} width={x2 - x1 + 8} height={12} rx={6} fill="rgba(110,160,255,.28)" filter="url(#v3glow)" data-testid="v3-lifeline-glow" />}
                <line data-testid="v3-lifeline" x1={x1} x2={x2} y1={y} y2={y} stroke={glow ? C.accent : C.life} strokeWidth={glow ? 2.4 : 1.6} />
                <line x1={x1} x2={x2} y1={y} y2={y} stroke="transparent" strokeWidth={10} data-mk="1"
                  onMouseEnter={(e) => setHover({ t: l.row.key, x: e.clientX, y: e.clientY, text: `${l.row.label} · pid ${n.pid || "?"} · process instance ${n.iid}` })}
                  onMouseLeave={() => setHover(null)} onContextMenu={(e) => { e.preventDefault(); e.stopPropagation();
                    const it = vis.find((x) => [x.actorIid, x.targetIid].includes(n.iid)); if (it) onContext(e, it); }} />
              </g>);
            })}
            {leads.map(([a, b, key], i) => <line key={`l${i}`} x1={x(a) + 7} x2={x(b) - 7} y1={yOf.get(key)} y2={yOf.get(key)} stroke={C.muted} strokeDasharray="1.5 3" />)}
            {!small && vis.map((it) => {
              const ty = yOf.get(rk(it.target, it.targetIid));
              if (ty == null) return null;
              const on = sel?.col === it.col || hover?.col === it.col;
              if (!it.actor) return <g key={`c${it.col}`} data-testid={`v3-connector-${it.col}`} data-causal="UNRESOLVED">
                <line x1={x(it.col)} x2={x(it.col)} y1={ty - 20} y2={ty - 8} stroke={C.muted} strokeDasharray="1.5 2.5" />
                <text x={x(it.col) - 3.5} y={ty - 21} fill={C.amber} fontSize={10} fontWeight={700}>?</text></g>;
              const ay = yOf.get(rk(it.actor, it.actorIid));
              if (ay == null || it.actor === it.target && ay === ty) return null;
              const dir = ty > ay ? 1 : -1, end = ty - dir * 8;
              return (<g key={`c${it.col}`} data-testid={`v3-connector-${it.col}`} data-causal={it.causal}>
                <line x1={x(it.col)} x2={x(it.col)} y1={ay} y2={end} stroke={on ? C.accent : C.life} strokeWidth={on ? 2 : 1.2}
                  strokeDasharray={it.causal === "CORRELATED" ? "4 3" : undefined} />
                <path d={`M${x(it.col) - 3},${end - dir * 4} L${x(it.col)},${end} L${x(it.col) + 3},${end - dir * 4}`} fill="none" stroke={on ? C.accent : C.life} strokeWidth={1.2} />
                <circle cx={x(it.col)} cy={ay} r={2.2} fill={on ? C.accent : C.life} />
              </g>);
            })}
            {marks.map(({ it, n }) => {
              const ty = yOf.get(rk(it.target, it.targetIid));
              if (ty == null) return null;
              return (<g key={`m${it.col}`} data-mk="1" data-testid={`v3-marker-${it.col}`} data-shape={it.shape} data-glyph={it.kind.glyph} data-detection={it.ev.e3_detection ? "1" : "0"}
                data-event-iid={it.ev.event_iid} data-selected={sel?.col === it.col ? "1" : "0"} transform={`translate(${x(it.col)},${ty})`} style={{ cursor: "pointer" }}
                onClick={() => onSelect(it)} onContextMenu={(e) => { e.preventDefault(); e.stopPropagation(); onContext(e, it); }}
                onMouseEnter={(e) => setHover({ a: it.actor?.key, t: it.target?.key, col: it.col, x: e.clientX, y: e.clientY, it })} onMouseLeave={() => setHover(null)}>
                <g data-testid="dt-marker"><Mark it={it} selected={sel?.col === it.col} small={small} /></g>
                {n > 1 && <text data-testid="v3-cluster" x={5} y={-5} fill={C.text} fontSize={9.5}>{n}</text>}
              </g>);
            })}
          </svg>
        </div>
      </div>
    </div>
  );
}
