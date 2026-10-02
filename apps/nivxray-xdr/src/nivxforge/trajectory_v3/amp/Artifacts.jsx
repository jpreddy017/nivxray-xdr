import React, { useEffect, useState } from "react";
import api from "@/lib/api";
import { buildSections, imageSha, networkSummary } from "./fields";
import { short, TYPE_DESC } from "./model";
import { C } from "./theme";
import { wrapText } from "./Activity";

const Btn = ({ onClick, children, title, testid }) => (
  <button type="button" data-testid={testid} title={title} onClick={onClick} style={{ background: "none", border: 0, color: C.accent, cursor: "pointer", padding: "0 3px", fontSize: 12 }}>{children}</button>
);

function Row({ r, onCopy, onSearch, onJump }) {
  const [more, setMore] = useState(false);
  const v = r.truncate && !more && r.v.length > r.truncate ? `${r.v.slice(0, r.truncate)}…` : r.v;
  return (
    <div data-testid="dt-field-row" style={{ display: "grid", gridTemplateColumns: "118px minmax(0,1fr) auto", gap: 6, padding: "3px 0", fontSize: 12.5, borderBottom: `1px solid rgba(255,255,255,.04)` }}>
      <span style={{ color: C.muted }}>{r.k}</span>
      <span style={{ color: C.text, overflowWrap: "anywhere" }}>
        {r.link ? <a data-testid="dt-mitre-link" href={r.link} target="_blank" rel="noreferrer" style={{ color: C.accent }}>{v}</a>
          : r.hash ? <span title={r.v} style={{ fontFamily: "ui-monospace, Menlo, monospace" }}>{short(r.v)}<br /><span style={{ color: C.muted, fontSize: 11 }}>{wrapText(r.v)}</span></span>
            : r.search ? <span role="button" tabIndex={0} onClick={() => onSearch(r.v)} style={{ borderBottom: `1px dotted ${C.muted}`, cursor: "pointer" }}>{wrapText(v)}</span> : wrapText(v)}
        {r.truncate && r.v.length > r.truncate && <Btn onClick={() => setMore(!more)} testid="dt-field-expand">{more ? "less" : "more"}</Btn>}
      </span>
      <span style={{ whiteSpace: "nowrap" }}>
        {r.jump && <Btn testid="dt-field-jump" title="Jump to event" onClick={() => onJump(r.jump)}>↗</Btn>}
        <Btn testid="dt-field-copy" title="Copy" onClick={() => onCopy(r.v)}>⧉</Btn>
      </span>
    </div>
  );
}

export function Artifacts({ it, model, computer, device, approvals, onCopy, onSearch, onJump }) {
  const [facts, setFacts] = useState(null);
  const isExec = it.ev.event_type === "process_create", sha = isExec ? imageSha(it) : it.ev.file_sha256, path = it.target?.path;
  useEffect(() => {
    let live = true;
    setFacts(null);
    if (!sha && !path) return undefined;
    api.get(`/edr/endpoints/${encodeURIComponent(device)}/trajectory/file-facts`, { params: { sha256: sha || undefined, path: path || undefined } })
      .then(({ data }) => { if (live && data.state !== "NO_KEY") setFacts(data); }).catch(() => {});
    return () => { live = false; };
  }, [device, sha, path]);
  const secs = buildSections(it, { model, facts, computer, approvals, typeDesc: (t) => (t ? TYPE_DESC[t.type] || t.type : null) });
  const missing = secs.flatMap((s) => s.missing.map((m) => ({ ...m, sec: s.title })));
  return (
    <div data-testid="dt-artifacts" style={{ marginTop: 10 }}>
      {secs.filter((s) => s.rows.length).map((s) => (
        <details key={s.id} open={s.open} data-testid={`dt-sec-${s.id}`} style={{ marginBottom: 6 }}>
          <summary style={{ cursor: "pointer", fontWeight: 600, fontSize: 13.5, padding: "4px 0", color: C.text }}>{s.title}</summary>
          {s.rows.map((r, i) => <Row key={i} r={r} onCopy={onCopy} onSearch={onSearch} onJump={onJump} />)}
        </details>))}
      <details data-testid="dt-not-collected" style={{ marginBottom: 6 }}>
        <summary style={{ cursor: "pointer", fontWeight: 600, fontSize: 13.5, padding: "4px 0", color: C.muted }}>Not collected for this event ({missing.length})</summary>
        {missing.map((m, i) => <div key={i} data-testid="dt-not-collected-row" style={{ display: "grid", gridTemplateColumns: "118px minmax(0,1fr)", gap: 6, fontSize: 12, padding: "2px 0", color: C.muted }}>
          <span>{m.k}</span><span style={{ overflowWrap: "anywhere" }}>{m.reason} · {m.sec}</span></div>)}
      </details>
    </div>
  );
}

export function NetworkSummary({ model, onBack, onFilter, height }) {
  const s = networkSummary(model);
  let lastT = null, lastH = null;
  return (
    <div data-testid="dt-network-summary" className="v3-scroll" style={{ padding: "12px 16px", height, boxSizing: "border-box", overflowY: "auto", fontSize: 13 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
        <button data-testid="dt-network-summary-back" onClick={onBack} style={{ background: "none", border: 0, color: C.accent, fontSize: 22, cursor: "pointer", lineHeight: 1 }}>‹</button>
        <b>Network summary</b></div>
      <div data-testid="dt-net-totals" style={{ color: C.label, marginBottom: 8 }}>{s.total} connections · {s.unique} unique destinations (loaded window)</div>
      {s.rows.map((r, i) => {
        const showT = r.tld !== lastT, showH = r.host !== lastH || showT;
        lastT = r.tld; lastH = r.host;
        return (<div key={i}>
          {showT && <div style={{ fontWeight: 700, marginTop: 8, color: C.text }}>{r.tld}</div>}
          {showH && <div role="button" tabIndex={0} onClick={() => onFilter(r.host === "(no domain)" ? r.ip : r.host)} style={{ paddingLeft: 10, color: C.accent, cursor: "pointer" }}>{r.host}</div>}
          <div data-testid="dt-net-row" role="button" tabIndex={0} onClick={() => onFilter(r.ip)} style={{ paddingLeft: 22, display: "grid", gridTemplateColumns: "minmax(0,1fr) auto", cursor: "pointer", color: C.label }}>
            <span>{r.ip}</span><span style={{ color: C.muted, fontSize: 11.5 }}>{r.n}× · {new Date(r.first).toISOString().slice(11, 19)}–{new Date(r.last).toISOString().slice(11, 19)} · {Math.round((r.last - r.first) / 1000)}s</span></div>
        </div>);
      })}
    </div>
  );
}
