import { Maximize2, Share2 } from "lucide-react";
import React, { useState } from "react";
import { C } from "./theme";

const Pop = ({ children, testid, right }) => (
  <div data-testid={testid} onClick={(e) => e.stopPropagation()} style={{ position: "absolute", top: 44, [right ? "right" : "left"]: 0, zIndex: 50, background: C.tip,
    border: `1px solid ${C.line}`, borderRadius: 8, padding: "12px 16px", minWidth: 340, fontSize: 13, color: C.text, boxShadow: "0 14px 40px rgba(0,0,0,.55)", animation: "v3in .12s ease-out" }}>{children}</div>
);
const utc = (x) => { const ms = typeof x === "number" ? x : Date.parse(x || ""); return Number.isFinite(ms) ? `${new Date(ms).toISOString().replace("T", " ").slice(0, 19)} UTC` : null; };

// Isolation chip: sensor-reported state when present; a pending request is shown as REQUESTED, never as isolated.
function IsolationChip({ c, pending }) {
  const st = String((c.isolation && typeof c.isolation === "object" ? c.isolation.state : c.isolation) || c.isolation_status || "").toUpperCase();
  const [txt, col] = pending === "ISOLATE_DEVICE" ? ["Isolation approval requested", C.amber] : pending === "STOP_ISOLATION" ? ["Stop isolation approval requested", C.amber]
    : st === "ISOLATED" ? ["Isolated", C.red] : st === "PENDING_START" ? ["Isolation pending", C.amber] : st === "NOT_ISOLATED" ? ["Not isolated", C.muted] : ["Isolation not reported", C.muted];
  return <span data-testid="v3-isolation-chip" data-state={pending ? `REQUESTED_${pending}` : st || "NOT_REPORTED"} title="Isolation state as reported by the sensor; requests are approval-only"
    style={{ border: `1px solid ${col}`, color: col, borderRadius: 12, padding: "2px 10px", fontSize: 12, whiteSpace: "nowrap" }}>{txt}</span>;
}

const DetLinks = ({ dets, onJump, testid }) => dets.length ? dets.slice(0, 8).map((d, i) => (
  <div key={i} style={{ display: "flex", gap: 10, padding: "1px 0" }}>
    <button className="v3-link" data-testid={`${testid}-${i}`} style={{ fontSize: 12.5, whiteSpace: "nowrap" }} onClick={() => onJump(d)}>{utc(d.ms || d.at)}</button>
    <span style={{ color: C.red, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{d.name}</span></div>))
  : <span style={{ color: C.muted }}>No compromise events recorded.</span>;

export default function Header({ data, device, dets, onActions, onShare, onJump, pendingIso }) {
  const [pop, setPop] = useState(null);
  const c = data?.computer || {}, v = (x) => (x && typeof x === "object" ? x.state : x) || "not collected";
  const attn = dets.length > 0;
  const toggle = (k) => (e) => { e.stopPropagation(); setPop(pop === k ? null : k); };
  const jump = (d) => { setPop(null); onJump(d); };
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 14, marginBottom: 18, flexWrap: "wrap" }} onClick={() => setPop(null)}>
      <h1 data-testid="v3-hostname" style={{ margin: 0, fontSize: 34, fontWeight: 700, color: C.text, letterSpacing: "-.01em" }}>{c.hostname || device}</h1>
      <IsolationChip c={c} pending={pendingIso} />
      <div style={{ position: "relative" }}>
        <button className="v3-btn v3-btn-outline" data-testid="v3-show-details" onClick={toggle("details")}>Show details</button>
        {pop === "details" && <Pop testid="v3-details-pop">
          {[["Operating system", v(c.operating_system)], ["Sensor version", v(c.connector_version)], ["Device", c.device_iid || device], ["Endpoint", c.endpoint_id],
            ["Last telemetry", utc(c.last_telemetry_at)], ["Group", v(c.group)], ["Policy", v(c.policy)]].map(([k, val]) =>
            <div key={k} data-testid={`v3-details-row-${k.toLowerCase().replace(/ /g, "-")}`} style={{ display: "grid", gridTemplateColumns: "130px 1fr", padding: "2px 0" }}>
              <span style={{ color: C.muted }}>{k}</span><span>{val || "not collected"}</span></div>)}
          <div style={{ color: C.muted, margin: "10px 0 4px", borderTop: `1px solid ${C.line}`, paddingTop: 8 }}>Related compromise events · {dets.length}</div>
          <DetLinks dets={dets} onJump={jump} testid="v3-details-det" />
        </Pop>}
      </div>
      <button className="v3-btn v3-btn-blue" data-testid="v3-actions" onClick={(e) => { e.stopPropagation(); onActions(e); }}>Actions ▾</button>
      <span style={{ flex: 1 }} />
      <div style={{ position: "relative" }}>
        <button className="v3-btn" data-testid="v3-inbox-status" onClick={toggle("inbox")} style={{ border: 0, fontSize: 14 }}>
          <span style={{ color: C.muted }}>Inbox status: </span><b style={{ color: attn ? C.red : C.text }}>{attn ? "Requires attention" : "No open items"}</b> ▾</button>
        {pop === "inbox" && <Pop testid="v3-inbox-pop" right>
          <div style={{ color: C.muted, marginBottom: 6 }}>Mapped from NivXForge detections on this device (incident inbox is owned by XDR).</div>
          <DetLinks dets={dets} onJump={jump} testid="v3-inbox-det" />
        </Pop>}
      </div>
      <button className="v3-btn v3-sq" data-testid="v3-share" title="Copy deep link" onClick={onShare}><Share2 size={16} /></button>
      <button className="v3-btn v3-sq" data-testid="v3-fullscreen" title="Fullscreen" onClick={() => document.documentElement.requestFullscreen?.().catch(() => {})}><Maximize2 size={16} /></button>
    </div>
  );
}
