import React, { useState } from "react";
import { C } from "./theme";

export const APPROVALS = [["ADD_HASH_TO_BLOCKLIST", "Add hash to block list"], ["BLOCK_APPLICATION", "Block application"],
  ["QUARANTINE_FILE", "Quarantine file"], ["ISOLATE_DEVICE", "Start Isolation"], ["STOP_ISOLATION", "Stop Isolation"],
  ["RUN_SCAN", "Scan"], ["FORENSIC_SNAPSHOT", "Take Forensic Snapshot"], ["DIAGNOSE_SENSOR", "Diagnose Sensor"], ["MOVE_TO_GROUP", "Move to Group"]];
const label = (a) => APPROVALS.find(([k]) => k === a)?.[1];

// AMP device Actions: pivots open another page (›); mutating actions only ever record APPROVAL_REQUESTED.
export const DEVICE_PIVOTS = [["events", "Events"], ["process-tree", "Process Tree"], ["campaign-story", "Campaign Story"], ["live-query", "Live Query"], ["view-changes", "View Changes"]];
const DEVICE_MUTATING = (isolated) => ["FORENSIC_SNAPSHOT", isolated ? "STOP_ISOLATION" : "ISOLATE_DEVICE", "RUN_SCAN", "DIAGNOSE_SENSOR", "MOVE_TO_GROUP"];

const DT = { "copy-hash": "dt-ctx-copy-hash", "isolate-lineage": "dt-ctx-isolate-lineage", QUARANTINE_FILE: "dt-ctx-quarantine" };
const Item = ({ id, label: l, onClick, disabled, sub, note }) => (
  <div data-testid={`v3-ctx-${id}`} onClick={disabled ? undefined : onClick} style={{ padding: "7px 16px", cursor: disabled ? "default" : "pointer", display: "flex", alignItems: "center", gap: 8,
    color: disabled ? C.muted : C.text, transition: "background-color .1s" }}
    onMouseEnter={(e) => { if (!disabled) e.currentTarget.style.background = "rgba(110,160,255,.14)"; }} onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}>
    <span style={{ flex: 1 }}>{DT[id] ? <span data-testid={DT[id]}>{l}</span> : l}</span>
    {note && <span style={{ color: C.amber, fontSize: 11 }}>{note}</span>}
    {sub && <span aria-hidden style={{ color: C.muted, fontSize: 15 }}>›</span>}</div>
);
const Sect = ({ children }) => <div style={{ padding: "6px 16px 2px", color: C.muted, fontSize: 11, letterSpacing: ".06em", borderTop: `1px solid ${C.line}`, marginTop: 4 }}>{children}</div>;

function DeviceItems({ menu, onAction }) {
  const pending = menu.pending || {};
  return <>
    {DEVICE_PIVOTS.map(([k, l]) => <Item key={k} id={`dev-${k}`} label={l} sub onClick={() => onAction("pivot", l)} />)}
    <Item id="copy-device" label="Copy device id" onClick={() => onAction("copy-path", menu.device)} />
    <Sect>APPROVAL REQUEST ONLY</Sect>
    {DEVICE_MUTATING(menu.isolated).map((a) => <Item key={a} id={a} label={`${label(a)}…`} note={pending[a] ? "Approval requested" : null} onClick={() => onAction("approve", a)} />)}
  </>;
}

export function ContextMenu({ menu, onAction }) {
  const it = menu.it, hash = it?.target?.hash || it?.ev?.file_sha256;
  return (
    <div data-testid="v3-context-menu" onClick={(e) => e.stopPropagation()} style={{ position: "fixed", left: Math.max(8, Math.min(menu.x, window.innerWidth - 280)),
      top: Math.max(8, Math.min(menu.y, window.innerHeight - 400)), zIndex: 60, background: C.tip,
      border: `1px solid ${C.line}`, borderRadius: 8, padding: "6px 0", minWidth: 260, fontSize: 13.5, boxShadow: "0 14px 40px rgba(0,0,0,.55)", animation: "v3in .1s ease-out" }}>
      <div data-testid={menu.deviceOnly ? "dt-device-actions-menu" : "dt-context-menu"}>
      {menu.deviceOnly ? <DeviceItems menu={menu} onAction={onAction} /> : <>
        <Item id="copy-hash" label={hash ? "Copy hash" : "Copy hash (not collected)"} disabled={!hash} onClick={() => onAction("copy-hash", hash)} />
        <Item id="copy-path" label="Copy path" disabled={!it?.target?.path} onClick={() => onAction("copy-path", it.target.path)} />
        <Item id="search" label="Search trajectory" onClick={() => onAction("search", it?.target?.label)} />
        <Item id="isolate-lineage" label="Isolate lineage" onClick={() => onAction("isolate", it)} />
        <Item id="file-trajectory" label="Open File Trajectory (not yet built)" sub onClick={() => onAction("nyb", "File Trajectory")} />
        <Item id="file-analysis" label="File Analysis (not yet built)" sub onClick={() => onAction("nyb", "File Analysis")} />
        <Sect>APPROVAL REQUEST ONLY</Sect>
        {APPROVALS.slice(0, 4).map(([a, l]) => <Item key={a} id={a} label={`${a === "ISOLATE_DEVICE" ? "Isolate device" : l}…`} onClick={() => onAction("approve", a)} />)}
      </>}
      </div>
    </div>
  );
}

export function ApprovalDialog({ req, onCancel, onConfirm }) {
  const [group, setGroup] = useState("");
  const needsGroup = req.action === "MOVE_TO_GROUP";
  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 80, background: "rgba(0,0,0,.55)", display: "flex", alignItems: "center", justifyContent: "center" }} onClick={onCancel}>
      <div data-testid="v3-approval-dialog" onClick={(e) => e.stopPropagation()} style={{ width: 460, background: C.panel, border: `1px solid ${C.line}`, borderRadius: 10,
        padding: 22, color: C.text, boxShadow: "0 20px 60px rgba(0,0,0,.6)", animation: "v3in .15s ease-out" }}>
        <div data-testid="dt-approval-dialog" style={{ fontSize: 18, fontWeight: 600, marginBottom: 10 }}>Request approval: {label(req.action)}</div>
        <div style={{ fontSize: 13.5, color: C.label, lineHeight: 1.6 }}>Target: <b data-testid="v3-approval-target">{req.target}</b><br />
          This records an approval <b>request</b> only. Nothing is executed from this page. Execution is owned by the response plane, and
          REQUESTED ≠ EXECUTED ≠ VERIFIED.</div>
        {needsGroup && <input data-testid="v3-approval-group" value={group} onChange={(e) => setGroup(e.target.value)} placeholder="Destination group"
          style={{ marginTop: 12, width: "100%", boxSizing: "border-box", background: C.page, border: `1px solid ${C.line}`, borderRadius: 4, color: C.text, padding: "7px 10px", fontSize: 13.5 }} />}
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 16, marginTop: 20, alignItems: "center" }}>
          <button className="v3-link" data-testid="v3-approval-cancel" onClick={onCancel}>Cancel</button>
          <button className="v3-btn v3-btn-blue" data-testid="v3-approval-confirm" disabled={needsGroup && !group.trim()} onClick={() => onConfirm(needsGroup ? { group: group.trim() } : {})}>Request approval</button>
        </div>
      </div>
    </div>
  );
}
