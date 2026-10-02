import React from "react";
import { C } from "./theme";

export const APPROVALS = [["ADD_HASH_TO_BLOCKLIST", "Add hash to block list"], ["BLOCK_APPLICATION", "Block application"],
  ["QUARANTINE_FILE", "Quarantine file"], ["ISOLATE_DEVICE", "Isolate device"]];

const Item = ({ id, label, onClick, disabled }) => (
  <div data-testid={`v3-ctx-${id}`} onClick={disabled ? undefined : onClick} style={{ padding: "7px 16px", cursor: disabled ? "default" : "pointer",
    color: disabled ? C.muted : C.text, transition: "background-color .1s" }}
    onMouseEnter={(e) => { if (!disabled) e.currentTarget.style.background = "rgba(110,160,255,.14)"; }} onMouseLeave={(e) => { e.currentTarget.style.background = "transparent"; }}>{label}</div>
);

export function ContextMenu({ menu, onAction }) {
  const it = menu.it, hash = it?.target?.hash || it?.ev?.file_sha256;
  return (
    <div data-testid="v3-context-menu" onClick={(e) => e.stopPropagation()} style={{ position: "fixed", left: Math.max(8, Math.min(menu.x, window.innerWidth - 280)),
      top: Math.max(8, Math.min(menu.y, window.innerHeight - (menu.deviceOnly ? 120 : 400))), zIndex: 60, background: C.tip,
      border: `1px solid ${C.line}`, borderRadius: 8, padding: "6px 0", minWidth: 260, fontSize: 13.5, boxShadow: "0 14px 40px rgba(0,0,0,.55)", animation: "v3in .1s ease-out" }}>
      {!menu.deviceOnly && <>
        <Item id="copy-hash" label={hash ? "Copy hash" : "Copy hash (not collected)"} disabled={!hash} onClick={() => onAction("copy-hash", hash)} />
        <Item id="copy-path" label="Copy path" disabled={!it?.target?.path} onClick={() => onAction("copy-path", it.target.path)} />
        <Item id="search" label="Search trajectory" onClick={() => onAction("search", it?.target?.label)} />
        <Item id="isolate-lineage" label="Isolate lineage" onClick={() => onAction("isolate", it)} />
        <Item id="file-trajectory" label="Open File Trajectory (not yet built)" onClick={() => onAction("nyb", "File Trajectory")} />
        <Item id="file-analysis" label="File Analysis (not yet built)" onClick={() => onAction("nyb", "File Analysis")} />
      </>}
      {menu.deviceOnly && <Item id="copy-device" label="Copy device id" onClick={() => onAction("copy-path", menu.device)} />}
      <div style={{ padding: "6px 16px 2px", color: C.muted, fontSize: 11, letterSpacing: ".06em", borderTop: `1px solid ${C.line}`, marginTop: 4 }}>APPROVAL REQUEST ONLY</div>
      {APPROVALS.filter(([a]) => !menu.deviceOnly || a === "ISOLATE_DEVICE").map(([a, l]) => <Item key={a} id={a} label={`${l}…`} onClick={() => onAction("approve", a)} />)}
    </div>
  );
}

export function ApprovalDialog({ req, onCancel, onConfirm }) {
  const label = APPROVALS.find(([a]) => a === req.action)?.[1];
  return (
    <div style={{ position: "fixed", inset: 0, zIndex: 80, background: "rgba(0,0,0,.55)", display: "flex", alignItems: "center", justifyContent: "center" }} onClick={onCancel}>
      <div data-testid="v3-approval-dialog" onClick={(e) => e.stopPropagation()} style={{ width: 460, background: C.panel, border: `1px solid ${C.line}`, borderRadius: 10,
        padding: 22, color: C.text, boxShadow: "0 20px 60px rgba(0,0,0,.6)", animation: "v3in .15s ease-out" }}>
        <div style={{ fontSize: 18, fontWeight: 600, marginBottom: 10 }}>Request approval: {label}</div>
        <div style={{ fontSize: 13.5, color: C.label, lineHeight: 1.6 }}>Target: <b>{req.target}</b><br />
          This records an approval <b>request</b> only. Nothing is executed from this page. Execution is owned by the response plane, and
          REQUESTED ≠ EXECUTED ≠ VERIFIED.</div>
        <div style={{ display: "flex", justifyContent: "flex-end", gap: 16, marginTop: 20, alignItems: "center" }}>
          <button className="v3-link" data-testid="v3-approval-cancel" onClick={onCancel}>Cancel</button>
          <button className="v3-btn v3-btn-blue" data-testid="v3-approval-confirm" onClick={onConfirm}>Request approval</button>
        </div>
      </div>
    </div>
  );
}
