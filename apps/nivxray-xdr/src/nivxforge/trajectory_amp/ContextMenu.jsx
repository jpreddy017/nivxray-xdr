import React, { useState } from "react";
import { PAL, approvalText } from "./model";
import { ui } from "./ui";

export const ACTIONS = [
  { action: "BLOCK_APPLICATION", label: "Block application", testid: "ctx-block-application", needs: (t) => t.image || t.sha256 },
  { action: "ADD_HASH_TO_BLOCKLIST", label: "Add hash to block list", testid: "ctx-add-hash-blocklist", needs: (t) => t.sha256 },
  { action: "QUARANTINE_FILE", label: "Quarantine file", testid: "ctx-quarantine-file", needs: (t) => t.path || t.image },
  { action: "ISOLATE_DEVICE", label: "Isolate device", testid: "ctx-isolate-device", needs: (t) => t.device_id },
];
const PIVOTS = [
  { kind: "COPY_HASH", label: "Copy hash", testid: "ctx-copy-hash", needs: (t) => t.sha256 },
  { kind: "SEARCH_HASH", label: "Search hash", testid: "ctx-search-hash", needs: (t) => t.sha256 },
  { kind: "SEARCH_FILENAME", label: "Search name", testid: "ctx-search-name", needs: (t) => t.name },
  { kind: "OPEN_FILE_TRAJECTORY", label: "Open File Trajectory (not yet built)", testid: "ctx-open-file-trajectory", needs: (t) => t.sha256 || t.name },
];

const item = (on) => ({ display: "block", width: "100%", textAlign: "left", background: "transparent", border: 0, padding: "6px 12px",
  color: on ? PAL.text : PAL.faint, fontSize: 12.5, cursor: on ? "pointer" : "not-allowed" });

export function ContextMenu({ menu, onPivot, onAction }) {
  const t = menu.target;
  return (
    <div data-testid="context-menu" onClick={(e) => e.stopPropagation()} onContextMenu={(e) => e.preventDefault()}
      style={{ position: "fixed", left: menu.x, top: menu.y, zIndex: 50, minWidth: 250, ...ui.panel, background: PAL.panelAlt, padding: "4px 0", boxShadow: "0 12px 32px rgba(0,0,0,.5)" }}>
      <div style={{ padding: "4px 12px", fontSize: 10.5, color: PAL.muted, letterSpacing: 1 }}>READ-ONLY PIVOTS</div>
      {PIVOTS.map((p) => <button key={p.kind} data-testid={p.testid} disabled={!p.needs(t)} style={item(!!p.needs(t))} onClick={() => onPivot(p.kind)}>{p.label}{!p.needs(t) && " · no value in evidence"}</button>)}
      <div style={{ padding: "6px 12px 4px", fontSize: 10.5, color: PAL.muted, letterSpacing: 1, borderTop: `1px solid ${PAL.grid}` }}>RESPONSE · APPROVAL REQUEST ONLY</div>
      {ACTIONS.map((a) => <button key={a.action} data-testid={a.testid} disabled={!a.needs(t)} style={item(!!a.needs(t))} onClick={() => onAction(a.action)}>{a.label}…{!a.needs(t) && " · no target in evidence"}</button>)}
    </div>
  );
}

export function ApprovalDialog({ dialog, onConfirm, onClose }) {
  const [reason, setReason] = useState("");
  const a = ACTIONS.find((x) => x.action === dialog.action);
  const t = dialog.target;
  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(3,6,10,.66)", zIndex: 60, display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div data-testid="approval-dialog" role="dialog" style={{ ...ui.panel, background: PAL.panelAlt, width: 520, padding: 20 }}>
        <div style={{ fontSize: 16, fontWeight: 600, marginBottom: 8 }}>{a?.label}</div>
        <div style={{ fontSize: 12.5, color: PAL.muted, marginBottom: 12 }}>
          Target: <span style={ui.mono}>{t.sha256 || t.path || t.image || t.device_id}</span> on {t.device_id}
        </div>
        {dialog.phase === "confirm" && <>
          <div style={{ fontSize: 13, marginBottom: 10 }}>This records an <b>approval request</b> only. E3 sends nothing to the endpoint; execution is owned by E1.</div>
          <textarea data-testid="approval-reason" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Reason (audited)"
            style={{ ...ui.btn, width: "100%", height: 64, cursor: "text", background: PAL.bg, boxSizing: "border-box" }} />
          <div style={{ display: "flex", gap: 8, justifyContent: "flex-end", marginTop: 12 }}>
            <button data-testid="approval-cancel" style={ui.btn} onClick={onClose}>Cancel</button>
            <button data-testid="approval-confirm" style={{ ...ui.btn, ...ui.btnOn }} onClick={() => onConfirm(reason)}>Request approval</button>
          </div>
        </>}
        {dialog.phase === "pending" && <div style={{ fontSize: 13 }}>Recording request…</div>}
        {dialog.phase === "result" && <>
          <div data-testid="approval-result-text" style={{ fontSize: 14, color: "#BFF1FA", padding: "10px 12px", border: `1px solid ${PAL.accent}`, borderRadius: 4 }}>
            {dialog.error ? `Request not recorded: ${dialog.error}` : approvalText(dialog.result.request)}
          </div>
          {!dialog.error && <div data-testid="approval-result-meta" style={{ fontSize: 12, color: PAL.muted, marginTop: 8 }}>
            {dialog.result.created ? "New request" : "Already requested earlier (idempotent)"} · {dialog.result.request.request_id} · state {dialog.result.request.state}
          </div>}
          <div style={{ display: "flex", justifyContent: "flex-end", marginTop: 12 }}><button data-testid="approval-close" style={ui.btn} onClick={onClose}>Close</button></div>
        </>}
      </div>
    </div>
  );
}
