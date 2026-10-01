/**
 * Round 46 · Analyst Intelligence Overlay — inline editor.
 *
 * Owner rule: editing the NARRATIVE, never the underlying evidence.
 * Machine value is always shown alongside the analyst interpretation
 * — never replaced or hidden.
 *
 * Props:
 *   incidentId, targetKind, targetId, fieldKey
 *   machineValue        · verbatim engine output
 *   overlay             · optional overlay envelope from the API
 *   onChange(overlay?)  · called after PUT / DELETE
 *   label               · e.g. "Analyst Interpretation"
 *   readOnlyReason      · if set, disables edit (e.g. permission)
 */
import React, { useState } from "react";
import { Pencil, RotateCcw, X, Save, AlertTriangle,
                Loader2, History } from "lucide-react";
import api from "@/lib/api";


function EffectiveBadge({ overlay, machineValue }) {
  if (!overlay || overlay.analyst_value == null) {
    return <span data-testid="ovr-badge-machine"
                          style={badgeStyle("#1e40af")}>NIVXRAY GENERATED</span>;
  }
  // Drift detection: the stored machine_value snapshot on the
  // overlay differs from what the tab is showing now.  The
  // server-side hash is the governance authority; on the client
  // we compare literal strings — good enough for the UI signal.
  const drift = overlay.machine_value !== undefined
                    && overlay.machine_value !== null
                    && overlay.machine_value !== (machineValue || "");
  if (drift) {
    return (
      <span data-testid="ovr-badge-drift" style={badgeStyle("#b45309")}>
        <AlertTriangle size={9} style={{ marginRight: 3 }} />
        MACHINE SOURCE UPDATED · v{overlay.version}
      </span>
    );
  }
  return (
    <span data-testid="ovr-badge-analyst" style={badgeStyle("#78350f")}>
      ANALYST EDITED · v{overlay.version}
    </span>
  );
}


/* Kept for future crypto integration if we ever ship WebCrypto in
   the client.  Today the badge relies on a literal machine_value
   comparison against the snapshot the server persisted. */
function sha256Hint(_s) { return null; }


export default function IntelligenceOverlayEditor({
  incidentId, targetKind, targetId, fieldKey,
  machineValue, overlay, onChange,
  label = "Analyst Interpretation",
  readOnlyReason,
}) {
  const [editing, setEditing]   = useState(false);
  const [draft, setDraft]       = useState("");
  const [reason, setReason]     = useState("");
  const [busy, setBusy]         = useState(false);
  const [err, setErr]           = useState(null);
  const [showHist, setShowHist] = useState(false);
  const [history, setHistory]   = useState(null);

  const effective = overlay?.analyst_value ?? machineValue;
  const hasOverlay = !!overlay && overlay.analyst_value != null;
  const version = overlay?.version || 0;

  const openEdit = () => {
    setDraft(effective || "");
    setReason("");
    setErr(null);
    setEditing(true);
  };

  const save = async () => {
    setBusy(true); setErr(null);
    try {
      const { data } = await api.put(
        `/incidents/${incidentId}/intelligence/overlays/${targetKind}/`
        + `${encodeURIComponent(targetId)}/${fieldKey}`,
        { analyst_value: draft, machine_value: machineValue || "",
           reason: reason, expected_version: version || null });
      setEditing(false);
      onChange && onChange(data.overlay);
    } catch (e) {
      const d = e?.response?.data?.detail;
      setErr(typeof d === "string" ? d
                : d?.message || e?.message || "Save failed");
    } finally { setBusy(false); }
  };

  const revert = async () => {
    if (!hasOverlay) return;
    const r = window.prompt(
      "Reason for reverting to machine value?\n"
      + "(Required — recorded in the audit trail.)");
    if (!r || !r.trim()) return;
    setBusy(true); setErr(null);
    try {
      const { data } = await api.delete(
        `/incidents/${incidentId}/intelligence/overlays/${targetKind}/`
        + `${encodeURIComponent(targetId)}/${fieldKey}`,
        { data: { machine_value: machineValue || "", reason: r,
                       expected_version: version } });
      onChange && onChange(data.overlay);
    } catch (e) {
      const d = e?.response?.data?.detail;
      setErr(typeof d === "string" ? d
                : d?.message || e?.message || "Revert failed");
    } finally { setBusy(false); }
  };

  const loadHistory = async () => {
    if (history) { setShowHist((v) => !v); return; }
    setBusy(true);
    try {
      const { data } = await api.get(
        `/incidents/${incidentId}/intelligence/overlays/${targetKind}/`
        + `${encodeURIComponent(targetId)}/${fieldKey}/history`);
      setHistory(data.entries || []);
      setShowHist(true);
    } catch (e) {
      setErr(e?.message || "History unavailable");
    } finally { setBusy(false); }
  };

  return (
    <div data-testid={`ovr-editor-${targetKind}-${targetId}-${fieldKey}`}
          style={{
            marginTop: 8, border: "1px solid #e2e8f0", borderRadius: 4,
            background: hasOverlay ? "#fffbeb" : "#f8fafc",
          }}>
      <div style={{ padding: "6px 10px", display: "flex",
                       alignItems: "center", gap: 8,
                       borderBottom: "1px solid #e2e8f0",
                       background: "#fff" }}>
        <b style={{ fontSize: 10, letterSpacing: 0.4,
                        textTransform: "uppercase",
                        color: "#7c3aed" }}>{label}</b>
        <EffectiveBadge overlay={overlay} machineValue={machineValue} />
        <span style={{ flex: 1 }} />
        {!editing && !readOnlyReason && (
          <button data-testid={`ovr-edit-${targetKind}-${targetId}-${fieldKey}`}
                       onClick={openEdit}
                       style={btn}
                       title="Edit the analyst interpretation">
            <Pencil size={11} /> Edit
          </button>
        )}
        {hasOverlay && !editing && (
          <button data-testid={`ovr-revert-${targetKind}-${targetId}-${fieldKey}`}
                       onClick={revert} disabled={busy}
                       style={btn}
                       title="Revert to the NivXRay machine value (audited)">
            <RotateCcw size={11} /> Revert
          </button>
        )}
        <button data-testid={`ovr-history-${targetKind}-${targetId}-${fieldKey}`}
                     onClick={loadHistory} disabled={busy}
                     style={btn}>
          <History size={11} /> History
        </button>
      </div>

      {!editing && (
        <div style={{ padding: "8px 10px", color: "#0f172a",
                         fontSize: 12, lineHeight: 1.5 }}>
          {effective || (
            <i style={{ color: "#94a3b8" }}>
              (no interpretation yet — NivXRay machine value shown below)
            </i>
          )}
          {hasOverlay && (
            <div style={{ marginTop: 8, paddingTop: 6,
                             borderTop: "1px dashed #e2e8f0",
                             fontSize: 10, color: "#64748b" }}>
              <div><b>NivXRay machine value:</b> {machineValue || <i>(empty)</i>}</div>
              <div style={{ marginTop: 4 }}>
                edited by <b>{overlay.author_email}</b> ·
                {" "}reason: <i>{overlay.reason}</i>
              </div>
            </div>
          )}
        </div>
      )}

      {editing && (
        <div style={{ padding: "8px 10px" }}>
          <textarea
            data-testid={`ovr-textarea-${targetKind}-${targetId}-${fieldKey}`}
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            rows={4}
            style={{ width: "100%", fontSize: 12, padding: 6,
                          border: "1px solid #cbd5e1", borderRadius: 3 }}
          />
          <input
            data-testid={`ovr-reason-${targetKind}-${targetId}-${fieldKey}`}
            placeholder="Reason for change (required — recorded in audit)"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            style={{ width: "100%", fontSize: 11, padding: 6,
                          marginTop: 6, border: "1px solid #cbd5e1",
                          borderRadius: 3 }}
          />
          <div style={{ marginTop: 6, fontSize: 10, color: "#64748b" }}>
            <b>NivXRay machine value (immutable):</b> {machineValue || <i>(empty)</i>}
          </div>
          <div style={{ display: "flex", gap: 6, marginTop: 8 }}>
            <button data-testid={`ovr-save-${targetKind}-${targetId}-${fieldKey}`}
                         onClick={save}
                         disabled={busy || !draft.trim() || !reason.trim()}
                         style={{ ...btn, background: "#7c3aed",
                                     color: "#fff", borderColor: "#7c3aed" }}>
              {busy ? <Loader2 className="rl-spin" size={11} /> : <Save size={11} />}
              Save v{version + 1}
            </button>
            <button onClick={() => setEditing(false)}
                         disabled={busy} style={btn}>
              <X size={11} /> Cancel
            </button>
          </div>
        </div>
      )}

      {err && (
        <div style={{ padding: "6px 10px",
                         background: "#fee2e2", color: "#7f1d1d",
                         fontSize: 11 }}>
          <AlertTriangle size={11} style={{ marginRight: 4,
                                                            verticalAlign: -2 }} />
          {err}
        </div>
      )}

      {showHist && history && (
        <div data-testid={`ovr-history-panel-${targetKind}-${targetId}-${fieldKey}`}
              style={{ padding: "6px 10px",
                          background: "#f1f5f9",
                          borderTop: "1px solid #e2e8f0",
                          fontSize: 10, color: "#334155" }}>
          <b>Audit trail</b>
          {history.length === 0 && <div style={{ opacity: 0.6 }}>No entries.</div>}
          {history.map((e) => (
            <div key={e.version}
                  style={{ paddingTop: 4, marginTop: 4,
                              borderTop: "1px dashed #cbd5e1" }}>
              <b>v{e.version}</b> · {e.action} · {e.author_email} · {e.at}
              <div style={{ opacity: 0.8 }}>reason: {e.reason}</div>
              {e.previous_value != null && (
                <div>prev: <i>{e.previous_value}</i></div>
              )}
              {e.new_value != null && (
                <div>new: <i>{e.new_value}</i></div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}


const btn = {
  display: "inline-flex", alignItems: "center", gap: 4,
  background: "#fff", color: "#0f172a",
  border: "1px solid #cbd5e1", borderRadius: 3,
  padding: "3px 8px", fontSize: 10, fontWeight: 600,
  cursor: "pointer", letterSpacing: 0.3,
  textTransform: "uppercase",
};

function badgeStyle(color) {
  return {
    display: "inline-flex", alignItems: "center", gap: 3,
    background: color, color: "#fff",
    padding: "2px 6px", borderRadius: 3,
    fontSize: 8.5, fontWeight: 700, letterSpacing: 0.5,
    textTransform: "uppercase",
  };
}
