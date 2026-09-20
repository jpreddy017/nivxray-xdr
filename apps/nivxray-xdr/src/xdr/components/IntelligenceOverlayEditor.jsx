/**
 * Round 46 · Analyst Intelligence Overlay — inline editor.
 *
 * Owner rule: editing the NARRATIVE, never the underlying evidence.
 * Machine value is always shown alongside the analyst interpretation
 * — never replaced or hidden.
 *
 * 2026-06 · contrast defect closed: the surface used to hard-code a light
 * paper palette while its text read the theme tokens, so in the default
 * dark console the paragraph, the section label and the Edit/History
 * controls were light-on-white. It now renders entirely through the
 * `nx-ovr` component classes and the `--nx-surf-note` token pair, which
 * `scripts/nx_contrast_audit.py` gates in both themes. No colour is
 * hard-coded here.
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
import { NxChip } from "@/xdr/nx";
import "@/xdr/nx/nx-form.css";


function EffectiveBadge({ overlay, machineValue }) {
  if (!overlay || overlay.analyst_value == null) {
    return <NxChip tone="low" size="sm" data-testid="ovr-badge-machine">
      NIVXRAY GENERATED
    </NxChip>;
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
      <NxChip tone="high" size="sm" data-testid="ovr-badge-drift">
        <AlertTriangle size={9} />
        MACHINE SOURCE UPDATED · v{overlay.version}
      </NxChip>
    );
  }
  return (
    <NxChip tone="purple" size="sm" data-testid="ovr-badge-analyst">
      ANALYST EDITED · v{overlay.version}
    </NxChip>
  );
}


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
          className={`nx-ovr${hasOverlay ? " nx-ovr--edited" : ""}`}>
      <div className="nx-ovr__head">
        <b className="nx-ovr__label">{label}</b>
        <EffectiveBadge overlay={overlay} machineValue={machineValue} />
        <span className="nx-ovr__spacer" />
        {!editing && !readOnlyReason && (
          <button data-testid={`ovr-edit-${targetKind}-${targetId}-${fieldKey}`}
                       data-ovr-action="edit"
                       onClick={openEdit}
                       className="nx-btn"
                       title="Edit the analyst interpretation">
            <Pencil size={11} /> Edit
          </button>
        )}
        {hasOverlay && !editing && (
          <button data-testid={`ovr-revert-${targetKind}-${targetId}-${fieldKey}`}
                       data-ovr-action="revert"
                       onClick={revert} disabled={busy}
                       className="nx-btn"
                       title="Revert to the NivXRay machine value (audited)">
            <RotateCcw size={11} /> Revert
          </button>
        )}
        <button data-testid={`ovr-history-${targetKind}-${targetId}-${fieldKey}`}
                       data-ovr-action="history"
                     onClick={loadHistory} disabled={busy}
                     className="nx-btn">
          <History size={11} /> History
        </button>
      </div>

      {!editing && (
        <div className="nx-ovr__body">
          {effective || (
            <i className="nx-ovr__absent">
              (no interpretation yet — NivXRay machine value shown below)
            </i>
          )}
          {hasOverlay && (
            <div className="nx-ovr__machine">
              <div><b>NivXRay machine value:</b> {machineValue || <i>(empty)</i>}</div>
              <div className="nx-ovr__meta">
                edited by <b>{overlay.author_email}</b> ·
                {" "}reason: <i>{overlay.reason}</i>
              </div>
            </div>
          )}
        </div>
      )}

      {editing && (
        <div className="nx-ovr__edit">
          <textarea
            data-testid={`ovr-textarea-${targetKind}-${targetId}-${fieldKey}`}
                       data-ovr-action="value"
            className="nx-textarea"
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            rows={4}
          />
          <input
            data-testid={`ovr-reason-${targetKind}-${targetId}-${fieldKey}`}
                       data-ovr-action="reason"
            className="nx-input"
            placeholder="Reason for change (required — recorded in audit)"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
          />
          <div className="nx-ovr__machine" style={{ marginTop: 0 }}>
            <b>NivXRay machine value (immutable):</b> {machineValue || <i>(empty)</i>}
          </div>
          <div className="nx-actions">
            <button data-testid={`ovr-save-${targetKind}-${targetId}-${fieldKey}`}
                       data-ovr-action="save"
                         onClick={save}
                         disabled={busy || !draft.trim() || !reason.trim()}
                         className="nx-btn nx-btn--primary">
              {busy ? <Loader2 className="rl-spin" size={11} /> : <Save size={11} />}
              Save v{version + 1}
            </button>
            <button onClick={() => setEditing(false)}
                         disabled={busy} className="nx-btn">
              <X size={11} /> Cancel
            </button>
          </div>
        </div>
      )}

      {err && (
        <div className="nx-alert nx-alert--error">
          <AlertTriangle size={11} />
          {err}
        </div>
      )}

      {showHist && history && (
        <div data-testid={`ovr-history-panel-${targetKind}-${targetId}-${fieldKey}`}
              className="nx-ovr__audit">
          <b>Audit trail</b>
          {history.length === 0 && <div>No entries.</div>}
          {history.map((e) => (
            <div key={e.version} className="nx-ovr__audit-row">
              <b>v{e.version}</b> · {e.action} · {e.author_email} · {e.at}
              <div>reason: {e.reason}</div>
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
