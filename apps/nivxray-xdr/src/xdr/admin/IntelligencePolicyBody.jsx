/**
 * Administration › Intelligence Policy — the ONE editable surface.
 *
 * Simple on top, advanced underneath. The primary surface offers three
 * modes, the current effective status in analyst language, an audited
 * reason, and save. Everything technical (per-permission detail, raw
 * provisioning state, change history) is progressive disclosure.
 *
 * RBAC is server-enforced; a denial is surfaced verbatim and nothing in
 * this component decides authority.
 */
import React, { useEffect, useMemo, useState } from "react";
import { RefreshCw } from "lucide-react";
import { NxSurface } from "@/xdr/nx";
import AdminTenantGate from "@/xdr/admin/AdminTenantGate";
import useIntelligencePolicy from "@/xdr/intelligence/useIntelligencePolicy";
import { MODES, statusRows } from "@/xdr/intelligence/intelligenceModel";
import "@/xdr/intelligence/intel.css";

export default function IntelligencePolicyBody() {
  return (
    <AdminTenantGate label="Intelligence Policy">
      <IntelligencePolicyEditor />
    </AdminTenantGate>
  );
}


function IntelligencePolicyEditor() {
  const {
    values, health, mode, loading, saving, error, history,
    reload, save, loadHistory,
  } = useIntelligencePolicy({ scope: "global" });

  const [selected, setSelected] = useState(null);
  const [reason, setReason] = useState("");
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [showHistory, setShowHistory] = useState(false);
  const [saved, setSaved] = useState(false);

  useEffect(() => { setSelected(mode?.id || null); }, [mode?.id]);

  const rows = useMemo(() => statusRows({ values, health }),
    [values, health]);
  const dirty = !!selected && selected !== mode?.id;

  const onSave = async () => {
    const next = MODES.find((m) => m.id === selected);
    if (!next) return;
    const res = await save(next.values, reason);
    if (res.ok) {
      setSaved(true);
      setReason("");
      setTimeout(() => setSaved(false), 2500);
    }
  };

  return (
    <div data-testid="xdr-admin-intelligence-policy">
      {error && (
        <div className="nx-intel-err" data-testid="xdr-intel-policy-error">
          {error}
        </div>
      )}

      <NxSurface
        title="Intelligence Policy"
        subtitle="Which intelligence NivXRay is permitted to use for this tenant. Applies to every investigation unless an incident narrows it."
        testid="xdr-intel-policy-surface"
        action={
          <button className="rl-btn" onClick={reload} disabled={loading}
                  data-testid="xdr-intel-policy-refresh">
            <RefreshCw size={12}
              style={loading ? { animation: "nx-spin 0.9s linear infinite" } : {}} />
            Refresh
          </button>
        }
      >
        <div className="nx-intel-modes" data-testid="xdr-intel-policy-modes">
          {MODES.map((m) => (
            <button key={m.id}
                    className="nx-intel-mode"
                    data-testid={`xdr-intel-policy-mode-${m.id}`}
                    data-selected={selected === m.id ? "true" : "false"}
                    disabled={loading || saving}
                    onClick={() => setSelected(m.id)}>
              {m.label}
            </button>
          ))}
        </div>
        <p className="nx-intel-hint" data-testid="xdr-intel-policy-hint">
          {MODES.find((m) => m.id === selected)?.hint
            || "No policy resolved yet."}
        </p>

        <div style={{ marginTop: 22 }}>
          <div className="nx-intel-strip__k" style={{ marginBottom: 8 }}>
            Current status
          </div>
          <div className="nx-intel-status" data-testid="xdr-intel-policy-status">
            {rows.map((r) => (
              <div key={r.key} className="nx-intel-status__row"
                   data-testid={`xdr-intel-policy-status-${r.key}`}>
                <span className="nx-intel-status__label">{r.label}</span>
                <span className="nx-intel-status__value">
                  <span className={`nx-intel-dot nx-intel-dot--${
                    r.tone === "ok" ? "ok" : r.tone === "warn" ? "warn" : "off"}`} />
                  {r.text}
                  {r.note && (
                    <span className="nx-intel-status__note">{r.note}</span>
                  )}
                </span>
              </div>
            ))}
          </div>
        </div>

        <div style={{ marginTop: 22 }}>
          <label className="nx-intel-strip__k"
                 htmlFor="nx-intel-reason"
                 style={{ display: "block", marginBottom: 8 }}>
            Reason for change
          </label>
          <input id="nx-intel-reason"
                 className="nx-intel-reason"
                 data-testid="xdr-intel-policy-reason"
                 placeholder="Recorded in the audit trail"
                 value={reason}
                 onChange={(e) => setReason(e.target.value)} />
        </div>

        <div className="nx-intel-actions">
          <button className="nx-intel-btn nx-intel-btn--primary"
                  data-testid="xdr-intel-policy-save"
                  disabled={!dirty || saving}
                  onClick={onSave}>
            {saving ? "Saving…" : "Save changes"}
          </button>
          <button className="nx-intel-btn"
                  data-testid="xdr-intel-policy-cancel"
                  disabled={!dirty || saving}
                  onClick={() => { setSelected(mode?.id || null); setReason(""); }}>
            Cancel
          </button>
          {saved && (
            <span style={{ fontSize: 12, color: "var(--nx-benign)" }}
                  data-testid="xdr-intel-policy-saved">
              Saved · recorded in audit
            </span>
          )}
        </div>

        <div className="nx-intel-disclose">
          <button data-testid="xdr-intel-policy-advanced-toggle"
                  onClick={() => setShowAdvanced((v) => !v)}>
            {showAdvanced ? "Hide advanced settings" : "Advanced settings ›"}
          </button>
          <button data-testid="xdr-intel-policy-history-toggle"
                  onClick={() => {
                    setShowHistory((v) => !v);
                    if (!showHistory && history === null) loadHistory();
                  }}>
            {showHistory ? "Hide policy history" : "View policy history ›"}
          </button>
        </div>

        {showAdvanced && (
          <div className="nx-intel-adv" data-testid="xdr-intel-policy-advanced">
            <div style={{ marginBottom: 8, fontWeight: 600,
                          color: "var(--nx-text)" }}>
              What these four facts mean
            </div>
            <div>
              <strong>Policy</strong> is what an administrator permits.{" "}
              <strong>Provisioning</strong> is whether a runtime exists.{" "}
              <strong>Availability</strong> is whether it can answer now.{" "}
              <strong>Effective</strong> is what actually applied to an
              investigation. NivXRay keeps these separate and never reports
              one as another.
            </div>
            <div style={{ marginTop: 10, fontFamily: "var(--xmono, monospace)",
                          fontSize: 11, color: "var(--nx-muted)" }}
                 data-testid="xdr-intel-policy-raw">
              online_ai={values?.online_ai ?? "—"} ·
              online_llm={values?.online_llm ?? "—"} ·
              offline_ai={health?.offline_ai?.health ?? "not reported"} ·
              offline_llm={health?.offline_llm?.health ?? "not reported"}
            </div>
            <div style={{ marginTop: 8, color: "var(--nx-muted)" }}>
              Offline AI, the offline LLM and the NivXRay narration engine
              have no off switch — they are the guaranteed baseline, so they
              are reported here rather than offered as controls.
            </div>
          </div>
        )}

        {showHistory && (
          <div className="nx-intel-hist" data-testid="xdr-intel-policy-history">
            {history === null && <div>Loading history…</div>}
            {history?.length === 0 && (
              <div data-testid="xdr-intel-policy-history-empty">
                No policy change has been recorded.
              </div>
            )}
            {(history || []).map((h, i) => (
              <div key={h.audit_id || i} className="nx-intel-hist__row"
                   data-testid={`xdr-intel-policy-history-${i}`}>
                <div style={{ color: "var(--nx-purple)" }}>{h.recorded_at}</div>
                <div>{h.changed_by} · {h.changed_by_role}</div>
                <div style={{ color: "var(--nx-muted)" }}>
                  {JSON.stringify(h.previous)} → {JSON.stringify(h.new)}
                  {h.reason ? ` · ${h.reason}` : ""}
                </div>
              </div>
            ))}
          </div>
        )}
      </NxSurface>
    </div>
  );
}
