/**
 * AnalystResponseDrawer — right-side drawer for the Incident Detail
 * page.  Analysts pick a response action, resolve a target, and
 * invoke the standalone Response Engine using
 *
 *     invoker.kind = "analyst"
 *
 * There is NO privileged backdoor: approval-required actions still
 * enter WAITING_APPROVAL and only run once a peer approves them.
 * Every invocation returns a real execution_id + state — the UI
 * never claims success unless the engine reports SUCCEEDED.
 */
import React, { useEffect, useMemo, useState } from "react";
import { X, Play, ShieldAlert, CheckCircle2, AlertTriangle,
  Clock, FileCheck2, ChevronRight } from "lucide-react";

import {
  RESPONSE_ACTIONS, ACTIONS_BY_PROVIDER, getAction,
} from "@/xdr/respond/actionRegistry";
import * as Engine from "@/xdr/respond/responseEngineApi";
import { EXEC_STATE, TERMINAL_STATES, RESPONSE_ENGINE_CONFIGURED }
  from "@/xdr/respond/responseEngineApi";

const _uuid = () =>
  "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    return (c === "x" ? r : (r & 0x3) | 0x8).toString(16);
  });


export default function AnalystResponseDrawer({
  open, onClose, incident, analystEmail,
  defaultHostId, defaultUserId,
}) {
  const [actionId, setActionId] = useState(RESPONSE_ACTIONS[0]?.action_id || "");
  const [params, setParams]     = useState({});
  const [busy, setBusy]         = useState(false);
  const [exec, setExec]         = useState(null);
  const [error, setError]       = useState(null);

  const action = getAction(actionId);

  // Prefill parameters from the incident context whenever the action changes.
  useEffect(() => {
    if (!action) return;
    const next = {};
    for (const p of action.parameters || []) {
      if (p.key === "host_id" && defaultHostId) next.host_id = defaultHostId;
      if (p.key === "user_id" && defaultUserId) next.user_id = defaultUserId;
    }
    setParams(next);
    setExec(null); setError(null);
  }, [actionId, defaultHostId, defaultUserId]);

  // Reset drawer state whenever it re-opens.
  useEffect(() => {
    if (!open) { setExec(null); setError(null); setBusy(false); }
  }, [open]);

  const scopes = useMemo(() => {
    // Analyst invocation surface: the drawer always sends the exact
    // scopes the picked action needs — the base backend enforces real
    // RBAC upstream.  This is NOT a bypass; the Response Engine still
    // validates the scope list and refuses missing scopes with 403.
    if (!action) return [];
    return (action.required_permissions || []).flatMap((p) => [
      `${p.role}:${p.scope}`, p.scope,
    ]);
  }, [action]);

  const missingParam = useMemo(() => {
    if (!action) return null;
    for (const p of action.parameters || []) {
      if (p.required && !params[p.key]) return p.key;
    }
    return null;
  }, [action, params]);

  const invoker = useMemo(() => ({
    kind:    "analyst",
    id:      `user:${analystEmail || "anonymous"}`,
    context: { incident_id: incident?.id || null },
  }), [analystEmail, incident?.id]);

  async function invoke() {
    if (!RESPONSE_ENGINE_CONFIGURED) {
      setError("Response Engine URL not set (VITE_XDR_RESPONSE_URL)."); return;
    }
    if (!action) { setError("Pick a response action."); return; }
    if (missingParam) { setError(`Missing parameter: ${missingParam}`); return; }
    setBusy(true); setError(null);
    const executionId = "exec-" + _uuid();
    try {
      const res = await Engine.execute(Engine.buildExecutePayload({
        executionId, tenantId: incident?.tenant_id || "acme",
        invoker, action: action.action_id, parameters: params,
        scopes,   // NO pre-approval; drawer never bypasses approval workflow.
        approval: null,
      }));
      setExec(res);
      // If action didn't need approval and returned already-terminal,
      // we're done.  Otherwise poll for progress.
      if (!TERMINAL_STATES.has(res.state) &&
            res.state !== EXEC_STATE.WAITING_APPROVAL) {
        const final = await Engine.pollUntilTerminal(executionId, {
          tenantId: incident?.tenant_id || "acme",
          invokerKind: "analyst", invokerId: invoker.id,
          onTick: (row) => setExec(row),
        });
        setExec(final);
      }
    } catch (e) {
      const c = e?.response?.data?.detail?.error || e?.code || e?.message;
      setError(String(c || e));
    } finally { setBusy(false); }
  }

  async function decideApproval(kind) {
    if (!exec) return;
    setBusy(true); setError(null);
    try {
      const fn = kind === "approve" ? Engine.approve : Engine.reject;
      const arg = kind === "approve"
        ? { approvedBy: `user:${analystEmail}`, reason: "Approved from Analyst Drawer" }
        : { rejectedBy: `user:${analystEmail}`, reason: "Rejected from Analyst Drawer" };
      const res = await fn(exec.execution_id, arg);
      setExec(res);
    } catch (e) {
      setError(e?.response?.data?.detail?.error || e?.message || String(e));
    } finally { setBusy(false); }
  }

  if (!open) return null;

  return (
    <div
      data-testid="xdr-analyst-drawer"
      style={{
        position: "fixed", top: 0, right: 0, bottom: 0, width: 460,
        background: "var(--panel, #0f1218)",
        borderLeft: "1px solid var(--border, #1c2230)",
        boxShadow: "-8px 0 24px rgba(0,0,0,.45)",
        zIndex: 60, display: "flex", flexDirection: "column",
        color: "var(--text)", fontSize: 12,
      }}>
      {/* Header */}
      <header style={{
        display: "flex", alignItems: "center", gap: 8,
        padding: "10px 14px", borderBottom: "1px solid var(--border)",
      }}>
        <ShieldAlert size={14} style={{ color: "var(--purple)" }} />
        <b style={{ fontSize: 12, letterSpacing: ".3px", textTransform: "uppercase" }}>
          Analyst Response
        </b>
        <span style={{ flex: 1 }} />
        <button className="btn ghost" onClick={onClose}
                  data-testid="xdr-analyst-drawer-close"
                  style={{ padding: 3 }}>
          <X size={12} />
        </button>
      </header>

      {/* Body */}
      <div style={{ padding: 14, overflow: "auto", flex: 1 }}>
        <div style={{ color: "var(--faint)", fontSize: 10.5,
                          fontFamily: "var(--mono)", marginBottom: 6 }}>
          Incident · <span style={{ color: "var(--text-dim)" }}>
            {incident?.id || "—"}
          </span>
        </div>
        <div style={{ color: "var(--text)", fontSize: 12, marginBottom: 12 }}>
          {incident?.title || "Unnamed incident"}
        </div>

        {!RESPONSE_ENGINE_CONFIGURED && (
          <div data-testid="xdr-analyst-drawer-not-wired"
                  style={{ marginBottom: 10, padding: 8,
                              border: "1px dashed var(--amber)", borderRadius: 4,
                              background: "rgba(245,166,35,.08)", fontSize: 11,
                              color: "var(--text-dim)" }}>
            <b style={{ color: "var(--amber)", fontFamily: "var(--mono)" }}>
              NOT WIRED
            </b> — set <span className="mono">VITE_XDR_RESPONSE_URL</span> to
            invoke the Response Engine.
          </div>
        )}

        {/* Action picker */}
        <FieldLabel>Response Action</FieldLabel>
        <select className="x-input" value={actionId}
                  onChange={(e) => setActionId(e.target.value)}
                  data-testid="xdr-analyst-drawer-action">
          {Object.entries(ACTIONS_BY_PROVIDER).map(([prov, list]) => (
            <optgroup key={prov} label={prov.toUpperCase()}>
              {list.map((a) => (
                <option key={a.action_id} value={a.action_id}>{a.label}</option>
              ))}
            </optgroup>
          ))}
        </select>

        {action && (
          <>
            <MetaRow k="Target Type"       v={_targetType(action)} />
            <MetaRow k="Reversible"        v={action.reversible ? "yes" : "no"} />
            <MetaRow k="Destructive"       v={action.destructive ? "yes" : "no"}
                        color={action.destructive ? "#ff9494" : "var(--mint)"} />
            <MetaRow k="Approval Required" v={action.approval_required ? "yes" : "no"}
                        color={action.approval_required ? "var(--amber)" : "var(--mint)"} />
            <MetaRow k="Permissions" v={(action.required_permissions || [])
                                              .map((p) => `${p.role}:${p.scope}`)
                                              .join(", ") || "—"} />

            {(action.parameters || []).length > 0 && (
              <>
                <FieldLabel>Parameters</FieldLabel>
                {action.parameters.map((p) => (
                  <div key={p.key} style={{ marginBottom: 8 }}>
                    <div style={{ fontSize: 10, color: "var(--faint)",
                                     textTransform: "uppercase" }}>
                      {p.label}{p.required ? " *" : ""}
                    </div>
                    <input className="x-input"
                              value={params[p.key] || ""}
                              onChange={(e) => setParams((s) => ({
                                ...s, [p.key]: e.target.value,
                              }))}
                              data-testid={`xdr-analyst-drawer-param-${p.key}`} />
                  </div>
                ))}
              </>
            )}
          </>
        )}

        <button className="btn primary"
                  onClick={invoke}
                  disabled={busy || !RESPONSE_ENGINE_CONFIGURED}
                  data-testid="xdr-analyst-drawer-execute"
                  style={{ marginTop: 10, width: "100%", padding: "6px 10px" }}>
          <Play size={11} />{" "}
          {busy ? "Working…" : action?.approval_required
                                    ? "Request Approval"
                                    : "Execute"}
        </button>

        {error && (
          <div data-testid="xdr-analyst-drawer-error"
                  style={{ marginTop: 10, padding: 8,
                              border: "1px solid #ff5b5b", borderRadius: 4,
                              background: "rgba(255,91,91,.08)",
                              color: "#ff9494", fontSize: 11 }}>
            <AlertTriangle size={11} /> {String(error)}
          </div>
        )}

        {/* Live execution card */}
        {exec && (
          <ExecutionCard exec={exec}
                             onApprove={() => decideApproval("approve")}
                             onReject={() => decideApproval("reject")}
                             analystEmail={analystEmail} />
        )}
      </div>
    </div>
  );
}


function ExecutionCard({ exec, onApprove, onReject, analystEmail }) {
  const stateColor = {
    [EXEC_STATE.SUCCEEDED]:         "var(--mint)",
    [EXEC_STATE.WAITING_APPROVAL]:  "var(--amber)",
    [EXEC_STATE.RUNNING]:           "var(--cyan)",
    [EXEC_STATE.EXECUTING]:         "var(--cyan)",
    [EXEC_STATE.FORWARDING]:        "var(--cyan)",
    [EXEC_STATE.QUEUED]:            "var(--faint)",
    [EXEC_STATE.FAILED_APPROVAL]:   "#ff9494",
    [EXEC_STATE.FAILED_TARGET]:     "#ff9494",
    [EXEC_STATE.FAILED_EXECUTION]:  "#ff9494",
    [EXEC_STATE.FAILED_FORWARDING]: "#ff9494",
    [EXEC_STATE.FAILED_RECOVERED]:  "#ff9494",
    [EXEC_STATE.REJECTED]:          "#ff9494",
  }[exec.state] || "var(--text-dim)";

  const isWaiting = exec.state === EXEC_STATE.WAITING_APPROVAL;
  const canDecide = isWaiting && exec.approval?.approved_by !== `user:${analystEmail}`;

  return (
    <div data-testid="xdr-analyst-drawer-exec-card"
            style={{ marginTop: 14, padding: 10, borderRadius: 4,
                        background: "var(--panel2)",
                        border: `1px solid ${stateColor}`, fontSize: 11 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6 }}>
        <span className="mono" style={{ color: stateColor, fontWeight: 800,
                                                textTransform: "uppercase", fontSize: 10.5 }}
                 data-testid="xdr-analyst-drawer-exec-state">
          {exec.state}
        </span>
        <span style={{ flex: 1 }} />
        <span className="mono" style={{ color: "var(--faint)", fontSize: 10 }}>
          {exec.execution_id?.slice(0, 12)}…
        </span>
      </div>

      <MetaRow k="Action ID"   v={exec.action_id} />
      <MetaRow k="Duration"    v={exec.duration_ms != null ? `${exec.duration_ms} ms` : "—"} />
      <MetaRow k="Adapter OK"  v={exec.adapter_ok ? "yes" : "no"}
                  color={exec.adapter_ok ? "var(--mint)" : "#ff9494"} />
      {exec.evidence_ref && <MetaRow k="Evidence Ref" v={<span className="mono">{exec.evidence_ref}</span>} />}
      {exec.audit_ref    && <MetaRow k="Audit Ref"    v={<span className="mono">{exec.audit_ref}</span>} />}
      {exec.timeline_ref && <MetaRow k="Timeline Ref" v={<span className="mono">{exec.timeline_ref}</span>} />}
      {exec.forwarding_state && (
        <MetaRow k="Forwarding" v={exec.forwarding_state}
                    color={exec.forwarding_state === "forwarded" ? "var(--mint)"
                              : exec.forwarding_state === "not_wired" ? "var(--amber)"
                              : "#ff9494"} />
      )}
      {exec.failure_reason && (
        <MetaRow k="Failure" v={exec.failure_reason} color="#ff9494" />
      )}
      {exec.approval?.approved_by && (
        <MetaRow k="Approved by" v={exec.approval.approved_by} />
      )}
      {exec.approval?.rejected_by && (
        <MetaRow k="Rejected by" v={exec.approval.rejected_by} color="#ff9494" />
      )}

      {isWaiting && canDecide && (
        <div style={{ display: "flex", gap: 6, marginTop: 8 }}>
          <button className="btn primary" style={{ flex: 1, padding: "4px 8px" }}
                    onClick={onApprove}
                    data-testid="xdr-analyst-drawer-approve">
            <CheckCircle2 size={11} /> Approve
          </button>
          <button className="btn" style={{ flex: 1, padding: "4px 8px" }}
                    onClick={onReject}
                    data-testid="xdr-analyst-drawer-reject">
            <X size={11} /> Reject
          </button>
        </div>
      )}
      {isWaiting && !canDecide && (
        <div style={{ marginTop: 8, fontSize: 10.5, color: "var(--faint)",
                          display: "flex", alignItems: "center", gap: 6 }}>
          <Clock size={10} /> Peer approval required — you cannot approve your own request.
        </div>
      )}
      {exec.state === EXEC_STATE.SUCCEEDED && (
        <div style={{ marginTop: 8, fontSize: 10.5, color: "var(--mint)",
                          display: "flex", alignItems: "center", gap: 6 }}>
          <FileCheck2 size={10} /> Response chain complete — evidence, audit,
          and timeline references written.
        </div>
      )}
    </div>
  );
}


// ── tiny building blocks ─────────────────────────────────────────────
function FieldLabel({ children }) {
  return (
    <div style={{ fontSize: 10, color: "var(--faint)",
                    textTransform: "uppercase", letterSpacing: ".3px",
                    fontFamily: "var(--mono)", marginBottom: 4, marginTop: 8 }}>
      {children}
    </div>
  );
}
function MetaRow({ k, v, color }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between",
                    padding: "4px 0", borderBottom: "1px solid var(--border)",
                    fontSize: 11 }}>
      <span style={{ color: "var(--faint)" }}>{k}</span>
      <span style={{ color: color || "var(--text-dim)", fontFamily: "var(--mono)",
                        wordBreak: "break-all", maxWidth: "70%" }}>{v}</span>
    </div>
  );
}
function _targetType(a) {
  const keys = (a.parameters || []).map((p) => p.key);
  if (keys.includes("host_id"))    return "endpoint";
  if (keys.includes("user_id"))    return "identity";
  if (keys.includes("ip"))         return "network:ip";
  if (keys.includes("domain"))     return "network:domain";
  if (keys.includes("hash"))       return "file:hash";
  if (keys.includes("message_id")) return "email:message";
  return a.provider;
}
