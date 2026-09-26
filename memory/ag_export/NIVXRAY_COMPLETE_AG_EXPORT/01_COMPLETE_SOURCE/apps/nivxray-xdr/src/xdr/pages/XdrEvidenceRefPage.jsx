/**
 * XdrEvidenceRefPage · `/xdr/evidence/:executionId`
 *
 * Evidence Deep-Link surface.  Given a Response Engine `execution_id`,
 * fetches the persisted ref triple from the base backend and the
 * execution itself from the Response Engine, then renders the full
 * response chain in one place:
 *
 *     Incident → Evidence → Execution → Action → Result → refs
 *
 * Owner-locked: every displayed field is real.  If either side is
 * unavailable we show an explicit gap — never fake refs.
 */
import React, { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ChevronLeft, ExternalLink, AlertTriangle, ShieldCheck,
  FileCheck2, Zap, User } from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import api from "@/lib/api";
import * as Engine from "@/xdr/respond/responseEngineApi";
import { RESPONSE_ENGINE_CONFIGURED, EXEC_STATE }
  from "@/xdr/respond/responseEngineApi";
import { getAction } from "@/xdr/respond/actionRegistry";


export default function XdrEvidenceRefPage() {
  const { executionId } = useParams();
  const [state, setState] = useState({ loading: true, err: null, exec: null, refs: null });

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setState({ loading: true, err: null, exec: null, refs: null });
      const out = { exec: null, refs: null, errs: [] };
      // 1. Execution row from the Response Engine (own SQLite spine).
      if (RESPONSE_ENGINE_CONFIGURED) {
        try {
          out.exec = await Engine.getExecution(executionId);
        } catch (e) {
          const c = e?.response?.data?.detail?.error || e?.message;
          out.errs.push(`Response Engine: ${c}`);
        }
      } else {
        out.errs.push("Response Engine URL not set (VITE_XDR_RESPONSE_URL).");
      }
      // 2. Persisted evidence refs from the base backend.
      try {
        const r = await api.get(`/xdr/response-evidence/${executionId}`);
        out.refs = r.data;
      } catch (e) {
        const c = e?.response?.data?.detail?.error || e?.response?.status || e?.message;
        out.errs.push(`Base evidence sink: ${c}`);
      }
      if (!cancelled) setState({ loading: false, err: null, ...out });
    })();
    return () => { cancelled = true; };
  }, [executionId]);

  const exec  = state.exec;
  const refs  = state.refs;
  const action = exec ? getAction(exec.action_id) : null;
  const incidentId = exec?.invoker?.context?.incident_id;

  return (
    <XdrShell activeTop="respond">
      <div style={{ marginBottom: 10 }}>
        <Link to="/xdr/incidents" style={{
          display: "inline-flex", alignItems: "center", gap: 6,
          color: "var(--muted)", textDecoration: "none",
          fontSize: 10.5, letterSpacing: ".4px",
          textTransform: "uppercase", fontWeight: 700,
        }}>
          <ChevronLeft size={12} /> Back to incidents
        </Link>
      </div>

      <h1 className="page-h1" data-testid="xdr-evidence-ref-heading">
        Response Chain · <span className="mono">{executionId?.slice(0, 20)}…</span>
      </h1>
      <div className="page-sub">
        Deep-link surface joining the Response Engine execution record
        with the base-backend evidence / audit / timeline triple.
      </div>

      {state.loading && <div className="x-empty">LOADING…</div>}

      {!state.loading && state.errs?.length > 0 && !exec && !refs && (
        <div className="x-empty"
                data-testid="xdr-evidence-ref-error"
                style={{ color: "#ff9494" }}>
          <AlertTriangle size={13} style={{ verticalAlign: "middle",
                                                            marginRight: 6 }} />
          {state.errs.join(" · ")}
        </div>
      )}

      {(exec || refs) && (
        <div style={{ display: "grid", gap: 12,
                          gridTemplateColumns: "minmax(320px, 1fr) 320px" }}>
          {/* Chain */}
          <section className="panel" data-testid="xdr-evidence-ref-chain"
                      style={{ padding: 14 }}>
            <ChainRow icon={ShieldCheck} color="#f87171" label="INCIDENT">
              {incidentId
                ? <Link to={`/xdr/incidents/${incidentId}`}
                              style={{ color: "var(--cyan)" }}>
                    {incidentId} <ExternalLink size={10} />
                  </Link>
                : <span style={{ color: "var(--faint)" }}>—</span>}
            </ChainRow>

            <ChainRow icon={User} color="#c084fc" label="INVOKER">
              <span className="mono">
                {exec?.invoker?.kind}:{exec?.invoker?.id}
              </span>
            </ChainRow>

            <ChainRow icon={Zap} color="#34d399" label="EXECUTION">
              <div className="mono" style={{ fontSize: 11 }}>
                {executionId}
                <span style={{ marginLeft: 8, padding: "1px 6px",
                                    borderRadius: 3,
                                    color: exec?.state === EXEC_STATE.SUCCEEDED
                                              ? "var(--mint)" : "#ff9494",
                                    border: `1px solid ${
                                      exec?.state === EXEC_STATE.SUCCEEDED
                                        ? "var(--mint)" : "#ff9494"}`,
                                    fontSize: 9.5, letterSpacing: ".3px" }}>
                  {exec?.state || "UNKNOWN"}
                </span>
              </div>
              {exec && (
                <div style={{ fontSize: 10.5, color: "var(--faint)",
                                    marginTop: 4 }}>
                  {exec.completed_at ? `Completed ${exec.completed_at}` : ""}
                  {exec.duration_ms != null ? ` · ${exec.duration_ms} ms` : ""}
                </div>
              )}
            </ChainRow>

            <ChainRow icon={Zap} color="#a78bfa" label="ACTION">
              <b>{action?.label || exec?.action_id || "—"}</b>
              {action && (
                <div style={{ fontSize: 10.5, color: "var(--faint)",
                                    marginTop: 4 }}>
                  {action.provider} · {action.capability} ·{" "}
                  {action.destructive ? "destructive · " : ""}
                  {action.approval_required ? "approval required" : "auto-approved"}
                </div>
              )}
            </ChainRow>

            <ChainRow icon={FileCheck2} color="#fbbf24" label="EVIDENCE"
                          testid="xdr-evidence-ref-evidence">
              {refs?.evidence_ref
                ? <span className="mono">{refs.evidence_ref}</span>
                : <span style={{ color: "var(--faint)" }}>—</span>}
            </ChainRow>
            <ChainRow icon={FileCheck2} color="#38bdf8" label="AUDIT"
                          testid="xdr-evidence-ref-audit">
              {refs?.audit_ref
                ? <span className="mono">{refs.audit_ref}</span>
                : <span style={{ color: "var(--faint)" }}>—</span>}
            </ChainRow>
            <ChainRow icon={FileCheck2} color="#f472b6" label="TIMELINE"
                          testid="xdr-evidence-ref-timeline">
              {refs?.timeline_ref
                ? <span className="mono">{refs.timeline_ref}</span>
                : <span style={{ color: "var(--faint)" }}>—</span>}
            </ChainRow>
          </section>

          {/* Metadata sidebar */}
          <aside className="panel" style={{ padding: 12, fontSize: 11 }}
                    data-testid="xdr-evidence-ref-meta">
            <div className="section-title" style={{ marginBottom: 6 }}>
              Approval trail
            </div>
            <Meta k="Status"        v={exec?.approval?.status} />
            <Meta k="Approved by"   v={exec?.approval?.approved_by} />
            <Meta k="Approved at"   v={exec?.approval?.approved_at} />
            <Meta k="Approval ref"  v={exec?.approval?.ref} mono />
            <Meta k="Reason"        v={exec?.approval?.reason} />

            {exec?.approval?.rejected_by && (
              <>
                <Meta k="Rejected by" v={exec.approval.rejected_by} color="#ff9494" />
                <Meta k="Rejected at" v={exec.approval.rejected_at} />
                <Meta k="Rejection reason" v={exec.approval.rejection_reason} />
              </>
            )}

            <div className="section-title" style={{ marginTop: 12,
                                                                marginBottom: 6 }}>
              Forwarding
            </div>
            <Meta k="State"    v={exec?.forwarding_state}
                     color={exec?.forwarding_state === "forwarded" ? "var(--mint)"
                               : exec?.forwarding_state === "not_wired" ? "var(--amber)"
                               : "#ff9494"} />
            <Meta k="Error"    v={exec?.forwarding_error} color="#ff9494" />
            <Meta k="Ingested" v={refs?.ingested_at} />
            {state.errs?.length > 0 && (
              <div style={{ marginTop: 10, padding: 6, borderRadius: 3,
                                border: "1px solid var(--amber)",
                                background: "rgba(245,166,35,.08)",
                                color: "var(--text-dim)", fontSize: 10.5 }}>
                {state.errs.join(" · ")}
              </div>
            )}
          </aside>
        </div>
      )}
    </XdrShell>
  );
}


function ChainRow({ icon: Icon, color, label, children, testid }) {
  return (
    <div data-testid={testid}
            style={{ display: "grid",
                        gridTemplateColumns: "140px 1fr",
                        gap: 12, padding: "10px 0",
                        borderBottom: "1px solid var(--border)",
                        alignItems: "center" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 6,
                        color: color, fontFamily: "var(--mono)",
                        fontSize: 10.5, fontWeight: 800,
                        letterSpacing: ".3px" }}>
        <Icon size={12} /> {label}
      </div>
      <div style={{ color: "var(--text)", fontSize: 12 }}>{children}</div>
    </div>
  );
}
function Meta({ k, v, color, mono }) {
  if (!v) return null;
  return (
    <div style={{ display: "flex", justifyContent: "space-between",
                    padding: "3px 0", borderBottom: "1px solid var(--border)",
                    fontSize: 11 }}>
      <span style={{ color: "var(--faint)" }}>{k}</span>
      <span style={{ color: color || "var(--text-dim)",
                        fontFamily: mono ? "var(--mono)" : "inherit",
                        wordBreak: "break-all", maxWidth: "70%" }}>{v}</span>
    </div>
  );
}
