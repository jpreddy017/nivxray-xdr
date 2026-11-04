/**
 * XdrApprovalsPage · `/xdr/respond/approvals`
 *
 * Peer-approval queue for the Response Engine.  Lists every execution
 * currently parked in `WAITING_APPROVAL` and lets an authorized peer
 * approve or reject inline.  Runs on the same execution contract as
 * the Analyst Response Drawer and the Visual Execution Studio — the
 * SAME row is transitioned in-place, never re-submitted.
 *
 * Owner-locked:
 *   – Never fake-approve.  An approval decision fails immutably with
 *     `409 invalid_state_for_approval` if the row is no longer pending.
 *   – Peer requirement: the same analyst that requested an action
 *     CANNOT approve their own request.  The drawer / studio /
 *     approvals page all enforce this client-side; the engine has
 *     scope-based authz upstream.
 */
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { RefreshCw, CheckCircle2, XCircle, AlertTriangle,
  Filter as FilterIcon, Clock, ExternalLink } from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import { useAuth } from "@/lib/auth";
import * as Engine from "@/xdr/respond/responseEngineApi";
import { RESPONSE_ENGINE_CONFIGURED } from "@/xdr/respond/responseEngineApi";
import { getAction } from "@/xdr/respond/actionRegistry";


export default function XdrApprovalsPage() {
  const { user } = useAuth();
  const [rows, setRows]     = useState([]);
  const [loading, setL]     = useState(true);
  const [error, setError]   = useState(null);
  const [busyId, setBusyId] = useState(null);
  const [reasonById, setReasonById] = useState({});
  const [q, setQ]           = useState("");
  const [tenantFilter, setTF] = useState("");

  const load = useCallback(async () => {
    setL(true); setError(null);
    try {
      const res = await Engine.listPendingApprovals(
        tenantFilter ? { tenantId: tenantFilter } : {});
      setRows(res.rows || []);
    } catch (e) {
      const c = e?.code === "RESPONSE_ENGINE_NOT_DEPLOYED"
        ? "Response Engine URL not set (VITE_XDR_RESPONSE_URL)."
        : (e?.response?.data?.detail?.error || e?.message || String(e));
      setError(c);
    } finally { setL(false); }
  }, [tenantFilter]);
  useEffect(() => { load(); }, [load]);
  // Auto-refresh every 8s — approvals are time-sensitive; keep the
  // queue fresh without hammering the engine.
  useEffect(() => {
    if (!RESPONSE_ENGINE_CONFIGURED) return;
    const t = setInterval(load, 8000);
    return () => clearInterval(t);
  }, [load]);

  const visible = useMemo(() => {
    let list = rows;
    if (q) {
      const needle = q.toLowerCase();
      list = list.filter((r) =>
        (r.execution_id || "").toLowerCase().includes(needle) ||
        (r.action_id || "").toLowerCase().includes(needle) ||
        (r.invoker?.id || "").toLowerCase().includes(needle) ||
        (r.tenant_id || "").toLowerCase().includes(needle));
    }
    return list;
  }, [rows, q]);

  async function decide(row, kind) {
    setBusyId(row.execution_id);
    try {
      const reason = (reasonById[row.execution_id] || "").trim() || undefined;
      const fn  = kind === "approve" ? Engine.approve : Engine.reject;
      const arg = kind === "approve"
        ? { approvedBy: `user:${user?.email || "unknown"}`, reason }
        : { rejectedBy: `user:${user?.email || "unknown"}`, reason };
      await fn(row.execution_id, arg);
      await load();
    } catch (e) {
      const c = e?.response?.data?.detail?.error || e?.message;
      setError(`Decision failed on ${row.execution_id}: ${c}`);
    } finally { setBusyId(null); }
  }

  return (
    <XdrShell activeTop="respond">
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <h1 className="page-h1" data-testid="xdr-approvals-heading">
          Approvals Queue
        </h1>
        <span style={{ flex: 1 }} />
        <button className="btn ghost" onClick={load}
                  data-testid="xdr-approvals-refresh"
                  style={{ padding: "4px 10px" }}>
          <RefreshCw size={11} /> Refresh
        </button>
      </div>
      <div className="page-sub">
        Every response execution currently parked in{" "}
        <span className="mono" style={{ color: "var(--amber)" }}>
          WAITING_APPROVAL
        </span>. A peer approval resumes the SAME execution — no
        duplicate request is submitted.
      </div>

      {!RESPONSE_ENGINE_CONFIGURED && (
        <div data-testid="xdr-approvals-not-wired"
                style={{ marginTop: 10, padding: 10,
                            border: "1px dashed var(--amber)", borderRadius: 4,
                            background: "rgba(245,166,35,.08)",
                            color: "var(--text-dim)", fontSize: 11.5 }}>
          <b style={{ color: "var(--amber)", fontFamily: "var(--mono)" }}>
            NOT WIRED
          </b> — set <span className="mono">VITE_XDR_RESPONSE_URL</span>
          {" "}to see live pending approvals.
        </div>
      )}

      {/* Filter bar */}
      <div style={{ display: "flex", gap: 8, alignItems: "center",
                        margin: "12px 0" }}>
        <input className="x-input"
                  placeholder="Search execution id, action, invoker…"
                  value={q} onChange={(e) => setQ(e.target.value)}
                  data-testid="xdr-approvals-search"
                  style={{ maxWidth: 360 }} />
        <input className="x-input"
                  placeholder="Tenant filter (blank = all)"
                  value={tenantFilter}
                  onChange={(e) => setTF(e.target.value)}
                  data-testid="xdr-approvals-tenant"
                  style={{ maxWidth: 180 }} />
        <span className="mono" style={{ fontSize: 10.5, color: "var(--faint)" }}>
          {visible.length} pending
        </span>
      </div>

      {error && (
        <div data-testid="xdr-approvals-error"
                style={{ padding: 10, marginBottom: 10, borderRadius: 4,
                            border: "1px solid #ff5b5b",
                            background: "rgba(255,91,91,.08)",
                            color: "#ff9494", fontSize: 11.5 }}>
          <AlertTriangle size={11} /> {error}
        </div>
      )}

      {loading && <div className="x-empty">LOADING…</div>}
      {!loading && !error && visible.length === 0 && (
        <div className="x-empty" data-testid="xdr-approvals-empty">
          <CheckCircle2 size={13} style={{ verticalAlign: "middle",
                                                            marginRight: 6, color: "var(--mint)" }} />
          No pending approvals.
        </div>
      )}

      {visible.map((r) => {
        const action = getAction(r.action_id);
        const isMine = r.approval?.approved_by === `user:${user?.email}` ||
                          r.invoker?.id === `user:${user?.email}`;
        return (
          <div key={r.execution_id}
                  data-testid={`xdr-approvals-row-${r.execution_id}`}
                  className="panel"
                  style={{ padding: 12, marginBottom: 10,
                              borderLeft: "3px solid var(--amber)" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10,
                              flexWrap: "wrap" }}>
              <span className="mono" style={{ color: "var(--amber)",
                                                            fontSize: 10.5, fontWeight: 800,
                                                            letterSpacing: ".4px" }}>
                WAITING_APPROVAL
              </span>
              <b style={{ fontSize: 13, color: "var(--text)" }}>
                {action?.label || r.action_id}
              </b>
              {action?.destructive && (
                <span className="mono"
                         style={{ padding: "1px 6px", borderRadius: 3,
                                     border: "1px solid #ff9494", color: "#ff9494",
                                     fontSize: 9.5, letterSpacing: ".3px",
                                     textTransform: "uppercase" }}>
                  Destructive
                </span>
              )}
              <span style={{ flex: 1 }} />
              <span className="mono" style={{ color: "var(--faint)",
                                                            fontSize: 10 }}>
                {r.execution_id?.slice(0, 20)}…
              </span>
            </div>

            <div style={{ display: "grid",
                              gridTemplateColumns: "1fr 1fr 1fr", gap: 12,
                              marginTop: 10, fontSize: 11 }}>
              <Field k="Tenant"       v={r.tenant_id} />
              <Field k="Invoker"      v={`${r.invoker?.kind}: ${r.invoker?.id}`} />
              <Field k="Requested at" v={r.requested_at} />
              <Field k="Incident"     v={r.invoker?.context?.incident_id}
                        link={r.invoker?.context?.incident_id
                                  ? `/xdr/incidents/${r.invoker.context.incident_id}` : null} />
              <Field k="Playbook"     v={r.invoker?.context?.playbook_id}
                        link={r.invoker?.context?.playbook_id
                                  ? `/xdr/respond/playbooks/${r.invoker.context.playbook_id}` : null} />
              <Field k="Reversible"   v={action?.reversible ? "yes" : "no"}
                        color={action?.reversible ? "var(--mint)" : "#ff9494"} />
            </div>

            <div style={{ marginTop: 10, display: "flex", gap: 8,
                              alignItems: "flex-start" }}>
              <input className="x-input"
                        placeholder="Reason (optional; recorded in audit)"
                        value={reasonById[r.execution_id] || ""}
                        onChange={(e) => setReasonById((s) => ({
                          ...s, [r.execution_id]: e.target.value,
                        }))}
                        data-testid={`xdr-approvals-reason-${r.execution_id}`}
                        style={{ flex: 1 }} />
              <button className="btn primary"
                        disabled={busyId === r.execution_id || isMine}
                        onClick={() => decide(r, "approve")}
                        title={isMine ? "You requested this action — a peer must approve"
                                             : "Approve and resume execution"}
                        data-testid={`xdr-approvals-approve-${r.execution_id}`}
                        style={{ padding: "4px 12px" }}>
                <CheckCircle2 size={11} /> Approve
              </button>
              <button className="btn"
                        disabled={busyId === r.execution_id}
                        onClick={() => decide(r, "reject")}
                        data-testid={`xdr-approvals-reject-${r.execution_id}`}
                        style={{ padding: "4px 12px" }}>
                <XCircle size={11} /> Reject
              </button>
            </div>
            {isMine && (
              <div style={{ marginTop: 6, fontSize: 10.5,
                                color: "var(--faint)",
                                display: "flex", alignItems: "center", gap: 4 }}>
                <Clock size={10} /> You requested this action — approval must
                come from a peer.
              </div>
            )}
          </div>
        );
      })}
    </XdrShell>
  );
}


function Field({ k, v, link, color }) {
  return (
    <div>
      <div style={{ fontSize: 9.5, color: "var(--faint)",
                        textTransform: "uppercase", letterSpacing: ".3px",
                        fontFamily: "var(--mono)", marginBottom: 2 }}>{k}</div>
      <div style={{ color: color || "var(--text-dim)",
                        fontFamily: "var(--mono)", fontSize: 11,
                        wordBreak: "break-all" }}>
        {link
          ? <Link to={link} style={{ color: "var(--cyan)",
                                                textDecoration: "underline" }}>
              {v || "—"} <ExternalLink size={9} style={{ verticalAlign: "middle" }} />
            </Link>
          : (v || "—")}
      </div>
    </div>
  );
}
