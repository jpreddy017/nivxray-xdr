/**
 * `/xdr/clients` — Client Management (MDR tenant estate).
 *
 * The authority is `GET /api/xdr/scope/authorized`: the tenants this
 * principal may enter, the resolution basis, and the tenant-group
 * contract state. Operational volume comes from the same queue
 * predicate the incident queue uses, so this page can never disagree
 * with the queue it links to.
 *
 * Nothing here GRANTS anything. Selecting a client requests a scope
 * through the authoritative selector; the server decides.
 */
import React, { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { RefreshCw, Users, ShieldCheck } from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import { getAuthorizedScope, selectScope } from "@/lib/scopeApi";
import { setActiveTenant } from "@/lib/tenant";
import { getMssCustomerOperations } from "@/lib/incidentsApi";
import "@/xdr/nx/nx-cc.css";

export default function XdrClientManagementPage() {
  const navigate = useNavigate();
  const [scope, setScope] = useState(null);
  const [ops, setOps] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const [denied, setDenied] = useState(null);

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const s = await getAuthorizedScope();
      setScope(s);
    } catch (e) {
      setError(e?.response?.data?.detail || e?.message || "Failed to load.");
    }
    try {
      setOps(await getMssCustomerOperations());
    } catch (e) {
      setOps({ error: e?.response?.data?.detail || e?.message });
    }
    setLoading(false);
  }, []);
  useEffect(() => { load(); }, [load]);

  const enter = async (tenantId) => {
    setDenied(null);
    try {
      const eff = await selectScope({ kind: "tenant", tenantId });
      if (eff?.authorized) {
        setActiveTenant(tenantId);
        navigate(`/xdr/incidents?customer=${encodeURIComponent(tenantId)}`);
      }
    } catch (e) {
      setDenied({ tenantId, detail: e?.response?.data?.detail || e?.message });
    }
  };

  const opsBy = {};
  (ops?.rows || []).forEach((r) => { opsBy[r.customer] = r; });

  return (
    <XdrShell>
      <div className="cc" data-testid="xdr-clients-page"
           style={{ padding: "12px 16px 24px" }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: 12,
                      flexWrap: "wrap" }}>
          <h1 style={{ margin: 0, fontSize: 19, fontWeight: 700 }}
              data-testid="xdr-clients-title">
            Client Management
          </h1>
          <span style={{ fontSize: 11, color: "var(--nx-muted, var(--muted))",
                         maxWidth: 740, lineHeight: 1.6 }}>
            The tenants your identity is authorized to enter, resolved by the
            server. This page reports authority — it never grants it.
          </span>
          <div style={{ marginLeft: "auto", display: "flex", gap: 8 }}>
            <button className="cx-pill" data-testid="xdr-clients-users-roles"
                    onClick={() => navigate("/xdr/admin/users-roles")}>
              <Users size={11} /> Users &amp; roles
            </button>
            <button className="cx-pill" onClick={load} disabled={loading}
                    data-testid="xdr-clients-refresh">
              <RefreshCw size={11} /> Refresh
            </button>
          </div>
        </div>

        <div className="cc-cond" data-testid="xdr-clients-authority">
          <span className="cc-cond__i">
            <span className="cc-cond__k">Principal</span>
            <span className="cc-cond__v">
              {scope?.principal?.email || "NOT RESOLVED"}
            </span>
          </span>
          <span className="cc-cond__i">
            <span className="cc-cond__k">Basis</span>
            <span className="cc-cond__v" data-testid="xdr-clients-basis">
              {scope?.basis || "UNRESOLVED"}
            </span>
          </span>
          <span className="cc-cond__i">
            <span className="cc-cond__k">Authorized tenants</span>
            <span className="cc-cond__v">
              {typeof scope?.authorized_count === "number"
                ? scope.authorized_count : "NOT AVAILABLE"}
            </span>
          </span>
          <span className="cc-cond__i">
            <span className="cc-cond__k">Cross-tenant role</span>
            <span className="cc-cond__v"
                  data-state={scope?.cross_tenant_role ? "warn" : "ok"}>
              {scope ? (scope.cross_tenant_role ? "YES" : "NO") : "NOT EVALUATED"}
            </span>
          </span>
        </div>

        {error && (
          <div className="cc-card"><div className="cc-empty"
               data-testid="xdr-clients-error">
            <b>NOT AUTHORIZED / NOT AVAILABLE</b> — {String(
              typeof error === "object" ? JSON.stringify(error) : error)}
          </div></div>
        )}

        <div className="cc-card" data-testid="xdr-clients-table-card">
          <div className="cc-card__h">
            <span className="cc-card__t">Authorized clients</span>
            <span className="cc-card__s">
              volume from the same predicate as the incident queue
            </span>
          </div>
          <div className="cc-card__b">
            {loading && <div className="cc-empty">Reading the tenant authority…</div>}
            {!loading && (scope?.tenants || []).length === 0 && !error && (
              <div className="cc-empty" data-testid="xdr-clients-empty">
                <b>NO CLIENT IN SCOPE</b> — your identity resolves to no
                authorized tenant. There is no default tenant: an unresolved
                scope is a denial, never a substitution.
              </div>
            )}
            {(scope?.tenants || []).length > 0 && (
              <table className="cc-tb" data-testid="xdr-clients-table">
                <thead>
                  <tr>
                    <th>Client</th><th className="num">Open</th>
                    <th className="num">Incidents</th><th className="num">Critical</th>
                    <th className="num">SLA risk</th><th className="num">Unassigned</th>
                    <th>Scope</th>
                  </tr>
                </thead>
                <tbody>
                  {(scope.tenants || []).map((t) => {
                    const o = opsBy[t.customer];
                    return (
                      <tr key={t.customer}
                          data-testid={`xdr-clients-row-${t.customer}`}
                          onClick={() => navigate(t.queue_href)}>
                        <td className="mono"><b>{t.customer}</b></td>
                        <td className="num">{t.open_incidents}</td>
                        <td className="num">{t.incidents}</td>
                        <td className="num">
                          {o ? o.critical : <span className="cc-tb__na">—</span>}
                        </td>
                        <td className="num">
                          {o ? o.sla_risk : <span className="cc-tb__na">—</span>}
                        </td>
                        <td className="num">
                          {o ? o.unassigned : <span className="cc-tb__na">—</span>}
                        </td>
                        <td>
                          <button className="cx-pill"
                                  data-testid={`xdr-clients-enter-${t.customer}`}
                                  onClick={(e) => { e.stopPropagation();
                                                    enter(t.customer); }}>
                            <ShieldCheck size={11} /> Enter scope
                          </button>
                          {denied?.tenantId === t.customer && (
                            <span className="cc-tb__na" style={{ marginLeft: 8 }}
                                  data-testid={`xdr-clients-denied-${t.customer}`}>
                              DENIED · {String(denied.detail?.code
                                || denied.detail?.reason || denied.detail)}
                            </span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            )}
          </div>
        </div>

        <div className="cc-card" data-testid="xdr-clients-groups">
          <div className="cc-card__h">
            <span className="cc-card__t">Tenant groups</span>
            <span className="cc-card__s">contract state, not a feature claim</span>
          </div>
          <div className="cc-card__b cc-card__b--pad">
            <div className="cc-empty" style={{ padding: 0 }}>
              <b>{scope?.tenant_groups?.state || "NOT EVALUATED"}</b>
              {scope?.tenant_groups?.reason ? ` — ${scope.tenant_groups.reason}` : ""}
            </div>
          </div>
        </div>
      </div>
    </XdrShell>
  );
}
