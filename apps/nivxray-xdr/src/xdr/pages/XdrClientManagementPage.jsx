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
import { apiErrorText } from "@/xdr/nx/apiError";
import { NxDataTable, opsLabel } from "@/xdr/nx";

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
      setError(apiErrorText(e, "Failed to load."));
    }
    try {
      setOps(await getMssCustomerOperations());
    } catch (e) {
      setOps({ error: apiErrorText(e) });
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
      setDenied({ tenantId, detail: apiErrorText(e) });
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
              {scope?.principal?.email || opsLabel("NOT_ESTABLISHED")}
            </span>
          </span>
          <span className="cc-cond__i">
            <span className="cc-cond__k">Basis</span>
            <span className="cc-cond__v" data-testid="xdr-clients-basis">
              {scope?.basis || opsLabel("NOT_ESTABLISHED")}
            </span>
          </span>
          <span className="cc-cond__i">
            <span className="cc-cond__k">Authorized tenants</span>
            <span className="cc-cond__v">
              {typeof scope?.authorized_count === "number"
                ? scope.authorized_count : opsLabel("NOT_AVAILABLE")}
            </span>
          </span>
          <span className="cc-cond__i">
            <span className="cc-cond__k">Cross-tenant role</span>
            <span className="cc-cond__v"
                  data-state={scope?.cross_tenant_role ? "warn" : "ok"}>
              {scope ? (scope.cross_tenant_role ? "Yes" : "No")
                : opsLabel("NOT_EVALUATED")}
            </span>
          </span>
        </div>

        {error && (
          <div className="cc-card"><div className="cc-empty"
               data-testid="xdr-clients-error">
            <b>Not authorized, or not available</b> — {String(
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
                <b>No client in scope</b> — your identity resolves to no
                authorized tenant. There is no default tenant: an unresolved
                scope is a denial, never a substitution.
              </div>
            )}
            {(scope?.tenants || []).length > 0 && (
              <NxDataTable rows={scope.tenants || []} pageSize={25}
                           searchPlaceholder="Search client"
                           rowKey={(t) => t.customer}
                           onRowClick={(t) => navigate(t.queue_href)}
                           testid="xdr-clients-table"
                           emptyTitle="No client in scope"
                           columns={[
                { key: "customer", header: "Client", width: "220px",
                  value: (t) => t.customer,
                  render: (t) => (
                    <strong className="nx-mono"
                            data-testid={`xdr-clients-row-${t.customer}`}>
                      {t.customer}
                    </strong>) },
                { key: "open", header: "Open", width: "90px", align: "right",
                  value: (t) => t.open_incidents },
                { key: "incidents", header: "Incidents", width: "100px",
                  align: "right", value: (t) => t.incidents },
                { key: "critical", header: "Critical", width: "95px",
                  align: "right",
                  value: (t) => opsBy[t.customer]?.critical ?? -1,
                  render: (t) => (opsBy[t.customer]
                    ? opsBy[t.customer].critical
                    : <span className="nx-absent">—</span>) },
                { key: "sla_risk", header: "SLA risk", width: "95px",
                  align: "right",
                  value: (t) => opsBy[t.customer]?.sla_risk ?? -1,
                  render: (t) => (opsBy[t.customer]
                    ? opsBy[t.customer].sla_risk
                    : <span className="nx-absent">—</span>) },
                { key: "unassigned", header: "Unassigned", width: "110px",
                  align: "right",
                  value: (t) => opsBy[t.customer]?.unassigned ?? -1,
                  render: (t) => (opsBy[t.customer]
                    ? opsBy[t.customer].unassigned
                    : <span className="nx-absent">—</span>) },
                { key: "scope", header: "Scope", width: "230px",
                  sortable: false,
                  render: (t) => (
                    <span>
                      <button className="nx-btn"
                              data-testid={`xdr-clients-enter-${t.customer}`}
                              onClick={(e) => { e.stopPropagation();
                                                enter(t.customer); }}>
                        <ShieldCheck size={11} /> Enter scope
                      </button>
                      {denied?.tenantId === t.customer && (
                        <span className="nx-absent" style={{ marginLeft: 8 }}
                              data-testid={`xdr-clients-denied-${t.customer}`}>
                          Denied · {String(denied.detail?.code
                            || denied.detail?.reason || denied.detail)}
                        </span>
                      )}
                    </span>) },
              ]} />
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
              <b>{opsLabel(scope?.tenant_groups?.state
                || "NOT_EVALUATED")}</b>
              {scope?.tenant_groups?.reason ? ` — ${scope.tenant_groups.reason}` : ""}
            </div>
          </div>
        </div>
      </div>
    </XdrShell>
  );
}
