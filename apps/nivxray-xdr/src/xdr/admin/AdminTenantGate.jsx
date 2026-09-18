/**
 * Administration · TENANT GATE.
 *
 * A0.5 made the control plane fail closed: an unresolved tenant is a
 * denial, never the literal tenant `"default"`. Administration surfaces
 * must therefore state which customer they are administering.
 *
 * The tenant list is SERVER-RESOLVED from the A0.5 contract
 * `GET /api/xdr/scope/authorized`. This component never invents a tenant,
 * never defaults to one, and grants nothing — the server still resolves
 * and authorizes the effective scope on every request.
 */
import React, { useEffect, useState } from "react";
import { Building2, Lock } from "lucide-react";
import api from "@/lib/api";
import { activeTenant, setActiveTenant } from "@/lib/tenant";
import { refusalText } from "@/lib/refusal";

export default function AdminTenantGate({ label = "this surface", children }) {
  const [tenant, setTenant] = useState(() => activeTenant() || "");
  const [scope, setScope] = useState(null);
  const [err, setErr] = useState(null);

  useEffect(() => {
    (async () => {
      try {
        const r = await api.get("/xdr/scope/authorized");
        const d = r?.data?.data || null;
        setScope(d);
        // Exactly one authorized tenant → the server has already resolved
        // it; adopt it rather than asking a pointless question.
        const only = d?.tenants?.length === 1 ? d.tenants[0].customer : null;
        if (!activeTenant() && only) {
          setActiveTenant(only);
          setTenant(only);
        }
      } catch (e) {
        setErr(refusalText(e, "authorized scope unavailable"));
      }
    })();
  }, []);

  const choose = (v) => {
    setActiveTenant(v || null);
    setTenant(v || "");
  };

  const options = scope?.tenants || [];

  return (
    <div data-testid="xdr-admin-tenant-gate" data-tenant={tenant || "none"}>
      <div style={{
        display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap",
        padding: "8px 12px", marginBottom: 12,
        border: "1px solid var(--nx-divider, #E7E5E4)",
        borderRadius: 4, background: "var(--nx-inset, #F7F7F6)",
        fontSize: 12,
      }}>
        <Building2 size={13} style={{ color: "var(--nx-purple, #6D4EE0)" }} />
        <span style={{ fontSize: 10, letterSpacing: ".08em",
                             textTransform: "uppercase",
                             color: "var(--nx-faint, #9CA3AF)" }}>
          Administering
        </span>
        <select
          data-testid="xdr-admin-tenant-select"
          value={tenant}
          onChange={(e) => choose(e.target.value)}
          style={{
            padding: "4px 8px", fontSize: 12, borderRadius: 4,
            border: "1px solid var(--nx-divider-strong, #D6D3D1)",
            background: "var(--nx-elevated, #fff)",
            color: "var(--nx-text, #111827)",
          }}>
          <option value="">— select a customer —</option>
          {options.map((t) => (
            <option key={t.customer} value={t.customer}>{t.customer}</option>
          ))}
        </select>
        {scope?.basis && (
          <span data-testid="xdr-admin-tenant-basis"
                title={`Resolution basis: ${scope.basis}`}
                style={{ color: "var(--nx-muted, #6B7280)" }}>
            {scope.basis_label}
          </span>
        )}
        {err && (
          <span data-testid="xdr-admin-tenant-error"
                style={{ color: "var(--nx-critical, #991B1B)" }}>{err}</span>
        )}
      </div>

      {tenant
        ? <div key={tenant}>{children}</div>
        : (
          <div data-testid="xdr-admin-tenant-required"
               data-state="TENANT_REQUIRED"
               style={{
                 padding: "18px 20px", borderRadius: 6,
                 border: "1px solid var(--nx-divider, #E7E5E4)",
                 background: "var(--nx-elevated, #fff)",
                 color: "var(--nx-text-dim, #4B5563)", fontSize: 13,
               }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8,
                                 fontWeight: 600,
                                 color: "var(--nx-text, #111827)" }}>
              <Lock size={13} /> Select a customer to continue
            </div>
            <div style={{ marginTop: 8 }}>
              {label} is tenant-scoped. There is no default customer, so
              NivXRay will not guess one — choose the customer you are
              administering above. The server resolves and authorizes the
              effective scope for every request.
            </div>
          </div>
        )}
    </div>
  );
}
