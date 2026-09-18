/**
 * Scope Navigator — the console's tenant authority surface.
 *
 * Owner invariant:
 *     Effective Scope = Requested Scope ∩ Authorized Scope
 *
 * The control REQUESTS a scope through `POST /api/xdr/scope/select` and
 * renders only what the server returned. It never computes membership,
 * never shows a tenant the principal is not authorized for and never
 * prints "All Customers" (an estate claim); a multi-tenant principal is
 * scoped to **All Authorized Tenants**.
 *
 * Incident-bound investigations are LOCKED: when the authoritative
 * resolver answers `INHERITED_FROM_INCIDENT` the selector is disabled
 * and reads `TENANT · Incident locked`.
 */
import React, { useCallback, useEffect, useMemo, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { ChevronDown, Lock, Users } from "lucide-react";

import { useAuth } from "@/lib/auth";
import { getAuthorizedScope, selectScope, scopeLabel } from "@/lib/scopeApi";
import { activeTenant, setActiveTenant } from "@/lib/tenant";

/** The resource the current route binds scope to, if any. */
function useBoundIncident() {
  const { pathname } = useLocation();
  return useMemo(() => {
    const m = pathname.match(/^\/xdr\/incidents\/([^/?#]+)/);
    if (!m) return null;
    const id = m[1];
    if (id.startsWith("_")) return null;       // /xdr/incidents/_table
    return id;
  }, [pathname]);
}

export default function XdrScopeNavigator() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const incidentId = useBoundIncident();

  const [authorized, setAuthorized] = useState(null);
  const [eff, setEff] = useState(null);
  const [denied, setDenied] = useState(null);
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let live = true;
    getAuthorizedScope()
      .then((d) => { if (live) setAuthorized(d); })
      .catch((e) => {
        if (live) setAuthorized({ error: e?.response?.data?.detail || e?.message });
      });
    return () => { live = false; };
  }, []);

  /** Resolve the EFFECTIVE scope for the route we are on. Incident
   *  context wins: the server decides whether it locks. */
  const resolve = useCallback(async (request) => {
    setBusy(true); setDenied(null);
    try {
      const out = await selectScope({ ...request, incidentId });
      setEff(out);
      if (out?.basis === "INHERITED_FROM_INCIDENT") {
        setActiveTenant((out.tenant_ids || [])[0] || null);
      } else if (request.kind === "tenant") {
        setActiveTenant(request.tenantId);
      } else if (request.kind === "all_authorized") {
        setActiveTenant(null);
      }
      return out;
    } catch (e) {
      const d = e?.response?.data?.detail;
      setDenied(d || { code: "SCOPE_NOT_AUTHORIZED",
                       reason: e?.message || "scope could not be resolved" });
      setEff(null);
      return null;
    } finally { setBusy(false); }
  }, [incidentId]);

  useEffect(() => {
    // Incident context WINS. Sending a stored tenant selection alongside an
    // incident made the server answer SCOPE_LOCKED_TO_INCIDENT, which the
    // pill then printed as "NOT AUTHORIZED" — the analyst was authorized,
    // the scope was simply locked. Inside an incident we ask for the
    // authorized scope and let the resolver bind it to the incident.
    //
    // `resolve` is async: its return value is a Promise, and an effect may
    // only return a cleanup function. Returning it made React call
    // `destroy()` on a Promise, which threw and unmounted the whole shell.
    const t = activeTenant();
    const request = incidentId
      ? { kind: "all_authorized" }
      : (t ? { kind: "tenant", tenantId: t } : { kind: "all_authorized" });
    resolve(request);
  }, [resolve, incidentId]);

  // A denial that names the incident lock is a LOCK, not a loss of
  // authority — it is rendered as such.
  const lockDenied = denied
    && (denied.basis === "INHERITED_FROM_INCIDENT" || denied.locked);
  const locked = Boolean(eff?.locked) || Boolean(lockDenied);
  const label = lockDenied
    ? ((denied.tenant_ids || [])[0] || "◇ NOT RESOLVED")
    : denied ? "NOT AUTHORIZED" : scopeLabel(eff);
  const tenants = authorized?.tenants || [];

  const pick = async (tenantId) => {
    if (locked) return;
    const out = await resolve(tenantId
      ? { kind: "tenant", tenantId } : { kind: "all_authorized" });
    setOpen(false);
    if (out?.authorized) {
      // A scope change re-reads every scoped surface — navigate the
      // queue so the analyst sees the scope they just entered.
      navigate(tenantId
        ? `/xdr/incidents?customer=${encodeURIComponent(tenantId)}`
        : "/xdr/incidents");
    }
  };

  return (
    <div style={{ position: "relative" }} data-testid="xdr-scope-navigator">
      <button
        onClick={() => !locked && setOpen((v) => !v)}
        disabled={locked}
        aria-expanded={open}
        title={locked
          ? (eff?.lock_reason || "scope is locked to the incident's customer")
          : "Effective scope · resolved by the server from your authorization"}
        data-testid="xdr-tenant-pill"
        data-active-customer={(eff?.tenant_ids || [])[0] || ""}
        data-customer-basis={eff?.basis || denied?.basis || ""}
        data-scope-locked={locked || undefined}
        style={{ display: "flex", alignItems: "center", gap: 8,
                 background: "transparent", border: "none",
                 cursor: locked ? "default" : "pointer",
                 padding: "2px 2px 2px 6px", color: "var(--text)" }}
      >
        {locked ? <Lock size={14} style={{ opacity: .85 }} />
                : <Users size={15} style={{ opacity: .8 }} />}
        <span style={{ display: "flex", flexDirection: "column",
                       alignItems: "flex-start", lineHeight: 1.15,
                       maxWidth: 210 }}>
          <span style={{ fontSize: 11.5, fontWeight: 700, whiteSpace: "nowrap",
                         overflow: "hidden", textOverflow: "ellipsis",
                         maxWidth: 210 }}
                data-testid="xdr-tenant-pill-label">
            <span data-testid="xdr-scope-label">{label}</span>
            {locked && (
              <span style={{ fontWeight: 600, color: "var(--muted)" }}
                    data-testid="xdr-scope-lock-suffix">
                {" · Incident locked"}
              </span>
            )}
          </span>
          <span style={{ fontSize: 10, color: "var(--muted)",
                         whiteSpace: "nowrap", overflow: "hidden",
                         textOverflow: "ellipsis", maxWidth: 210 }}
                data-testid="xdr-principal">
            {user?.email || "—"}
          </span>
        </span>
        {!locked && <ChevronDown size={13} style={{ opacity: .7 }} />}
      </button>

      {open && !locked && (
        <div data-testid="xdr-scope-menu"
             style={{ position: "absolute", top: "calc(100% + 6px)", right: 0,
                      width: 330, zIndex: 1200, background: "var(--panel)",
                      border: "1px solid var(--border)", borderRadius: 6,
                      overflow: "hidden",
                      boxShadow: "0 18px 48px rgba(0,0,0,.45)" }}>
          <div style={{ fontSize: 9.2, letterSpacing: .7,
                        textTransform: "uppercase", padding: "8px 12px 6px",
                        color: "var(--muted)",
                        borderBottom: "1px solid var(--border)" }}>
            Effective scope · server-resolved
          </div>

          <div style={{ padding: "8px 12px", fontSize: 10.4,
                        color: "var(--muted)",
                        borderBottom: "1px solid var(--border)" }}
               data-testid="xdr-scope-basis">
            <span className="mono">{eff?.basis || denied?.basis || "UNRESOLVED"}</span>
            {eff?.basis_label ? ` · ${eff.basis_label}` : ""}
            {typeof eff?.authorized_count === "number" && (
              <> · {eff.authorized_count} authorized tenant(s)</>
            )}
          </div>

          <button onClick={() => pick(null)}
                  data-testid="xdr-scope-all-authorized"
                  style={{ display: "flex", width: "100%", gap: 8,
                           alignItems: "baseline", cursor: "pointer",
                           padding: "8px 12px", fontSize: 11.5,
                           background: "transparent", border: "none",
                           borderBottom: "1px solid var(--border)",
                           color: "var(--text)", textAlign: "left" }}>
            <span style={{ flex: 1, fontWeight: 700 }}>All Authorized Tenants</span>
            <span className="mono" style={{ fontSize: 10, color: "var(--faint)" }}>
              {authorized?.authorized_count ?? "—"}
            </span>
          </button>

          <div style={{ maxHeight: 260, overflowY: "auto" }}>
            {tenants.length === 0 && (
              <div style={{ fontSize: 11, padding: "10px 12px",
                            color: "var(--faint)" }}
                   data-testid="xdr-scope-no-tenants">
                ◇ no tenant is resolvable from your authorization
              </div>
            )}
            {tenants.map((t) => (
              <div key={t.customer} role="button" tabIndex={0}
                   onClick={() => pick(t.customer)}
                   onKeyDown={(e) => { if (e.key === "Enter") pick(t.customer); }}
                   data-testid={`xdr-scope-tenant-${t.customer}`}
                   style={{ display: "flex", alignItems: "baseline", gap: 10,
                            width: "100%", cursor: "pointer",
                            padding: "7px 12px", fontSize: 11.5,
                            color: "var(--text)" }}>
                <span style={{ flex: 1, minWidth: 0, overflow: "hidden",
                               textOverflow: "ellipsis",
                               whiteSpace: "nowrap" }}>
                  {t.customer}
                </span>
                <span className="mono" style={{ fontSize: 10,
                        color: "var(--faint)", flex: "0 0 auto" }}>
                  {t.open_incidents} open
                </span>
              </div>
            ))}
          </div>

          {(authorized?.tenant_groups?.state
            || denied) && (
            <div style={{ fontSize: 10, padding: "8px 12px",
                          color: "var(--faint)", lineHeight: 1.55,
                          borderTop: "1px solid var(--border)" }}
                 data-testid="xdr-scope-groups-state">
              {denied
                ? <>Scope denied · <span className="mono">
                    {denied.code || denied.basis}</span>
                    {denied.reason ? ` — ${denied.reason}` : ""}</>
                : <>Tenant groups ·{" "}
                    <span className="mono">
                      {authorized.tenant_groups.state}
                    </span>{" "}— {authorized.tenant_groups.reason}</>}
            </div>
          )}

          <button onClick={logout} data-testid="xdr-user-logout"
                  style={{ display: "flex", width: "100%", gap: 8,
                           alignItems: "center", cursor: "pointer",
                           padding: "8px 12px", fontSize: 11.5,
                           background: "transparent", border: "none",
                           borderTop: "1px solid var(--border)",
                           color: "var(--text-dim)" }}>
            <Lock size={11} /> Sign out
          </button>
        </div>
      )}

      {busy && (
        <span data-testid="xdr-scope-resolving"
              style={{ position: "absolute", inset: "auto 0 -14px auto",
                       fontSize: 9, color: "var(--faint)" }}>
          resolving…
        </span>
      )}
    </div>
  );
}
