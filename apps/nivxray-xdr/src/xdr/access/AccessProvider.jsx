/**
 * AccessProvider · the SPA's ONE authorization adapter.
 *
 * Owner directive §23/§24/§27:
 *   · navigation and in-page actions derive from EFFECTIVE PERMISSIONS,
 *     never from a hard-coded `role === "admin"` check;
 *   · hiding a control is UX, not security — the backend stays authoritative;
 *   · the frontend is never the authorization authority.
 *
 * Contract: `GET /api/xdr/rbac/me/effective` — a self-scoped projection of the
 * existing RBAC resolver. It returns `{permissions[], roles[], groups[],
 * scopes[], cross_tenant, basis}`.
 *
 * Three-valued logic, deliberately:
 *   can(p) === true   the contract says ALLOWED
 *   can(p) === false  the contract says NOT AUTHORIZED
 *   can(p) === null   the contract is UNAVAILABLE — we do not know
 *
 * `null` must never be silently coerced. A caller that hides a destination on
 * `null` would black out the console on a transient failure; a caller that
 * shows a dangerous control on `null` relies on the backend's 403. So:
 * navigation treats `null` as visible, mutating controls surface it as
 * "authorization unavailable", and the backend rejects regardless.
 */
import React, { createContext, useCallback, useContext, useEffect,
                useMemo, useState, useRef } from "react";
import api from "@/lib/api";
import { activeTenant } from "@/lib/tenant";
import { securitySnapshot, subscribeSecurity } from "@/lib/securityState";

const Ctx = createContext(null);

/** Basis values that mean "resolved, and the answer is an empty set". */
const RESOLVED_BASES = new Set([
  "CROSS_TENANT_ADMIN_ROLE", "TENANT_SCOPED_RBAC_GRANT",
  "USER_NOT_PROVISIONED", "USER_DISABLED", "NO_TENANT_SCOPE",
]);

export function effectivePermission(state, perm, tenant = activeTenant()) {
  if (!state.available || (tenant && state.data?.tenant
      && !state.data?.cross_tenant && tenant !== state.data.tenant)) return null;
  if (!perm) return true;
  return (state.data?.permissions || []).includes(perm);
}

export function AccessProvider({ children }) {
  const [state, setState] = useState({
    loading: true, available: false, error: null, data: null,
  });

  const generation = useRef(0);
  const load = useCallback(async () => {
    const ticket = ++generation.current;
    setState({ loading: true, available: false, error: null, data: null });
    try {
      const { data } = await api.get("/xdr/rbac/me/effective");
      if (ticket !== generation.current) return;
      const d = data?.data || null;
      setState({
        loading: false,
        available: !!d && RESOLVED_BASES.has(d.basis),
        error: null,
        data: d,
      });
    } catch (e) {
      if (ticket !== generation.current) return;
      setState({
        loading: false, available: false, data: null,
        error: e?.response?.data?.detail?.reason
            || e?.response?.status
            || e?.message || "unavailable",
      });
    }
  }, []);

  useEffect(() => {
    const refresh = () => {
      ++generation.current;
      const reason = securitySnapshot().reason;
      // While a reload is about to run the answer is UNRESOLVED, not "denied":
      // publishing `loading: false` first makes every guard render its refusal
      // for a frame before the contract has even been asked.
      const willLoad = !!localStorage.getItem("nvx_token")
        && !["expired", "denied"].includes(reason);
      setState({ loading: willLoad, available: false,
                 error: willLoad ? null : reason, data: null });
      if (willLoad) load();
    };
    refresh();
    const unsubscribe = subscribeSecurity(refresh);
    return () => { ++generation.current; unsubscribe(); };
  }, [load]);

  const value = useMemo(() => {
    const can = (perm) => effectivePermission(state, perm);
    /** true when EVERY listed permission is allowed; null if any is unknown. */
    const canAll = (list) => {
      const r = (list || []).map(can);
      if (r.some((x) => x === null)) return null;
      return r.every(Boolean);
    };
    /** true when ANY listed permission is allowed; null if unknown. */
    const canAny = (list) => {
      const r = (list || []).map(can);
      if (r.some((x) => x === true)) return true;
      if (r.some((x) => x === null)) return null;
      return false;
    };
    return {
      loading: state.loading,
      available: state.available,
      error: state.error,
      basis: state.data?.basis || null,
      note: state.data?.note || null,
      principal: state.data?.principal || null,
      tenant: state.data?.tenant || null,
      crossTenant: !!state.data?.cross_tenant,
      roles: state.data?.roles || [],
      groups: state.data?.groups || [],
      groupsConferAccess: state.data?.groups_confer_access ?? null,
      scopes: state.data?.scopes || [],
      permissions: state.data?.permissions || [],
      can, canAll, canAny, refresh: load,
    };
  }, [state, load]);

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAccess() {
  return useContext(Ctx) || {
    loading: false, available: false, error: "provider-missing",
    basis: null, note: null, principal: null, tenant: null,
    crossTenant: false, roles: [], groups: [], scopes: [], permissions: [],
    can: () => null, canAll: () => null, canAny: () => null,
    refresh: () => {},
  };
}

export default AccessProvider;
