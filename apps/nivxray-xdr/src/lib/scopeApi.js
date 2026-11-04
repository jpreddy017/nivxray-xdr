/**
 * Authoritative TENANT SCOPE client (A0.5 contracts).
 *
 *   ScopeSelection is CLIENT INTENT.  EffectiveScope is SERVER TRUTH.
 *   EffectiveScope = RequestedScope ∩ AuthorizedScope
 *
 * This module REQUESTS a scope and reports what the server DETERMINED.
 * It never computes a scope, never unions anything, never invents a
 * tenant group and has no `"default"`. A 403 is an answer, not an error
 * to work around.
 */
import api from "@/lib/api";

/** C1 · which scopes this principal may enter. */
export async function getAuthorizedScope() {
  const { data } = await api.get("/xdr/scope/authorized");
  return data?.data || null;
}

/** C2 · resolve a requested scope into the authoritative EffectiveScope. */
export async function selectScope({ kind = "all_authorized", tenantId = null,
                                    incidentId = null } = {}) {
  const body = { kind };
  if (tenantId) body.tenant_id = tenantId;
  if (incidentId) body.incident_id = incidentId;
  const { data } = await api.post("/xdr/scope/select", body);
  return data?.data || null;
}

/** A0.5-5 · which consoles the verified principal may enter, and why. */
export async function getConsoleAccess() {
  const { data } = await api.get("/xdr/scope/console");
  return data?.data || null;
}

/** Analyst wording for an EffectiveScope. Presentation only — `basis`
 *  stays the authoritative reason and is always rendered beside it. */
export function scopeLabel(eff) {
  if (!eff) return "◇ SCOPE NOT RESOLVED";
  if (!eff.authorized) return "NOT AUTHORIZED";
  const ids = eff.tenant_ids || [];
  if (eff.basis === "INHERITED_FROM_INCIDENT") return ids[0] || "◇ NOT RESOLVED";
  if (eff.basis === "CROSS_TENANT_ROLE_NO_SINGLE_CUSTOMER"
      || eff.basis === "MULTIPLE_AUTHORIZED_TENANTS") {
    return "All Authorized Tenants";
  }
  if (ids.length === 1) return ids[0];
  if (ids.length > 1) return "All Authorized Tenants";
  return "◇ SCOPE NOT RESOLVED";
}
