/**
 * The ONE place a structured refusal becomes readable text.
 *
 * The NivXRay control planes refuse with a structured body:
 *
 *     403 {"detail": {"code": "TENANT_NOT_FOUND", "reason": "…", "tenant_id": "…"}}
 *
 * Administration surfaces stored `detail` in state and rendered `{err}`. React
 * cannot render an object, so it threw #31 DURING RENDER, nothing caught it,
 * and React unmounted the tree — `/xdr/admin/collectors` and
 * `/xdr/admin/audit-log` went completely black on arrival in production. It
 * was invisible in preview because the preview registry still carries a
 * legacy `default` tenant, so those requests succeeded and the crash path was
 * never taken.
 *
 * PRESENTATION ONLY. This helper never retries, never substitutes a tenant,
 * never invents `"default"`, never widens scope to all tenants, never
 * fabricates an empty success and never softens an authorization result. A 403
 * stays a 403; it just stops blanking the screen. The authoritative sequence
 * AUTHENTICATION → PERMISSION → TENANT AUTHORITY → CAPABILITY is untouched.
 *
 * No credential, token, header or stack trace is ever surfaced: only the
 * server's own `code` and `reason`, which are written for operators.
 */

const REMEDY = {
  TENANT_REQUIRED:
    "Name the authoritative tenant on this surface — there is no default tenant.",
  TENANT_NOT_FOUND:
    "Use a registered tenant. Tenancy is established in the platform registry, never by this console.",
  TENANT_NOT_ACTIVE:
    "That tenant exists but is not ACTIVE.",
  ACCESS_DENIED:
    "This session is not authorised for that operation.",
  MACHINE_ACCESS_DENIED:
    "The presented machine credential is not authorised for that operation.",
  COLLECTOR_ROUTE_UNCLASSIFIED:
    "That collector operation is not classified, so it is refused by design.",
  COLLECTOR_AUTH_UNAVAILABLE:
    "The collector is running standalone, where no authority exists to authenticate against.",
  TEST_PLANE_DISABLED:
    "Synthetic injection is not enabled on this deployment.",
};

/** The server's refusal code, or "" when the failure was not structured. */
export function refusalCode(e) {
  const detail = e?.response?.data?.detail;
  if (detail && typeof detail === "object")
    return String(detail.code || detail.error || "");
  return "";
}

/** `CODE — reason · remedy`, always a string, never an object. */
export function refusalText(e, fallback = "Request failed.") {
  const detail = e?.response?.data?.detail;

  if (typeof detail === "string" && detail.trim()) return detail;

  if (detail && typeof detail === "object") {
    const code = detail.code || detail.error || "";
    const reason = detail.reason || detail.message || detail.detail || "";
    const head = [code, typeof reason === "string" ? reason : ""]
      .filter(Boolean).join(" — ");
    const remedy = REMEDY[code] ? ` ${REMEDY[code]}` : "";
    // Nothing recognisable: serialise rather than hand React an object.
    const body = head || JSON.stringify(detail);
    return body + remedy;
  }

  if (typeof detail === "number" || typeof detail === "boolean")
    return String(detail);

  return e?.message || fallback;
}

export default refusalText;
