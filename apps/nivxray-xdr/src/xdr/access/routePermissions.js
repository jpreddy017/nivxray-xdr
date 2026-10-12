/** Existing backend RBAC resource/action names, never role-label checks.
 * null marks an unresolved capability mapping, not unrestricted access.
 * Core read mappings use the backend catalogue; they do not certify backend enforcement.
 */
export const ADMIN_PERMISSIONS = {
  overview: ["platform.read"], "audit-log": ["audit.read"], secrets: ["secrets.read"],
  "content-pack-lolbas": ["lolbas.read"], "capability-hub": ["extensions.read"],
  "detection-registry": ["detections.read"], "correlation-rules": ["correlation.read"],
  engines: ["engines.read"], corpus: null, integrations: ["data_sources.read"],
  "data-sources": ["data_sources.read"], "ingest-routing": ["data_sources.read"],
  collectors: ["collectors.read"], agents: null, "telemetry-studio": null,
  "telemetry-health": ["collectors.read"], parsers: ["parsers.read"],
  normalization: ["normalization.read"], "response-policies": null,
  "intelligence-policy": ["intelligence_policy.read"], "users-roles": ["users.read", "roles.read"],
  "api-keys": ["api_keys.read"], "api-webhooks": ["webhooks.read"],
  "response-strategies": ["response.read"], "platform-health": ["platform.read"],
  "edr-enrollment": null, "edr-response": null, "edr-capability-truth": null,
};
export function routePermissions(pathname) {
  if (pathname === "/xdr/intelligence/mitre") return null; // XDR-S1 not integrated/reviewed.
  if (!pathname.startsWith("/xdr/")) return undefined; // EDR keeps its existing product gate.
  if (pathname === "/xdr/admin" || pathname.startsWith("/xdr/admin/")) {
    return ADMIN_PERMISSIONS[pathname.split("/")[3] || "overview"] ?? null;
  }
  if (/^\/xdr\/(incidents|control-center|mss-dashboard|_ux0)/.test(pathname)) return ["incidents.read"];
  if (/^\/xdr\/investigations/.test(pathname)) return ["investigations.read"];
  if (/^\/xdr\/evidence/.test(pathname)) return ["evidence.read"];
  if (/^\/xdr\/(hunting|search|events)/.test(pathname)) return ["threat_hunting.read"];
  if (/^\/xdr\/(clients|client-management)/.test(pathname)) return ["tenants.read"];
  if (/^\/xdr\/reports/.test(pathname)) return ["reports.read"];
  if (/^\/xdr\/data-sources/.test(pathname)) return ["data_sources.read"];
  if (/^\/xdr\/(detections|detect\/tuning|rule-studio)/.test(pathname)) return ["detections.read"];
  if (pathname.startsWith("/xdr/respond/approvals")) return ["response.approve"];
  if (pathname.startsWith("/xdr/respond/")) return ["playbooks.read"];
  if (/^\/xdr\/(intelligence|kb)/.test(pathname)) return ["intel.read"];
  // Assets, exposure, docs and legacy EDR pivots have no compatible page capability
  // projection yet. Their existing authenticated/tenant backend boundaries remain.
  return undefined;
}
export function permissionState(access, permissions) {
  if (permissions === undefined) return "allowed";
  if (access.loading) return "loading";
  if (permissions === null) return "unavailable";
  const decision = access.canAny(permissions);
  return decision === true ? "allowed" : decision === false ? "denied" : "unavailable";
}

export function consolePermissions(pathname) {
  if (pathname === "/xdr/admin" || pathname.startsWith("/xdr/admin/")) return ["console.admin.access"];
  if (pathname === "/xdr/docs") return ["console.soc.access", "console.admin.access"];
  if (pathname.startsWith("/xdr/")) return ["console.soc.access"];
  return undefined; // Existing EDR host/session boundary is retained.
}
