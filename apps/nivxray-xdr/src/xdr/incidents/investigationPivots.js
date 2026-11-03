/**
 * investigationPivots · the ONE pivot contract for the investigation.
 *
 * A pivot is a navigation with CONTEXT: the incident that justified it, the
 * entity or artifact it is about and, where the target supports it, the time
 * window. Tenant is never carried in a URL — the session is the tenant
 * authority and the target surface resolves it server-side — so a pivot can
 * never be used to widen scope.
 *
 * Each builder returns `{ to, label, why }` or `null`. `null` means the
 * platform cannot honestly offer that pivot for this entity: the control is
 * then not rendered, rather than navigating somewhere unrelated.
 */

const enc = encodeURIComponent;

import { buildEdrTrajectoryLink } from "@/xdr/components/OpenInEdr";

/** Event Explorer reads `q · host · channel · event_id · user · process`. */
export function pivotRelatedEvents(entity, incident) {
  if (!entity?.value) return null;
  const key = { device: "host", server: "host", user: "user",
                process: "process", command: "process" }[entity.kind] || "q";
  const qs = new URLSearchParams({ [key]: entity.value });
  return {
    to: `/xdr/events?${qs.toString()}`,
    label: "Related events",
    why: `Canonical events where ${key} = ${entity.value}`,
  };
}

/** Hunting reads `q`. Task 5 builds the surface; this is the contract. */
export function pivotHunt(entity, incident) {
  if (!entity?.value) return null;
  const qs = new URLSearchParams({ q: entity.value });
  if (incident?.id) qs.set("incident", incident.id);
  return {
    to: `/xdr/hunting?${qs.toString()}`,
    label: "Hunt this entity",
    why: "Interrogate the estate for this entity outside this incident",
  };
}

/** IOC Intelligence reads `q` (+ `incident_id`). Observables only. */
export function pivotIocIntelligence(entity, incident) {
  if (!entity?.value) return null;
  if (!["hash", "ip", "domain", "url"].includes(entity.kind)) return null;
  const qs = new URLSearchParams({ q: entity.value });
  if (incident?.id) qs.set("incident_id", incident.id);
  return {
    to: `/xdr/intelligence/iocs?${qs.toString()}`,
    label: "IOC intelligence",
    why: "Reputation and attribution for this observable",
  };
}

/** Device / process trajectory — endpoint identity is required.
 *
 *  This one LEAVES the product: Device Trajectory is a NivXForge EDR
 *  surface. It opens in a new tab so the incident being read here stays
 *  open, and it carries the customer, the incident and the incident's
 *  time range so the canvas opens on the evidence rather than on an
 *  unrelated present. EDR re-authorises every one of those server-side.
 */
export function pivotTrajectory(entity, incident) {
  const device = entity?.kind === "device" || entity?.kind === "server"
    ? (entity.id || entity.value) : null;
  if (!device) return null;
  const { href } = buildEdrTrajectoryLink({
    device,
    incidentId: incident?.id,
    tenant: incident?.tenant,
    timeStart: incident?.created_at,
    timeEnd: incident?.updated_at,
  });
  return {
    to: href,
    label: "Process / device trajectory",
    why: "Endpoint event stream for this device in NivXForge EDR, anchored on "
       + "this incident — opens in a new tab, this incident stays open",
    newTab: true,
    product: "edr",
  };
}

/** Detection → the evidence that substantiates it (stays in-workspace). */
export function pivotDetectionEvidence(ruleId, incident) {
  if (!ruleId || !incident?.id) return null;
  return {
    to: `/xdr/incidents/${incident.id}?tab=evidence&detection=${enc(ruleId)}`,
    label: "Supporting evidence",
    why: `Canonical evidence rows that matched ${ruleId}`,
  };
}

/** Evidence → the activity it appears in (stays in-workspace). */
export function pivotEvidenceActivity(evidenceId, incident) {
  if (!evidenceId || !incident?.id) return null;
  return {
    to: `/xdr/incidents/${incident.id}?tab=activity&evidence=${enc(evidenceId)}`,
    label: "Related activity",
    why: "Where this evidence row appears in the incident's activity",
  };
}

/** Every pivot the platform can honestly offer for one entity. */
export function pivotsFor(entity, incident) {
  return [pivotRelatedEvents(entity, incident),
          pivotTrajectory(entity, incident),
          pivotIocIntelligence(entity, incident),
          pivotHunt(entity, incident)].filter(Boolean);
}
