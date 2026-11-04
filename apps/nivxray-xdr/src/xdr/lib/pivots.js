/**
 * Y3.1 · one canonical pivot builder for BOTH products.
 *
 * Reference behaviour (Cisco XDR docs): clicking an observable opens an
 * object-oriented menu whose actions are grouped by verb —
 * `deliberate` (reputation/disposition), `observe` (sightings),
 * `respond` (enforcement) and `refer` (external references).
 *
 * This module owns every pivot URL in the platform so the carried
 * context cannot drift between call sites. It grants nothing: each
 * destination re-authorises the customer, endpoint, incident and
 * evidence identity server-side.
 */
import { buildEdrPivot } from "@/xdr/components/OpenInEdr";

/** Observable typing from the value itself — a hint for routing, never a
 *  claim about the thing. */
export const observableType = (value) => {
  const v = String(value ?? "").trim();
  if (!v) return null;
  if (/^[a-fA-F0-9]{64}$/.test(v)) return "SHA256";
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return "IP";
  if (/^(inc_[a-f0-9]+|INC\d+)$/i.test(v)) return "INCIDENT";
  if (/^(raw_|cev_|evt_)/.test(v)) return "EVIDENCE";
  if (/^proc_/.test(v)) return "PROCESS";
  if (/^(dev_|ep_)/.test(v)) return "ENDPOINT";
  if (/^[\\/]/.test(v)) return "FILE_PATH";
  if (/^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(v)) return "DOMAIN_OR_HOST";
  return "TEXT";
};

/** OBSERVE · where has this platform actually seen it. Tenant-scoped by
 *  the server; no index of its own. */
export const buildSightingsPivot = (value) =>
  `/xdr/search?q=${encodeURIComponent(String(value))}`;

export const buildFileTrajectoryPivot = (key) =>
  `/xdr/intelligence/files/${encodeURIComponent(String(key))}`;

export const buildProcessTreePivot = ({ device, processIid }) =>
  `/edr/process-tree?device=${encodeURIComponent(device || "")}`
  + (processIid ? `&process_iid=${encodeURIComponent(processIid)}` : "");

export const buildIncidentPivot = (id) =>
  `/xdr/incidents/${encodeURIComponent(String(id))}`;

export { buildEdrPivot };

/** Capabilities this platform does NOT have. Named, so the menu can say
 *  so instead of offering an action that goes nowhere. */
export const ABSENT = {
  reputation: "no threat-intelligence enricher is configured, so no "
              + "reputation or disposition can be asserted",
  externalRefer: "no external reference source (relay) is registered",
  enforcement: "no response driver is registered for this observable type",
  detonation: "dynamic detonation is not configured — static only",
};
