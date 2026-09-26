/**
 * NivXRay Capability Registry — frontend consumer.
 *
 * Loads the machine-readable inventory from ``docs/NIVXRAY_CAPABILITY_REGISTRY.json``
 * and exposes typed helpers so any XDR surface can render an honest
 * "AVAILABLE IN NIVXRAY — XDR ADAPTER NOT YET CONNECTED" banner when a
 * base capability is not yet wired.  Adopt before invent, surfaced in UI.
 */
import registry from "../../docs/NIVXRAY_CAPABILITY_REGISTRY.json";

export const CAPABILITIES  = registry.capabilities;
export const PRINCIPLE     = registry.principle;

export function getCapability(id) {
  return CAPABILITIES.find((c) => c.id === id) || null;
}
export function statusOf(id) {
  const c = getCapability(id);
  if (!c) return "NOT_IMPLEMENTED";
  return c.status;
}
export function isConnected(id) {
  return String(statusOf(id)).toUpperCase().startsWith("CONNECTED");
}

/**
 * honestyBanner
 *   → `null`               capability is CONNECTED (nothing to warn about)
 *   → `{ kind, text }`     banner to render
 *
 * Kinds:
 *   not_wired          — base exposes it, XDR adapter not connected
 *   base_only          — deliberately not surfaced in XDR analyst UI
 *   external           — requires an external dependency / standard
 *   not_present        — verified absent from base after code inspection
 *   not_implemented    — capability id unknown to the registry
 */
export function honestyBanner(id) {
  const c = getCapability(id);
  if (!c) return {
    kind: "not_implemented",
    text: `NOT IMPLEMENTED · capability "${id}" is not in the registry`,
  };
  const s = String(c.status).toUpperCase();
  if (s.startsWith("CONNECTED")) return null;
  if (s === "ADOPT" || s === "EXTEND" || s === "ADAPT") return {
    kind: "not_wired",
    text: `AVAILABLE IN NIVXRAY — XDR ADAPTER NOT YET CONNECTED · `
             + `${c.name} lives in ${c.base_api || c.source}.  Wire via ${c.adoption}.`,
  };
  if (s === "BASE_ONLY") return {
    kind: "base_only",
    text: `AVAILABLE IN NIVXRAY — analyst surface intentionally not built in XDR · `
             + `${c.name} lives in ${c.base_api || c.source}.`,
  };
  if (s === "NOT_PRESENT") return {
    kind: "not_present",
    text: `NOT PRESENT IN NIVXRAY — verified absent after code inspection · ${c.name}.`,
  };
  if (s === "EXTERNAL") return {
    kind: "external",
    text: `EXTERNAL DEPENDENCY REQUIRED · ${c.name}`,
  };
  return { kind: "not_implemented", text: `${c.name}: ${c.status}` };
}
