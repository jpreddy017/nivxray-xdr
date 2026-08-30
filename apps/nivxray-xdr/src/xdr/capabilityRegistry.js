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
  if (s === "EXTERNAL") return {
    kind: "external",
    text: `EXTERNAL DEPENDENCY REQUIRED · ${c.name}`,
  };
  return { kind: "not_implemented", text: `${c.name}: ${c.status}` };
}
