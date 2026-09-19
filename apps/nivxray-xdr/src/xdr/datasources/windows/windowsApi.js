/**
 * Data Sources → Windows · authoritative read surface.
 *
 * Every value rendered by the Windows console comes from
 * `/api/xdr/windows/*`, which is computed server-side by
 * `services/windows_channel_truth.py`. Nothing is synthesised here and
 * nothing is combined: the five dimensions arrive independent and stay
 * independent.
 *
 * A measurement the platform does not make arrives as `null` and is
 * rendered `—` / `NOT AVAILABLE`. It is never rendered `0`.
 */
import api from "@/lib/api";

const unwrap = (res) => {
  const body = res?.data;
  if (body && body.ok === false) {
    const err = body.error || {};
    throw new Error(err.reason || err.code || "request failed");
  }
  return body?.data ?? body;
};

const fail = (e) => {
  const raw = e?.response?.data?.detail ?? e?.response?.data?.error
    ?? e?.message ?? e;
  if (typeof raw === "string") return raw;
  if (raw && typeof raw === "object") {
    return raw.reason || raw.code || raw.message || JSON.stringify(raw);
  }
  return String(raw);
};

async function get(path, params) {
  try {
    return unwrap(await api.get(path, { params }));
  } catch (e) {
    throw new Error(fail(e));
  }
}

export const getWindowsOverview = () => get("/xdr/windows/overview");
export const getWindowsChannels = () => get("/xdr/windows/channels");
export const getWindowsChannel = (channel) =>
  get(`/xdr/windows/channels/${encodeURIComponent(channel)}`);
export const getWindowsDevices = () => get("/xdr/windows/devices");
export const getWindowsDevice = (origin) =>
  get(`/xdr/windows/devices/${encodeURIComponent(origin)}`);
export const getWindowsCollectors = () => get("/xdr/windows/collectors");
export const getWindowsConfiguration = () => get("/xdr/windows/configuration");

/** Event Explorer · source-agnostic canonical event search. */
export const searchEvents = (params) => get("/xdr/events/search", params);
export const getEventFacets = () => get("/xdr/events/facets");
export const getEventDetail = (eventId) =>
  get(`/xdr/events/${encodeURIComponent(eventId)}`);

/** `—` for a measurement that was never taken. Never `0`. */
export const measured = (value) =>
  value === null || value === undefined ? "—" : String(value);

/** The tone each state carries. Mirrors the server vocabularies exactly. */
export const STATE_TONE = {
  RECEIVING: "ok",
  AVAILABLE: "ok",
  SUPPORTED: "ok",
  MATERIALISED: "ok",
  OBSERVED: "ok",
  MATCHED: "warn",
  PARTIAL: "warn",
  DEGRADED: "warn",
  "GAP DETECTED": "warn",
  CONFIGURED: "info",
  "NOT OBSERVED": "info",
  "NOT EVALUATED": "muted",
  "NOT CONFIGURED": "muted",
  "NOT AVAILABLE": "muted",
  "NOT PROVEN": "muted",
  "NOT ESTABLISHED": "muted",
  UNSUPPORTED: "muted",
  ERROR: "bad",
};
