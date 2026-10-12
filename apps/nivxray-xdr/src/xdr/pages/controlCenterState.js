// A rows projection is not the tenant authorization inventory.
// Never turn denied, unavailable or malformed responses into an empty result.
export function projectionState(body) {
  if (body == null) return "loading";
  if (body.status === 401 || body.status === 403) return "denied";
  if (body.error || body.source === "unavailable") return "unavailable";
  if (body.source === "empty") return "no_scope";
  if (!Array.isArray(body.rows)) return "unavailable";
  return body.rows.length ? "ready" : "empty";
}
