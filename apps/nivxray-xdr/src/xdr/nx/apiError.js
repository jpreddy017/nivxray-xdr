/**
 * ONE reader for a backend refusal.
 *
 * NivXRay fails closed, so `detail` is frequently a STRUCTURE
 * (`{code, reason, basis, risk, fail_closed}`) — not a string. Handing that
 * object to React crashed whole pages ("Objects are not valid as a React
 * child"), and because every page mounts its own shell it took the
 * navigation down with it (DataSources, Exposure).
 *
 * This returns the analyst sentence the refusal actually is, so an
 * authorization decision reads as one instead of as an empty dataset.
 */
export function apiErrorText(x, fallback = "request failed") {
  const d = x?.response?.data?.detail;
  if (d && typeof d === "object") {
    const code = d.code || d.error || "NOT AUTHORIZED";
    const bits = [
      d.reason || d.message,
      d.basis ? `basis ${d.basis}` : null,
      d.requested_tenant ? `tenant ${d.requested_tenant}` : null,
      d.risk ? `risk ${d.risk}` : null,
    ].filter(Boolean);
    return `${code}${bits.length ? ` — ${bits.join(" · ")}` : ""}`;
  }
  if (typeof d === "string" && d) return d;
  if (typeof x === "string" && x) return x;
  return x?.message || fallback;
}

export default apiErrorText;
