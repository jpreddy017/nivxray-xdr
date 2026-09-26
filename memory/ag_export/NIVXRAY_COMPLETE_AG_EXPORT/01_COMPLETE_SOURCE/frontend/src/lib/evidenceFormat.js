/**
 * formatEvidence — render-safe projection of the P0.2 structured evidence
 * chain ({source, event_or_rule, field, observed_value, evidence_ref,
 * confidence}) into a readable string. Accepts string | record | record[].
 * Never returns an object (raw objects crash React as children).
 */
export function formatEvidence(ev) {
  if (ev == null) return "";
  if (typeof ev === "string") return ev;
  if (Array.isArray(ev)) return ev.map(formatEvidence).filter(Boolean).join("  ·  ");
  if (typeof ev === "object") {
    if (ev.event_or_rule || ev.observed_value != null) {
      const bits = [];
      if (ev.event_or_rule) bits.push(String(ev.event_or_rule));
      if (ev.field && ev.observed_value != null) bits.push(`${ev.field}=${ev.observed_value}`);
      else if (ev.observed_value != null) bits.push(String(ev.observed_value));
      if (ev.confidence) bits.push(`confidence:${ev.confidence}`);
      if (ev.evidence_ref) bits.push(`[${ev.evidence_ref}]`);
      return bits.join(" · ");
    }
    try { return JSON.stringify(ev); } catch { return String(ev); }
  }
  return String(ev);
}

/** Array-of-records view for per-line rendering; wraps non-arrays. */
export function evidenceRecords(ev) {
  if (ev == null) return [];
  return Array.isArray(ev) ? ev : [ev];
}
