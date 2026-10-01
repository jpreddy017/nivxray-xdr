/**
 * P0-2C · the console half of the endpoint-identity invariant.
 *
 * The backend now says `ENDPOINT_NOT_RESOLVED` when an identifier was
 * supplied but resolves to no endpoint the principal may see. That
 * honesty is worth nothing if the page renders it as "0 records", which
 * is visually identical to a real endpoint that genuinely has none —
 * the exact ambiguity the sweep exists to remove.
 *
 * `notResolved(payload)` reads the invariant's own state field; it never
 * infers unresolved from an empty collection, because an empty
 * collection is a legitimate answer for a resolved endpoint.
 */
import React from "react";
import { ShieldAlert } from "lucide-react";

export const ENDPOINT_NOT_RESOLVED = "ENDPOINT_NOT_RESOLVED";

export const notResolved = (payload) => {
  if (!payload) return false;
  const s = payload.state || payload.reason
            || payload?.epistemic_state?.state;
  return String(s || "") === ENDPOINT_NOT_RESOLVED;
};

export const EndpointNotResolved = ({ supplied, payload,
                                      testid = "edr-endpoint-not-resolved" }) => (
  <div className="x-empty" data-testid={testid}
       data-state={ENDPOINT_NOT_RESOLVED}
       style={{ borderColor: "var(--amber)", textAlign: "left" }}>
    <div style={{ display: "flex", alignItems: "center", gap: 8,
                  fontWeight: 800, color: "var(--amber)" }}>
      <ShieldAlert size={13} /> {ENDPOINT_NOT_RESOLVED}
    </div>
    <div style={{ marginTop: 6 }}>
      No endpoint that this identifier resolves to.{" "}
      {supplied && (
        <>The reference <span className="mono"
                              data-testid={`${testid}-ref`}>{supplied}</span>{" "}
        was not resolved under your authorisation.</>
      )}
    </div>
    <div style={{ marginTop: 6, fontSize: 10.5, color: "var(--faint)" }}>
      {payload?.note
       || "This is an authorisation or identity outcome, not a statement "
          + "about the evidence. Nothing is claimed about any endpoint, "
          + "and no record was searched."}
    </div>
  </div>
);

export default EndpointNotResolved;
