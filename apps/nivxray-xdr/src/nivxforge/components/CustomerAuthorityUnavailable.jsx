/**
 * P0-FIX-4B · the fail-closed state for tenant-bound EDR content.
 *
 * When the authoritative customer context cannot be established, the
 * console says so and renders nothing customer-bound. It does not name a
 * customer, does not guess one, and does not show the one the browser was
 * acting as a moment ago.
 */
import React from "react";
import { ShieldAlert, RotateCw } from "lucide-react";

export default function CustomerAuthorityUnavailable({ onRetry, retrying }) {
  return (
    <section className="card" data-testid="nvf-customer-authority-unavailable"
             style={{ maxWidth: 620, margin: "48px auto", padding: 22 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
        <ShieldAlert size={15} color="var(--amber)" />
        <h2 style={{ margin: 0, fontSize: 13, letterSpacing: ".08em" }}>
          CUSTOMER AUTHORITY UNAVAILABLE
        </h2>
      </div>
      <p style={{ fontSize: 13, color: "var(--muted)", marginTop: 12 }}>
        Unable to establish the authorized customer context. No endpoint,
        detection, event or trajectory data is shown, because the platform
        will not display customer data it cannot attribute to an authorized
        customer.
      </p>
      <button className="btn" data-testid="nvf-customer-authority-retry"
              onClick={onRetry} disabled={retrying}
              style={{ marginTop: 6, display: "inline-flex",
                       alignItems: "center", gap: 6 }}>
        <RotateCw size={12} />
        {retrying ? "Retrying…" : "Retry"}
      </button>
    </section>
  );
}
