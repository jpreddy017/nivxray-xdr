/**
 * The customer/tenant a principal is BOUND to, shown as context.
 *
 * P0-FIX-4A · not a selector. A principal the server resolved to exactly
 * one customer has nothing to choose, so this states the customer and
 * offers no menu, no chevron and no click target. The value comes from
 * the server's `active_customer`, never from `?tenant=` or localStorage.
 */
import React from "react";
import { Building2 } from "lucide-react";

export default function CustomerContext({ label, tenantId, basis }) {
  return (
    <span className="pill" data-testid="nvf-customer-context"
          data-customer={tenantId || ""}
          data-customer-basis={basis || ""}
          data-selectable="false"
          title={tenantId || undefined}
          style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
      <span className="k">Customer</span>
      <Building2 size={11} color="var(--faint)" />
      <span className="mono"
            style={{ fontSize: 11, color: tenantId ? "var(--cyan)"
                                                   : "var(--faint)" }}>
        {label || tenantId || "◇ NOT RESOLVED"}
      </span>
    </span>
  );
}
