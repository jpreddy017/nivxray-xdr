import React, { useState, useRef, useEffect } from "react";
import { activeTenant, tenantIsSwitchable } from "@/lib/tenant";
import { selectScope } from "@/lib/scopeApi";
import { applyCustomerSelection } from "@/lib/customerSelection";
import { createRequestFence } from "@/lib/requestFence";

/** Retain the existing text control, but authorize committed edits before fetching another customer. */
export default function CustomerContextInput({ onApplied, ...props }) {
  const [draft, setDraft] = useState(() => activeTenant() || "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const fence = useRef(createRequestFence());
  useEffect(() => () => fence.current.cancel(), []);
  const commit = async () => {
    const tenant = draft.trim();
    if (tenant === activeTenant()) return;
    const ticket = fence.current.begin();
    setBusy(true); setError(null);
    try {
      const result = await selectScope({ kind: "tenant", tenantId: tenant });
      if (!fence.current.current(ticket)) return;
      const selected = applyCustomerSelection(result, tenant);
      onApplied?.(selected);
    } catch (err) {
      if (fence.current.current(ticket)) {
        setDraft(activeTenant() || ""); setError(err.message || "Customer selection failed");
      }
    } finally { if (fence.current.current(ticket)) setBusy(false); }
  };
  return <>
    <input {...props} value={draft} aria-label="Customer context" aria-invalid={!!error}
      disabled={busy || !tenantIsSwitchable()} onChange={(e) => setDraft(e.target.value)}
      onBlur={commit} onKeyDown={(e) => { if (e.key === "Enter") e.currentTarget.blur(); }} />
    {error && <span role="alert">{error}</span>}
  </>;
}
