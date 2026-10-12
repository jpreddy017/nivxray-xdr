import { useEffect, useState, useSyncExternalStore } from "react";
import { securitySnapshot, subscribeSecurity } from "@/lib/securityState";
import { activeTenant } from "@/lib/tenant";
import { startScopedRead } from "./scopedRead";

export default function useScopedRead(read, key, enabled = true) {
  const privacy = useSyncExternalStore(subscribeSecurity, securitySnapshot, securitySnapshot);
  const context = JSON.stringify([key, activeTenant(), privacy.epoch]);
  const blocked = ["denied", "expired", "session"].includes(privacy.reason);
  const [record, setRecord] = useState(null);
  useEffect(() => {
    if (!enabled || blocked) return;
    const request = startScopedRead(read, result => setRecord({ ...result, context }));
    return request.cancel;
  }, [read, context, enabled, blocked]);
  // Hide old data in the render BEFORE effects run, including already-completed reads.
  if (blocked) return { context, data: null, loading: false, error: new Error("Search or investigation unavailable: access or session changed.") };
  if (!enabled) return { context, data: null, loading: false, error: null };
  return record?.context === context ? record : { context, data: null, loading: true, error: null };
}
