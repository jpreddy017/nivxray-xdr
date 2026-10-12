import { activeTenant, setActiveTenant } from "./tenant";
/** Apply only a server-authorized single-customer selection; never relabel a locked context. */
export function applyCustomerSelection(result, requested) {
  if (!requested || !result?.authorized || !result.tenant_ids?.includes(requested)) {
    throw Object.assign(new Error("Customer scope was not authorized"), { code: "SCOPE_NOT_AUTHORIZED" });
  }
  setActiveTenant(requested);
  if (activeTenant() !== requested) {
    throw Object.assign(new Error("Customer context is locked"), { code: "SCOPE_LOCKED" });
  }
  return requested;
}
