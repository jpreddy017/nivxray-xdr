/**
 * The acting customer, as a STATE a tenant-scoped surface can act on.
 *
 * The backend has no default customer: `routers.edr_tenancy` refuses a
 * tenant-scoped read with `TENANT_REQUIRED` when the request names none.
 * That refusal is correct, so the console must not produce it — it must not
 * issue the request until a customer is actually resolved.
 *
 * Four distinct states, because an analyst must never be shown "the backend
 * failed" for any of the last three:
 *   PENDING · the server's customer authority has not answered yet
 *   NONE    · resolved, and this principal has selected no customer
 *   SEALED  · the authority could not be established — fail closed
 *   READY   · a customer is resolved and may be named on a request
 *
 * This changes WHEN the browser asks, never WHO may see what: the server
 * re-authorises the tenant on every single request.
 */
import { useEffect, useState } from "react";

import {
  TENANT_BOUND_EVENT, activeTenant, tenantAuthorityResolved,
  tenantAuthoritySealed,
} from "@/lib/tenant";

export const CUSTOMER_PENDING = "PENDING";
export const CUSTOMER_NONE = "NONE";
export const CUSTOMER_SEALED = "SEALED";
export const CUSTOMER_READY = "READY";

export function readActingCustomer() {
  if (!tenantAuthorityResolved()) {
    return { state: CUSTOMER_PENDING, tenant: null };
  }
  if (tenantAuthoritySealed()) {
    return { state: CUSTOMER_SEALED, tenant: null };
  }
  const tenant = activeTenant();
  return tenant
    ? { state: CUSTOMER_READY, tenant }
    : { state: CUSTOMER_NONE, tenant: null };
}

export function useActingCustomer() {
  const [value, setValue] = useState(readActingCustomer);
  useEffect(() => {
    const sync = () => setValue((prev) => {
      const next = readActingCustomer();
      return (prev.state === next.state && prev.tenant === next.tenant)
        ? prev : next;
    });
    window.addEventListener(TENANT_BOUND_EVENT, sync);
    sync();                       // the console may have bound before we mounted
    return () => window.removeEventListener(TENANT_BOUND_EVENT, sync);
  }, []);
  return value;
}
