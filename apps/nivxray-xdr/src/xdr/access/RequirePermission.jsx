import React from "react";
import { invalidateSecurity } from "@/lib/securityState";
import { useAccess } from "./AccessProvider";
import { permissionState } from "./routePermissions";

export function PermissionNotice({ state, label = "this page", retryable = true }) {
  const access = useAccess();
  return <div className="nx-page" role="alert" data-testid={`route-${state}`}>
    {state === "loading" ? "Checking authorization …"
      : state === "denied" ? `You are not authorized for ${label}`
      : "Authorization unavailable. This page has not loaded sensitive data."}
    {state === "unavailable" && retryable && <button onClick={() => access.refresh()}>Retry authorization</button>}
    {state === "denied" && <button onClick={() => invalidateSecurity("permission")}>Recheck access</button>}
  </div>;
}
export default function RequirePermission({ anyOf, label, children }) {
  const state = permissionState(useAccess(), anyOf);
  return state === "allowed" ? children : <PermissionNotice state={state} label={label} retryable={anyOf !== null} />;
}
