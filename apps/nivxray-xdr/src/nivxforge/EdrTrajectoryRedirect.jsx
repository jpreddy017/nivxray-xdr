/**
 * Y1 · D-2 · permanent compatibility redirect.
 *
 * `/xdr/edr/device-trajectory` was the canonical route while the two
 * products were merged, and every proven deep link in the programme
 * (detection handoffs, incident pivots, search results, the P0-F.13.5
 * and Detection Attribution proofs) points at it. It therefore lives
 * FOREVER, and it must carry the whole context across — tenant,
 * organization/customer, endpoint, incident, detection, evidence/event,
 * timestamp and process identity — because a redirect that drops a
 * query parameter silently downgrades an exact handoff into a guess.
 */
import React from "react";
import { Navigate, useLocation } from "react-router-dom";

export default function EdrTrajectoryRedirect() {
  const { search, hash } = useLocation();
  return (
    <Navigate replace
              to={`/edr/device-trajectory${search || ""}${hash || ""}`} />
  );
}
