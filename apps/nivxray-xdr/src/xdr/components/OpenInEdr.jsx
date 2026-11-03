/**
 * Y2 · M-4 · the XDR → EDR product pivot.
 *
 * NivXRay XDR and NivXForge EDR are peer products, so moving between
 * them is an explicit act with an explicit control — not an
 * indistinguishable in-app tab change. One component builds the link
 * everywhere so the carried context can never drift between call sites:
 *
 *   customer/tenant · organization · endpoint · incident · detection ·
 *   evidence (raw + canonical) · timestamp · process identity · time range
 *
 * Context is CARRIED, never granted: the EDR side re-authorises every
 * one of these server-side, and an identifier the caller was not
 * entitled to simply fails closed there. Nothing secret travels in the
 * URL — a tenant id and an endpoint id are names, not permissions.
 *
 * The incident stays OPEN: this opens EDR in a new browser tab, so the
 * analyst keeps the XDR incident they were reading and can work both
 * independently.
 */
import React from "react";
import { ExternalLink } from "lucide-react";

import { isCrossOrigin, productHref } from "@/productOrigins";

export const EDR_TRAJECTORY_PATH = "/edr/device-trajectory";

/**
 * Resolve the ONE endpoint this record is about.
 *
 * Two different identities on one record is ambiguity, not a choice to
 * make silently — opening the wrong device's trajectory during an
 * investigation is worse than opening nothing.
 */
export function resolveEndpoint({ device, endpointId } = {}) {
  const names = [device, endpointId]
    .map((v) => (v == null ? "" : String(v).trim()))
    .filter(Boolean);
  const unique = [...new Set(names)];
  if (unique.length === 0) return { endpoint: null, reason: "NO_ENDPOINT" };
  if (unique.length > 1) {
    return { endpoint: null, reason: "AMBIGUOUS_ENDPOINT", candidates: unique };
  }
  return { endpoint: unique[0], reason: null };
}

/** The deep link, or why it cannot honestly be offered. */
export function buildEdrTrajectoryLink(ctx = {}) {
  const { endpoint, reason, candidates } = resolveEndpoint(ctx);
  if (!endpoint) return { href: null, reason, candidates };

  const p = new URLSearchParams();
  const put = (k, v) => {
    const s = v == null ? "" : String(v).trim();
    if (s) p.set(k, s);
  };
  put("device", endpoint);
  put("incident_id", ctx.incidentId);
  put("detection_id", ctx.detectionId);
  put("raw_event_id", ctx.rawEventId);
  put("canonical_event_id", ctx.canonicalEventId);
  put("event", ctx.eventIid);
  put("process_iid", ctx.processIid);
  put("at", ctx.at);
  // The range the incident is actually about, so the canvas opens on the
  // evidence rather than on "the last 24 hours" of an unrelated present.
  put("time_start", ctx.timeStart);
  put("time_end", ctx.timeEnd);
  // Names the customer to act in. The EDR side adopts it only after the
  // SERVER authorises this principal for it, and re-authorises every
  // request after that — so it can never widen scope.
  put("tenant", ctx.tenant);

  const qs = p.toString();
  return {
    href: productHref("edr", `${EDR_TRAJECTORY_PATH}${qs ? `?${qs}` : ""}`),
    reason: null,
    crossOrigin: isCrossOrigin("edr"),
  };
}

/** Back-compatible string form. */
export const buildEdrPivot = (ctx) =>
  buildEdrTrajectoryLink(ctx).href || EDR_TRAJECTORY_PATH;

const NOTE = {
  NO_ENDPOINT: "This record names no endpoint, so there is nothing to open.",
  AMBIGUOUS_ENDPOINT: "This record names more than one endpoint, so NivXRay "
    + "will not guess which trajectory you meant.",
};

export default function OpenInEdr({ label = "Open in NivXRay EDR",
                                    compact = false, disabledReason,
                                    testid = "open-in-edr", ...ctx }) {
  const { href, reason, candidates } = buildEdrTrajectoryLink(ctx);

  if (!href) {
    // Say which fact is missing rather than offering a control that would
    // open somebody else's trajectory.
    return (
      <span data-testid={`${testid}-unavailable`}
            data-reason={reason}
            title={candidates?.length
              ? `${NOTE[reason]} Candidates: ${candidates.join(" · ")}`
              : NOTE[reason]}
            style={{ fontSize: 10, color: "var(--faint)" }}>
        {reason === "AMBIGUOUS_ENDPOINT"
          ? "◇ more than one endpoint on this record"
          : "◇ no endpoint on this record"}
      </span>
    );
  }

  if (disabledReason) {
    return (
      <span data-testid={`${testid}-disabled`} title={disabledReason}
            style={{ fontSize: 10, color: "var(--faint)" }}>
        ◇ {compact ? "EDR" : label} unavailable
      </span>
    );
  }

  return (
    <a data-testid={testid}
       data-target={ctx.device || ctx.endpointId}
       data-incident={ctx.incidentId || ""}
       data-cross-origin={String(Boolean(isCrossOrigin("edr")))}
       href={href}
       target="_blank"
       rel="noopener noreferrer"
       onClick={(e) => e.stopPropagation()}
       title={"Opens the NivXRay EDR Device Trajectory for this customer, "
              + "endpoint, incident and time range in a new tab. This "
              + "incident stays open here."}
       className="btn ghost"
       style={{ display: "inline-flex", alignItems: "center", gap: 6,
                textDecoration: "none",
                fontSize: compact ? 10 : 11,
                padding: compact ? "3px 8px" : "5px 11px" }}>
      {compact ? "EDR" : label}
      <ExternalLink size={compact ? 9 : 10} aria-hidden="true" />
      <span className="sr-only">(opens in a new tab)</span>
    </a>
  );
}
