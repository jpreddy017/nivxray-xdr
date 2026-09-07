/**
 * Y2 · M-4 · the XDR → EDR product pivot.
 *
 * NivXRay XDR and NivXForge EDR are peer products, so moving between
 * them is an explicit act with an explicit control — not an
 * indistinguishable in-app tab change. One component builds the link
 * everywhere so the carried context can never drift between call sites:
 *
 *   customer/tenant · organization · endpoint · incident · detection ·
 *   evidence (raw + canonical) · timestamp · process identity
 *
 * Context is CARRIED, never granted: the EDR side re-authorises every
 * one of these server-side, and an identifier the caller was not
 * entitled to simply fails closed there.
 */
import React from "react";
import { useNavigate } from "react-router-dom";
import { ExternalLink } from "lucide-react";

export const buildEdrPivot = ({
  device, endpointId, incidentId, detectionId, rawEventId,
  canonicalEventId, eventIid, processIid, at, tenant,
} = {}) => {
  const p = new URLSearchParams();
  const put = (k, v) => { if (v) p.set(k, String(v)); };
  put("device", device || endpointId);
  put("incident_id", incidentId);
  put("detection_id", detectionId);
  put("raw_event_id", rawEventId);
  put("canonical_event_id", canonicalEventId);
  put("event", eventIid);
  put("process_iid", processIid);
  put("at", at);
  // Declared for traceability only. The EDR side reads the customer off
  // the server-resolved session/incident, never off this parameter.
  put("tenant", tenant);
  const qs = p.toString();
  return `/edr/device-trajectory${qs ? `?${qs}` : ""}`;
};

export default function OpenInEdr({ label = "Open in NivXForge EDR",
                                    compact = false, disabledReason,
                                    testid = "open-in-edr", ...ctx }) {
  const navigate = useNavigate();
  const target = ctx.device || ctx.endpointId;

  if (!target) {
    // No endpoint identity on the record — say so rather than offering a
    // button that would open somebody's trajectory at random.
    return (
      <span data-testid={`${testid}-unavailable`}
            title="This record names no endpoint, so there is nothing to open"
            style={{ fontSize: 10, color: "var(--faint)" }}>
        ◇ no endpoint on this record
      </span>
    );
  }

  return (
    <button data-testid={testid}
            data-target={target}
            data-incident={ctx.incidentId || ""}
            disabled={Boolean(disabledReason)}
            title={disabledReason
              || "Opens the NivXForge EDR Device Trajectory with this "
                 + "customer, endpoint, incident and evidence context"}
            onClick={(e) => { e.stopPropagation();
                              navigate(buildEdrPivot(ctx)); }}
            className="btn ghost"
            style={{ display: "inline-flex", alignItems: "center", gap: 6,
                     fontSize: compact ? 10 : 11,
                     padding: compact ? "3px 8px" : "5px 11px" }}>
      {compact ? "EDR" : label}
      <ExternalLink size={compact ? 9 : 10} />
    </button>
  );
}
