/**
 * EdrTrajectoryResolver · `/edr/trajectory`
 *
 * P0 · 2026-09-05 · owner-authorised.
 *
 * `/edr/trajectory` was linked from seven call sites but was never
 * registered as a route, so React Router matched `<Route path="*">` and
 * bounced every click to the Incident Queue.  This resolver ends that
 * silent fall-through WITHOUT creating a second trajectory canvas:
 * `/xdr/endpoints/:device/trajectory` remains the single authoritative
 * surface and this component only resolves an identity and redirects.
 *
 * Resolution order (never fabricated):
 *   1. ?device_iid=   → authoritative endpoint entity IID
 *   2. ?device=       → IID or hostname, matched case-insensitively
 *   3. ?incident_id=  → the incident's projected endpoint entity
 *   4. nothing resolvable → explicit ⊘ CAPABILITY UNAVAILABLE state
 */
import React, { useEffect, useState } from "react";
import { Navigate, useSearchParams, Link } from "react-router-dom";
import { Loader2, Radar } from "lucide-react";

import XdrShell from "@/xdr/XdrShell";
import { listEndpoints } from "@/nivxforge/edrApi";

export default function EdrTrajectoryResolver() {
  const [params] = useSearchParams();
  const [state, setState] = useState({ status: "resolving" });

  const deviceIid  = params.get("device_iid");
  const device     = params.get("device");
  const incidentId = params.get("incident_id");
  const rule       = params.get("rule");

  useEffect(() => {
    let cancel = false;
    const ref = deviceIid || device;

    (async () => {
      try {
        const data = await listEndpoints();
        const rows = data.endpoints || [];
        let match = null;

        if (ref) {
          const needle = String(ref).trim().toLowerCase();
          match = rows.find((r) =>
            String(r.device_iid || "").toLowerCase() === needle ||
            String(r.hostname  || "").toLowerCase() === needle ||
            String(r.device_ref || "").toLowerCase() === needle);
        }
        if (!match && incidentId) {
          match = rows.find((r) =>
            (r.case_ids || []).includes(incidentId) ||
            r.latest_incident_id === incidentId);
        }

        if (cancel) return;
        if (match) {
          setState({ status: "resolved", ref: match.device_ref });
        } else {
          setState({ status: "unresolved", candidates: rows.length });
        }
      } catch (e) {
        if (!cancel) {
          setState({
            status: "unresolved",
            error: e?.response?.data?.detail || e?.message,
            candidates: 0,
          });
        }
      }
    })();
    return () => { cancel = true; };
  }, [deviceIid, device, incidentId]);

  if (state.status === "resolved") {
    const qs = new URLSearchParams();
    if (incidentId) qs.set("incident_id", incidentId);
    if (rule) qs.set("rule", rule);
    const suffix = qs.toString() ? `?${qs.toString()}` : "";
    return (
      <Navigate
        replace
        to={`/xdr/endpoints/${encodeURIComponent(state.ref)}/trajectory${suffix}`}
      />
    );
  }

  return (
    <XdrShell>
      {state.status === "resolving" && (
        <div className="x-empty" data-testid="edr-trajectory-resolving">
          <Loader2 size={13} className="spin"
                    style={{ verticalAlign: "middle", marginRight: 6 }} />
          Resolving endpoint entity …
        </div>
      )}
      {state.status === "unresolved" && (
        <section className="panel" style={{ padding: 18 }}
                  data-testid="edr-trajectory-unresolved">
          <div className="nx-ep" data-ep="capability_unavailable" data-known="true"
                style={{ marginBottom: 10 }}>
            ⊘ CAPABILITY UNAVAILABLE — NO ENDPOINT ENTITY
          </div>
          <h1 className="page-h1" style={{ margin: "0 0 8px" }}>
            Device Trajectory could not be opened
          </h1>
          <div style={{ color: "var(--text-dim)", fontSize: 11.5,
                          lineHeight: 1.7, maxWidth: 720 }}>
            No authoritative endpoint entity could be resolved from the
            reference supplied to this link.
            {ReferenceLine({ deviceIid, device, incidentId })}
            NivXRay does not synthesise a device identity, so the canvas is
            not opened rather than shown against a fabricated host.
            {typeof state.candidates === "number" && (
              <div style={{ marginTop: 8 }}>
                <span className="mono" style={{ color: "var(--faint)" }}>
                  {state.candidates} endpoint entit
                  {state.candidates === 1 ? "y" : "ies"} are currently
                  projected for your tenant scope.
                </span>
              </div>
            )}
            {state.error && (
              <div className="mono" style={{ marginTop: 8, color: "#ff9494",
                                                  fontSize: 10.5 }}>
                {String(state.error)}
              </div>
            )}
          </div>
          <div style={{ marginTop: 14, display: "flex", gap: 8 }}>
            <Link to="/xdr/endpoints" className="btn primary"
                    style={{ padding: "5px 10px", textDecoration: "none" }}
                    data-testid="edr-trajectory-unresolved-endpoints">
              <Radar size={11} /> Open Endpoint Inventory
            </Link>
            {incidentId && (
              <Link to={`/xdr/incidents/${incidentId}`} className="btn"
                      style={{ padding: "5px 10px", textDecoration: "none" }}
                      data-testid="edr-trajectory-unresolved-incident">
                Back to Incident
              </Link>
            )}
          </div>
        </section>
      )}
    </XdrShell>
  );
}

function ReferenceLine({ deviceIid, device, incidentId }) {
  const parts = [];
  if (deviceIid) parts.push(`device_iid=${deviceIid}`);
  if (device) parts.push(`device=${device}`);
  if (incidentId) parts.push(`incident_id=${incidentId}`);
  if (!parts.length) {
    return (
      <div className="mono" style={{ marginTop: 8, color: "var(--faint)",
                                          fontSize: 10.5 }}>
        No device_iid, device or incident_id was supplied.
      </div>
    );
  }
  return (
    <div className="mono" style={{ marginTop: 8, color: "var(--faint)",
                                        fontSize: 10.5 }}>
      Reference: {parts.join(" · ")}
    </div>
  );
}
