/**
 * P0-3 · the console half of blindness detection.
 *
 * The defect this closes is not a missing widget — it is that for months
 * the console could not tell an analyst the difference between
 * "this endpoint did nothing" and "we have not received anything from
 * this endpoint since September". Both rendered as an empty screen.
 *
 * Every token and every threshold shown here is READ FROM THE BACKEND
 * (`GET /api/edr/telemetry/freshness`). Nothing is computed in the
 * browser, because a UI-side timeout would be exactly the arbitrary
 * threshold this phase forbids.
 */
import React, { useEffect, useState } from "react";
import { Activity, AlertTriangle, EyeOff } from "lucide-react";

import { getTelemetryFreshness } from "@/nivxforge/edrApi";

const TONE = {
  DELIVERING:        { color: "var(--mint)",  Icon: Activity,      label: "DELIVERING" },
  STALE:             { color: "#ffb454",       Icon: AlertTriangle, label: "STALE" },
  BLIND_NO_DELIVERY: { color: "#ff6b6b",       Icon: EyeOff,        label: "BLIND · NO DELIVERY" },
};

const FLEET_TONE = {
  DELIVERING:           "var(--mint)",
  PARTIALLY_DELIVERING: "#ffb454",
  FLEET_BLIND:          "#ff6b6b",
  NEVER_DELIVERED:      "#ff6b6b",
  NO_ENROLLED_ENDPOINTS: "var(--faint)",
};

export const DeliveryChip = ({ delivery, testid = "edr-delivery-chip" }) => {
  if (!delivery) return null;
  const tone = TONE[delivery.state] || TONE.BLIND_NO_DELIVERY;
  const { Icon } = tone;
  return (
    <span className="nx-ep" data-testid={testid}
          data-delivery-state={delivery.state}
          data-delivery-basis={delivery.basis}
          title={delivery.statement || ""}
          style={{ color: tone.color, borderColor: tone.color,
                   display: "inline-flex", alignItems: "center", gap: 5,
                   fontSize: 9 }}>
      <Icon size={10} /> {tone.label}
      {delivery.delivery_age_s !== null
        && delivery.delivery_age_s !== undefined && (
        <span className="mono" style={{ opacity: 0.8 }}>
          · {delivery.delivery_age_s}s
        </span>)}
    </span>
  );
};

/** Fleet-wide truth about our own pipeline, plus the scoped endpoint. */
export const TelemetryFreshnessBanner = ({ endpoint = null }) => {
  const [state, setState] = useState({ loading: true, error: null, data: null });

  useEffect(() => {
    let cancelled = false;
    const load = () => getTelemetryFreshness(endpoint)
      .then((d) => !cancelled && setState({ loading: false, error: null, data: d }))
      .catch((e) => !cancelled && setState({
        loading: false, data: null,
        error: e?.response?.data?.detail || e.message || "unreachable" }));
    load();
    // Freshness is a clock-sensitive fact; a stale banner about staleness
    // would be its own defect.
    const t = setInterval(load, 30000);
    return () => { cancelled = true; clearInterval(t); };
  }, [endpoint]);

  const { loading, error, data } = state;
  if (loading) {
    return (
      <div className="x-empty" data-testid="edr-freshness-loading"
           style={{ textAlign: "left", padding: "8px 10px", fontSize: 11 }}>
        Reading telemetry freshness …
      </div>);
  }
  if (error) {
    return (
      <div className="x-empty" data-testid="edr-freshness-error"
           style={{ textAlign: "left", padding: "8px 10px", fontSize: 11,
                    color: "#ff9494" }}>
        TELEMETRY FRESHNESS UNAVAILABLE ({String(error)}) — the console
        cannot currently prove whether this product is receiving anything.
      </div>);
  }

  const fleet = data?.fleet;
  const scoped = (data?.endpoints || [])[0];
  const unresolved = data?.state === "ENDPOINT_NOT_RESOLVED";
  const color = FLEET_TONE[fleet?.state] || "var(--faint)";

  return (
    <div className="panel" data-testid="edr-freshness-banner"
         data-fleet-state={fleet?.state || "UNKNOWN"}
         data-endpoint-state={unresolved ? "ENDPOINT_NOT_RESOLVED"
                                         : (scoped?.delivery?.state || "NONE")}
         style={{ borderColor: color, padding: "10px 12px", marginBottom: 12 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10,
                    flexWrap: "wrap" }}>
        <span style={{ fontWeight: 800, letterSpacing: ".4px", fontSize: 10.5,
                       textTransform: "uppercase", color }}
              data-testid="edr-freshness-fleet-state">
          PIPELINE · {String(fleet?.state || "UNKNOWN").replace(/_/g, " ")}
        </span>
        {scoped && <DeliveryChip delivery={scoped.delivery}
                                 testid="edr-freshness-endpoint-chip" />}
        {unresolved && (
          <span className="nx-ep" data-testid="edr-freshness-endpoint-unresolved"
                data-delivery-state="ENDPOINT_NOT_RESOLVED"
                style={{ color: "var(--amber)", borderColor: "var(--amber)",
                         fontSize: 9 }}>
            ENDPOINT NOT RESOLVED · NO DELIVERY RECORD
          </span>)}
        <div style={{ flex: 1 }} />
        <span className="mono" style={{ fontSize: 10, color: "var(--faint)" }}
              data-testid="edr-freshness-counts">
          {fleet?.by_delivery_state?.DELIVERING ?? 0} delivering ·{" "}
          {fleet?.by_delivery_state?.STALE ?? 0} stale ·{" "}
          {fleet?.by_delivery_state?.BLIND_NO_DELIVERY ?? 0} blind ·{" "}
          {fleet?.enrolled ?? 0} enrolled
        </span>
      </div>
      <div style={{ marginTop: 6, fontSize: 11, color: "var(--text-dim)" }}
           data-testid="edr-freshness-statement">
        {fleet?.statement}
        {unresolved && (
          <span style={{ color: "var(--amber)" }}>
            {" "}This is the fleet answer for your scope — it says nothing
            about the identifier you supplied, which resolves to no enrolled
            endpoint, so no delivery record exists for it.
          </span>)}
      </div>
      {scoped && (
        <div style={{ marginTop: 4, fontSize: 10.5, color: "var(--muted)" }}
             data-testid="edr-freshness-endpoint-statement">
          <span className="mono">{scoped.hostname || scoped.endpoint_id}</span>
          {" · "}{scoped.delivery.basis}{" · "}{scoped.delivery.statement}
        </div>)}
      {scoped?.delivery?.thresholds && (
        <div style={{ marginTop: 4, fontSize: 10, color: "var(--faint)" }}
             data-testid="edr-freshness-thresholds">
          Thresholds derived from this sensor's own cadence
          {" ("}{scoped.delivery.thresholds.cadence_basis}
          {", "}{scoped.delivery.thresholds.report_interval_s}s{"): "}
          {scoped.delivery.thresholds.formula}
        </div>)}
      {fleet?.state !== "DELIVERING" && (
        <div style={{ marginTop: 6, fontSize: 10.5, color: "#ffb454" }}
             data-testid="edr-freshness-blindness-note">
          {data?.note}
        </div>)}
    </div>
  );
};

export default TelemetryFreshnessBanner;
