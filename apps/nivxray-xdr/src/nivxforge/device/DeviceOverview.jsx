/**
 * Device Overview — one computer, entirely from recorded truth.
 *
 * Three independent dimensions are kept independent: enrolment,
 * credential and sensor state are different facts, and none of them
 * implies visibility. Telemetry freshness and detection counts come from
 * the platform's own authorities; a fact the record does not carry reads
 * unavailable rather than zero.
 */
import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";

import LinkedXdrIncidents from "@/nivxforge/components/LinkedXdrIncidents";
import { getComputer } from "@/nivxforge/onboardingApi";
import { listEndpointDetections } from "@/nivxforge/edrApi";
import { Ago, Kpi, NA, OpsTable, Refusal, Skeleton, StateChip }
  from "@/nivxforge/components/OpsPrimitives";
import { apiErrorText } from "@/xdr/nx/apiError";

export default function DeviceOverview({ endpointId }) {
  const nav = useNavigate();
  const [data, setData] = useState(null);
  const [dets, setDets] = useState(null);
  const [err, setErr] = useState(null);

  useEffect(() => {
    let live = true;
    setData(null); setErr(null); setDets(null);
    getComputer(endpointId, 24)
      .then((d) => { if (live) setData(d); })
      .catch((e) => { if (live) setErr(apiErrorText(e, "device unavailable")); });
    listEndpointDetections(endpointId, 24)
      .then((d) => { if (live) setDets(d); })
      .catch(() => { if (live) setDets({ detections: [], count: 0,
                                         state: "UNAVAILABLE" }); });
    return () => { live = false; };
  }, [endpointId]);

  if (err) {
    return <Refusal title="Device unavailable" body={err}
                    testid="edr-device-refusal" />;
  }
  if (!data) return <Skeleton rows={9} testid="edr-device-loading" />;

  const c = data.computer;
  const detRows = (dets?.detections || []).slice(0, 25);

  return (
    <div data-testid="edr-device-overview">
      <div className="kpi-rail">
        <Kpi label="Status" value={c.status.replace(/_/g, " ")}
             tone={c.status === "CONNECTED" ? "mint" : "amber"}
             title={c.status_basis} testid="edr-device-kpi-status" />
        <Kpi label="Detections · 24h" value={c.detections_24h}
             tone={c.detections_24h ? "red" : undefined}
             title={c.detections_basis} testid="edr-device-kpi-det24" />
        <Kpi label="Detections · total" value={c.detections_total}
             tone={c.detections_total ? "red" : undefined}
             testid="edr-device-kpi-dettotal" />
        <Kpi label="Events received" value={(c.telemetry?.event_count ?? 0)
               .toLocaleString()} testid="edr-device-kpi-events" />
        <Kpi label="Sensor" value={c.sensor_version}
             testid="edr-device-kpi-sensor" />
        <Kpi label="Prevention"
             value={c.protection?.prevention_enabled ? "ENABLED" : "NOT ENFORCED"}
             tone={c.protection?.prevention_enabled ? "mint" : "amber"}
             title={c.protection?.basis} testid="edr-device-kpi-prevention" />
      </div>

      <div className="ci-grid" style={{ alignItems: "start" }}>
        <div className="panel" style={{ padding: "12px 14px" }}>
          <div className="section-title" style={{ marginBottom: 9 }}>
            Why this status
          </div>
          <div className="basis" data-testid="edr-device-status-basis">
            {c.status_basis}
          </div>
          <div className="section-title" style={{ margin: "14px 0 8px" }}>
            Three independent dimensions
          </div>
          <div className="kv">
            <span className="k">Enrolment</span>
            <span className="v"><StateChip token={c.enrollment_state} /></span>
            <span className="k">Credential</span>
            <span className="v"><StateChip token={c.credential_state} /></span>
            <span className="k">Sensor</span>
            <span className="v"><StateChip token={c.sensor_state} /></span>
          </div>
          <div className="basis" style={{ marginTop: 10 }}>
            {data.status_contract}
          </div>
        </div>

        <div className="panel" style={{ padding: "12px 14px" }}>
          <div className="section-title" style={{ marginBottom: 9 }}>
            Computer
          </div>
          <div className="kv">
            <span className="k">Hostname</span>
            <span className="v">{c.hostname || <NA />}</span>
            <span className="k">Endpoint</span>
            <span className="v">{c.endpoint_id}</span>
            <span className="k">Operating system</span>
            <span className="v">{c.os || <NA />}</span>
            <span className="k">OS version</span>
            <span className="v">{c.os_version || <NA label="NOT REPORTED" />}</span>
            <span className="k">Architecture</span>
            <span className="v">{c.architecture || <NA label="NOT REPORTED" />}</span>
            <span className="k">Group</span>
            <span className="v">{c.group || <NA label="NOT ASSIGNED" />}</span>
            <span className="k">Policy</span>
            <span className="v">{c.policy || <NA label="NOT ASSIGNED" />}</span>
            <span className="k">Enrolled</span>
            <span className="v"><Ago iso={data.enrolment?.enrolled_at} /></span>
            <span className="k">Device identity</span>
            <span className="v">
              {data.enrolment?.device_iid || <NA label="NOT MINTED" />}
            </span>
          </div>
          {c.unavailable_fields?.length ? (
            <div className="basis" style={{ marginTop: 10 }}
                 data-testid="edr-device-unavailable-fields">
              Not reported by this sensor:{" "}
              {c.unavailable_fields.join(", ")}. These are absent facts, not
              defaults.
            </div>
          ) : null}
        </div>

        <div className="panel" style={{ padding: "12px 14px" }}>
          <div className="section-title" style={{ marginBottom: 9 }}>
            Telemetry
          </div>
          <div className="kv">
            <span className="k">Last telemetry</span>
            <span className="v"><Ago iso={c.telemetry?.last_telemetry_at} /></span>
            <span className="k">Last heartbeat</span>
            <span className="v"><Ago iso={c.telemetry?.last_heartbeat_at} /></span>
            <span className="k">Declared cadence</span>
            <span className="v">
              {c.telemetry?.report_interval_seconds
                ? `${c.telemetry.report_interval_seconds}s`
                : <NA label="NOT DECLARED" />}
            </span>
            <span className="k">Queued at sensor</span>
            <span className="v">
              {c.telemetry?.queue_depth_at_sensor ?? <NA label="NOT REPORTED" />}
            </span>
            <span className="k">Last detection</span>
            <span className="v"><Ago iso={c.last_detection_at} /></span>
          </div>
          <div style={{ marginTop: 12, display: "flex", gap: 8, flexWrap: "wrap" }}>
            <button className="btn" data-testid="edr-device-go-trajectory"
                    onClick={() => nav(
                      `/edr/computers/${encodeURIComponent(endpointId)}/trajectory`)}>
              Device Trajectory
            </button>
            <button className="btn" data-testid="edr-device-go-commands"
                    onClick={() => nav(
                      `/edr/computers/${encodeURIComponent(endpointId)}/commands`)}>
              Command Intelligence
            </button>
          </div>
        </div>
      </div>

      <div style={{ marginTop: 14 }}>
        <LinkedXdrIncidents device={endpointId} />
      </div>

      <div style={{ marginTop: 14 }}>
        <div className="section-title" style={{ marginBottom: 7 }}>
          Detections on this computer · last 24 hours
        </div>
        {!dets ? <Skeleton rows={4} /> : null}
        {dets && detRows.length === 0 ? (
          <div className="x-empty" data-testid="edr-device-detections-empty">
            {dets.state === "UNAVAILABLE"
              ? "The endpoint detection projection could not be read."
              : `No rule matched on this computer in the last 24 hours. `
                + `${dets.events_evaluated ?? 0} event(s) were evaluated and `
                + `${dets.events_not_evaluated ?? 0} were NOT evaluated — a `
                + `detection gap is not an absence of malicious activity.`}
          </div>
        ) : null}
        {detRows.length ? (
          <OpsTable
            testid="edr-device-detections"
            rows={detRows}
            rowKey={(r) => r.raw_id}
            initialSort={{ key: "detected_at", dir: -1 }}
            columns={[
              { key: "detected_at", label: "Detected",
                render: (r) => <Ago iso={r.detected_at} /> },
              { key: "rule_ids", label: "Rules",
                sortValue: (r) => (r.rule_ids || []).join(","),
                render: (r) => (r.rule_ids?.length
                  ? <span className="chipline">
                      {r.rule_ids.map((x) => (
                        <span className="chip mint" key={x}>{x}</span>))}
                    </span>
                  : <NA label="NOT CITED" />) },
              { key: "verdict", label: "Verdict",
                render: (r) => <StateChip token={r.verdict} tone="warn" /> },
              { key: "command_line", label: "Command line", width: "42%",
                render: (r) => (
                  <span className="mono" title={r.command_line}
                        style={{ display: "block", maxWidth: 520,
                                 overflow: "hidden",
                                 textOverflow: "ellipsis" }}>
                    {r.command_line || <NA label="NOT OBSERVED" />}
                  </span>) },
              { key: "trust_state", label: "Evidence trust",
                render: (r) => <StateChip token={r.trust_state} tone="ok" /> },
            ]} />
        ) : null}
        {dets?.note ? (
          <div className="basis" style={{ marginTop: 9 }}>{dets.note}</div>
        ) : null}
      </div>
    </div>
  );
}
