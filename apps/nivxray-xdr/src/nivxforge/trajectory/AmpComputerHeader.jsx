/**
 * Computer card — the Cisco Secure Endpoint Device Trajectory computer
 * panel, reproduced from NivXForge's authoritative endpoint record:
 *
 *   ▼ <hostname> in group <group>            <compromise summary>
 *   ▶ <isolation state>
 *   ┌ two-column attribute table ─────────────────────────────────┐
 *   │ Related Compromise Events │ Vulnerabilities                 │
 *   └ action row ─────────────────────────────────────────────────┘
 *
 * A field the sensor does not report renders as an explicit
 * "not collected"; an action NivXForge does not implement renders
 * disabled and says so. An analyst must be able to tell "no policy"
 * from "policy is not a concept this platform collects", and "no
 * vulnerabilities" from "vulnerability data is not collected".
 */
import React, { useState } from "react";
import { AlertTriangle, ChevronDown, ChevronRight, Monitor,
         ShieldOff } from "lucide-react";

import { C } from "./ampModel";

const nc = (v) => v == null || v === "" ||
  (typeof v === "object" && v.state === "NOT_COLLECTED");

const Cell = ({ k, v, testid, link }) => (
  <>
    <td style={{ padding: "4px 8px", fontSize: 10.6, color: C.inkDim,
                 background: C.paperAlt, borderBottom: `1px solid ${C.grid}`,
                 whiteSpace: "nowrap", width: 148 }}>{k}</td>
    <td data-testid={testid} className="mono"
        title={nc(v) && typeof v === "object" ? v.reason : undefined}
        style={{ padding: "4px 8px", fontSize: 10.6, wordBreak: "break-all",
                 borderBottom: `1px solid ${C.grid}`,
                 color: nc(v) ? C.inkFaint : (link ? C.link : C.ink) }}>
      {nc(v) ? "◇ not collected" : String(v)}
    </td>
  </>
);

const ActionBtn = ({ label, onClick, disabled, title, testid }) => (
  <button onClick={onClick} disabled={disabled} title={title}
          data-testid={testid}
          style={{ fontSize: 10.4, padding: "4px 10px", borderRadius: 2,
                   cursor: disabled ? "not-allowed" : "pointer",
                   background: C.paper, color: disabled ? C.inkFaint : C.link,
                   border: `1px solid ${disabled ? C.grid : C.gridStrong}`,
                   opacity: disabled ? 0.75 : 1 }}>
    {label}
  </button>
);

export default function AmpComputerHeader({ computer, epistemic, malicious,
                                            detections, onAction }) {
  // Cisco shows this as a single collapsed strip by default, giving the
  // trajectory the page. It expands to the full attribute table.
  const [open, setOpen] = useState(false);
  const [isoOpen, setIsoOpen] = useState(false);
  if (!computer) return null;
  const c = computer;
  const compromise = (malicious || 0) + (detections || 0);

  return (
    <section data-testid="amp-computer-header"
             style={{ background: C.paper,
                      border: `1px solid ${C.gridStrong}`,
                      borderRadius: 6, width: "100%", height: "fit-content",
                      display: "flex", flexDirection: "column" }}>
      <button onClick={() => setOpen((v) => !v)}
              data-testid="amp-computer-collapse"
              style={{ width: "100%", display: "flex", alignItems: "center",
                       gap: 7, padding: "7px 10px", cursor: "pointer",
                       background: C.paper, border: "none",
                       borderBottom: `1px solid ${C.grid}` }}>
        {open ? <ChevronDown size={12} color={C.inkDim} />
              : <ChevronRight size={12} color={C.inkDim} />}
        <Monitor size={13} color={C.inkDim} />
        <span data-testid="amp-computer-hostname"
              style={{ fontSize: 11.6, color: C.ink, fontWeight: 600 }}>
          {c.hostname || c.device_iid || "unresolved endpoint"}
        </span>
        <span style={{ fontSize: 11, color: C.inkDim }}>
          in group{" "}
          <span style={{ color: nc(c.group) ? C.inkFaint : C.link }}>
            {nc(c.group) ? "◇ not collected" : String(c.group)}
          </span>
        </span>
        <span data-testid="amp-compromise-summary"
              style={{ marginLeft: 14, fontSize: 11,
                       color: compromise ? C.malicious : C.inkDim }}>
          {compromise ? `${compromise} compromise event${compromise === 1
            ? "" : "s"}` : "No compromise events"}
        </span>
        <span style={{ flex: 1 }} />
        <span data-testid="amp-computer-state"
              style={{ fontSize: 9.4, fontWeight: 700, padding: "2px 7px",
                       borderRadius: 2, letterSpacing: ".4px",
                       color: epistemic?.state === "OBSERVED"
                         ? "#1C6B4B" : "#8A5B00",
                       background: epistemic?.state === "OBSERVED"
                         ? "#EAF6F0" : "#FDF3E0",
                       border: `1px solid ${epistemic?.state === "OBSERVED"
                         ? "#C3E3D4" : "#EFD9A8"}` }}>
          {epistemic?.state || "UNKNOWN"}
        </span>
      </button>

      {open && (
        <>
          <button onClick={() => setIsoOpen((v) => !v)}
                  data-testid="amp-isolation-row"
                  style={{ width: "100%", display: "flex", gap: 7,
                           alignItems: "center", padding: "6px 10px",
                           background: C.paper, cursor: "pointer",
                           border: "none",
                           borderBottom: `1px solid ${C.grid}` }}>
            {isoOpen ? <ChevronDown size={11} color={C.inkDim} />
                     : <ChevronRight size={11} color={C.inkDim} />}
            <ShieldOff size={12} color={C.inkDim} />
            <span style={{ fontSize: 11, color: C.ink }}>
              {c.isolation_state || "Not Isolated"}
            </span>
            <AlertTriangle size={11} color="#E0A200" />
          </button>
          {isoOpen && (
            <div data-testid="amp-isolation-detail"
                 style={{ fontSize: 10.4, color: C.inkDim, padding: "7px 30px",
                          borderBottom: `1px solid ${C.grid}`,
                          lineHeight: 1.55 }}>
              Isolation is requested, executed and verified by the NivXForge
              response plane, never from this read-only trajectory. Open{" "}
              <button onClick={() => onAction("isolation")}
                      data-testid="amp-isolation-open"
                      style={{ background: "none", border: "none", padding: 0,
                               color: C.link, cursor: "pointer",
                               fontSize: 10.4 }}>
                Response
              </button>{" "}
              to request it with its verification record.
            </div>
          )}

          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <tbody>
              <tr>
                <Cell k="Hostname" v={c.hostname} testid="amp-hdr-hostname" />
                <Cell k="Group" v={c.group} testid="amp-hdr-group" link />
              </tr>
              <tr>
                <Cell k="Operating System" v={c.operating_system}
                      testid="amp-hdr-os" />
                <Cell k="Policy" v={c.policy} testid="amp-hdr-policy" link />
              </tr>
              <tr>
                <Cell k="Connector Version" v={c.connector_version}
                      testid="amp-hdr-connector" />
                <Cell k="Internal IP" v={c.internal_ip}
                      testid="amp-hdr-int-ip" />
              </tr>
              <tr>
                <Cell k="First Observed" v={c.first_observed}
                      testid="amp-hdr-first-observed" />
                <Cell k="External IP" v={c.external_ip}
                      testid="amp-hdr-ext-ip" />
              </tr>
              <tr>
                <Cell k="Device IID" v={c.device_iid}
                      testid="amp-hdr-device-iid" />
                <Cell k="Last Seen" v={c.last_telemetry_at}
                      testid="amp-hdr-last-telemetry" />
              </tr>
              <tr>
                <Cell k="Endpoint ID" v={c.endpoint_id}
                      testid="amp-hdr-endpoint-id" />
                <Cell k="Definitions Last Updated" v={c.definitions_version}
                      testid="amp-hdr-definitions" />
              </tr>
              <tr>
                <Cell k="Enrollment" v={c.enrollment_state}
                      testid="amp-hdr-enrollment" />
                <Cell k="Identity Confidence" v={c.identity_confidence}
                      testid="amp-hdr-identity" />
              </tr>
              <tr>
                <Cell k="Sensor State" v={c.sensor_state}
                      testid="amp-hdr-sensor" />
                <Cell k="Customer / Tenant" v={c.tenant}
                      testid="amp-hdr-tenant" />
              </tr>
              <tr>
                <Cell k="Observations" v={c.observations_all_time}
                      testid="amp-hdr-observations" />
                <Cell k="Activity Rows" v={c.lane_total}
                      testid="amp-hdr-lanes" />
              </tr>
            </tbody>
          </table>

          <div style={{ display: "flex", gap: 10, padding: "9px 10px" }}>
            {[["Related Compromise Events",
               compromise
                 ? `${compromise} compromise event(s) observed on this endpoint.`
                 : "No related compromise events observed.",
               "amp-related-compromise"],
              ["Vulnerabilities",
               "Vulnerability data is not collected by NivXForge — this is "
               + "an absence of collection, not an absence of vulnerabilities.",
               "amp-vulnerabilities"]].map(([title, body, tid]) => (
              <div key={tid} style={{ flex: 1 }}>
                <div style={{ fontSize: 11, color: C.ink, fontWeight: 600,
                              marginBottom: 5 }}>{title}</div>
                <div data-testid={tid}
                     style={{ border: `1px solid ${C.grid}`, minHeight: 62,
                              background: C.paperAlt, padding: "8px 9px",
                              fontSize: 10.4, color: C.inkDim,
                              lineHeight: 1.5 }}>
                  {body}
                </div>
              </div>
            ))}
          </div>

          <div style={{ display: "flex", gap: 6, flexWrap: "wrap",
                        padding: "0 10px 10px", alignItems: "center" }}>
            <ActionBtn label="Forensic Snapshot" testid="amp-act-forensics"
                       onClick={() => onAction("forensics")}
                       title="Open NivXForge Forensics" />
            <ActionBtn label="Live Query" testid="amp-act-live-query"
                       onClick={() => onAction("live-query")}
                       title="Open NivXForge Live Query" />
            <ActionBtn label="Events" testid="amp-act-events"
                       onClick={() => onAction("detections")}
                       title="Open endpoint detections" />
            <ActionBtn label="Process Tree" testid="amp-act-process-tree"
                       onClick={() => onAction("process-tree")} />
            <ActionBtn label="Campaign Story" testid="amp-act-campaign"
                       onClick={() => onAction("campaign-story")} />
            <ActionBtn label="Response · Isolate / Kill"
                       testid="amp-act-response"
                       onClick={() => onAction("isolation")} />
            <ActionBtn label="Scan…" disabled testid="amp-act-scan"
                       title="On-demand scanning is not implemented by the NivXForge sensor" />
            <ActionBtn label="Diagnose…" disabled testid="amp-act-diagnose"
                       title="Connector diagnostics are not implemented by the NivXForge sensor" />
            <ActionBtn label="Move to Group…" disabled
                       testid="amp-act-move-group"
                       title="Endpoint groups are not a NivXForge concept" />
            <span style={{ fontSize: 9.6, color: C.inkFaint }}>
              greyed actions are not implemented by this platform — hover for
              why
            </span>
          </div>
        </>
      )}

      {epistemic?.message && (
        <div data-testid="amp-computer-epistemic"
             style={{ margin: "0 10px 10px", fontSize: 10.4, color: "#8A5B00",
                      background: "#FDF3E0", border: "1px solid #EFD9A8",
                      padding: "6px 9px", borderRadius: 2 }}>
          {epistemic.message}
        </div>
      )}
    </section>
  );
}
