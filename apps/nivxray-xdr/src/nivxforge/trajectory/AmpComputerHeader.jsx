/**
 * Device header — Cisco's one-line endpoint strip with **Show details**
 * and **Actions**, as the live Secure Endpoint console presents it:
 *
 *   ▸ 🖥 <hostname> in group <g>   N compromise events   [Show details] [Actions ⌄]
 *
 * "Show details" opens a right-side drawer of endpoint properties — it
 * never navigates away from the trajectory. "Actions" is the endpoint
 * command surface, wired to real NivXForge capabilities; anything this
 * platform does not implement is disabled and says why on hover.
 *
 * A field the sensor does not report renders as an explicit
 * "not collected": an analyst must be able to tell "no policy" from
 * "policy is not a concept this platform collects".
 */
import React, { useState } from "react";
import { AlertTriangle, ChevronDown, Monitor, X } from "lucide-react";

import { C } from "./ampModel";

const nc = (v) => v == null || v === "" ||
  (typeof v === "object" && v.state === "NOT_COLLECTED");

const val = (v) => (nc(v) ? "◇ not collected" : String(v));

const Prop = ({ k, v, testid }) => (
  <div style={{ display: "flex", gap: 8, padding: "5px 0",
                borderBottom: `1px solid ${C.grid}` }}>
    <span style={{ width: 132, flexShrink: 0, fontSize: 10.2,
                   color: C.inkDim }}>{k}</span>
    <span className="mono" data-testid={testid}
          title={nc(v) && typeof v === "object" ? v.reason : undefined}
          style={{ flex: 1, fontSize: 10.4, wordBreak: "break-all",
                   color: nc(v) ? C.inkFaint : C.ink }}>
      {val(v)}
    </span>
  </div>
);

/** Cisco's Actions menu, mapped to what NivXForge actually implements. */
const ACTIONS = [
  ["detections", "Events", true],
  ["process-tree", "Process Tree", true],
  ["campaign-story", "Campaign Story", true],
  ["live-query", "Live Query", true],
  ["forensics", "Take System Snapshot", true],
  ["isolation", "Start Isolation…", true],
  ["scan", "Scan…", false,
   "On-demand scanning is not implemented by the NivXForge sensor"],
  ["diagnose", "Diagnose Connector…", false,
   "Connector diagnostics are not implemented by the NivXForge sensor"],
  ["move-group", "Move to Group…", false,
   "Endpoint groups are not a NivXForge concept"],
  ["audit", "Device Audit Log", false,
   "A per-device audit log is not collected by NivXForge"],
];

export default function AmpComputerHeader({ computer, epistemic, malicious,
                                            detections, onAction }) {
  const [drawer, setDrawer] = useState(false);
  const [menu, setMenu] = useState(false);
  if (!computer) return null;
  const c = computer;
  const compromise = (malicious || 0) + (detections || 0);

  return (
    <section data-testid="amp-computer-header"
             style={{ background: C.paper,
                      border: `1px solid ${C.gridStrong}`, borderRadius: 6,
                      width: "100%", height: "fit-content", padding: "7px 10px",
                      display: "flex", alignItems: "center", gap: 9,
                      flexWrap: "wrap" }}>
      <Monitor size={13} color={C.inkDim} />
      <span data-testid="amp-computer-hostname"
            style={{ fontSize: 11.6, color: C.ink, fontWeight: 600 }}>
        {c.hostname || c.device_iid || "unresolved endpoint"}
      </span>
      <span style={{ fontSize: 11, color: C.inkDim }}>
        in group{" "}
        <span style={{ color: nc(c.group) ? C.inkFaint : C.link }}>
          {val(c.group)}
        </span>
      </span>
      <span data-testid="amp-compromise-summary"
            style={{ fontSize: 11,
                     color: compromise ? C.malicious : C.inkDim }}>
        {compromise ? `${compromise} compromise event${compromise === 1
          ? "" : "s"}` : "No compromise events"}
      </span>
      <span data-testid="amp-isolation-row"
            style={{ fontSize: 11, color: C.inkDim, display: "flex",
                     alignItems: "center", gap: 4 }}>
        {c.isolation_state || "Not Isolated"}
        <AlertTriangle size={10} color={C.suspicious} />
      </span>
      <span style={{ flex: 1 }} />
      <span data-testid="amp-computer-state"
            style={{ fontSize: 9.4, fontWeight: 700, padding: "2px 7px",
                     borderRadius: 2, letterSpacing: ".4px",
                     color: epistemic?.state === "OBSERVED"
                       ? "#2FBF71" : C.suspicious,
                     background: C.paperAlt,
                     border: `1px solid ${C.gridStrong}` }}>
        {epistemic?.state || "UNKNOWN"}
      </span>

      <button onClick={() => setDrawer(true)} data-testid="amp-show-details"
              style={{ fontSize: 10.6, padding: "4px 9px", borderRadius: 2,
                       cursor: "pointer", background: C.paper, color: C.link,
                       border: `1px solid ${C.gridStrong}` }}>
        Show details
      </button>

      <div style={{ position: "relative" }}>
        <button onClick={() => setMenu((v) => !v)}
                data-testid="amp-actions-button"
                style={{ fontSize: 10.6, padding: "4px 9px", borderRadius: 2,
                         cursor: "pointer", background: C.paper,
                         color: C.link, display: "flex", gap: 4,
                         alignItems: "center",
                         border: `1px solid ${C.gridStrong}` }}>
          Actions <ChevronDown size={10} />
        </button>
        {menu && (
          <div data-testid="amp-actions-menu"
               style={{ position: "absolute", right: 0, top: 26, zIndex: 70,
                        background: C.paper, minWidth: 236, borderRadius: 3,
                        border: `1px solid ${C.gridStrong}`,
                        boxShadow: "0 10px 26px rgba(0,0,0,.34)" }}>
            {ACTIONS.map(([k, label, enabled, why]) => (
              <button key={k} disabled={!enabled} title={why}
                      data-testid={`amp-action-${k}`}
                      onClick={() => { onAction(k); setMenu(false); }}
                      style={{ display: "block", width: "100%",
                               textAlign: "left", fontSize: 10.5,
                               padding: "6px 10px", background: "none",
                               border: "none",
                               cursor: enabled ? "pointer" : "not-allowed",
                               color: enabled ? C.ink : C.inkFaint }}>
                {label}
              </button>
            ))}
            <div style={{ fontSize: 9, color: C.inkFaint,
                          padding: "5px 10px",
                          borderTop: `1px solid ${C.grid}` }}>
              greyed actions are not implemented by this platform — hover
              for why
            </div>
          </div>
        )}
      </div>

      {epistemic?.message && (
        <div data-testid="amp-computer-epistemic"
             style={{ width: "100%", marginTop: 6, fontSize: 10.4,
                      color: C.suspicious, background: C.paperAlt,
                      border: `1px solid ${C.gridStrong}`,
                      padding: "5px 8px", borderRadius: 2 }}>
          {epistemic.message}
        </div>
      )}

      {/* Show details · right-side drawer, never a navigation away */}
      {drawer && (
        <div data-testid="amp-details-drawer-backdrop"
             onClick={() => setDrawer(false)}
             style={{ position: "fixed", inset: 0, zIndex: 3000,
                      background: "rgba(0,0,0,.42)" }}>
          <aside data-testid="amp-details-drawer"
                 onClick={(e) => e.stopPropagation()}
                 style={{ position: "absolute", top: 0, right: 0, bottom: 0,
                          width: 392, background: C.paper, overflowY: "auto",
                          borderLeft: `1px solid ${C.gridStrong}`,
                          padding: "12px 14px 24px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8,
                          borderBottom: `1px solid ${C.gridStrong}`,
                          paddingBottom: 8 }}>
              <span style={{ fontSize: 12.5, fontWeight: 600, color: C.ink,
                             flex: 1 }}>
                Device details
              </span>
              <button onClick={() => setDrawer(false)}
                      data-testid="amp-details-drawer-close"
                      style={{ background: C.paperAlt, cursor: "pointer",
                               border: `1px solid ${C.gridStrong}`,
                               borderRadius: 3, color: C.ink, padding: 3,
                               display: "flex" }}>
                <X size={12} />
              </button>
            </div>
            <div style={{ marginTop: 8 }}>
              <Prop k="Hostname" v={c.hostname} testid="amp-hdr-hostname" />
              <Prop k="Device IID" v={c.device_iid}
                    testid="amp-hdr-device-iid" />
              <Prop k="Endpoint ID" v={c.endpoint_id}
                    testid="amp-hdr-endpoint-id" />
              <Prop k="Operating System" v={c.operating_system}
                    testid="amp-hdr-os" />
              <Prop k="Connector Version" v={c.connector_version}
                    testid="amp-hdr-connector" />
              <Prop k="Enrollment" v={c.enrollment_state}
                    testid="amp-hdr-enrollment" />
              <Prop k="Sensor State" v={c.sensor_state}
                    testid="amp-hdr-sensor" />
              <Prop k="Isolation" v={c.isolation_state || "Not Isolated"}
                    testid="amp-hdr-isolation" />
              <Prop k="Group" v={c.group} testid="amp-hdr-group" />
              <Prop k="Policy" v={c.policy} testid="amp-hdr-policy" />
              <Prop k="Internal IP" v={c.internal_ip}
                    testid="amp-hdr-int-ip" />
              <Prop k="External IP" v={c.external_ip}
                    testid="amp-hdr-ext-ip" />
              <Prop k="Definitions Last Updated" v={c.definitions_version}
                    testid="amp-hdr-definitions" />
              <Prop k="Identity Confidence" v={c.identity_confidence}
                    testid="amp-hdr-identity" />
              <Prop k="Customer / Tenant" v={c.tenant}
                    testid="amp-hdr-tenant" />
              <Prop k="First Observed" v={c.first_observed}
                    testid="amp-hdr-first-observed" />
              <Prop k="Last Seen" v={c.last_telemetry_at}
                    testid="amp-hdr-last-telemetry" />
              <Prop k="Observations" v={c.observations_all_time}
                    testid="amp-hdr-observations" />
              <Prop k="Activity Rows" v={c.lane_total}
                    testid="amp-hdr-lanes" />
            </div>

            <div style={{ marginTop: 12 }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: C.ink,
                            marginBottom: 5 }}>
                Related Compromise Events
              </div>
              <div data-testid="amp-related-compromise"
                   style={{ border: `1px solid ${C.grid}`,
                            background: C.paperAlt, padding: "7px 9px",
                            fontSize: 10.4, color: C.inkDim,
                            lineHeight: 1.5 }}>
                {compromise
                  ? `${compromise} compromise event(s) observed on this `
                    + "endpoint."
                  : "No related compromise events observed."}
              </div>
              <div style={{ fontSize: 11, fontWeight: 600, color: C.ink,
                            margin: "9px 0 5px" }}>
                Vulnerabilities
              </div>
              <div data-testid="amp-vulnerabilities"
                   style={{ border: `1px solid ${C.grid}`,
                            background: C.paperAlt, padding: "7px 9px",
                            fontSize: 10.4, color: C.inkDim,
                            lineHeight: 1.5 }}>
                Vulnerability data is not collected by NivXForge — this is
                an absence of collection, not an absence of
                vulnerabilities.
              </div>
            </div>
          </aside>
        </div>
      )}
    </section>
  );
}
