/**
 * DT2-3a · AMP parity — the Device Trajectory page header.
 *
 * Cisco (User Guide p.402 figure): the page is titled with the DEVICE
 * NAME, followed by `Show details` and `Actions ⌄`. `Show details` opens a
 * right-side drawer (p.404 figure) titled with the device name, carrying
 * Device details / Connector / Antivirus / Compromise events and a footer
 * action bar.
 *
 * Fields the sensor does not report say so; a Cisco-visible field with no
 * truthful NivXForge equivalent is left unavailable rather than filled in.
 */
import React, { useState } from "react";
import { AlertTriangle, ChevronDown, X } from "lucide-react";

import { C } from "./ampModel";

const nc = (v) => v == null || v === "" ||
  (typeof v === "object" && v.state === "NOT_COLLECTED");

const val = (v) => (nc(v) ? "Not collected" : String(v));

const Prop = ({ k, v, testid }) => (
  <div style={{ display: "flex", gap: 8, padding: "5px 0",
                borderBottom: `1px solid ${C.grid}` }}>
    <span style={{ width: 146, flexShrink: 0, fontSize: 10.6,
                   color: C.inkDim }}>{k}</span>
    <span className="mono" data-testid={testid}
          title={v && typeof v === "object" ? v.reason : undefined}
          style={{ flex: 1, fontSize: 10.6, wordBreak: "break-all",
                   color: nc(v) ? C.inkFaint : C.ink }}>
      {val(v)}
    </span>
  </div>
);

const Group = ({ title, chip, children, testid }) => {
  const [open, setOpen] = useState(Boolean(children));
  return (
    <div style={{ borderBottom: `1px solid ${C.gridStrong}`,
                  padding: "9px 0" }} data-testid={testid}>
      <div onClick={() => setOpen((v) => !v)}
           style={{ display: "flex", alignItems: "center", gap: 8,
                    cursor: "pointer" }}>
        <span style={{ fontSize: 12, fontWeight: 600, color: C.ink,
                       flex: 1 }}>{title}</span>
        {chip}
        <ChevronDown size={12} color={C.inkDim}
                     style={{ transform: open ? "rotate(180deg)" : "none" }} />
      </div>
      {open && children ? <div style={{ marginTop: 6 }}>{children}</div>
        : null}
    </div>
  );
};

/** The Actions menu button is screenshot-verified; Cisco's menu contents
 *  are not visible in the reference, so NivXForge's real capabilities are
 *  offered and anything unimplemented is disabled with the reason. */
const ACTIONS = [
  ["detections", "Events", true],
  ["process-tree", "Process Tree", true],
  ["campaign-story", "Campaign Story", true],
  ["live-query", "Live Query", true],
  ["forensics", "Take System Snapshot", true],
  ["isolation", "Start Isolation…", true],
  ["scan", "Scan…", false,
   "On-demand scanning is not implemented by the NivXRay EDR sensor"],
  ["diagnose", "Diagnose Connector…", false,
   "Connector diagnostics are not implemented by the NivXRay EDR sensor"],
  ["move-group", "Move to Group…", false,
   "Endpoint groups are not a NivXRay EDR concept"],
];

export default function AmpComputerHeader({ computer, malicious, detections,
                                            onAction }) {
  const [drawer, setDrawer] = useState(false);
  const [menu, setMenu] = useState(false);
  if (!computer) return null;
  const c = computer;
  const compromise = (malicious || 0) + (detections || 0);

  return (
    <div data-testid="amp-computer-header"
         style={{ display: "flex", alignItems: "center", gap: 10,
                  minWidth: 0 }}>
      <span data-testid="amp-computer-hostname"
            style={{ fontSize: 28, fontWeight: 700, color: C.ink,
                     letterSpacing: "-.4px", whiteSpace: "nowrap",
                     overflow: "hidden", textOverflow: "ellipsis" }}>
        {c.hostname || c.device_iid || "Unresolved endpoint"}
      </span>

      <button onClick={() => setDrawer(true)} data-testid="amp-show-details"
              style={{ ...btn, border: `1px solid ${C.link}` }}>
        Show details
      </button>

      <div style={{ position: "relative" }}>
        <button onClick={() => setMenu((v) => !v)}
                data-testid="amp-actions-button"
                style={{ ...btn, display: "flex", gap: 7,
                         alignItems: "center", background: C.link,
                         color: "#FFFFFF", borderColor: C.link,
                         fontWeight: 600 }}>
          Actions <ChevronDown size={13} />
        </button>
        {menu && (
          <div data-testid="amp-actions-menu"
               style={{ position: "absolute", left: 0, top: 28, zIndex: 70,
                        background: C.paper, minWidth: 236, borderRadius: 3,
                        border: `1px solid ${C.gridStrong}`,
                        boxShadow: "0 10px 26px rgba(0,0,0,.34)" }}>
            {ACTIONS.map(([k, label, enabled, why]) => (
              <button key={k} disabled={!enabled} title={why}
                      data-testid={`amp-action-${k}`}
                      onClick={() => { onAction(k); setMenu(false); }}
                      style={{ display: "block", width: "100%",
                               textAlign: "left", fontSize: 10.8,
                               padding: "6px 10px", background: "none",
                               border: "none",
                               cursor: enabled ? "pointer" : "not-allowed",
                               color: enabled ? C.ink : C.inkFaint }}>
                {label}
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Show details · right-side drawer */}
      {drawer && (
        <div data-testid="amp-details-drawer-backdrop"
             onClick={() => setDrawer(false)}
             style={{ position: "fixed", inset: 0, zIndex: 3000,
                      background: "rgba(0,0,0,.42)" }}>
          <aside data-testid="amp-details-drawer"
                 onClick={(e) => e.stopPropagation()}
                 style={{ position: "absolute", top: 0, right: 0, bottom: 0,
                          width: 404, background: C.paper,
                          display: "flex", flexDirection: "column",
                          borderLeft: `1px solid ${C.gridStrong}` }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8,
                          borderBottom: `1px solid ${C.gridStrong}`,
                          padding: "12px 14px" }}>
              <span style={{ fontSize: 17, fontWeight: 700, color: C.ink,
                             flex: 1 }}>
                {c.hostname || c.device_iid}
              </span>
              <button onClick={() => setDrawer(false)}
                      data-testid="amp-details-drawer-close"
                      style={{ background: "none", cursor: "pointer",
                               border: "none", color: C.inkDim, padding: 3,
                               display: "flex" }}>
                <X size={14} />
              </button>
            </div>

            <div style={{ overflowY: "auto", flex: 1,
                          padding: "0 14px 14px" }}>
              <Group title="Device details" testid="amp-drawer-device">
                <Prop k="Operating system" v={c.operating_system}
                      testid="amp-hdr-os" />
                <Prop k="Local IPs" v={c.internal_ip}
                      testid="amp-hdr-int-ip" />
                <Prop k="Public IP" v={c.external_ip}
                      testid="amp-hdr-ext-ip" />
                <Prop k="Last active" v={c.last_telemetry_at}
                      testid="amp-hdr-last-telemetry" />
                <Prop k="Group" v={c.group} testid="amp-hdr-group" />
                <Prop k="Policy" v={c.policy} testid="amp-hdr-policy" />
                <Prop k="Host Firewall" v={null}
                      testid="amp-hdr-host-firewall" />
              </Group>

              <Group title="Connector" testid="amp-drawer-connector">
                <Prop k="Connector version" v={c.connector_version}
                      testid="amp-hdr-connector" />
                <Prop k="Enrollment" v={c.enrollment_state}
                      testid="amp-hdr-enrollment" />
                <Prop k="Sensor state" v={c.sensor_state}
                      testid="amp-hdr-sensor" />
                <Prop k="Definitions" v={c.definitions_version}
                      testid="amp-hdr-definitions" />
                <Prop k="First observed" v={c.first_observed}
                      testid="amp-hdr-first-observed" />
                <Prop k="Events recorded" v={c.observations_all_time}
                      testid="amp-hdr-observations" />
              </Group>

              <Group title="Antivirus"
                     testid="amp-drawer-antivirus"
                     chip={(
                       <span data-testid="amp-antivirus-chip"
                             style={{ fontSize: 9.6, color: C.inkFaint,
                                      background: C.paperAlt,
                                      border: `1px solid ${C.grid}`,
                                      borderRadius: 10,
                                      padding: "1px 8px" }}>
                         Not collected
                       </span>
                     )} />

              <Group title="Compromise events"
                     testid="amp-drawer-compromise"
                     chip={(
                       <span data-testid="amp-related-compromise"
                             data-malicious={malicious || 0}
                             data-detections={detections || 0}
                             style={{ fontSize: 9.8, display: "flex",
                                      alignItems: "center", gap: 4,
                                      color: compromise ? C.malicious
                                        : C.inkFaint,
                                      background: C.paperAlt,
                                      border: `1px solid ${compromise
                                        ? C.malicious : C.grid}`,
                                      borderRadius: 10,
                                      padding: "1px 8px" }}>
                         {compromise
                           ? <AlertTriangle size={9} color={C.malicious} />
                           : null}
                         {compromise}
                       </span>
                     )} />
            </div>

            <div style={{ display: "flex", alignItems: "center", gap: 12,
                          padding: "10px 14px",
                          borderTop: `1px solid ${C.gridStrong}` }}>
              <button onClick={() => onAction("detections")}
                      data-testid="amp-drawer-events"
                      style={{ background: "none", border: "none",
                               color: C.link, fontSize: 11.5,
                               cursor: "pointer", padding: 0 }}>
                Events
              </button>
              <span style={{ flex: 1 }} />
              <button onClick={() => onAction("scan")} disabled
                      data-testid="amp-drawer-scan"
                      title="On-demand scanning is not implemented by the NivXRay EDR sensor"
                      style={{ ...btn, color: C.inkFaint,
                               cursor: "not-allowed" }}>
                Scan
              </button>
              <button onClick={() => onAction("move-group")} disabled
                      data-testid="amp-drawer-move-group"
                      title="Endpoint groups are not a NivXRay EDR concept"
                      style={{ ...btn, color: C.inkFaint,
                               cursor: "not-allowed" }}>
                Move to group
              </button>
            </div>
          </aside>
        </div>
      )}
    </div>
  );
}

const btn = {
  fontSize: 14, padding: "7px 14px", borderRadius: 4, cursor: "pointer",
  background: C.paper, color: C.link, whiteSpace: "nowrap",
  border: `1px solid ${C.gridStrong}`,
};
