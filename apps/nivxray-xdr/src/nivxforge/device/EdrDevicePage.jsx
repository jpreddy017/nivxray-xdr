/**
 * The device workspace — one computer, many lenses, one context.
 *
 * `/edr/computers/:endpointId/:tab` keeps the device in the URL so every
 * lens is a shareable deep link and the analyst never loses the computer
 * while changing question. Trajectory reuses the canonical AMP-class
 * renderer (embedded, not duplicated); Commands reads observed endpoint
 * command evidence.
 */
import React, { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { ArrowLeft, Binary, Network, Radar, Shield, Terminal,
         FileSearch, LayoutGrid } from "lucide-react";

import NivXForgeConsole from "@/nivxforge/NivXForgeConsole";
import EdrDeviceTrajectoryPage from "@/nivxforge/trajectory/EdrDeviceTrajectoryPage";
import { NotImplementedBody } from "@/nivxforge/pages/EdrNotImplementedPage";
import { getComputer } from "@/nivxforge/onboardingApi";
import { Ago, Skeleton, StateChip } from "@/nivxforge/components/OpsPrimitives";
import DeviceOverview from "./DeviceOverview";
import CommandIntelligence from "./CommandIntelligence";
import "@/nivxforge/nvf-ops.css";

const TABS = [
  { key: "overview",   label: "Overview",             icon: LayoutGrid },
  { key: "trajectory", label: "Trajectory",           icon: Radar },
  { key: "commands",   label: "Command Intelligence", icon: Terminal },
  { key: "files",      label: "Files",                icon: Binary,
    ni: ["File evidence for this computer",
         "Writes, drops, signers and hashes observed by the sensor, each "
         + "pivoting into IOC and Malware Intelligence.",
         "The Windows V1 sensor reports process execution and event-log "
         + "acquisition. File-system observation is not collected yet, so "
         + "there is no evidence to render and nothing is inferred from "
         + "process paths."] },
  { key: "network",    label: "Network",              icon: Network,
    ni: ["Endpoint-observed connections and DNS",
         "Per-process network attribution with pivots into the network "
         + "plane.",
         "Endpoint network observation is not part of the V1 sensor, and "
         + "network telemetry acquired elsewhere is not attributed to this "
         + "endpoint's processes — presenting it here would imply an "
         + "attribution the evidence does not carry."] },
  { key: "response",   label: "Response",             icon: Shield,
    ni: ["Endpoint response for this computer",
         "Isolate, kill process, quarantine file and collect artifact, each "
         + "through Approval → Execution → Verification → Audit.",
         "The response plane is a separate authority and is reachable from "
         + "Response in the product navigation. A device-scoped response "
         + "console is not implemented in this wave, and dispatched actions "
         + "are never shown as observed endpoint execution."] },
  { key: "forensics",  label: "Forensics",            icon: FileSearch,
    ni: ["Forensic collection for this computer",
         "Targeted snapshot and live query, each carrying an evidence id and "
         + "an audit trail.",
         "No forensic collection capability is implemented on the endpoint "
         + "sensor yet, so this surface would have no evidence to present."] },
];

export default function EdrDevicePage() {
  const { endpointId, tab } = useParams();
  const nav = useNavigate();
  const active = tab || "overview";
  const [head, setHead] = useState(null);
  const [headReady, setHeadReady] = useState(false);

  // The device identity is fetched BEFORE the lens mounts. Trajectory's
  // first projection request is heavy, and letting it race the header made
  // the workspace title fall back to the raw endpoint id.
  useEffect(() => {
    let live = true;
    setHead(null); setHeadReady(false);
    getComputer(endpointId, 24)
      .then((d) => { if (live) { setHead(d.computer); setHeadReady(true); } })
      .catch(() => { if (live) setHeadReady(true); });
    return () => { live = false; };
  }, [endpointId]);

  const current = TABS.find((t) => t.key === active) || TABS[0];

  return (
    <NivXForgeConsole activeTab="computers">
      <div className="ops-head">
        <div style={{ minWidth: 0 }}>
          <span className="eyebrow">
            <button className="btn" data-testid="edr-device-back"
                    style={{ padding: "1px 7px", marginRight: 8,
                             fontSize: 9, letterSpacing: 1 }}
                    onClick={() => nav("/edr/computers")}>
              <ArrowLeft size={9} /> Computers
            </button>
            Device workspace
          </span>
          <h1 className="ttl" data-testid="edr-device-title">
            {head?.hostname || endpointId}
          </h1>
          <div className="sub" style={{ display: "flex", gap: 12,
                                        alignItems: "center",
                                        flexWrap: "wrap" }}>
            {head ? <StateChip token={head.status} title={head.status_basis}
                               testid="edr-device-head-status" /> : null}
            <span className="mono" style={{ fontSize: 10.4 }}>
              {endpointId}
            </span>
            {head ? (
              <span>
                {head.os || "OS not reported"} · sensor{" "}
                {head.sensor_version || "not reported"} · last seen{" "}
                <Ago iso={head.last_seen} />
              </span>
            ) : null}
          </div>
        </div>
      </div>

      <div className="dev-tabs" data-testid="edr-device-tabs">
        {TABS.map((t) => {
          const Icon = t.icon;
          return (
            <button key={t.key} data-on={String(t.key === active)}
                    data-testid={`edr-device-tab-${t.key}`}
                    onClick={() => nav(
                      `/edr/computers/${encodeURIComponent(endpointId)}/${t.key}`)}>
              <Icon size={12} /> {t.label}
              {t.ni ? <span className="chip" style={{ fontSize: 8.4 }}>N/I</span>
                    : null}
            </button>
          );
        })}
      </div>

      {!headReady ? <Skeleton rows={7} testid="edr-device-head-loading" /> : null}
      {headReady && active === "overview"
        ? <DeviceOverview endpointId={endpointId} /> : null}
      {headReady && active === "trajectory"
        ? <EdrDeviceTrajectoryPage embedded device={endpointId} /> : null}
      {headReady && active === "commands"
        ? <CommandIntelligence endpointId={endpointId} /> : null}
      {headReady && current.ni ? (
        <NotImplementedBody heading={current.ni[0]} body={current.ni[1]}
                            why={current.ni[2]}
                            testid={`edr-device-ni-${current.key}`} />
      ) : null}
    </NivXForgeConsole>
  );
}
