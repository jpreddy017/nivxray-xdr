import React, { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { MonitorSmartphone } from "lucide-react";
import NivXForgeConsole from "@/nivxforge/NivXForgeConsole";
import EdrDeviceTrajectoryPage from "@/nivxforge/trajectory/EdrDeviceTrajectoryPage";
import TrajectoryPage from "./amp/TrajectoryPage";
import { C, CSS } from "./amp/theme";

/**
 * No device selected is a PRECONDITION, not a failure.
 *
 * Opening the canvas with no `?device=` used to request
 * `/edr/endpoints/null/trajectory`, fail, and render "Trajectory
 * unavailable — the trajectory request failed", which blamed the backend
 * for the analyst not having picked a computer yet.
 */
function NoDeviceSelected() {
  return (
    <div className="v3amp" data-testid="v3-no-device"
         style={{ color: C.text, background: C.page, padding: "20px 24px", minHeight: "100%" }}>
      <style>{CSS}</style>
      <div style={{ background: C.panel, border: `1px solid ${C.line}`, borderRadius: 12,
                    padding: 28, display: "flex", flexDirection: "column", alignItems: "flex-start", gap: 10 }}>
        <MonitorSmartphone size={22} color="currentColor" style={{ color: C.muted }} />
        <strong style={{ fontSize: 16 }}>Select a computer to view its trajectory</strong>
        <p style={{ color: C.label, fontSize: 13.5, margin: 0, maxWidth: 620 }}>
          Device Trajectory reads the recorded activity of one endpoint. No
          evidence is requested until a computer is chosen, so this state is a
          starting point rather than an error.
        </p>
        <Link to="/edr/computers" className="v3-btn" data-testid="v3-no-device-open-computers"
              style={{ textDecoration: "none", marginTop: 4 }}>
          Open Computers
        </Link>
      </div>
    </div>
  );
}

export default function DeviceTrajectoryPage({ embedded = false, device: suppliedDevice } = {}) {
  const [params] = useSearchParams();
  const [legacy, setLegacy] = useState(params.get("legacy") === "1");
  const raw = suppliedDevice ?? params.get("device");
  const device = raw == null ? null : String(raw).trim() || null;
  if (legacy) return <div><button data-testid="v3-back-to-new" onClick={() => setLegacy(false)} style={{ margin: 8 }}>Use new Device Trajectory</button><EdrDeviceTrajectoryPage embedded={embedded} device={device} /></div>;
  const trajectory = device
    ? <TrajectoryPage key={device} device={device} onLegacy={() => setLegacy(true)} />
    : <NoDeviceSelected />;
  return embedded ? trajectory : <NivXForgeConsole activeTab="device-trajectory">{trajectory}</NivXForgeConsole>;
}
