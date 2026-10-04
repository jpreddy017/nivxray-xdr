import React, { useState } from "react";
import { useSearchParams } from "react-router-dom";
import NivXForgeConsole from "@/nivxforge/NivXForgeConsole";
import EdrDeviceTrajectoryPage from "@/nivxforge/trajectory/EdrDeviceTrajectoryPage";
import TrajectoryPage from "./amp/TrajectoryPage";

export default function DeviceTrajectoryPage() {
  const [params] = useSearchParams();
  const [legacy, setLegacy] = useState(params.get("legacy") === "1");
  if (legacy) return <div><button data-testid="v3-back-to-new" onClick={() => setLegacy(false)} style={{ margin: 8 }}>Use new Device Trajectory</button><EdrDeviceTrajectoryPage /></div>;
  return <NivXForgeConsole activeTab="device-trajectory"><TrajectoryPage device={params.get("device")} onLegacy={() => setLegacy(true)} /></NivXForgeConsole>;
}
