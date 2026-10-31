import React, { useState } from "react";
import { useSearchParams } from "react-router-dom";
import NivXForgeConsole from "@/nivxforge/NivXForgeConsole";
import EdrDeviceTrajectoryPage from "@/nivxforge/trajectory/EdrDeviceTrajectoryPage";
import TrajectoryPage from "./amp/TrajectoryPage";

export default function DeviceTrajectoryPage({ embedded = false, device: suppliedDevice } = {}) {
  const [params] = useSearchParams();
  const [legacy, setLegacy] = useState(params.get("legacy") === "1");
  const device = suppliedDevice ?? params.get("device");
  if (legacy) return <div><button data-testid="v3-back-to-new" onClick={() => setLegacy(false)} style={{ margin: 8 }}>Use new Device Trajectory</button><EdrDeviceTrajectoryPage embedded={embedded} device={device} /></div>;
  const trajectory = <TrajectoryPage key={device} device={device} onLegacy={() => setLegacy(true)} />;
  return embedded ? trajectory : <NivXForgeConsole activeTab="device-trajectory">{trajectory}</NivXForgeConsole>;
}
