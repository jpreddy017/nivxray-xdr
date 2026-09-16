/**
 * XdrDeviceTrajectoryPage · `/xdr/endpoints/:device/trajectory`
 *
 * The trajectory canvas now lives inside the Entity 360 workspace so the
 * navigator, canvas, compromise band, ledger and lane grids share one
 * temporal state.  This route is preserved (it is linked from seven call
 * sites) and simply opens the workspace on its Device Trajectory tab.
 */
import React from "react";

import XdrEntity360Page from "@/xdr/pages/XdrEntity360Page";

export default function XdrDeviceTrajectoryPage() {
  return <XdrEntity360Page initialTab="trajectory" />;
}
