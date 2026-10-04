// E3 contract-preview data source on /edr/device-trajectory. OFF unless VITE_E3_DT_CONTRACT_PREVIEW=1 at build time.
export const E3_DT_CONTRACT_PREVIEW = import.meta.env?.VITE_E3_DT_CONTRACT_PREVIEW === "1";
// Device Trajectory V3 (AMP-parity page) + EDR sidebar icon rail. OFF unless VITE_E3_DT_V3=1 at build time; OFF = legacy page, expanded sidebar.
export const E3_DT_V3 = import.meta.env?.VITE_E3_DT_V3 === "1";
