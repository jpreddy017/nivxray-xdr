// E3 contract-preview data source on /edr/device-trajectory. OFF unless VITE_E3_DT_CONTRACT_PREVIEW=1 at build time.
export const E3_DT_CONTRACT_PREVIEW = import.meta.env?.VITE_E3_DT_CONTRACT_PREVIEW === "1";
