// E3 → E1 REVIEW: ATT&CK HeatMap ⇄ Device Trajectory pivot. OFF unless VITE_E3_ATTACK_PIVOT=1 at build time.
export const E3_ATTACK_PIVOT = import.meta.env?.VITE_E3_ATTACK_PIVOT === "1";
