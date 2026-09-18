/**
 * Nx · Phase B primitive index.
 *
 * Import from `@/xdr/nx` — never reach into an individual file.
 */
export { default as NxChip, NxHonestyChip } from "./NxChip";
export { default as NxProvenance }          from "./NxProvenance";
export { default as NxLink }                from "./NxLink";
export { default as NxIkgGlyph }            from "./NxIkgGlyph";
export { default as NxExecPulse }           from "./NxExecPulse";
export { default as NxHeroHeader }          from "./NxHeroHeader";
export { default as NxDonut }               from "./NxDonut";
export { default as NxAreaSpark }           from "./NxAreaSpark";
export { default as NxHBar }                from "./NxHBar";
export { default as NxPageShell }           from "./NxPageShell";
export { NxSurface, NxKpi, NxPill }         from "./NxSurface";
export { NxEmpty as NxEmptyBlock }          from "./NxSurface";
export { NxEmpty, NxSkeleton }              from "./NxEmpty";
export { NxDensityProvider, useNxDensity }  from "./NxDensity";

// Slice 1 · enterprise primitives. One table, one flyout, one status
// grammar, one tab bar — every page composes these instead of its own.
export { default as NxDataTable }           from "./NxDataTable";
export { default as NxFlyout }              from "./NxFlyout";
export { default as NxTabs }                from "./NxTabs";
export { default as NxStatus, NxHealthVerdict, NxMetric } from "./NxStatus";
