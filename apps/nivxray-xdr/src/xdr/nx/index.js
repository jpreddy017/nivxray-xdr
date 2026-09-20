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
export { default as NxErrorBoundary }       from "./NxErrorBoundary";

// Investigation experience · one table, one empty state, one absence
// vocabulary, one place for engine detail. Every incident tab composes
// these instead of inventing its own presentation.
export { NxInvSection, NxInvTable, NxInvEmpty, NxInvFilters, NxInvTech,
         NxInvMetrics, NxInvValue, ABSENCE, fmtTime } from "./NxInv";

// ONE analyst vocabulary for capabilities — backend ids are never renamed.
export { CAPABILITY_LABELS, capabilityLabel, capabilityIsMapped,
         capabilityEngineId } from "./capabilityLabels";

// Slice 1 · enterprise primitives. One table, one flyout, one status
// grammar, one tab bar — every page composes these instead of its own.
export { default as NxDataTable }           from "./NxDataTable";
export { default as NxFlyout }              from "./NxFlyout";
export { default as NxTabs }                from "./NxTabs";
export { default as NxStatus, NxHealthVerdict, NxMetric } from "./NxStatus";

// E2E waves 1-3 · one severity grammar, one entity header, one attack chain.
// Incidents, Investigation and every Entity 360 compose these.
export { default as NxVerdict, NxLifecycle, NxPriority, NxConfidence,
         NxRisk, NxProvenanceChip }                from "./NxSeverity";
export { default as NxEntityHeader, NxFact } from "./NxEntityHeader";
export { default as NxAttackChain }                from "./NxAttackChain";

// ── Phase 0 · operational composition layer (console-wide) ─────────
// ONE section, toolbar, metric strip, key-fact block, token list,
// technical-details disclosure and button for every operational surface.
// Theme-token only: both light and dark are first-class.
export { NxSection, NxToolbar, NxField, NxMetricStrip, NxDimensionStrip,
         NxBlockerGroup, NxFacts, NxKeyFact, NxToken, NxTokenList,
         NxTechnical, NxRaw, NxButton, measured, nxSlug } from "./NxOps";

// ONE presentation mapping for backend state tokens. The token stays the
// authority and is preserved in `data-nx-state`; only the LABEL is ours.
export { default as NxState, opsState, opsLabel, opsKey,
         OPS_STATES } from "./NxOpsState";

// Product identity: authentic vendor assets for third-party integrations,
// our own coherent family for NivXRay-native concepts.
export { default as NxVendorIcon }                 from "./NxVendorIcon";
export { default as NxEntityIcon, ENTITY_ICONS }   from "./NxEntityIcon";
export { resolveIntegrationIcon, integrationIconInventory,
         INTEGRATION_ICONS } from "./integrations/iconRegistry";

// ── P1.1 · the remaining shared primitives ─────────────────────────
// One filter grammar (with visible active constraints), one entity
// reference, one provenance chain, one temporal view and one deterministic
// graph — so no surface hand-rolls these again.
export { default as NxFilter }                     from "./NxFilter";
export { default as NxEntity, NxEntityList }       from "./NxEntity";
export { default as NxProvenanceChain }            from "./NxProvenanceChain";
export { default as NxTimeline }                   from "./NxTimeline";
export { default as NxGraph }                      from "./NxGraph";
