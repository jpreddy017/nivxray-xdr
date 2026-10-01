/**
 * ADR-0020 · CIO selector hooks.
 *
 * The ONLY sanctioned way to read the CIO from a Lab 2.0 component.
 * Each hook returns a slice of the CIO — never transforms, sorts,
 * filters, or composes. Missing data returns null / [] / {}.
 *
 * Provider: `<CIOProvider value={cio}>` wraps a subtree.
 */
import React, { createContext, useContext, useMemo } from "react";

const CIOContext = createContext(/** @type {import("../types/cio").CIO|null} */ (null));

export function CIOProvider({ value, children }) {
  return <CIOContext.Provider value={value}>{children}</CIOContext.Provider>;
}

/** @returns {import("../types/cio").CIO|null} */
export function useCIO() {
  return useContext(CIOContext);
}

/** @returns {import("../types/cio").Summary|null} */
export function useSummary() {
  const cio = useCIO();
  return useMemo(() => (cio ? cio.summary || null : null), [cio]);
}

/** @returns {import("../types/cio").VerdictNode|null} */
export function useVerdict() {
  const cio = useCIO();
  return useMemo(() => (cio ? cio.verdict || null : null), [cio]);
}

/** @returns {{ nodes:Array, edges:Array }} */
export function useGraph() {
  const cio = useCIO();
  return useMemo(
    () => (cio && cio.evidence_graph) || { nodes: [], edges: [] },
    [cio]
  );
}

/** @returns {Array} */
export function useTimeline() {
  const cio = useCIO();
  return useMemo(() => (cio ? cio.timeline || [] : []), [cio]);
}

/** @returns {Array} */
export function useKeyFindings() {
  const s = useSummary();
  return useMemo(() => (s ? s.key_findings || [] : []), [s]);
}

/** @returns {Array} */
export function useRecommendations() {
  const s = useSummary();
  return useMemo(() => (s ? s.recommendations || [] : []), [s]);
}

/** @returns {"0.1"|null} */
export function useSchemaVersion() {
  const cio = useCIO();
  return cio ? cio.schema_version : null;
}
