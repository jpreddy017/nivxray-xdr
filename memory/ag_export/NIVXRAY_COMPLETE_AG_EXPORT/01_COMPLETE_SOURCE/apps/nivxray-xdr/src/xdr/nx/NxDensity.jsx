/**
 * NxDensity · §12 density mode context.
 *
 * Two modes only (owner amendment A12): `comfort` and `compact`.
 * Persists per-user under localStorage key `xdr.pref.density`.
 * The console reads the active mode via `data-density` on
 * `.xdr-console` so every downstream component consumes the same
 * `--nx-row-h`, `--nx-cell-py`, `--nx-cell-px`, `--nx-body-sz`
 * tokens.
 */
import React, { createContext, useContext, useEffect, useMemo, useState } from "react";

const STORAGE_KEY = "xdr.pref.density";
const DEFAULT = "comfort";
const MODES = ["comfort", "compact"];

const DensityContext = createContext({
  mode: DEFAULT,
  setMode: () => {},
  cycle: () => {},
});

export function NxDensityProvider({ children }) {
  const [mode, setMode] = useState(() => {
    try {
      const v = localStorage.getItem(STORAGE_KEY);
      if (v && MODES.includes(v)) return v;
    } catch (_) { /* noop */ }
    return DEFAULT;
  });

  useEffect(() => {
    try { localStorage.setItem(STORAGE_KEY, mode); } catch (_) { /* noop */ }
    if (typeof document !== "undefined") {
      const root = document.querySelector(".xdr-console");
      if (root) root.setAttribute("data-density", mode);
    }
  }, [mode]);

  const value = useMemo(() => ({
    mode, setMode,
    cycle: () => setMode(m => (m === "comfort" ? "compact" : "comfort")),
  }), [mode]);

  return <DensityContext.Provider value={value}>{children}</DensityContext.Provider>;
}

export function useNxDensity() {
  return useContext(DensityContext);
}
