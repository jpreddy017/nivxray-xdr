/**
 * ADR-0021 · Lab2Provider — workspace state container.
 *
 * Single source of workspace-level state for Lab 2.0. Owns:
 *   - active investigation (CIO)
 *   - selected evidence node (for cross-panel highlighting)
 *   - docked-panel visibility (left nav, right context, status bar)
 *   - theme (dark | light | high-contrast — future ADR)
 *   - command-palette open/close (Cmd+K, future slice)
 *
 * Providers WRAP the shell, not the other way around, so any child
 * component can read/write workspace state via `useLab2()`. Every
 * future component reads state via this context — never props-drills.
 *
 * Contract:
 *   <Lab2Provider initialCIO={cio}>
 *     <Lab2Shell />
 *   </Lab2Provider>
 *
 * @tier 2 · Provider (workspace state)
 * @a11y no direct DOM output
 * @perf state changes are memoised; components subscribe to slices via selectors
 */
import React, {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useReducer,
} from "react";
import { CIOProvider } from "../hooks/useCIO";

/**
 * @typedef {"dark"|"light"|"hc"} Lab2Theme
 * @typedef {"left"|"right"|"bottom"} Lab2DockRegion
 */

const initialState = {
  cio: null,
  selectedNodeId: null,
  dockedPanels: { left: true, right: true, bottom: true },
  theme: "dark",
  paletteOpen: false,
};

function reducer(state, action) {
  switch (action.type) {
    case "SET_CIO":
      return { ...state, cio: action.payload, selectedNodeId: null };
    case "SELECT_NODE":
      return { ...state, selectedNodeId: action.payload };
    case "TOGGLE_PANEL":
      return {
        ...state,
        dockedPanels: {
          ...state.dockedPanels,
          [action.payload]: !state.dockedPanels[action.payload],
        },
      };
    case "SET_THEME":
      return { ...state, theme: action.payload };
    case "TOGGLE_PALETTE":
      return { ...state, paletteOpen: !state.paletteOpen };
    case "CLOSE_PALETTE":
      return { ...state, paletteOpen: false };
    default:
      return state;
  }
}

const Lab2Context = createContext(null);

export function Lab2Provider({ initialCIO = null, children }) {
  const [state, dispatch] = useReducer(reducer, {
    ...initialState,
    cio: initialCIO,
  });

  const setCIO = useCallback((cio) => dispatch({ type: "SET_CIO", payload: cio }), []);
  const selectNode = useCallback(
    (nodeId) => dispatch({ type: "SELECT_NODE", payload: nodeId }),
    []
  );
  const togglePanel = useCallback(
    (region) => dispatch({ type: "TOGGLE_PANEL", payload: region }),
    []
  );
  const setTheme = useCallback(
    (theme) => dispatch({ type: "SET_THEME", payload: theme }),
    []
  );
  const togglePalette = useCallback(() => dispatch({ type: "TOGGLE_PALETTE" }), []);
  const closePalette = useCallback(() => dispatch({ type: "CLOSE_PALETTE" }), []);

  const value = useMemo(
    () => ({
      ...state,
      setCIO,
      selectNode,
      togglePanel,
      setTheme,
      togglePalette,
      closePalette,
    }),
    [state, setCIO, selectNode, togglePanel, setTheme, togglePalette, closePalette]
  );

  // CIO context is nested so components can call `useCIO()` /
  // `useVerdict()` without knowing about Lab2Provider. Lab2Provider
  // is a superset — it owns the CIO plus workspace-level state.
  return (
    <Lab2Context.Provider value={value}>
      <CIOProvider value={state.cio}>{children}</CIOProvider>
    </Lab2Context.Provider>
  );
}

export function useLab2() {
  const ctx = useContext(Lab2Context);
  if (!ctx) {
    throw new Error("useLab2() must be used inside <Lab2Provider>");
  }
  return ctx;
}

export function useSelectedNode() {
  const { selectedNodeId, selectNode } = useLab2();
  return { selectedNodeId, selectNode };
}

export function useDockedPanels() {
  const { dockedPanels, togglePanel } = useLab2();
  return { dockedPanels, togglePanel };
}

export function usePalette() {
  const { paletteOpen, togglePalette, closePalette } = useLab2();
  return { paletteOpen, togglePalette, closePalette };
}
