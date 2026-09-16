/**
 * WorkspaceSelectionContext — the single selection bus for the
 * NivXRay XDR Investigator Workspace.
 *
 *   selection = { kind, ref, source, meta? }
 *
 *   kind ∈ {
 *     "process"   · pid / process image / command_line
 *     "ioc"       · ip / domain / url / hash / sha256 / md5
 *     "host"      · host_id
 *     "user"      · user_id
 *     "evidence"  · evidence_ref
 *     "technique" · MITRE technique_id (e.g. T1059.001)
 *     "rule"      · rule_id
 *     "response"  · execution_id
 *     "playbook"  · playbook_id
 *   }
 *
 * Panels subscribe with useSelection().  They MAY also request a
 * selection with setSelection({ kind, ref, source }).  The bus is
 * intentionally global-per-incident — clicking a MITRE chip on the
 * canvas selects the same technique in the Rule/Evidence/Attack Story
 * panels; clicking an IOC in the IOC panel highlights it on the
 * canvas + timeline; clicking a process in the tree filters the
 * Evidence Ledger.
 *
 * Never fabricates a selection.  If the requested ref is not present
 * in the incident, `resolvedFor(kind)` returns null and the panel
 * must render its own "no selection" honesty state.
 */
import React, { createContext, useCallback, useContext,
  useMemo, useReducer } from "react";


const CTX = createContext(null);

const INITIAL = { selection: null, hover: null, history: [] };

function reducer(s, a) {
  switch (a.type) {
    case "select":
      return {
        selection: a.selection,
        hover: null,
        history: [a.selection, ...s.history].slice(0, 20),
      };
    case "clear":
      return { selection: null, hover: null, history: s.history };
    case "hover":
      return { ...s, hover: a.hover };
    default:
      return s;
  }
}


export function WorkspaceSelectionProvider({ incident, children }) {
  const [state, dispatch] = useReducer(reducer, INITIAL);

  const setSelection = useCallback((sel) => {
    if (!sel || !sel.kind || !sel.ref) {
      dispatch({ type: "clear" });
      return;
    }
    dispatch({ type: "select", selection: { ...sel,
                                                                       at: new Date().toISOString() } });
  }, []);

  const setHover = useCallback((h) => {
    dispatch({ type: "hover", hover: h });
  }, []);

  const clear = useCallback(() => dispatch({ type: "clear" }), []);

  // Resolve a selection to its "for" facets — used by panels that
  // want "the process id if the selection is a process, otherwise
  // null".  Panels MUST never fabricate.
  const value = useMemo(() => ({
    incident,
    selection: state.selection,
    hover:     state.hover,
    history:   state.history,
    setSelection,
    setHover,
    clear,
    // Selection facets: null if no selection or wrong kind.
    processId: state.selection?.kind === "process" ? state.selection.ref : null,
    iocRef:    state.selection?.kind === "ioc"     ? state.selection : null,
    hostId:    state.selection?.kind === "host"    ? state.selection.ref : null,
    userId:    state.selection?.kind === "user"    ? state.selection.ref : null,
    technique: state.selection?.kind === "technique" ? state.selection.ref : null,
    ruleId:    state.selection?.kind === "rule"    ? state.selection.ref : null,
    evidenceRef: state.selection?.kind === "evidence" ? state.selection.ref : null,
    responseExecId: state.selection?.kind === "response" ? state.selection.ref : null,
    playbookId: state.selection?.kind === "playbook" ? state.selection.ref : null,
  }), [incident, state, setSelection, setHover, clear]);

  return <CTX.Provider value={value}>{children}</CTX.Provider>;
}


export function useSelection() {
  const v = useContext(CTX);
  if (!v) {
    // Deliberate: outside the provider, panels get a no-op selection.
    // Prevents crashes in older screens.  Never fabricates data.
    return {
      incident: null, selection: null, hover: null, history: [],
      setSelection: () => {}, setHover: () => {}, clear: () => {},
      processId: null, iocRef: null, hostId: null, userId: null,
      technique: null, ruleId: null, evidenceRef: null,
      responseExecId: null, playbookId: null,
    };
  }
  return v;
}


/** Convenience: subscribe to only one facet.  Returns null when the
 *  current selection is not of the requested kind. */
export function useSelectionOf(kind) {
  const s = useSelection();
  return s.selection?.kind === kind ? s.selection : null;
}
