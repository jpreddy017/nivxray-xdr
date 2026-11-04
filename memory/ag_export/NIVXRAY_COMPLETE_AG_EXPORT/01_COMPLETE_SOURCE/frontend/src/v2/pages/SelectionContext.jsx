/**
 * SelectionContext — the ONE global selection for the Investigation Workspace.
 *
 * Every view (Trajectory · Story · Graph · Process Tree · Evidence Card ·
 * ATT&CK · Reports) reads and writes this single object. Clicking an event
 * anywhere updates the context; every other view re-renders to reflect it.
 *
 *   selection : { kind, id, frame_iid, process_iid, source } | null
 *
 *     kind        — "event" | "process" | "technique" | null
 *     id          — the primary IKG node id (frame_iid, process iid, or T-id)
 *     frame_iid   — set when the underlying evidence is an event
 *     process_iid — set when the process is the anchor
 *     source      — free-text: "trajectory" | "story" | "graph" |
 *                   "process-tree" | "attack" | "url"
 *
 * URL-durability: the top-level workspace also mirrors the current
 * selection into ?focus=<frame_iid> so shareable links behave.
 */
import { createContext, useContext, useMemo, useState, useCallback } from "react";

const SelectionCtx = createContext({
  selection: null,
  setSelection: () => {},
  clearSelection: () => {},
});

export function SelectionProvider({ children, initial }) {
  const [selection, setSelectionState] = useState(initial || null);

  const setSelection = useCallback((next) => {
    // Normalise — accept a bare frame_iid string as a shortcut.
    if (typeof next === "string") {
      setSelectionState({ kind: "event", id: next, frame_iid: next,
                          process_iid: null, source: "url" });
      return;
    }
    if (next && !next.kind) {
      if (next.frame_iid)   next.kind = "event";
      else if (next.process_iid) next.kind = "process";
      else if (next.technique_id) next.kind = "technique";
    }
    setSelectionState(next);
  }, []);

  const clearSelection = useCallback(() => setSelectionState(null), []);

  const value = useMemo(
    () => ({ selection, setSelection, clearSelection }),
    [selection, setSelection, clearSelection]
  );

  return (
    <SelectionCtx.Provider value={value}>
      {children}
    </SelectionCtx.Provider>
  );
}

export function useSelection() {
  return useContext(SelectionCtx);
}
