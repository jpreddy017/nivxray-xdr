/**
 * ADR-0023 · Selection Context Bus
 *
 * The single channel every lens uses to read/write the "currently
 * selected" evidence node. No lens keeps its own selection state.
 * Any component may subscribe; changes propagate synchronously.
 *
 * Not to be confused with the Investigation Event Bus (ADR-0024) —
 * this is UI state, not a lifecycle timeline.
 */
import React, { createContext, useContext, useCallback, useMemo, useState, useEffect } from "react";

const Ctx = createContext(null);

export function SelectionProvider({ children, initial = null }) {
  const [selected, setSelected] = useState(initial);
  const select = useCallback((id) => setSelected(id || null), []);
  const clear = useCallback(() => setSelected(null), []);
  const value = useMemo(() => ({ selected, select, clear }), [selected, select, clear]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useSelection() {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useSelection must be used inside <SelectionProvider>");
  return ctx;
}

/** Subscribe imperatively to selection changes (rare — most callers should use useSelection). */
export function useOnSelectionChange(fn) {
  const { selected } = useSelection();
  useEffect(() => {
    fn(selected);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selected]);
}
