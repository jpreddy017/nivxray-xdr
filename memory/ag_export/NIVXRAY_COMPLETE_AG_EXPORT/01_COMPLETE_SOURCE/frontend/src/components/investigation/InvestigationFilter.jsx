/**
 * Global Investigation Filter — the shared state that lets every
 * major Workspace component participate in a single investigation
 * context.
 *
 * Selecting a Kill-Chain phase, a MITRE technique, a stage, or an
 * IOC in ONE panel updates every other panel simultaneously.
 * That's what makes the Workspace feel like one investigation
 * platform instead of a set of independent widgets (R8).
 *
 * Filter shape (all optional):
 *   { tactic?, killChain?, mitre?, family?, ioc?, stageId? }
 *
 * Any component that consumes this context can:
 *   · match(stage)           → true / false
 *   · matchTactic(t)         → true / false
 *   · matchMitre(list)       → true / false
 *   · matchFamily(id)        → true / false
 */
import { createContext, useCallback, useContext, useMemo, useState } from "react";

const InvestigationFilterCtx = createContext(null);

export function InvestigationFilterProvider({ children }) {
  const [filter, setFilter] = useState({});

  const clear = useCallback(() => setFilter({}), []);
  const toggle = useCallback((key, value) => {
    setFilter((cur) => {
      if (cur[key] === value) {
        const { [key]: _drop, ...rest } = cur;
        return rest;
      }
      return { ...cur, [key]: value };
    });
  }, []);
  const set = useCallback((patch) =>
    setFilter((cur) => ({ ...cur, ...patch })), []);

  // Predicate: does this stage match the currently active filter?
  const match = useCallback((stage) => {
    if (!stage) return true;
    if (filter.tactic     && stage.tactic         !== filter.tactic)     return false;
    if (filter.killChain  && !_killChainMatch(stage, filter.killChain))  return false;
    if (filter.mitre      && !(stage.mitre || []).includes(filter.mitre)) return false;
    if (filter.family     && stage.command_family !== filter.family)     return false;
    if (filter.stageId    && stage.id             !== filter.stageId)    return false;
    return true;
  }, [filter]);

  const active = useMemo(() => Object.keys(filter).length > 0, [filter]);

  const value = useMemo(() => ({
    filter, active, set, toggle, clear, match,
  }), [filter, active, set, toggle, clear, match]);

  return <InvestigationFilterCtx.Provider value={value}>
    {children}
  </InvestigationFilterCtx.Provider>;
}

export function useInvestigationFilter() {
  return useContext(InvestigationFilterCtx) || _NOOP;
}

/* ── Filter chip bar — sits at the top of the Workspace so the
 *    active filter is always visible and clearable. */
export function InvestigationFilterBar() {
  const ctx = useContext(InvestigationFilterCtx);
  if (!ctx || !ctx.active) return null;
  const chips = [];
  const { filter, toggle, clear } = ctx;
  for (const key of ["tactic", "killChain", "mitre", "family", "stageId"]) {
    if (filter[key]) chips.push({ key, value: filter[key] });
  }
  return (
    <div data-testid="global-filter-bar" style={{
      display: "flex", alignItems: "center", flexWrap: "wrap", gap: 6,
      padding: "8px 12px", margin: "0 12px 8px",
      background: "rgba(103,232,249,0.06)",
      border: "1px solid rgba(103,232,249,0.35)",
      borderRadius: 8, fontSize: 11,
      fontFamily: "JetBrains Mono, monospace",
    }}>
      <span style={{ fontSize: 10, letterSpacing: "0.2em",
                     textTransform: "uppercase", color: "#67e8f9",
                     fontWeight: 700 }}>
        INVESTIGATION FILTER
      </span>
      {chips.map((c) => (
        <span key={c.key} data-testid={`filter-chip-${c.key}`}
              style={{ padding: "2px 8px", color: "#67e8f9",
                       background: "rgba(103,232,249,0.10)",
                       border: "1px solid rgba(103,232,249,0.35)",
                       borderRadius: 4, display: "inline-flex",
                       gap: 6, alignItems: "center" }}>
          {c.key}: {c.value}
          <button onClick={() => toggle(c.key, c.value)}
                  style={{ background: "transparent", border: "none",
                           color: "#94a3b8", cursor: "pointer",
                           fontSize: 12, lineHeight: 1, padding: 0 }}>✕</button>
        </span>
      ))}
      <button data-testid="filter-clear" onClick={clear}
              style={{ padding: "2px 8px", marginLeft: "auto",
                       fontSize: 10, fontWeight: 700,
                       color: "#f87171", background: "rgba(248,113,113,0.10)",
                       border: "1px solid rgba(248,113,113,0.35)",
                       borderRadius: 4, cursor: "pointer",
                       fontFamily: "JetBrains Mono, monospace" }}>
        CLEAR ALL
      </button>
    </div>
  );
}

function _killChainMatch(stage, target) {
  const map = {
    "Initial Access": "Delivery / Exploitation",
    "Execution": "Exploitation",
    "Discovery": "Reconnaissance",
    "Credential Access": "Actions on Obj.",
    "Persistence": "Installation",
    "Defense Evasion": "Actions on Obj.",
    "Lateral Movement": "Actions on Obj.",
    "Command and Control": "Command & Control",
    "Exfiltration": "Actions on Obj.",
    "Impact": "Actions on Obj.",
  };
  return map[stage.tactic] === target;
}

// A safe no-op context for consumers that render outside a Provider.
const _NOOP = {
  filter: {}, active: false,
  set: () => {}, toggle: () => {}, clear: () => {},
  match: () => true,
};
