/**
 * ribbonSettings · shared, persisted ribbon preferences.
 *
 * Mirrors Cisco XDR's ribbon settings (docs.xdr.security.cisco.com/Content/
 * Ribbon/configure-ribbon-settings.htm): the ribbon's expanded/collapsed
 * state, its collapsed position, its height, and the DEFANG ON COPY toggle.
 *
 * Cisco behaviour that other components must honour:
 *   when `defangOnCopy` is ON, the pivot menu REMOVES "Copy defanged value"
 *   and "Copy value" copies the defanged form instead.
 */
const KEY = "nx.ribbon";

const DEFAULTS = {
  // E2E-1 · density (owner directive §15). Cisco's ribbon is a utility tray;
  // expanded-by-default cost 260px of a 800px SOC viewport, so the incident
  // queue lost half its rows before an analyst touched anything. It now
  // starts collapsed and is one click away; the preference still persists.
  expanded: false,
  height: 260,             // px, user-resizable by dragging the top edge
  side: "left",            // collapsed floating button position
  app: "incidents",        // active ribbon app
  defangOnCopy: false,
};

export function readRibbon() {
  try {
    const raw = window.localStorage.getItem(KEY);
    if (!raw) return { ...DEFAULTS };
    return { ...DEFAULTS, ...JSON.parse(raw) };
  } catch { return { ...DEFAULTS }; }
}

export function writeRibbon(patch) {
  try {
    const next = { ...readRibbon(), ...patch };
    window.localStorage.setItem(KEY, JSON.stringify(next));
    window.dispatchEvent(new CustomEvent("nx-ribbon-change", { detail: next }));
    return next;
  } catch { return readRibbon(); }
}

export const defangOnCopy = () => readRibbon().defangOnCopy === true;

export const RIBBON_MIN = 160;
export const RIBBON_MAX = 620;
