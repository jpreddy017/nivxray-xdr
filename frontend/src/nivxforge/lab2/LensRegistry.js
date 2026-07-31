/**
 * ADR-0025 · Lens Registry
 *
 * Every workspace lens is a self-declaring entry. The shell reads
 * this array to render the lensbar, dispatch keyboard shortcuts,
 * and enforce feature-flag / CIO-field gating. New lenses added
 * here light up automatically — no switch statements, no router,
 * no shell edits.
 *
 * Contract (each lens):
 *   id ............ stable string, used in ?lens=<id> deep links
 *   title .......... human label in the lensbar
 *   short .......... short label for tight tab bars (optional)
 *   icon ........... unicode / glyph (a real icon lib arrives later)
 *   order .......... display order (lower = leftmost)
 *   shortcut ....... keyboard key ("1".."9") — resolves to Number.parseInt
 *   featureFlag .... optional; lens hidden unless flag returns true
 *   requiredCIO .... array of dot-paths that must be present on the CIO
 *                    for the lens to render (else shows an empty-state)
 *   loading ........ "eager" | "lazy" — placeholder for future code-split
 *
 * The concrete UI content is still hosted inside LabV2 for now; a
 * follow-up slice will extract each lens into its own component and
 * point the registry entry's `component` field at it.
 */
export const LENSES = [
  { id: "exec",     title: "Executive",    short: "Exec",    icon: "◆", order: 1, shortcut: "1",                  requiredCIO: ["summary"],               loading: "eager" },
  { id: "story",    title: "Story",        short: "Story",   icon: "❖", order: 2, shortcut: "2",                  requiredCIO: ["summary"],               loading: "eager" },
  { id: "behavior", title: "Behaviour",    short: "Beh",     icon: "◈", order: 3, shortcut: "3",                  requiredCIO: ["evidence_graph"],        loading: "eager" },
  { id: "attack",   title: "Attack Chain", short: "ATT&CK",  icon: "△", order: 4, shortcut: "4",                  requiredCIO: ["summary.mitre_digest"],  loading: "eager" },
  { id: "source",   title: "Output",       short: "Output",  icon: "▤", order: 5, shortcut: "5",                  requiredCIO: ["decode_chain"],          loading: "eager" },
  { id: "osint",    title: "OSINT",        short: "OSINT",   icon: "◎", order: 6, shortcut: "6",                  requiredCIO: ["evidence_graph"],        loading: "lazy"  },
  { id: "raw",      title: "Source",       short: "Src",     icon: "☰", order: 7, shortcut: "7",                  requiredCIO: ["input_text"],            loading: "lazy"  },
  // Reserved future lenses (registered so the shell can announce them):
  // { id: "report",   title: "Report",      order: 8, shortcut: "8", requiredCIO: ["summary.report_sections"], loading: "lazy" },
  // { id: "timeline", title: "Timeline",    order: 9, shortcut: "9", requiredCIO: ["timeline"],                loading: "lazy" },
  // { id: "notebook", title: "Notebook",    order:10, shortcut: null, featureFlag: () => false,                loading: "lazy" },
];

/** Return lenses sorted by order, filtered by featureFlag(). */
export function listLenses() {
  return LENSES
    .filter((l) => (typeof l.featureFlag === "function" ? l.featureFlag() : true))
    .sort((a, b) => a.order - b.order);
}

export function getLensByShortcut(key) {
  const s = String(key);
  return LENSES.find((l) => l.shortcut === s) || null;
}

export function getLens(id) {
  return LENSES.find((l) => l.id === id) || null;
}
