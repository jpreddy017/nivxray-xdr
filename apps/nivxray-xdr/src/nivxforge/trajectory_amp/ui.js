import { PAL } from "./model";

export const FONT = "'IBM Plex Sans', 'Segoe UI', system-ui, sans-serif";
export const MONO = "'IBM Plex Mono', ui-monospace, Menlo, monospace";

export const ui = {
  panel: { background: PAL.panel, border: `1px solid ${PAL.grid}`, borderRadius: 6 },
  h4: { margin: "10px 0 6px", fontSize: 11, letterSpacing: 1.2, textTransform: "uppercase", color: PAL.muted, fontWeight: 600, breakAfter: "avoid" },
  code: { fontFamily: MONO, fontSize: 11, color: PAL.accent },
  btn: { background: PAL.panelAlt, color: PAL.text, border: `1px solid ${PAL.gridStrong}`, borderRadius: 4, padding: "5px 10px",
         fontSize: 12, cursor: "pointer", fontFamily: FONT, transition: "background-color .15s, border-color .15s" },
  btnOn: { background: "#123843", borderColor: PAL.accent, color: "#E8FAFD" },
  chip: { display: "inline-flex", alignItems: "center", gap: 6, borderRadius: 999, padding: "3px 10px", fontSize: 12 },
  hatch: { display: "inline-block", background: `repeating-linear-gradient(135deg, ${PAL.gap} 0 4px, transparent 4px 8px)`,
           border: `1px solid #6B5326` },
  mono: { fontFamily: MONO, fontSize: 11.5, wordBreak: "break-all" },
};
