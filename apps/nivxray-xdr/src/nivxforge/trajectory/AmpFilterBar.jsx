/**
 * DT2-3a · AMP parity — the Device Trajectory control row.
 *
 * Cisco (User Guide p.402 figure) puts the search box on the LEFT, full
 * width, with the magnifier inside it, and `Filters ⌄` on the RIGHT.
 * Nothing else is present in that row: no zoom, no stepping, no
 * counters, no presets.
 *
 * Search is submitted with Enter (User Guide p.407), not per keystroke.
 */
import React, { useEffect, useState } from "react";
import { ChevronDown, Search } from "lucide-react";

import { C, typeLabel } from "./ampModel";
import EventGlyph from "./AmpIcons";

/** Cisco's disposition set is malicious / clean / unknown. NivXForge has
 *  no CLEAN verdict, so none is offered — a clean option we cannot
 *  substantiate would be a manufactured Cisco state. SUSPICIOUS is a real
 *  NivXForge verdict and is never folded into malicious or clean. */
const DISPOSITIONS = [
  ["MALICIOUS", "Malicious", C.malicious],
  ["SUSPICIOUS", "Suspicious", C.suspicious],
  ["UNKNOWN_NOT_ASSESSED", "Unknown", C.inkFaint],
];

export default function AmpFilterBar({
  typeCounts = [], kinds, onKinds, dispositions, onDispositions,
  query, onQuery,
}) {
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState(query || "");

  useEffect(() => { setDraft(query || ""); }, [query]);

  const toggle = (list, setter) => (v) => setter(
    list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);

  return (
    <div style={{ display: "flex", gap: 8, alignItems: "center",
                  padding: "7px 9px" }}
         data-testid="amp-filter-bar">
      <div style={{ position: "relative", flex: 1, display: "flex",
                    alignItems: "center",
                    border: `1px solid ${C.gridStrong}`, borderRadius: 3,
                    background: C.paper }}>
        <span style={{ display: "flex", padding: "0 7px 0 9px" }}>
          <Search size={12} color={C.inkDim} />
        </span>
        <input value={draft}
               onChange={(e) => setDraft(e.target.value)}
               onKeyDown={(e) => {
                 if (e.key === "Enter") onQuery(draft.trim());
                 if (e.key === "Escape") { setDraft(""); onQuery(""); }
               }}
               data-testid="amp-filter-search"
               placeholder="Search Device Trajectory"
               style={{ flex: 1, fontSize: 11.5, color: C.ink,
                        padding: "6px 9px 6px 0", background: "transparent",
                        border: "none", outline: "none" }} />
      </div>

      <div style={{ position: "relative" }}>
        <button onClick={() => setOpen((v) => !v)}
                data-testid="amp-filters-button"
                style={{ fontSize: 11.5, padding: "6px 11px", borderRadius: 3,
                         cursor: "pointer", background: C.paper,
                         color: C.link, whiteSpace: "nowrap",
                         border: `1px solid ${C.gridStrong}`,
                         display: "flex", gap: 6, alignItems: "center" }}>
          Filters <ChevronDown size={11} />
        </button>
        {open && (
          <div data-testid="amp-filters-menu"
               style={{ position: "absolute", top: 30, right: 0, zIndex: 60,
                        background: C.paper, width: 268, maxHeight: 430,
                        overflowY: "auto", padding: 9, borderRadius: 3,
                        border: `1px solid ${C.gridStrong}`,
                        boxShadow: "0 10px 26px rgba(20,32,44,.18)" }}>
            <Section title="Activity" />
            {typeCounts.length === 0 && (
              <div style={{ fontSize: 10.4, color: C.inkFaint }}>
                No activity types recorded
              </div>
            )}
            {typeCounts.map((t) => (
              <label key={t.event_type}
                     data-testid={`amp-filter-type-${t.event_type}`}
                     style={{ display: "flex", alignItems: "center", gap: 7,
                              fontSize: 10.8, color: C.ink, padding: "3px 2px",
                              cursor: "pointer" }}>
                <input type="checkbox" checked={kinds.includes(t.event_type)}
                       onChange={() => toggle(kinds, onKinds)(t.event_type)} />
                <svg width={15} height={15} viewBox="-7.5 -7.5 15 15">
                  <EventGlyph event={{ event_type: t.event_type }}
                              color={C.glyph} />
                </svg>
                <span style={{ flex: 1 }}>{typeLabel(t.event_type)}</span>
              </label>
            ))}

            <Section title="Disposition" />
            {DISPOSITIONS.map(([key, label, color]) => (
              <label key={key} data-testid={`amp-filter-disp-${key}`}
                     style={{ display: "flex", alignItems: "center", gap: 7,
                              fontSize: 10.8, color: C.ink, padding: "3px 2px",
                              cursor: "pointer" }}>
                <input type="checkbox" checked={dispositions.includes(key)}
                       onChange={() => toggle(dispositions,
                                              onDispositions)(key)} />
                <span style={{ width: 8, height: 8, borderRadius: "50%",
                               background: color }} />
                {label}
              </label>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

const Section = ({ title }) => (
  <div style={{ fontSize: 10.4, fontWeight: 700, color: C.ink,
                margin: "8px 0 4px", borderBottom: `1px solid ${C.grid}`,
                paddingBottom: 3 }}>
    {title}
  </div>
);
