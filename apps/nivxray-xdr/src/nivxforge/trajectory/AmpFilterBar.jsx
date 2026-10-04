/**
 * DT2-3a / DT2-3a.1 · AMP parity — the Device Trajectory control row.
 *
 * Cisco (User Guide p.402 figure / p.406 "Filters" / p.407 "Search"):
 *   ‑ search on the LEFT, full width, magnifier inside, submitted with
 *     Enter; `Filters` on the RIGHT as a borderless control with a
 *     filter glyph and a chevron
 *   ‑ five filter categories — Activity, System, Disposition, Flags,
 *     File Type — and at least one item must be selected in each
 *     category to view results
 *   ‑ filters are applied explicitly with `Apply Filters`
 *
 * Categories are populated from REAL observed evidence only. Where
 * NivXForge does not collect what a Cisco category needs, the category
 * is present (Cisco structure) and states the gap. No value — and in
 * particular no CLEAN disposition — is manufactured to fill a control.
 */
import React, { useEffect, useState } from "react";
import { ChevronDown, Search, SlidersHorizontal } from "lucide-react";

import { C, typeLabel } from "./ampModel";
import { OTHER, OTHER_LABEL, TYPES } from "./dt2/fileType";
import EventGlyph from "./AmpIcons";

const SYSTEM_CLASS =
  /detect|compromis|reboot|policy|definition|scan|sensor|service|system|install/i;

const DISPOSITIONS = [
  ["MALICIOUS", "Malicious", C.malicious],
  ["SUSPICIOUS", "Suspicious", C.suspicious],
  ["UNKNOWN_NOT_ASSESSED", "Unknown", C.inkFaint],
];

export default function AmpFilterBar({
  typeCounts = [], kinds, onKinds, dispositions, onDispositions,
  fileTypes = [], onFileTypes, fileTypeCounts = new Map(),
  processes = [], hiddenProcesses = [], onHiddenProcesses,
  query, onQuery,
  /** Cisco reports how much evidence a search matched and reduces the
   *  trajectory to it. `null` = nothing counted yet; a real 0 is
   *  reported as 0 and never hidden. */
  matchCount = null,
}) {
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState(query || "");
  const [dKinds, setDKinds] = useState(kinds);
  const [dDisp, setDDisp] = useState(dispositions);
  const [dTypes, setDTypes] = useState(fileTypes);
  const [dHidden, setDHidden] = useState(hiddenProcesses);

  const allKinds = typeCounts.map((t) => t.event_type);
  const allDisp = DISPOSITIONS.map(([k]) => k);

  useEffect(() => { setDraft(query || ""); }, [query]);
  /** An empty selection means "everything" to the projection. Cisco's
   *  menu instead shows every item ticked, so the draft is expanded for
   *  display and collapsed again on Apply. */
  useEffect(() => {
    setDKinds(kinds.length ? kinds : typeCounts.map((t) => t.event_type));
  }, [kinds, typeCounts]);
  useEffect(() => {
    setDDisp(dispositions.length ? dispositions
      : DISPOSITIONS.map(([k]) => k));
  }, [dispositions]);
  useEffect(() => { setDTypes(fileTypes); }, [fileTypes]);
  useEffect(() => { setDHidden(hiddenProcesses); }, [hiddenProcesses]);

  const activity = typeCounts.filter((t) => !SYSTEM_CLASS.test(t.event_type));
  const system = typeCounts.filter((t) => SYSTEM_CLASS.test(t.event_type));

  const toggle = (list, set) => (v) => set(
    list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);

  // Cisco: at least one item from each category that HAS items.
  const chosen = (items) => items.some((t) => dKinds.includes(t.event_type));
  const ok = (!activity.length || chosen(activity))
    && (!system.length || chosen(system)) && dDisp.length > 0
    && dTypes.length > 0
    && (!processes.length || dHidden.length < processes.length);

  const apply = () => {
    if (!ok) return;
    onKinds(dKinds.length === allKinds.length ? [] : dKinds);
    onDispositions(dDisp.length === allDisp.length ? [] : dDisp);
    onFileTypes(dTypes);
    onHiddenProcesses(dHidden);
    setOpen(false);
  };

  return (
    <div style={{ display: "flex", gap: 22, alignItems: "center",
                  padding: "0 0 12px" }}
         data-testid="amp-filter-bar">
      <div style={{ position: "relative", flex: 1, display: "flex",
                    alignItems: "center",
                    border: `1px solid ${C.gridStrong}`, borderRadius: 4,
                    background: C.paper }}>
        <span style={{ display: "flex", padding: "0 9px 0 12px" }}>
          <Search size={14} color={C.inkDim} />
        </span>
        <input value={draft}
               onChange={(e) => setDraft(e.target.value)}
               onKeyDown={(e) => {
                 if (e.key === "Enter") onQuery(draft.trim());
                 if (e.key === "Escape") { setDraft(""); onQuery(""); }
               }}
               data-testid="amp-filter-search"
               placeholder="Search Device Trajectory"
               style={{ flex: 1, fontSize: 14, color: C.ink,
                        padding: "10px 12px 10px 0", background: "transparent",
                        border: "none", outline: "none" }} />
        {query ? (
          <span data-testid="amp-search-match-count"
                data-match-count={matchCount == null ? "" : String(matchCount)}
                style={{ fontSize: 12.5, color: C.inkDim, whiteSpace: "nowrap",
                         padding: "0 12px 0 6px" }}>
            {matchCount == null ? "searching…"
              : `${matchCount} matching observation`
                + `${matchCount === 1 ? "" : "s"}`}
          </span>
        ) : null}
      </div>

      <div style={{ position: "relative" }}>
        <button onClick={() => setOpen((v) => !v)}
                data-testid="amp-filters-button"
                style={{ fontSize: 14, padding: "6px 2px", border: "none",
                         cursor: "pointer", background: "transparent",
                         color: C.link, whiteSpace: "nowrap", fontWeight: 700,
                         display: "flex", gap: 7, alignItems: "center" }}>
          <SlidersHorizontal size={14} /> Filters <ChevronDown size={13} />
        </button>
        {open && (
          <div data-testid="amp-filters-menu"
               style={{ position: "absolute", top: 30, right: 0, zIndex: 60,
                        background: C.paper, width: 282, maxHeight: 460,
                        overflowY: "auto", padding: 10, borderRadius: 3,
                        border: `1px solid ${C.gridStrong}`,
                        boxShadow: "0 10px 26px rgba(20,32,44,.18)" }}>
            <Cat title="Activity" testid="amp-filter-cat-activity">
              {activity.length === 0
                ? <Gap text="No activity events recorded" />
                : activity.map((t) => (
                  <Check key={t.event_type}
                         testid={`amp-filter-type-${t.event_type}`}
                         checked={dKinds.includes(t.event_type)}
                         onChange={() => toggle(dKinds, setDKinds)(
                           t.event_type)}
                         glyph={<EventGlyph event={{ event_type: t.event_type }}
                                            color={C.glyph} />}
                         label={typeLabel(t.event_type)} />
                ))}
            </Cat>

            <Cat title="System" testid="amp-filter-cat-system">
              {system.length === 0
                ? <Gap text="No system or connector events recorded" />
                : system.map((t) => (
                  <Check key={t.event_type}
                         testid={`amp-filter-type-${t.event_type}`}
                         checked={dKinds.includes(t.event_type)}
                         onChange={() => toggle(dKinds, setDKinds)(
                           t.event_type)}
                         glyph={<EventGlyph event={{ event_type: t.event_type }}
                                            color={C.glyph} />}
                         label={typeLabel(t.event_type)} />
                ))}
            </Cat>

            <Cat title="Disposition" testid="amp-filter-cat-disposition">
              {DISPOSITIONS.map(([key, label, color]) => (
                <Check key={key} testid={`amp-filter-disp-${key}`}
                       checked={dDisp.includes(key)}
                       onChange={() => toggle(dDisp, setDDisp)(key)}
                       dot={color} label={label} />
              ))}
              <Gap text="Cisco's CLEAN disposition has no NivXForge verdict
                         behind it and is not offered." />
            </Cat>

            <Cat title="Flags" testid="amp-filter-cat-flags">
              <Gap text="Event flags are not collected by the NivXRay EDR
                         sensor." />
            </Cat>

            <Cat title="Processes" testid="amp-filter-cat-processes">
              {processes.length ? processes.map((p) => (
                <Check key={p.nodeId}
                       testid={`amp-filter-proc-${p.nodeId}`}
                       checked={!dHidden.includes(p.nodeId)}
                       onChange={() => toggle(dHidden, setDHidden)(p.nodeId)}
                       label={`${p.label}${p.pid ? ` · ${p.pid}` : ""}`} />
              )) : (
                <Gap text="No process trajectory in this window." />
              )}
              <Gap text="De-selecting a process removes its trajectory from
                         the graph only. The observations, its children and
                         every relationship stay in the evidence, and a child
                         is never re-attached to another process because its
                         parent is hidden." />
            </Cat>

            <Cat title="File Type" testid="amp-filter-cat-filetype">
              {[...TYPES, [OTHER, OTHER_LABEL]].map(([key, label]) => (
                <Check key={key} testid={`amp-filter-ftype-${key}`}
                       checked={dTypes.includes(key)}
                       onChange={() => toggle(dTypes, setDTypes)(key)}
                       label={`${label}${fileTypeCounts.get(key)
                         ? ` (${fileTypeCounts.get(key)})` : ""}`} />
              ))}
              <Gap text="Cisco displays ten file classes (User Guide p.401)
                         and narrows at the cloud query (TAC 118711) to
                         'accent the more important indications of
                         compromise'. Cisco identifies the class from file
                         CONTENT; the NivXForge sensor sends no file-type
                         verdict, so the class here is read from the observed
                         PATH EXTENSION and can be wrong about content.
                         Nothing is discarded — Other returns the rows and
                         Activity lists every observation." />
            </Cat>

            <div style={{ display: "flex", alignItems: "center", gap: 8,
                          marginTop: 10, borderTop: `1px solid ${C.grid}`,
                          paddingTop: 9 }}>
              <button onClick={apply} disabled={!ok}
                      data-testid="amp-apply-filters"
                      style={{ fontSize: 11.5, padding: "5px 12px",
                               borderRadius: 3, border: "none",
                               cursor: ok ? "pointer" : "not-allowed",
                               background: ok ? C.link : C.paperAlt,
                               color: ok ? "#fff" : C.inkFaint,
                               fontWeight: 600 }}>
                Apply Filters
              </button>
              {!ok && (
                <span data-testid="amp-filter-rule"
                      style={{ fontSize: 9.6, color: C.inkFaint,
                               lineHeight: 1.35 }}>
                  Select at least one item from each category to view results.
                </span>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

const Cat = ({ title, children, testid }) => (
  <div data-testid={testid}>
    <div style={{ fontSize: 10.4, fontWeight: 700, color: C.ink,
                  margin: "9px 0 4px", borderBottom: `1px solid ${C.grid}`,
                  paddingBottom: 3 }}>
      {title}
    </div>
    {children}
  </div>
);

const Gap = ({ text }) => (
  <div style={{ fontSize: 9.6, color: C.inkFaint, lineHeight: 1.4,
                padding: "2px 0" }}>
    {text}
  </div>
);

const Check = ({ checked, onChange, label, glyph, dot, testid }) => (
  <label data-testid={testid}
         style={{ display: "flex", alignItems: "center", gap: 7,
                  fontSize: 10.8, color: C.ink, padding: "3px 2px",
                  cursor: "pointer" }}>
    <input type="checkbox" checked={checked} onChange={onChange} />
    {glyph ? (
      <svg width={15} height={15} viewBox="-7.5 -7.5 15 15">{glyph}</svg>
    ) : null}
    {dot ? <span style={{ width: 8, height: 8, borderRadius: "50%",
                          background: dot }} /> : null}
    <span style={{ flex: 1 }}>{label}</span>
  </label>
);
