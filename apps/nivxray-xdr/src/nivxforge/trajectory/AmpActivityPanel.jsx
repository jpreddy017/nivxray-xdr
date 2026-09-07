/**
 * Right-hand pane — Cisco's **Activity** master list with an
 * **Activity Details** drill-in.
 *
 *   State A · Activity            list of the window's activity
 *   State B · ‹ Activity Details  the selected activity, in place
 *   State C · back arrow          returns to Activity
 *
 * In-place master/detail, exactly as the live console behaves: no
 * modal, no navigation away from Device Trajectory, and the trajectory
 * viewport is never disturbed.
 *
 * The list is the window's observations in chronological order — never
 * a sample; the header states the count in the window.
 */
import React, { useEffect, useMemo, useRef } from "react";

import { C, eventColor, isRed, fmtHMS } from "./ampModel";
import EventGlyph from "./AmpIcons";
import AmpEventDetails from "./AmpEventDetails";

const MAX_ROWS = 400;

/** What the observation acted ON — the artefact, from evidence only. */
const targetOf = (e) => e.file || e.network || e.entity || e.process
  || "◇ not reported";

/** Cisco's left column: the actor. Where no parent was observed it says
 *  so rather than repeating the child and implying self-parentage. */
const actorOf = (e, lanes) => {
  if (e.parent_process_name) return e.parent_process_name;
  if (e.parent_lane_index !== null && e.parent_lane_index !== undefined) {
    const ln = lanes.get(e.parent_lane_index);
    if (ln?.label) return ln.label;
  }
  if (e.parent_process_iid) return e.parent_process_iid;
  if (e.parent_state === "PARENT_NOT_OBSERVED_VISIBILITY_GAP") {
    return "◇ parent not observed";
  }
  if (e.parent_state === "PARENT_NOT_REPORTED_BY_SENSOR") {
    return `${e.process || e.lane_id} · root`;
  }
  return e.process || "◇ no lineage reported";
};

export default function AmpActivityPanel({ events, lanes, selected, onSelect,
                                           onPivot, width, height }) {
  const listRef = useRef(null);
  const selRef = useRef(null);

  const rows = useMemo(() => events.slice(0, MAX_ROWS), [events]);

  /** A selection made on the trajectory must be visible in the list
   *  when the analyst navigates back to it. */
  useEffect(() => {
    if (!selected && selRef.current && listRef.current) {
      selRef.current.scrollIntoView({ block: "nearest" });
    }
  }, [selected]);

  if (selected) {
    return (
      <AmpEventDetails event={selected}
                       lane={lanes.get(selected.lane_index)}
                       onPivot={onPivot} width={width} height={height}
                       onBack={() => onSelect(null)} />
    );
  }

  return (
    <aside data-testid="amp-activity-panel"
           style={{ width, height, flexShrink: 0, background: C.paper,
                    borderLeft: `1px solid ${C.gridStrong}`,
                    display: "flex", flexDirection: "column",
                    minWidth: 0 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8,
                    padding: "9px 10px",
                    borderBottom: `1px solid ${C.gridStrong}` }}>
        <span style={{ fontSize: 12.5, color: C.ink, fontWeight: 600,
                       flex: 1 }}>
          Activity
        </span>
        <span className="mono" data-testid="amp-activity-count"
              data-shown={rows.length} data-in-window={events.length}
              style={{ fontSize: 9.4, color: C.inkFaint }}>
          {events.length}
        </span>
      </div>

      <div ref={listRef} data-testid="amp-activity-list"
           style={{ overflowY: "auto", flex: 1, minHeight: 100 }}>
        {rows.length === 0 && (
          <div data-testid="amp-activity-empty"
               style={{ padding: "12px 10px", fontSize: 10.5,
                        color: C.inkFaint, lineHeight: 1.55 }}>
            No activity in this window. That is an absence of
            observation, not an absence of activity.
          </div>
        )}
        {rows.map((e) => {
          const red = isRed(e);
          return (
            <button key={e.event_iid} onClick={() => onSelect(e)}
                    data-testid={`amp-activity-row-${e.event_iid}`}
                    data-parent-state={e.parent_state}
                    data-lane-index={e.lane_index}
                    data-parent-lane-index={e.parent_lane_index}
                    style={{ display: "flex", width: "100%", gap: 6,
                             alignItems: "center", textAlign: "left",
                             padding: "5px 8px", cursor: "pointer",
                             background: "none", border: "none",
                             borderBottom: `1px solid ${C.grid}` }}>
              <span style={{ width: 6, height: 6, borderRadius: "50%",
                             flexShrink: 0,
                             background: red ? C.malicious
                               : (e.disposition === "SUSPICIOUS"
                                 ? C.suspicious : "transparent") }} />
              <span style={{ flex: 1, fontSize: 10.4, color: C.inkDim,
                             overflow: "hidden", textOverflow: "ellipsis",
                             whiteSpace: "nowrap" }}>
                {actorOf(e, lanes)}
              </span>
              <svg width={15} height={15} viewBox="-7.5 -7.5 15 15"
                   style={{ flexShrink: 0 }}>
                <EventGlyph event={e} color={eventColor(e)} red={red} />
              </svg>
              <span style={{ flex: 1.1, fontSize: 10.4,
                             color: red ? C.malicious : C.ink,
                             overflow: "hidden", textOverflow: "ellipsis",
                             whiteSpace: "nowrap" }}>
                {String(targetOf(e))}
              </span>
              <span className="mono" style={{ fontSize: 8.8,
                                              color: C.inkFaint,
                                              flexShrink: 0 }}>
                {e.timestamp ? fmtHMS(Date.parse(e.timestamp)) : ""}
              </span>
            </button>
          );
        })}
      </div>
    </aside>
  );
}
