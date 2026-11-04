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
import { AlertTriangle } from "lucide-react";

import { C, eventColor, isRed } from "./ampModel";
import EventGlyph from "./AmpIcons";
import AmpEventDetails from "./AmpEventDetails";

const MAX_ROWS = 400;

/** What the observation acted ON — the artefact, from evidence only. */
const targetOf = (e) => e.file || e.network || e.entity || e.process || "";

/** Cisco's left column: the actor. */
const actorOf = (e, lanes) => {
  if (e.parent_process_name) return e.parent_process_name;
  if (e.parent_lane_index !== null && e.parent_lane_index !== undefined) {
    const ln = lanes.get(e.parent_lane_index);
    if (ln?.label) return ln.label;
  }
  return e.process || "";
};

export default function AmpActivityPanel({ events, lanes, selected, onSelect,
                                           onPivot, width, height,
                                           windowState = null,
                                           emptiness = null , compromise = null }) {
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
      <AmpEventDetails event={selected} compromise={compromise}
                       lane={lanes.get(selected.lane_index)}
                       onPivot={onPivot} width={width} height={height}
                       onBack={() => onSelect(null)} />
    );
  }

  return (
    <aside data-testid="amp-activity-panel"
           data-dt2-scroll-domain="inspector"
           style={{ width, height, flexShrink: 0, background: C.paper,
                    borderLeft: `1px solid ${C.gridStrong}`,
                    display: "flex", flexDirection: "column",
                    overscrollBehavior: "contain",
                    minWidth: 0 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8,
                    padding: "22px 14px 20px",
                    borderBottom: `1px solid ${C.gridStrong}` }}>
        <span style={{ fontSize: 15, color: C.ink, fontWeight: 600,
                       flex: 1 }}>
          Activity
        </span>
      </div>

      <div style={{ display: "flex", flex: 1, minHeight: 0 }}>
      <div ref={listRef} data-testid="amp-activity-list"
           data-dt2-scroll-domain="inspector"
           style={{ overflowY: "auto", flex: 1, minHeight: 100,
                    minWidth: 0, overscrollBehavior: "contain" }}>
        {rows.length === 0 && (
          <div data-testid="amp-activity-empty"
               data-window-state={windowState || ""}
               data-observation-absence={String(
                 emptiness?.isObservationAbsence ?? "")}
               style={{ padding: "12px 10px", fontSize: 10.5,
                        color: C.inkFaint, lineHeight: 1.55 }}>
            No activity to display.
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
                    style={{ display: "flex", width: "100%", gap: 8,
                             alignItems: "center", textAlign: "left",
                             padding: "10px 12px", cursor: "pointer",
                             background: "none", border: "none",
                             borderBottom: `1px solid ${C.grid}` }}>
              <span style={{ width: 13, flexShrink: 0, display: "flex" }}>
                {red ? <AlertTriangle size={12} color={C.suspicious} />
                  : null}
              </span>
              <span style={{ flex: 1, fontSize: 13, color: C.inkDim,
                             overflow: "hidden", textOverflow: "ellipsis",
                             whiteSpace: "nowrap" }}>
                {actorOf(e, lanes)}
              </span>
              <svg width={16} height={16} viewBox="-8 -8 16 16"
                   style={{ flexShrink: 0 }}>
                <EventGlyph event={e} color={eventColor(e)} red={red} />
              </svg>
              <span style={{ flex: 1.1, fontSize: 13,
                             color: red ? C.malicious : C.ink,
                             overflow: "hidden", textOverflow: "ellipsis",
                             whiteSpace: "nowrap" }}>
                {String(targetOf(e))}
              </span>
            </button>
          );
        })}
      </div>
      {/* Cisco's Activity pane carries its own ▲ ▼ scroll track. */}
      <div style={{ width: 15, flexShrink: 0, display: "flex",
                    flexDirection: "column", background: C.paperAlt,
                    borderLeft: `1px solid ${C.grid}` }}>
        <button data-testid="amp-activity-up"
                onClick={() => listRef.current?.scrollBy(
                  { top: -120, behavior: "smooth" })}
                style={actArrow}>▲</button>
        <div style={{ flex: 1 }} />
        <button data-testid="amp-activity-down"
                onClick={() => listRef.current?.scrollBy(
                  { top: 120, behavior: "smooth" })}
                style={actArrow}>▼</button>
      </div>
      </div>
    </aside>
  );
}

const actArrow = {
  width: 15, height: 14, lineHeight: "12px", fontSize: 8, padding: 0,
  cursor: "pointer", background: C.paper, color: C.inkFaint,
  border: `1px solid ${C.grid}`, borderRadius: 2,
};
