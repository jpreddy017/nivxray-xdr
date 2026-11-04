/**
 * TrajectoryWorkspace · the Device Trajectory tab body.
 *
 * Presentational: every piece of temporal state is owned by the Entity
 * 360 page and shared by the navigator, the lifeline canvas, the
 * compromise band and the events ledger, so the four surfaces can never
 * disagree about the selected window.
 */
import React from "react";

import TrajectoryNavigator from "@/xdr/components/TrajectoryNavigator";
import TrajectoryLifelineCanvas from "@/xdr/components/TrajectoryLifelineCanvas";
import CompromiseBand from "@/xdr/components/CompromiseBand";
import EventsLedger from "@/xdr/components/EventsLedger";
import ActivityDetailsPanel from "@/xdr/components/ActivityDetailsPanel";
import { fmtUtc } from "@/xdr/lib/trajectoryModel";

export default function TrajectoryWorkspace({
  deviceRef, events, eventsInView, canvasEvents, matchedIds,
  query, onQueryChange, selectedDay, onSelectDay,
  viewStart, viewEnd, onWindowChange, onCenter,
  selectedId, selectedEvent, onSelect, hoverId, onHover,
  spans, caseRows, incidents, selectedSpanId, onSelectSpan, haloIds,
  onContextMenu, onStaticAnalysis, cursorTs, filterCount, onOpenFilters,
}) {
  return (
    <div data-testid="edr-trajectory-workspace">
      <TrajectoryNavigator
        events={events}
        matchedIds={matchedIds}
        query={query}
        onQueryChange={onQueryChange}
        selectedDay={selectedDay}
        onSelectDay={onSelectDay}
        viewStart={viewStart}
        viewEnd={viewEnd}
        onWindowChange={onWindowChange}
        onSelectEvent={onSelect}
        cursorTs={cursorTs}
        filterCount={filterCount}
        onOpenFilters={onOpenFilters}
      />

      <div style={{ display: "grid", gridTemplateColumns: "1fr 340px",
                    gap: 10, marginTop: 10 }}
           data-testid="xdr-trajectory-panes">
        <div style={{ display: "flex", flexDirection: "column", gap: 10,
                      minWidth: 0 }}>
          <section className="panel" style={{ padding: 8, overflow: "hidden" }}
                   data-testid="xdr-trajectory-center">
            <div style={{ display: "flex", alignItems: "center", gap: 10,
                          marginBottom: 6 }}>
              <span className="section-title" style={{ margin: 0 }}>
                Device Trajectory · Lifelines
              </span>
              <span className="mono" style={{ fontSize: 9.8, color: "var(--faint)" }}
                    data-testid="xdr-trajectory-event-count">
                {canvasEvents.length} / {events.length} observations ·{" "}
                {fmtUtc(viewStart)} → {fmtUtc(viewEnd)}
              </span>
            </div>
            {canvasEvents.length === 0 ? (
              <div className="x-empty" data-testid="xdr-trajectory-view-empty">
                <b>◇ NO OBSERVATIONS IN SELECTED WINDOW</b>
                <div style={{ marginTop: 4 }}>
                  {events.length} observations exist across the full observed
                  timeline. Use the navigator above to select a day with
                  activity, or widen the window.
                </div>
              </div>
            ) : (
              <TrajectoryLifelineCanvas
                events={canvasEvents}
                viewStart={viewStart}
                viewEnd={viewEnd}
                onWindowChange={onWindowChange}
                selectedId={selectedId}
                onSelect={onSelect}
                onContextMenu={onContextMenu}
                haloIds={haloIds}
                matchedIds={matchedIds}
                focusLabel={query}
                cursorTs={cursorTs}
                hoverId={hoverId}
                onHover={onHover}
              />
            )}
          </section>

          <CompromiseBand
            spans={spans}
            caseRows={caseRows}
            incidents={incidents}
            selectedSpanId={selectedSpanId}
            onSelectSpan={onSelectSpan}
            onFocusSpan={(s) => {
              const pad = Math.max(1000, (s.end - s.start) * 0.12);
              onWindowChange(s.start - pad, s.end + pad);
            }}
          />

          <EventsLedger
            events={eventsInView}
            selectedId={selectedId}
            hoverId={hoverId}
            onHover={onHover}
            onSelect={onSelect}
            onCenter={onCenter}
            onContextMenu={onContextMenu}
          />
        </div>

        <aside className="panel" style={{ padding: 12, overflow: "auto",
                                          maxHeight: 900 }}
               data-testid="xdr-trajectory-right">
          <div className="section-title" style={{ marginBottom: 10 }}>
            Activity Details
          </div>
          <ActivityDetailsPanel
            event={selectedEvent}
            deviceRef={deviceRef}
            incidents={incidents}
            onStaticAnalysis={onStaticAnalysis}
            onClose={() => onSelect(null)}
          />
        </aside>
      </div>
    </div>
  );
}
