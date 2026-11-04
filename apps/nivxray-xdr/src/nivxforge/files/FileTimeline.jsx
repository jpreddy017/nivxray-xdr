import React from "react";

export default function FileTimeline({ rows, endpointId, selected, onSelect, start, end }) {
  const events = rows.filter((row) => Number.isFinite(Date.parse(row.observed_at)))
    .slice().sort((a, b) => Date.parse(a.observed_at) - Date.parse(b.observed_at));
  const lanes = [];
  const positioned = events.map((row) => {
    const position = Math.max(0, Math.min(100, (Date.parse(row.observed_at) - start) / (end - start) * 100));
    let lane = lanes.findIndex((last) => position - last >= 7);
    if (lane < 0) lane = lanes.length;
    lanes[lane] = position;
    return { row, position, lane };
  });
  const paths = [...new Set(rows.map((row) => row.path).filter(Boolean))];
  const hashes = [...new Set(rows.map((row) => row.hashes?.sha256).filter(Boolean))];
  return <section className="ft-trajectory" aria-label="Trajectory timeline">
    <div className="ft-summary">
      <div><h3>Visibility</h3><strong>{rows.length}</strong><p>Loaded observations</p></div>
      <div><h3>File details</h3><strong>{hashes.length}</strong><p>Observed SHA-256 hashes · {paths.length} paths</p></div>
      <div><h3>First observed in loaded results</h3><p>{events[0]?.observed_at || "Unavailable from this source"}</p></div>
      <div><h3>Last observed in loaded results</h3><p>{events[events.length - 1]?.observed_at || "Unavailable from this source"}</p></div>
    </div>
    <h3>Trajectory</h3>
    <p>Select an event to inspect its file, process and source evidence. Times are UTC.</p>
    <div className="ft-timeline-scroll">
      <div className="ft-time-axis"><span>{new Date(start).toISOString()}</span><span>{new Date(end).toISOString()}</span></div>
      <div className="ft-host-label">{endpointId}</div>
      <div className="ft-time-track" style={{ height: Math.max(136, lanes.length * 32 + 24) }}>
        {positioned.map(({ row, position, lane }) => <button key={row.record_id} type="button"
          className="ft-time-event" aria-pressed={selected?.record_id === row.record_id}
          style={{ left: `${position}%`, top: `${12 + lane * 32}px` }}
          title={`${row.observed_at} · ${row.action || "Event"} · ${row.path || "Path unavailable"}`}
          aria-label={`Inspect event ${row.observed_at}, ${row.action || "Event"}, ${row.path || "Path unavailable"}`}
          onClick={(event) => onSelect(row, event.currentTarget)} />)}
      </div>
    </div>
    {!events.length && <p>No timed events in the loaded results.</p>}
  </section>;
}
