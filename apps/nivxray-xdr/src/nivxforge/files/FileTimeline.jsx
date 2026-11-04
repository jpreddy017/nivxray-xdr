import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import Icon from './TrajectoryIcon';
import { chronological, eventKey, eventStyle, clusterEvents, unique, unavailable } from './trajectoryModel.mjs';

const stamp = (t) => new Date(t).toISOString().replace('T', ' ').replace('.000Z', ' UTC');
function Field({ label, values }) {
  const list = unique(values);
  return <div><dt>{label}</dt><dd>{list.length ? list.map((v) => <div key={String(v)}>{String(v)}</div>) : unavailable}</dd></div>;
}
export default function FileTimeline({ rows, endpointId, selected, onSelect, start, end, computers = [] }) {
  const [zoom, setZoom] = useState(1), [offset, setOffset] = useState(0), [expanded, setExpanded] = useState({});
  const [cluster, setCluster] = useState(null);
  const events = chronological(rows);
  const ids = unique(rows.map((r) => r.endpoint_id || endpointId));
  const name = (id) => computers.find((c) => c.endpoint_id === id)?.hostname || id;
  const duration = (end - start) / zoom;
  const from = start + offset * (end - start - duration), to = from + duration;
  const first = events[0];
  const connections = [...new Map(rows.flatMap((r) => (r.network_connections || []).map((c) => {
    const record = { ...c, endpoint_id: r.endpoint_id || endpointId };
    return [JSON.stringify(record), record];
  }))).values()];
  const executions = rows.flatMap((r) => r.executions || []);
  const writers = unique(rows.map((r) => r.writer_image || r.process_image));
  return <>
    <div className="ft-top-grid">
      <section className="ft-card"><h3><Icon name="eye" />Visibility</h3>
        <div className="ft-metrics"><div><strong>{rows.length}</strong><span>Loaded events</span></div><div><strong>{ids.length}</strong><span>Computers in results</span></div></div>
        <dl><Field label="First seen in loaded results" values={[first?.observed_at]} /><Field label="Last seen in loaded results" values={[events[events.length - 1]?.observed_at]} /></dl>
      </section>
      <section className="ft-card"><h3><Icon name="entry" />Entry Point</h3>
        <p className="ft-unavailable">Origin not established</p><dl><Field label="Earliest computer in loaded results" values={[first && name(first.endpoint_id || endpointId)]} /><Field label="First observed path" values={[first?.path]} /></dl><p>Earliest loaded evidence does not establish how a file entered the environment.</p>
      </section>
      <section className="ft-card"><h3><Icon name="process" />Related Processes</h3>
        <strong>{writers.length}</strong><p>Source-stated process images</p><ul>{writers.slice(0, 3).map((w) => <li key={w}>{w}</li>)}</ul>{!writers.length && <p>{unavailable}</p>}
        <p>Process association alone does not prove which process created or delivered the file.</p><dl><Field label="Hash-matched executable images" values={executions.map((e) => e.image)} /><Field label="Source-stated parent images" values={executions.map((e) => e.parent_image)} /></dl>
      </section>
    </div>
    <details className="ft-card ft-disclosure" open><summary><Icon name="file" />File Details</summary>
      <div className="ft-attributes"><dl><Field label="Known As · SHA-256" values={rows.map((r) => r.hashes?.sha256)} /><Field label="SHA-1" values={rows.map((r) => r.hashes?.sha1)} /><Field label="MD5" values={rows.map((r) => r.hashes?.md5)} /></dl>
      <dl><Field label="Known Names" values={rows.map((r) => r.name)} /><Field label="Size (bytes)" values={rows.map((r) => r.size)} /><Field label="Signer" values={rows.map((r) => r.signer)} /></dl>
      <dl><Field label="File type" values={[]} /><Field label="Detected As" values={[]} /><Field label="Current disposition" values={[]} /><Field label="Evidence sources" values={rows.map((r) => r.source)} /></dl></div>
      <p>Attributes describe loaded observations. Name and path matches may represent different file contents. Missing detection data is not a clean verdict.</p>
    </details>
    <details className="ft-card ft-disclosure"><summary><Icon name="network" />Network Profile</summary>
      <div className="ft-attributes"><dl><Field label="IP addresses" values={connections.map((c) => c.dst_ip)} /><Field label="Ports" values={connections.map((c) => c.dst_port)} /></dl><dl><Field label="URLs" values={connections.map((c) => c.url)} /><Field label="DNS names" values={connections.map((c) => c.dns)} /><Field label="Flagged connections" values={[]} /></dl></div>
      <p>Connections require a matching file SHA-256 and source process GUID on the same authorized computer. Up to 1,000 recent source records per computer are examined within the requested time window; missing connections do not prove no network activity.</p>
      {rows.some((r) => r.context_coverage === 'BOUNDED_SCAN_INCOMPLETE' || r.context_results_truncated) && <p role="status">Network context scan is incomplete. Older records may contain additional connections.</p>}
      {connections.length > 0 && <div className="ft-timeline-scroll"><table><thead><tr><th>Computer</th><th>Time (UTC)</th><th>Process GUID</th><th>Destination</th><th>Port</th><th>Protocol</th><th>Evidence record</th></tr></thead><tbody>{connections.map((c, i) => <tr key={`${c.record_id}:${i}`}><td>{name(c.endpoint_id)}</td><td>{c.observed_at}</td><td>{c.process_guid}</td><td>{c.dst_ip || c.dns || c.url || unavailable}</td><td>{c.dst_port ?? unavailable}</td><td>{c.protocol || unavailable}</td><td>{c.record_id}</td></tr>)}</tbody></table></div>}
    </details>
    <section className="ft-card" aria-label="Trajectory timeline"><div className="ft-section-head"><h3><Icon name="timeline" />Trajectory</h3>
      <div className="ft-tools"><label>Zoom <select aria-label="Zoom" value={zoom} onChange={(e) => { setZoom(Number(e.target.value)); setOffset(0); }}><option value={1}>Full window</option><option value={2}>2×</option><option value={4}>4×</option><option value={8}>8×</option></select></label><button className="btn" onClick={() => { setZoom(1); setOffset(0); }}>Reset view</button></div></div>
      <div className="ft-legend">{['created','executed','quarantined','deleted','renamed','observed'].map((a) => { const s = eventStyle(a); return <span key={a} data-tone={s.tone}><Icon name={s.icon} />{s.label}</span>; })}</div>
      {zoom > 1 && <label className="ft-pan">Pan time window <input aria-label="Pan time window" type="range" min="0" max="100" value={offset * 100} onChange={(e) => setOffset(Number(e.target.value) / 100)} /></label>}
      <p>Click an event for details or a numbered cluster to expand nearby events. Expand a computer for related processes. Ordering shows time, not causality.</p>
      <div className="ft-timeline-scroll"><div className="ft-timeline-inner"><div className="ft-axis-row"><span>Computer</span><div className="ft-time-axis">{[0,1,2,3,4].map((n) => <time key={n}>{stamp(from + duration * n / 4)}</time>)}</div></div>
      {ids.map((id) => {
        const hostRows = rows.filter((r) => (r.endpoint_id || endpointId) === id);
        const positioned = clusterEvents(hostRows, from, to);
        const height = 80;
        const processes = unique(hostRows.map((r) => r.writer_image || r.process_image));
        return <div className="ft-host-group" key={id}><div className="ft-host-row"><button className="ft-host-label" aria-expanded={Boolean(expanded[id])} onClick={() => setExpanded((old) => ({ ...old, [id]: !old[id] }))}><Icon name="computer" /><span>{name(id)}<small>{hostRows.length} loaded events</small></span><span>{expanded[id] ? '−' : '+'}</span></button>
          <div className="ft-time-track" style={{ height }}>{positioned.map(({ rows: grouped, position }) => { const row = grouped[0], s = eventStyle(row.action); return <button key={eventKey(row)} type="button" className="ft-time-event" data-tone={grouped.length > 1 ? 'gray' : s.tone} aria-pressed={Boolean(selected && grouped.some((r) => eventKey(selected) === eventKey(r)))} style={{ left: `${position}%`, top: 22 }} title={grouped.length > 1 ? `${grouped.length} events · click to expand` : `${row.observed_at} · ${row.action || 'Observed'}`} aria-label={grouped.length > 1 ? `Expand ${grouped.length} events on ${name(id)}` : `Inspect event ${row.observed_at}, ${row.action || 'Observed'}, ${row.path || unavailable}`} onClick={(e) => grouped.length > 1 ? setCluster({ id, rows: grouped }) : onSelect(row, e.currentTarget)}>{grouped.length > 1 ? grouped.length : <Icon name={s.icon} />}</button>; })}{!positioned.length && <p>No loaded events in this zoom window</p>}</div></div>
          {cluster?.id === id && <div className="ft-cluster"><div className="ft-section-head"><h4>{cluster.rows.length} grouped events · {name(id)}</h4><button className="btn" onClick={() => setCluster(null)}>Close grouped events</button></div><div className="ft-cluster-list">{cluster.rows.map((r) => <button className="ft-cluster-event" key={eventKey(r)} onClick={(e) => onSelect(r, e.currentTarget)}><Icon name={eventStyle(r.action).icon} /><time>{r.observed_at}</time><span>{r.action || 'Observed'}</span><span>{r.path}</span></button>)}</div></div>}
          {expanded[id] && <div className="ft-host-processes"><h4>Related processes on {name(id)}</h4>{processes.length ? <ul>{processes.map((p) => <li key={p}>{p}</li>)}</ul> : <p>{unavailable}</p>}<Link to={`/edr/computers/${encodeURIComponent(id)}/trajectory?t0=${start}&t1=${end}`}>Open Device Trajectory →</Link></div>}
        </div>;
      })}{!ids.length && <div className="ft-empty">No matching file events in the loaded results.</div>}</div></div>
    </section>
  </>;
}
