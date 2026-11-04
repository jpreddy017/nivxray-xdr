export const unavailable = 'Unavailable from this source';
export const unique = (values) => [...new Set(values.filter((v) => v !== null && v !== undefined && v !== ''))];
export const eventKey = (row) => `${row.endpoint_id || ''}:${row.record_id}`;
export function chronological(rows) {
  return rows.slice().sort((a, b) => Date.parse(a.observed_at) - Date.parse(b.observed_at) || eventKey(a).localeCompare(eventKey(b)));
}
export function eventStyle(action = '') {
  const a = action.toLowerCase();
  if (a.includes('quarant')) return { icon: 'lock', label: 'Quarantine', tone: 'orange' };
  if (a.includes('delet') || a.includes('remov')) return { icon: 'trash', label: 'Delete', tone: 'red' };
  if (a.includes('creat') || a.includes('writ')) return { icon: 'file', label: 'Create / write', tone: 'blue' };
  if (a.includes('execut') || a.includes('launch')) return { icon: 'play', label: 'Execute', tone: 'purple' };
  if (a.includes('renam') || a.includes('mov')) return { icon: 'move', label: 'Move / rename', tone: 'teal' };
  return { icon: 'eye', label: 'Other observation', tone: 'gray' };
}
export function positionEvents(rows, start, end, gap = 7) {
  const lanes = [];
  const events = chronological(rows).filter((r) => Number.isFinite(Date.parse(r.observed_at)) && Date.parse(r.observed_at) >= start && Date.parse(r.observed_at) <= end);
  return events.map((row) => {
    const position = Math.max(0, Math.min(100, (Date.parse(row.observed_at) - start) / Math.max(1, end - start) * 100));
    let lane = lanes.findIndex((last) => position - last >= gap);
    if (lane < 0) lane = lanes.length;
    lanes[lane] = position;
    return { row, position, lane };
  });
}

// Every computer is read through the existing authorization-enforcing endpoint API.
// At most four bounded scans per user request; cursors remain independent per endpoint.
export async function readComputerPage(read, query, signal, continuation) {
  const { endpoint_ids, endpoint_id, ...filters } = query;
  if (!endpoint_ids) return read({ ...query, cursor: continuation || undefined }, signal);
  let queue = continuation ? continuation.map((p) => ({ ...p })) : unique(endpoint_ids).map((id) => ({ id, cursor: undefined }));
  const observations = [], issues = {};
  let scanned = 0, completed = 0;
  for (let count = 0; queue.length && count < 4; count += 1) {
    if (signal.aborted) throw new DOMException('Aborted', 'AbortError');
    const current = queue.shift();
    const value = await read({ ...filters, endpoint_id: current.id, cursor: current.cursor }, signal);
    if (value.state === 'ENDPOINT_NOT_RESOLVED') throw new Error(`Computer ${current.id} could not be resolved. Search results are incomplete.`);
    observations.push(...(value.observations || []).map((r) => ({ ...r, endpoint_id: current.id })));
    scanned += value.scanned_records || 0;
    for (const [key, n] of Object.entries(value.issues || {})) issues[key] = (issues[key] || 0) + n;
    if (value.next_cursor) queue.push({ id: current.id, cursor: value.next_cursor });
    else completed += 1;
  }
  return { observations, issues, scanned_records: scanned, completed_computers: completed,
    state: 'FILE_OBSERVATIONS', complete: queue.length === 0, next_cursor: queue.length ? queue : null };
}

export function clusterEvents(rows, start, end) {
  const clusters = [];
  for (const item of positionEvents(rows, start, end)) {
    const previous = clusters[clusters.length - 1];
    if (previous && item.position - previous.position < 6) previous.rows.push(item.row);
    else clusters.push({ position: item.position, rows: [item.row] });
  }
  return clusters;
}
