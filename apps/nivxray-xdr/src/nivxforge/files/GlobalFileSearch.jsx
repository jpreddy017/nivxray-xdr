import React, { useEffect, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import api from '@/lib/api';
import { TENANT_BOUND_EVENT } from '@/lib/tenant';
import FileEvidence from './FileEvidence';
import './file-evidence.css';

const day = 86400000;
const dateInput = ms => new Date(ms).toISOString().slice(0, 16);
const format = ms => new Date(ms).toISOString();
export default function GlobalFileSearch() {
  const [params, setParams] = useSearchParams();
  const [key, setKey] = useState(params.get('file_key') || '');
  const [kind, setKind] = useState('auto');
  const [start, setStart] = useState(dateInput(Date.now() - 30 * day));
  const [end, setEnd] = useState(dateInput(Date.now()));
  const [devices, setDevices] = useState([]), [data, setData] = useState(null);
  const [query, setQuery] = useState(null), [request, setRequest] = useState(null);
  const [selection, setSelection] = useState(null);
  const [busy, setBusy] = useState(false), [error, setError] = useState('');
  const generation = useRef(0);
  useEffect(() => {
    const clear = () => { generation.current++; setDevices([]); setData(null); setQuery(null); setRequest(null); setSelection(null); setBusy(false); setError(''); };
    window.addEventListener(TENANT_BOUND_EVENT, clear);
    return () => window.removeEventListener(TENANT_BOUND_EVENT, clear);
  }, []);
  useEffect(() => {
    if (!request) return undefined;
    const ac = new AbortController(), ticket = generation.current;
    setBusy(true); setError('');
    api.get('/edr/files/search', {params: request, signal: ac.signal}).then(({data: d}) => {
      if (ac.signal.aborted || ticket !== generation.current) return;
      setData(d); setDevices(old => request.cursor ? [...old, ...d.devices] : d.devices);
    }).catch(e => {
      if (!ac.signal.aborted && ticket === generation.current) setError(e.response?.data?.detail || 'File search could not complete. Retry; this is not a no-match result.');
    }).finally(() => { if (!ac.signal.aborted && ticket === generation.current) setBusy(false); });
    return () => ac.abort();
  }, [request]);
  function submit(e) {
    e.preventDefault();
    const a = Date.parse(start + ':00Z'), b = Date.parse(end + ':00Z');
    if (!key.trim() || !Number.isFinite(a) || !Number.isFinite(b) || b <= a || b - a > 31 * day) { setError('Enter a search value and an increasing UTC range of at most 31 days.'); return; }
    const q = {key: key.trim(), key_type: kind, time_start: a, time_end: b, limit: 50};
    generation.current++; setDevices([]); setData(null); setSelection(null); setQuery(q); setRequest(q);
    const next = new URLSearchParams(params); next.delete('device'); next.set('file_key', q.key); setParams(next, {replace: true});
  }
  return <>
    <section className="ft-workspace global-files" aria-label="Global file search">
      <h2>Search files across devices</h2>
      <p>Search all authorized devices in this customer. No computer selection required.</p>
      <form className="ft-query" onSubmit={submit}>
        <label className="ft-key">Filename, path or hash<input required value={key} maxLength={4096} placeholder="wevtutil.exe, full path, SHA-256, SHA-1 or MD5" onChange={e => setKey(e.target.value)} /></label>
        <label>Match by<select value={kind} onChange={e => setKind(e.target.value)}>{[['auto','Auto detect'],['name','Exact filename'],['path','Exact path'],['sha256','SHA-256'],['sha1','SHA-1'],['md5','MD5']].map(([v,l]) => <option key={v} value={v}>{l}</option>)}</select></label>
        <label>Start (UTC)<input required type="datetime-local" value={start} onChange={e => setStart(e.target.value)} /></label>
        <label>End (UTC, exclusive)<input required type="datetime-local" value={end} onChange={e => setEnd(e.target.value)} /></label>
        <button className="btn" disabled={busy}>Search all devices</button>
      </form>
      {error && <p role="alert" className="ft-error">{String(error)}</p>}
      {busy && <p role="status">Searching indexed evidence…</p>}
      {data && <>
        <p role="status">{devices.length} matching devices loaded{data.next_cursor ? ' · more devices available' : ''}. Counts represent unique indexed events.</p>
        <p className="ft-coverage">Index status: {data.coverage?.status || 'unknown'}. Last successful check: {data.coverage?.checked_at || 'Unavailable'}. {data.coverage?.caught_up_at_check ? 'Caught up at that check' : 'Backfill incomplete'} · unresolved source records: {data.coverage?.unresolved ?? 'unknown'}. Newer or unindexed evidence may not appear yet.</p>
        <div className="ft-table-wrap"><table><thead><tr><th>Device</th><th>Matching events</th><th>First seen (UTC)</th><th>Last seen (UTC)</th><th>Investigation</th></tr></thead><tbody>
          {devices.map(d => <tr key={d.endpoint_id}><td>{d.hostname}<small className="global-endpoint">{d.endpoint_id}</small></td><td>{d.matching_events}</td><td>{format(d.first_seen)}</td><td>{format(d.last_seen)}</td><td><button className="btn" onClick={() => setSelection({device: d, query: {...query, endpoint_id: d.endpoint_id}})}>View matching events & trajectory</button></td></tr>)}
        </tbody></table></div>
        {!devices.length && <p>No matches in indexed evidence for this time range. This does not establish that the file is absent.</p>}
        {data.next_cursor && <button className="btn" disabled={busy} onClick={() => setRequest({...query, cursor: data.next_cursor})}>Load more devices</button>}
      </>}
    </section>
    {selection && <section aria-label="Matching device investigation"><h2>{selection.device.hostname} — matching file evidence</h2><button className="btn" onClick={() => setSelection(null)}>Close device investigation</button><FileEvidence key={`${selection.device.endpoint_id}:${JSON.stringify(selection.query)}`} endpointId={selection.device.endpoint_id} computers={[selection.device]} indexSearch={selection.query} /></section>}
  </>;
}
