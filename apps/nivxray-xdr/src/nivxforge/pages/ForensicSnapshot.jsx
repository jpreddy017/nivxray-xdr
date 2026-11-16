import React, {useEffect, useRef, useState} from 'react';
import {useSearchParams, Link} from 'react-router-dom';
import api from '@/lib/api';
import {activeTenant, TENANT_BOUND_EVENT} from '@/lib/tenant';
import {completed, pending, scoped, snapshotError, validateJob, coverage} from './snapshot-contract.mjs';

const date = value => {if(!value)return 'Not reported';const d=new Date(value);return Number.isNaN(d.getTime())?'Invalid timestamp':d.toISOString();};
const label = value => String(value || 'UNKNOWN').replaceAll('_',' ');
export default function ForensicSnapshot(){
  const [params,setParams]=useSearchParams();
  const device=params.get('device')||'', jobId=params.get('job')||'';
  const [tenant,setTenant]=useState(activeTenant);
  const [computers,setComputers]=useState([]),[fleetError,setFleetError]=useState('');
  const [catalog,setCatalog]=useState(null),[catalogError,setCatalogError]=useState(''),[profile,setProfile]=useState('process');
  const [jobs,setJobs]=useState(null),[historyError,setHistoryError]=useState('');
  const [job,setJob]=useState(null),[jobError,setJobError]=useState('');
  const [reason,setReason]=useState(''),[busy,setBusy]=useState(false),[requestError,setRequestError]=useState('');
  const [refresh,setRefresh]=useState(0),[jobAttempt,setJobAttempt]=useState(0),[search,setSearch]=useState(''),[page,setPage]=useState(0);
  const generation=useRef(0);
  useEffect(()=>{const bound=()=>{generation.current++;setTenant(activeTenant());setJob(null);setJobs(null);setComputers([]);setReason('');setRequestError('');};window.addEventListener(TENANT_BOUND_EVENT,bound);return()=>{generation.current++;window.removeEventListener(TENANT_BOUND_EVENT,bound);};},[]);
  const navigate=(changes)=>{const next=new URLSearchParams(params);next.set('section','snapshot');Object.entries(changes).forEach(([k,v])=>v?next.set(k,v):next.delete(k));setParams(next);};
  useEffect(()=>{generation.current++;setBusy(false);setRequestError('');},[tenant,device]);
  useEffect(()=>{if(!tenant)return;let live=true;const controller=new AbortController();setCatalog(null);setCatalogError('');setProfile('process');api.get('/edr/forensics/snapshot-catalog',{params:device?{endpoint_id:device}:{},signal:controller.signal}).then(({data})=>{if(!live)return;scoped(data,tenant);if(!Array.isArray(data.categories))throw Error('Invalid snapshot catalog.');setCatalog(data);}).catch(e=>{if(live)setCatalogError(snapshotError(e));});return()=>{live=false;controller.abort();};},[tenant,device]);
  useEffect(()=>{
    if(!tenant)return;let live=true;const controller=new AbortController();setFleetError('');setComputers([]);
    api.get('/edr/onboarding/computers',{signal:controller.signal}).then(({data})=>{if(!live)return;scoped(data,tenant);if(!Array.isArray(data.computers))throw Error('Invalid computer inventory response.');setComputers(data.computers);}).catch(e=>{if(live)setFleetError(snapshotError(e));});
    return()=>{live=false;controller.abort();};
  },[tenant,refresh]);
  useEffect(()=>{
    if(!tenant)return;let live=true;const controller=new AbortController();setJobs(null);setHistoryError('');
    api.get('/edr/forensics/snapshots',{params:{limit:50,...(device?{endpoint_id:device}:{})},signal:controller.signal}).then(({data})=>{if(!live)return;scoped(data,tenant);if(!Array.isArray(data.jobs)||data.jobs.some(j=>j.tenant_id!==tenant))throw Error('Invalid snapshot history response.');setJobs(data.jobs);}).catch(e=>{if(live)setHistoryError(snapshotError(e));});
    return()=>{live=false;controller.abort();};
  },[tenant,device,refresh]);
  useEffect(()=>{
    setJob(null);setJobError('');setSearch('');setPage(0);if(!tenant||!jobId)return;
    let live=true,timer;const controller=new AbortController();
    async function poll(){try{const {data}=await api.get(`/edr/forensics/snapshots/${encodeURIComponent(jobId)}`,{signal:controller.signal});if(!live)return;validateJob(data,tenant,jobId);setJob(data);setJobError('');if(pending(data.status))timer=setTimeout(poll,5000);else setRefresh(v=>v+1);}catch(e){if(live)setJobError(snapshotError(e));}}
    poll();return()=>{live=false;clearTimeout(timer);controller.abort();};
  },[tenant,jobId,jobAttempt]);
  async function request(){
    if(!device||!tenant||!reason.trim()||busy)return;const ticket=++generation.current;setBusy(true);setRequestError('');
    try{const {data}=await api.post('/edr/forensics/snapshots',{endpoint_id:device,reason:reason.trim(),...(profile==='process'?{}:{profile})});if(ticket!==generation.current||activeTenant()!==tenant)return;scoped(data,tenant);if(data.endpoint_id!==device||!data.job_id)throw Error('The snapshot request returned a different endpoint.');navigate({job:data.job_id});setRefresh(v=>v+1);}catch(e){if(ticket===generation.current)setRequestError(snapshotError(e));}finally{if(ticket===generation.current)setBusy(false);}
  }
  async function exportEvidence(){try{const payload=JSON.stringify({schema:'nivxforge.forensic-snapshot.v1',exported_at:new Date().toISOString(),evidence:job},null,2);const bytes=new TextEncoder().encode(payload);const hash=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),v=>v.toString(16).padStart(2,'0')).join('');const body=JSON.stringify({sha256:hash,hash_basis:'UTF-8 bytes of payload_json; integrity checksum, not a digital signature',payload_json:payload},null,2);const url=URL.createObjectURL(new Blob([body],{type:'application/json'}));const a=document.createElement('a');a.href=url;a.download=`forensic-snapshot-${String(job.job_id).replace(/[^a-zA-Z0-9_-]/g,'_')}.json`;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}catch(e){setJobError(snapshotError(e));}}
  const filtered=(job?.rows||[]).filter(row=>[row.pid,row.name,row.path].some(v=>String(v||'').toLowerCase().includes(search.toLowerCase())));
  const shown=filtered.slice(page*100,(page+1)*100);
  const chosen=computers.find(c=>c.endpoint_id===device);
  return <section aria-label="Forensic Snapshot" data-testid="forensic-snapshot-view">
    <h2>Forensic Snapshot</h2><p>Capture endpoint evidence, track the collection job and review the result by category.</p>
    <div className="snapshot-alert"><strong>Endpoint forensic collection.</strong> Choose the legacy process profile or a supported Windows artifact profile. Each category reports its own collection interval, limits and failures. Automatic capture on compromise is not enabled.</div>
    <section className="snapshot-panel" aria-label="Request snapshot"><h3>New snapshot</h3>
      <p className="snapshot-note">A fresh sensor read at capture time. Historical telemetry is never substituted for a snapshot. This is metadata collection, not a memory or disk image.</p>
      {fleetError&&<p role="alert">Computer inventory unavailable: {fleetError}</p>}
      {catalogError&&<p role="status">Extended collection catalog unavailable: {catalogError}</p>}
      <div className="snapshot-controls"><label>Computer<select aria-label="Snapshot computer" value={device} disabled={busy} onChange={e=>navigate({device:e.target.value,job:''})}><option value="">Select a computer</option>{device&&!chosen&&<option value={device}>{device} — availability not confirmed</option>}{computers.map(c=><option key={c.endpoint_id} value={c.endpoint_id}>{c.hostname||c.endpoint_id} · {c.status||'Unknown status'}</option>)}</select></label>
      <label>Collection profile<select value={profile} disabled={busy} onChange={e=>setProfile(e.target.value)}><option value="process">Running processes (legacy collector)</option><option value="windows_standard" disabled={!catalog?.windows_ready}>Windows artifacts — standard</option><option value="windows_full" disabled={!catalog?.windows_ready}>Windows artifacts — all 41 categories, including sensitive history</option></select></label>
      <label>Reason<input value={reason} maxLength={1000} onChange={e=>setReason(e.target.value)} placeholder="Investigation purpose or case reference"/></label>
      <button type="button" onClick={request} disabled={!tenant||!device||!reason.trim()||busy}>{busy?'Requesting…':'Request snapshot'}</button></div>
      <p className="snapshot-note">Requests use your existing permissions and are audited. A queued request does not mean collection succeeded. Offline endpoints can time out; unsupported sensors report capability unavailable.</p>
      {device&&catalog&&!catalog.windows_ready&&<p className="snapshot-alert">Full Windows collection requires an upgraded endpoint sensor. No compatible collector has been advertised for this computer within the last 24 hours.</p>}
      {profile==='windows_full'&&<p className="snapshot-alert">This profile includes shell history, DNS, recent filenames, environment variables and other user artifacts. These can contain credentials and private activity. Collection is limited to readable sources; offline user hives are not mounted.</p>}
      {catalog?.categories?.length>0&&<details><summary>{catalog.categories.length} forensic artifact categories</summary><ul>{catalog.categories.map(c=><li key={c.id}>{c.name}{c.sensitive?' — sensitive profile':''}</li>)}</ul></details>}
      {requestError&&<p role="alert" className="snapshot-alert">{requestError}</p>}
    </section>
    {jobId&&<section className="snapshot-panel" aria-label="Snapshot evidence"><div className="snapshot-toolbar"><h3>Snapshot evidence</h3>{job&&<button onClick={exportEvidence}>Export evidence JSON</button>}</div>
      {jobError?<p role="alert">{jobError} <button onClick={()=>setJobAttempt(v=>v+1)}>Retry evidence</button></p>:!job?<p role="status">Loading snapshot evidence…</p>:<>
      <p className="snapshot-status" role="status">{label(job.status)}</p><p>{job.status_meaning}</p>
      <dl className="snapshot-meta">{[['Evidence / job ID',job.job_id],['Computer',job.endpoint_id],['Requested by',job.requested_by],['Requested (UTC)',date(job.requested_at)],['Capture started (UTC)',date(job.capture_started_at)],['Capture finished (UTC)',date(job.capture_finished_at)],['Reported (UTC)',date(job.reported_at)],['Sensor',job.sensor_version||'Not reported'],['Rows',job.row_count??'Not reported'],['Collection basis',job.collection_basis||'Not reported']].map(([k,v])=><React.Fragment key={k}><dt>{k}</dt><dd>{String(v)}</dd></React.Fragment>)}</dl>
      {job.detail&&<p>{String(job.detail)}</p>}{job.rows_truncated&&<p role="status" className="snapshot-alert">Partial evidence: the sensor reached its row limit. This is not a complete process inventory.</p>}
      <p><Link to={`/edr/device-trajectory?device=${encodeURIComponent(job.endpoint_id)}`}>Open this computer’s Device Trajectory</Link></p>
      {job.categories?.length>0?<ArtifactCategories categories={job.categories}/>:<><h3>Collection coverage</h3><div className="snapshot-table-wrap"><table className="snapshot-table"><thead><tr><th>Category</th><th>State</th><th>Coverage</th></tr></thead><tbody>{coverage(job).map(s=><tr key={s.name}><td>{s.name}</td><td>{label(s.state)}</td><td>{s.note}</td></tr>)}</tbody></table></div></>}
      {job.limitations?.length>0&&<ul>{job.limitations.map((item,i)=><li key={i}>{item}</li>)}</ul>}
      {!job.categories?.length&&<>
      <h3>Running processes</h3>{!completed(job.status)?<p>No completed process capture is available for this job.</p>:!job.rows.length?<p>The sensor completed the capture and returned zero rows. This does not establish that the endpoint had no processes.</p>:<>
      <label>Filter captured processes <input className="snapshot-filter" value={search} onChange={e=>{setSearch(e.target.value);setPage(0);}} placeholder="PID, name or path"/></label><p>{filtered.length} matching rows · showing {shown.length} on page {page+1}</p>
      <div className="snapshot-table-wrap"><table className="snapshot-table"><thead><tr><th>PID</th><th>Name</th><th>Executable path</th></tr></thead><tbody>{shown.map((row,i)=><tr key={`${row.pid}-${i}`}><td>{row.pid}</td><td>{row.name||'Not readable'}</td><td>{row.path||`Not readable${row.path_unavailable?`: ${row.path_unavailable}`:''}`}</td></tr>)}</tbody></table></div><button disabled={!page} onClick={()=>setPage(p=>p-1)}>Previous rows</button> <button disabled={(page+1)*100>=filtered.length} onClick={()=>setPage(p=>p+1)}>Next rows</button></>}
      </>}
      <p className="snapshot-note">The export includes provenance and a SHA-256 checksum. It is not a digital signature. No automatic retention or deletion schedule is configured by this feature.</p>
      </>}
    </section>}
    <section className="snapshot-panel" aria-label="Snapshot history"><div className="snapshot-toolbar"><h3>Snapshot history{device?' · selected computer':''}</h3><button onClick={()=>setRefresh(v=>v+1)}>Refresh history</button></div>
      {historyError?<p role="alert">History unavailable: {historyError}</p>:jobs===null?<p role="status">Loading snapshot history…</p>:jobs.length===0?<p>No snapshot requests were returned for this selection.</p>:<div className="snapshot-table-wrap"><table className="snapshot-table"><thead><tr><th>Requested (UTC)</th><th>Computer</th><th>Status</th><th>Requester</th><th>Evidence</th></tr></thead><tbody>{jobs.map(j=><tr key={j.job_id}><td>{date(j.requested_at)}</td><td>{computers.find(c=>c.endpoint_id===j.endpoint_id)?.hostname||j.endpoint_id}</td><td>{label(j.status)}</td><td>{j.requested_by||'Not reported'}</td><td><button onClick={()=>navigate({job:j.job_id})}>Open {j.job_id}</button></td></tr>)}</tbody></table></div>}
      <p className="snapshot-note">Showing at most the 50 most recent requests. Select a computer to narrow the history. Pending job details refresh every five seconds; polling stops on completion, failure or timeout.</p>
    </section>
  </section>;
}

function ArtifactCategories({categories}){
 const [selected,setSelected]=useState(categories[0]?.category_id||''),[query,setQuery]=useState(''),[page,setPage]=useState(0);
 const category=categories.find(c=>c.category_id===selected)||categories[0];
 const rows=(category?.rows||[]).filter(r=>JSON.stringify(r).toLowerCase().includes(query.toLowerCase()));
 const columns=Array.from(new Set(rows.slice(0,100).flatMap(r=>typeof r==='object'&&r!==null?Object.keys(r):['value']))).slice(0,24);
 const value=v=>v==null?'—':typeof v==='object'?JSON.stringify(v):String(v);
 return <section aria-label="Artifact category evidence"><h3>Artifact categories</h3>
 <div className="snapshot-table-wrap"><table className="snapshot-table"><thead><tr><th>Category</th><th>State</th><th>Rows</th><th>Open</th></tr></thead><tbody>{categories.map(c=><tr key={c.category_id}><td>{c.name}</td><td>{label(c.state)}</td><td>{c.row_count??c.rows?.length??0}</td><td><button onClick={()=>{setSelected(c.category_id);setQuery('');setPage(0);}}>Inspect {c.name}</button></td></tr>)}</tbody></table></div>
 <h4>{category?.name}</h4><p>{label(category?.state)} · {date(category?.capture_started_at)} → {date(category?.capture_finished_at)}</p>
 {category?.detail&&<p>{category.detail}</p>}{category?.rows_truncated&&<p className="snapshot-alert">The category row limit was reached; evidence is partial.</p>}{category?.issues?.map((issue,i)=><p key={i}>{issue}</p>)}
 <label>Filter category evidence <input className="snapshot-filter" value={query} onChange={e=>{setQuery(e.target.value);setPage(0);}}/></label><p>{rows.length} matching rows</p>
 <div className="snapshot-table-wrap"><table className="snapshot-table"><thead><tr>{columns.map(c=><th key={c}>{c}</th>)}</tr></thead><tbody>{rows.slice(page*100,(page+1)*100).map((r,i)=><tr key={i}>{columns.map(c=><td key={c}>{value(typeof r==='object'&&r!==null?r[c]:r)}</td>)}</tr>)}</tbody></table></div>
 {!rows.length&&<p>No rows are available in this category. Read the category state before interpreting an empty result.</p>}<button disabled={!page} onClick={()=>setPage(v=>v-1)}>Previous category rows</button> <button disabled={(page+1)*100>=rows.length} onClick={()=>setPage(v=>v+1)}>Next category rows</button>
 </section>;
}
