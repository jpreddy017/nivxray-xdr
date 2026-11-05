import React, {useEffect,useMemo,useState} from 'react';
import ProviderEvidence,{reputationLabel} from './ProviderEvidence';
import {enrichIndicators} from './reputation-client.mjs';

export default function OsintDisposition(props) {
  return <DispositionResults key={JSON.stringify([props.tenantId,props.analysisId,props.indicators])} {...props}/>;
}
function DispositionResults({indicators,request,tenantId,analysisId,onSnapshot}) {
  const [results,setResults]=useState({});
  const [offset,setOffset]=useState(0),[busy,setBusy]=useState(false);
  useEffect(()=>{onSnapshot?.(results);},[results,onSnapshot]);
  const unique=useMemo(()=>[...new Map(indicators.map(i=>[i.type+':'+i.value,i])).values()],[indicators]);
  useEffect(()=>{
    const controller=new AbortController();setBusy(Boolean(tenantId && unique.length));
    if(tenantId && unique.length)enrichIndicators(unique.slice(offset,offset+50),{request,signal:controller.signal,onResult:(ioc,result)=>setResults(old=>({...old,[ioc.type+':'+ioc.value]:result}))}).catch(()=>{if(!controller.signal.aborted)setResults(old=>({...old,error:true}));}).finally(()=>{if(!controller.signal.aborted)setBusy(false);});
    return ()=>controller.abort();
  },[unique,request,tenantId,analysisId,offset]);
  const providers=['VirusTotal','Cisco Talos','AbuseIPDB','urlscan.io','AlienVault OTX','ThreatFox','MalwareBazaar','URLhaus'];
  return <section aria-label="OSINT Disposition"><h2>OSINT Disposition</h2>
    {results.error && <p role="alert">Some lookups could not be completed. Results already received are retained.</p>}
    <p role="status">{Object.keys(results).filter(k=>k!=='error').length} of {unique.length} indicators checked{busy?' · Checking…':''}.</p>
    {tenantId && offset+50<unique.length && <button type="button" disabled={busy} onClick={()=>setOffset(n=>n+50)}>Check next {Math.min(50,unique.length-offset-50)} indicators</button>}
    {unique.map((i,index)=>{const r=results[i.type+':'+i.value];return <details key={i.type+':'+i.value}><summary>{i.value} · {r?(r.status==='unavailable'?'Lookup unavailable':'Provider findings'):!tenantId?'Sign in to enrich':index>=offset+50?'Not checked — continue with next batch':results.error?'Enrichment unavailable':'Checking reputation…'}</summary>
      <p>Found in: {(i.source_layers||[]).map(layer=>layer===null?'Original command':`Decoded layer ${layer}`).join(', ')||'Source not recorded'}</p>
      <table><thead><tr><th>Provider</th><th>Disposition</th><th>Threat classification / categories</th><th>Evidence</th><th>Checked</th></tr></thead>
      <tbody>{providers.map(name=>{const p=r?.providers?.find(x=>x.provider===name);return <tr key={name}><th>{name}</th>
        <td>{p?reputationLabel(p):r?.status==='unavailable'?'Lookup unavailable':index>=offset+50?'Not checked':'Pending'}</td>
        <td>{[...(p?.threat_classifications||[]),...(p?.categories||[])].map(x=>x.label+' ('+x.source+')').join('; ')||'Not provided'}{p?.labels?.length>0 && <div>{p.labels.join('; ')}</div>}</td>
        <td>{p?.metrics?.total!==undefined?`${p.metrics.malicious??'Unknown'}/${p.metrics.total} malicious engine reports`:p?.metrics?.abuse_confidence!==undefined?`Abuse confidence ${p.metrics.abuse_confidence}% · ${p.metrics.reports??'Unknown'} reports`:p?.metrics?.matching_records!==undefined?`${p.metrics.matching_records} provider records`:p?.metrics?.pulse_count!==undefined?`${p.metrics.pulse_count} community pulses`:p?.metrics?.matching_scans_returned!==undefined?`${p.metrics.matching_scans_returned} matching scans`:'No provider evidence available'}{p?.interpretation && <div>{p.interpretation}</div>}<ProviderEvidence provider={p}/></td>
        <td>{p?.checked_at||'Not checked'}</td></tr>})}</tbody></table></details>})}
    {!indicators.length && <p>No extracted indicators to enrich.</p>}
  </section>;
}

