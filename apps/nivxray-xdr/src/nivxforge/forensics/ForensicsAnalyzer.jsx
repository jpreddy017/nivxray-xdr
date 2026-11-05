import React,{useCallback,useEffect,useMemo,useRef,useState} from 'react';
import OsintDisposition from './OsintDisposition';
import {decodedLayerText,download,printableHtml,reportText,summarizeAnalysis,wordDocument} from './analysis-report.mjs';
import './forensics.css';

function Panel({title,children}) {
  return <details className="forensics-panel" open><summary>{title}</summary><div className="forensics-panel-body" tabIndex={0}>{children}</div></details>;
}

// Composition boundary: the independent EDR shell supplies its authenticated client.
export default function ForensicsAnalyzer({request,tenantId}) {
  const [command,setCommand]=useState(''),[result,setResult]=useState(null),[error,setError]=useState(''),[busy,setBusy]=useState(false);
  const [enrichment,setEnrichment]=useState({});
  const active=useRef(null),generation=useRef(0);
  const invalidate=useCallback(()=>{generation.current++;active.current?.abort();setResult(null);setEnrichment({});setError('');setBusy(false);},[]);
  useEffect(()=>{invalidate();return ()=>{generation.current++;active.current?.abort();};},[tenantId,invalidate]);
  async function analyze(event){
    event.preventDefault();active.current?.abort();const controller=new AbortController();active.current=controller;
    const run=++generation.current;
    setBusy(true);setError('');setResult(null);setEnrichment({});
    try{const value=await request('/api/edr/forensics/command-analysis',{method:'POST',signal:controller.signal,body:{mode:'command',command_line:command}});if(!controller.signal.aborted&&run===generation.current)setResult(value);}
    catch(e){if(!controller.signal.aborted&&run===generation.current)setError('Analysis unavailable. Check your session or retry.');}
    finally{if(!controller.signal.aborted&&run===generation.current)setBusy(false);}
  }
  const indicators=useMemo(()=>result?.report?.recovered_layers?.indicators||[],[result]);
  const summary=useMemo(()=>summarizeAnalysis(result),[result]);
  const analysis=result?.report?.analysis||{};
  const exportReport=(format)=>{
    const text=reportText(result,enrichment);
    if(format==='word')download(wordDocument(text),'command-analysis.docx');
    else if(format==='json')download(new Blob([JSON.stringify({analysis:result,osint:enrichment,exported_at:new Date().toISOString()},null,2)],{type:'application/json'}),'command-analysis.json');
    else {
      const popup=window.open('','_blank');
      if(!popup){setError('Allow a report window to print or save as PDF.');return;}
      popup.opener=null;popup.document.write(printableHtml(text));popup.document.close();popup.focus();popup.print();
    }
  };
  return <section className="forensics-analyzer" aria-label="Command-line Analyzer"><h1>Command-line Analyzer</h1><form onSubmit={analyze}>
    <label htmlFor="forensics-command">Command line · Auto Detect</label>
    <textarea id="forensics-command" value={command} onChange={e=>{invalidate();setCommand(e.target.value);}} maxLength={65536} rows={8}/>
    <button disabled={busy||!tenantId||!command.trim()}>{busy?'Analyzing…':'Analyze'}</button>
    <button type="button" onClick={()=>{invalidate();setCommand('');}}>Clear</button>
  </form>{error&&<p role="alert">{error}</p>}
  {result&&<>
    <nav aria-label="Export complete analysis"><button onClick={()=>exportReport('pdf')}>Print / Save as PDF</button><button onClick={()=>exportReport('word')}>Export Word (.docx)</button><button onClick={()=>exportReport('json')}>Export complete JSON</button></nav>
    <p>Exports include the submitted command, full returned analysis and OSINT findings received so far. Unchecked providers remain unchecked.</p>
    <div className="forensics-grid">
      {Object.entries(summary).map(([key,text])=><Panel key={key} title={{arguments:'Command and arguments',activity:'Activity',lolbas:'LOLBAS context',intent:'Intent assessment',recommendations:'Recommendations'}[key]}><p>{text}</p></Panel>)}
    </div>
    <Panel title="Original command"><pre>{result.submission?.command_line??analysis.original_command??'Unavailable'}</pre></Panel>
    <Panel title="Parsed structure and arguments"><pre>{JSON.stringify(analysis.parsed_structure||{},null,2)}</pre></Panel>
    <Panel title="Recovered layers"><p>{result.report?.recovered_layers?.status}</p>
      {(result.report?.recovered_layers?.layers||[]).map(layer=><details key={layer.id}><summary>{(layer.operations||[]).map(o=>o.operation).join(' → ')} · {layer.output_bytes} bytes</summary><p>SHA-256: {layer.output_sha256}</p><pre>{decodedLayerText(layer)}</pre></details>)}
      <p>Text layers show their full returned content. Binary layers retain complete bytes in the evidence and exports.</p>
    </Panel>
    <Panel title="OSINT findings"><OsintDisposition indicators={indicators} request={request} tenantId={tenantId} analysisId={result.artifact_id} onSnapshot={setEnrichment}/></Panel>
    <Panel title="Complete analysis evidence"><pre>{JSON.stringify(result,null,2)}</pre></Panel>
  </>}
  </section>;
}
