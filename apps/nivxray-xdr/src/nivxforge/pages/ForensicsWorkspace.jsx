import React from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { FolderOpen, FileCode2, Camera, ChevronRight } from 'lucide-react';
import NivXForgeConsole from '@/nivxforge/NivXForgeConsole';
import CommandAnalyzerPreview from './CommandAnalyzerPreview';
import ForensicSnapshot from './ForensicSnapshot';
import './forensics-workspace.css';

export function ForensicsContent() {
  const [params] = useSearchParams();
  const selected = params.get('section') || (params.has('job') || params.has('device') ? 'snapshot' : '');
  const href = section => { const next = new URLSearchParams(params); if (section) next.set('section',section); else {next.delete('section');next.delete('job');next.delete('device');} return `/edr/forensics${next.size ? `?${next}` : ''}`; };
  const items = [{id:'analyzer',title:'Command-line Analyzer',icon:FileCode2,description:'Decode command text and inspect arguments, behavior and evidence without executing it.'},{id:'snapshot',title:'Forensic Snapshot',icon:Camera,description:'Request a fresh endpoint process capture, review collection status and export the evidence.'}];
  return <div className="forensics-workspace">
    <nav aria-label="Forensics breadcrumb" className="forensics-breadcrumb"><Link to={href('')}><FolderOpen size={18}/>Forensics</Link>{selected && <><ChevronRight size={14}/><span>{items.find(i=>i.id===selected)?.title || 'Unknown section'}</span></>}</nav>
    <h1>Forensics</h1>
    {!selected ? <><p>Choose an investigation tool.</p><div className="forensics-folder" aria-label="Forensics tools">{items.map(item=><Link key={item.id} to={href(item.id)} className="forensics-file"><item.icon size={28}/><div><h2>{item.title}</h2><p>{item.description}</p></div><ChevronRight size={20}/></Link>)}</div></> : <>
      <nav aria-label="Forensics sections" className="forensics-tabs">{items.map(item=><Link key={item.id} to={href(item.id)} aria-current={selected===item.id?'page':undefined}>{item.title}</Link>)}</nav>
      {selected==='analyzer'?<CommandAnalyzerPreview/>:selected==='snapshot'?<ForensicSnapshot/>:<p role="alert">This section does not exist. Choose one of the Forensics tools above.</p>}
    </>}
  </div>;
}
export default function ForensicsWorkspace(){return <NivXForgeConsole activeTab="forensics"><ForensicsContent/></NivXForgeConsole>;}
