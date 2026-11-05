// Pure reporting helpers. Submitted text is evidence, never executable markup.
export function summarizeAnalysis(result) {
  const a=result?.report?.analysis||{}, p=a.parsed_structure||{};
  const behaviors=(a.behaviors||[]).map(b=>b.detail||b.tag).filter(Boolean);
  const labels = (a.execution_flow || []).map(item => item.label).filter(Boolean);
  const tags = new Set((a.behaviors || []).map(item => item.tag));
  let intent = 'Intent cannot be confirmed from command text alone. Verify the parent process, user and outcome in EDR.';
  if (tags.has('download-and-execute')) {
    intent = 'Possible purpose: retrieve remote content and pass it to an interpreter. Confirm the destination and whether execution occurred.';
  } else if (tags.has('persistence')) {
    intent = 'Possible purpose: make execution survive a restart or sign-in. Check the targeted persistence location and whether the change succeeded.';
  } else if (tags.has('network-fetch')) {
    intent = 'Possible purpose: retrieve remote content. Verify the expected destination and how the returned content was used.';
  }
  const lolbas = (a.lolbins || []).map(item => [item.name, item.role].filter(Boolean).join(' · '));
  const meanings={'-nop':'skip the PowerShell profile','-noprofile':'skip the PowerShell profile','-noni':'disable interactive prompts','-noninteractive':'disable interactive prompts','-enc':'supply an encoded command','-encodedcommand':'supply an encoded command','-w':'set the window style','-windowstyle':'set the window style','-executionpolicy':'set the process execution policy','-ep':'set the process execution policy','-c':'supply command text','-command':'supply command text'};
  const switches=(p.switches||[]).map(s=>`${s}${p.interpreter==='powershell'&&meanings[String(s).toLowerCase()]?' ('+meanings[String(s).toLowerCase()]+')':''}`);
  return {
    arguments: `${p.executable||p.interpreter||'Interpreter not identified'}. ${switches.length ? 'Parsed switches: '+switches.join(', ')+'.' : 'No switches identified.'} Review the parsed arguments below for exact values.`,
    activity: labels.length ? 'Static signals in evidence order: ' + labels.slice(0,4).join(' → ') + '.' : behaviors.length ? behaviors.slice(0,2).join(' ').slice(0,440) : 'No specific activity was classified by the static analyzer. Review the original command and recovered layers.',
    lolbas: lolbas.length ? lolbas.join('; ') + '. These are legitimate tools whose use should be assessed in context.' : 'No living-off-the-land tool was identified by the static analyzer.',
    intent,
    recommendations: `${a.decode_status && a.decode_status!=='RECOVERED' && a.decode_status!=='NOT_REQUIRED' ? 'Review unresolved or partial decoding before relying on reconstructed content. ' : ''}Confirm the parent process, user authorization and destination context. Correlate provider findings with endpoint evidence before deciding on containment.`,
  };
}

export function reportText(result, enrichment={}, exportedAt=new Date().toISOString()) {
  const summary=summarizeAnalysis(result);
  return ['NivXForge EDR — Command analysis',`Exported: ${exportedAt}`,
    'Static analysis; the submitted command was not executed by this analyzer.',
    'Original command',result?.submission?.command_line??result?.report?.analysis?.original_command??'Original command unavailable',
    ...Object.entries(summary).flatMap(([key,value])=>[key.toUpperCase(),value]),
    ...(result?.report?.recovered_layers?.layers||[]).flatMap(layer=>[
      `Decoded layer ${layer.id} · SHA-256 ${layer.output_sha256||'unavailable'}`,
      decodedLayerText(layer),
    ]),
    'Complete analysis evidence (includes decoded content, arguments, IOCs and limitations)',JSON.stringify(result,null,2),
    'OSINT snapshot (only findings received at export time; missing indicators/providers are not checked)',JSON.stringify(enrichment,null,2)].join('\n\n');
}
export function decodedLayerText(layer) {
  if(typeof layer.output_base64!=='string')return layer.preview||'Layer output unavailable';
  try {
    const data=Uint8Array.from(atob(layer.output_base64),c=>c.charCodeAt(0));
    const text=new TextDecoder('utf-8',{fatal:true}).decode(data);
    if(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(text))return 'Binary layer; complete bytes are retained as output_base64 in the evidence.';
    return text;
  } catch {return 'Non-UTF-8 or invalid layer; inspect output_base64 in the evidence.';}
}
export const escapeHtml = value => String(value).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export function printableHtml(text) {
  return `<!doctype html><html><head><meta charset="utf-8"><title>Command analysis</title><style>@page{margin:18mm}body{font:11pt system-ui;color:#111}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:10pt monospace}</style></head><body><pre>${escapeHtml(text)}</pre></body></html>`;
}

// Minimal OOXML package, using stored ZIP entries (no external dependencies).
const encoder=new TextEncoder();
function crc32(bytes){let c=0xffffffff;for(const b of bytes){c^=b;for(let n=0;n<8;n++)c=(c>>>1)^((c&1)?0xedb88320:0);}return (c^0xffffffff)>>>0;}
function zip(entries){
  const local=[],central=[];let offset=0;
  const header=(size,fields)=>{const bytes=new Uint8Array(size),v=new DataView(bytes.buffer);for(const [at,value,width] of fields)width===2?v.setUint16(at,value,true):v.setUint32(at,value,true);return bytes;};
  for(const [path,text] of entries){const name=encoder.encode(path),data=encoder.encode(text),crc=crc32(data);
    const h=header(30,[[0,0x04034b50,4],[4,20,2],[14,crc,4],[18,data.length,4],[22,data.length,4],[26,name.length,2]]);
    local.push(h,name,data);
    central.push(header(46,[[0,0x02014b50,4],[4,20,2],[6,20,2],[16,crc,4],[20,data.length,4],[24,data.length,4],[28,name.length,2],[42,offset,4]]),name);
    offset+=h.length+name.length+data.length;
  }
  const size=central.reduce((n,b)=>n+b.length,0);
  return new Blob([...local,...central,header(22,[[0,0x06054b50,4],[8,entries.length,2],[10,entries.length,2],[12,size,4],[16,offset,4]])],{type:'application/vnd.openxmlformats-officedocument.wordprocessingml.document'});
}
export function wordDocument(text){
  const xml=escapeHtml(text.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\ufffe\uffff]/g,'\uFFFD'));
  return zip([
    ['[Content_Types].xml','<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>'],
    ['_rels/.rels','<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>'],
    ['word/document.xml',`<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>${xml.split('\n').map(line=>`<w:p><w:r><w:t xml:space="preserve">${line}</w:t></w:r></w:p>`).join('')}<w:sectPr/></w:body></w:document>`],
  ]);
}
export function download(blob,name){const url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
