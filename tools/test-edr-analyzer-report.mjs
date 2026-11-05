import {test} from 'node:test';
import assert from 'node:assert/strict';
import {writeFile} from 'node:fs/promises';
import {decodedLayerText,summarizeAnalysis,reportText,printableHtml,wordDocument} from '../apps/nivxray-xdr/src/nivxforge/forensics/analysis-report.mjs';

const command='  powershell -NoP <script>alert("x")</script>\n'+ '字'.repeat(12000);
const result={submission:{command_line:command},artifact_id:'tenant-bound-artifact',report:{executed:false,analysis:{decode_status:'PARTIALLY_RECOVERED',parsed_structure:{executable:'powershell',switches:['-NoP']},behaviors:[{detail:'Script text contains a download operation.'}],original_command:'legacy truncated'},recovered_layers:{layers:[{id:1,preview:'preview only',full_output:'complete decoded text'}]}}};
test('summary reports parsed evidence without asserting malicious intent',()=>{
  const s=summarizeAnalysis(result);assert.match(s.arguments,/-NoP/);assert.match(s.activity,/download/);assert.match(s.intent,/cannot be confirmed/);assert.match(s.recommendations,/partial/);
});
test('missing fields remain unknown',()=>{assert.match(summarizeAnalysis({}).arguments,/not identified/);assert.match(summarizeAnalysis({}).activity,/No specific activity/);});
test('full export preserves exact command, decoded evidence and provider failures',()=>{
  const text=reportText(result,{'ip:1.2.3.4':{status:'unavailable'}},'2026-11-05T00:00:00Z');
  assert.ok(text.includes(command));assert.match(text,/complete decoded text/);assert.match(text,/unavailable/);assert.match(text,/PARTIALLY_RECOVERED/);assert.match(text,/not checked/);
});
test('print export escapes hostile command markup',()=>{const html=printableHtml(reportText(result));assert.ok(!html.includes('<script>'));assert.match(html,/&lt;script&gt;/);assert.match(html,/white-space:pre-wrap/);});
test('DOCX package can be verified independently',async()=>{const blob=wordDocument(reportText(result));assert.equal(blob.type,'application/vnd.openxmlformats-officedocument.wordprocessingml.document');await writeFile('/tmp/analyzer-report-test.docx',new Uint8Array(await blob.arrayBuffer()));});
test('decoded text and export exceed preview length without truncation',()=>{
  const text='Write-Output "字"\n'.repeat(1000),layer={id:0,preview:text.slice(0,4000),output_base64:Buffer.from(text).toString('base64')};
  assert.equal(decodedLayerText(layer),text);
  assert.ok(reportText({report:{recovered_layers:{layers:[layer]}}}).includes(text));
});
test('binary and malformed layers remain explicit',()=>{
  assert.match(decodedLayerText({output_base64:'AA=='}),/Binary layer/);
  assert.match(decodedLayerText({output_base64:'not valid!'}),/invalid layer/);
});
