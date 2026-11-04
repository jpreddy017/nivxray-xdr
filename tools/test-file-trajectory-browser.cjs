// Isolated synthetic-fixture browser checks. No live API or tenant credentials.
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const http = require('node:http');
const assert = require('node:assert/strict');
const base = process.env.NIVX_TEST_NODE_MODULES || path.resolve(__dirname, '../apps/nivxray-xdr/node_modules');
const esbuild = require(path.join(base, 'esbuild'));
const { chromium } = require(process.env.NIVX_PLAYWRIGHT_MODULE || path.join(base, 'playwright'));
const root = path.resolve(__dirname, '..');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'file-trajectory-browser-'));
const source = path.join(root, 'apps/nivxray-xdr/src/nivxforge/files');
fs.writeFileSync(path.join(temp, 'router.js'), `import React from 'react'; export const Link=({to,children})=><a href={to}>{children}</a>; export const useSearchParams=()=>[new URLSearchParams({file_key_type:'sha256',file_key:'a'.repeat(64)}),()=>{}];`);
fs.writeFileSync(path.join(temp, 'api.js'), `export async function getFileObservations(q) { const actions=['file_created','file_deleted','file_renamed','file_executed']; return {state:'FILE_OBSERVATIONS', complete:true, issues:{}, observations:Array.from({length:32},(_,i)=>({record_id:String(i),endpoint_id:q.endpoint_id,path:'C:/example/file.exe',name:'file.exe',observed_at:new Date(q.time_start+(q.time_end-q.time_start)*.5+i*60000).toISOString(),action:actions[i%4],hashes:{sha256:'a'.repeat(64)},writer_image:'C:/example/parent.exe',source:'synthetic-browser-fixture',size:1024,assessment:'NOT_ASSESSED'}))}; }`);
fs.writeFileSync(path.join(temp, 'tenant.js'), `export const TENANT_BOUND_EVENT='nvx-tenant-bound';`);
fs.writeFileSync(path.join(temp, 'FileEvidence.jsx'), fs.readFileSync(path.join(source, 'FileEvidence.jsx'), 'utf8').replaceAll('"./', '"' + source + '/').replace('\"' + source + '/fileEvidenceApi\"', '"file-browser-api"'));
fs.writeFileSync(path.join(temp, 'entry.jsx'), `import React from 'react'; import {createRoot} from 'react-dom/client'; import FileEvidence from ${JSON.stringify(path.join(temp,'FileEvidence.jsx'))}; createRoot(document.getElementById('root')).render(<FileEvidence endpointIds={['a','b']} computers={[{endpoint_id:'a',hostname:'Computer A'},{endpoint_id:'b',hostname:'Computer B'}]}/>);`);
esbuild.buildSync({entryPoints:[path.join(temp,'entry.jsx')],bundle:true,outfile:path.join(temp,'app.js'),loader:{'.js':'jsx'},nodePaths:[base],plugins:undefined,
  alias:{'react-router-dom':path.join(temp,'router.js'),'@/lib/tenant':path.join(temp,'tenant.js'),'file-browser-api':path.join(temp,'api.js')},
});
fs.writeFileSync(path.join(temp, 'index.html'), `<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="stylesheet" href="/app.css"><style>:root{--text:#182432;--muted:#506075;--panel:#fff;--line:#cad3dd;--cyan:#067fa3}body{margin:24px;background:#f3f6f9}body.dark{background:#101417;--text:#eef3f7;--muted:#a9b5c1;--panel:#19232d;--line:#455462;--cyan:#49b9dc}button{padding:8px;border:1px solid var(--line);background:var(--panel);color:var(--text);border-radius:4px}a{color:var(--cyan)}</style></head><body><div id="root"></div><script src="/app.js"></script></body></html>`);
(async () => {
  const server = http.createServer((req,res) => { const name = req.url === '/app.js' ? 'app.js' : req.url === '/app.css' ? 'app.css' : 'index.html'; res.setHeader('Content-Type', name.endsWith('.js') ? 'text/javascript' : name.endsWith('.css') ? 'text/css' : 'text/html'); res.end(fs.readFileSync(path.join(temp,name))); });
  await new Promise(r => server.listen(0,'127.0.0.1',r));
  let browser;
  try {
    browser = await chromium.launch({headless:true,args:['--no-sandbox']});
    const page = await browser.newPage({viewport:{width:1440,height:1000}}), errors=[];
    page.on('pageerror',e=>errors.push(String(e)));
    await page.goto(`http://127.0.0.1:${server.address().port}`);
    await page.getByRole('button',{name:'Search observations',exact:true}).click();
    await page.getByText('64 observations loaded',{exact:false}).waitFor();
    assert.equal(await page.locator('.ft-time-event').count(),2);
    await page.locator('.ft-host-label').first().click();
    await page.getByRole('heading',{name:'Related processes on Computer A'}).waitFor();
    await page.locator('.ft-time-event').first().click();
    await page.locator('.ft-cluster-event').first().click();
    await page.getByRole('complementary',{name:'Selected file observation'}).waitFor();
    await page.getByRole('button',{name:'Close details',exact:true}).click();
    await page.getByRole('button',{name:'Close grouped events',exact:true}).click();
    await page.getByLabel('Zoom',{exact:true}).selectOption('4');
    await page.getByLabel('Pan time window').fill('100');
    await page.getByRole('button',{name:'Reset view'}).click();
    assert.equal(await page.locator('.ft-time-event').count(),2);
    await page.getByLabel('Search loaded events').fill('does-not-exist');
    await page.getByText('No loaded events match these filters.',{exact:true}).waitFor();
    await page.getByLabel('Search loaded events').fill('');
    await page.getByRole('button',{name:'Next',exact:true}).click();
    await page.getByText('Page 2 of 3',{exact:true}).waitFor();
    await page.getByLabel('Event type',{exact:true}).selectOption('file_created');
    assert.equal(await page.locator('tbody tr').count(),16);
    await page.getByLabel('Event type',{exact:true}).selectOption('');
    const downloadPromise = page.waitForEvent('download');
    await page.getByRole('button',{name:'Export loaded evidence'}).click();
    assert.equal((await downloadPromise).suggestedFilename(),'file-trajectory-evidence.json');
    if(process.env.NIVX_SCREENSHOT_DIR) {
      fs.mkdirSync(process.env.NIVX_SCREENSHOT_DIR,{recursive:true});
      await page.screenshot({path:path.join(process.env.NIVX_SCREENSHOT_DIR,'trajectory-light.png'),fullPage:true});
      await page.evaluate(()=>document.body.classList.add('dark'));
      await page.screenshot({path:path.join(process.env.NIVX_SCREENSHOT_DIR,'trajectory-dark.png'),fullPage:true});
    }
    await page.setViewportSize({width:390,height:844});
    assert(await page.evaluate(()=>document.documentElement.scrollWidth <= window.innerWidth + 1),'page must not overflow on mobile');
    assert.deepEqual(errors,[]);
    console.log('Browser checks passed: multi-computer results, selection, process expansion, zoom/pan/reset, filtering, pagination, export, mobile overflow and runtime errors. Synthetic fixtures only.');
  } finally { if(browser) await browser.close(); server.close(); fs.rmSync(temp,{recursive:true,force:true}); }
})().catch(e=>{console.error(e);process.exitCode=1;});
