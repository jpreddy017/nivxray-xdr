const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),cp=require('node:child_process'),assert=require('node:assert/strict');
const root=fs.mkdtempSync(path.join(os.tmpdir(),'edr-guard-'));
const prod='https://nivxray.nivxforge.com', preview='https://greeting-app-5782.preview.emergentagent.com';
const base={PATH:process.env.PATH,NIVX_PRODUCT_SCOPE:'edr'};
const integration={...base,NIVX_EDR_INTEGRATION_PREVIEW:'1',VERCEL_ENV:'preview',VERCEL_GIT_COMMIT_REF:'validation/edr-preview-backend-2026-10-31'};
fs.mkdirSync(path.join(root,'scripts'));fs.mkdirSync(path.join(root,'dist'));
fs.copyFileSync(path.join(__dirname,'verify-production-build.js'),path.join(root,'scripts/guard.mjs'));
let count=0;
function test(name,env,origin,pass,extra='',info={}){
 fs.writeFileSync(path.join(root,'dist/app.js'),JSON.stringify([origin,'collector_runtime_not_deployed','/api/xdr/collector',extra]));
 fs.writeFileSync(path.join(root,'dist/build-info.json'),JSON.stringify({product_scope:env.NIVX_PRODUCT_SCOPE,api_origin:origin,...info}));
 const r=cp.spawnSync(process.execPath,[path.join(root,'scripts/guard.mjs')],{env,encoding:'utf8'});
 assert.equal(r.status===0,pass,name+'\n'+r.stdout+r.stderr);count++;
}
try {
 test('production passes',base,prod,true);
 test('production rejects preview',base,preview,false);
 test('designated integration passes',integration,preview,true);
 test('production target rejects flag',{...integration,VERCEL_ENV:'production'},preview,false);
 test('wrong branch rejects flag',{...integration,VERCEL_GIT_COMMIT_REF:'main'},preview,false);
 test('xdr rejects flag',{...integration,NIVX_PRODUCT_SCOPE:'xdr'},preview,false);
 test('cross-product rejects flag',{...integration,NIVX_CROSS_PRODUCT_ORIGINS:'1'},preview,false);
 test('unknown flag rejected',{...base,NIVX_EDR_INTEGRATION_PREVIEW:'2'},prod,false);
 test('foreign preview rejected',integration,preview,false,'https://other.preview.emergentagent.com');
 test('production origin mixed into integration rejected',integration,preview,false,prod);
 test('localhost rejected',integration,preview,false,'http://localhost:8001');
 test('wrong metadata rejected',integration,preview,false,'',{api_origin:prod});
 test('suffix impersonation rejected',integration,preview,false,preview+'.evil.com');
 const xdr={...base,NIVX_PRODUCT_SCOPE:'xdr',NIVX_XDR_INTEGRATION_PREVIEW:'1',VERCEL_ENV:'preview',VERCEL_GIT_COMMIT_REF:'validation/xdr-preview-backend-2026-10-31'};
 test('xdr preview passes',xdr,preview,true);
 test('xdr production rejects preview flag',{...xdr,VERCEL_ENV:'production'},preview,false);
 test('xdr wrong branch rejected',{...xdr,VERCEL_GIT_COMMIT_REF:'main'},preview,false);
 test('xdr flag rejects edr scope',{...xdr,NIVX_PRODUCT_SCOPE:'edr'},preview,false);
 test('xdr cross product rejected',{...xdr,NIVX_CROSS_PRODUCT_ORIGINS:'1'},preview,false);
 test('both flags rejected',{...xdr,NIVX_EDR_INTEGRATION_PREVIEW:'1'},preview,false);
 test('xdr invalid flag rejected',{...base,NIVX_XDR_INTEGRATION_PREVIEW:'2'},prod,false);
 test('xdr mixed production rejected',xdr,preview,false,prod);
 test('xdr foreign preview rejected',xdr,preview,false,'https://other.preview.emergentagent.com');
 console.log(`PASS ${count} build-boundary cases`);
} finally {fs.rmSync(root,{recursive:true,force:true});}
