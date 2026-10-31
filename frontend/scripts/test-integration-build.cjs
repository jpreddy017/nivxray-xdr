const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),cp=require('node:child_process'),assert=require('node:assert/strict');
const root=fs.mkdtempSync(path.join(os.tmpdir(),'workspace-guard-'));
const prod='https://nivxray.nivxforge.com',preview='https://greeting-app-5782.preview.emergentagent.com';
fs.mkdirSync(path.join(root,'scripts'));fs.mkdirSync(path.join(root,'build/static/js'),{recursive:true});
fs.copyFileSync(path.join(__dirname,'verify-production-build.js'),path.join(root,'scripts/guard.cjs'));
const base={PATH:process.env.PATH};const integration={...base,NIVX_WORKSPACE_INTEGRATION_PREVIEW:'1',VERCEL_ENV:'preview',VERCEL_GIT_COMMIT_REF:'validation/workspace-preview-backend-2026-10-31'};
let count=0;
function test(name,env,origin,pass,extra=''){
 fs.writeFileSync(path.join(root,'build/static/js/main.js'),'REACT_APP_BACKEND_URL:'+JSON.stringify(origin)+';'+extra);
 const r=cp.spawnSync(process.execPath,[path.join(root,'scripts/guard.cjs')],{env,encoding:'utf8'});
 assert.equal(r.status===0,pass,name+'\n'+r.stdout+r.stderr);count++;
}
try {
 test('production unchanged',base,prod,true);
 test('production rejects preview',base,preview,false);
 test('preview passes',integration,preview,true);
 test('production target rejects flag',{...integration,VERCEL_ENV:'production'},preview,false);
 test('main rejects flag',{...integration,VERCEL_GIT_COMMIT_REF:'main'},preview,false);
 test('invalid flag rejects',{...base,NIVX_WORKSPACE_INTEGRATION_PREVIEW:'2'},prod,false);
 test('mixed production rejects',integration,preview,false,prod);
 test('other preview rejects',integration,preview,false,'https://other.preview.emergentagent.com');
 test('wrong origin rejects',integration,'https://example.org',false);
 test('shadow remains disabled',integration,preview,false,'REACT_APP_NIVX_FLAG_CASE_ENGINE:"shadow"');
 console.log(`PASS ${count} Workspace build-boundary cases`);
} finally {fs.rmSync(root,{recursive:true,force:true});}
