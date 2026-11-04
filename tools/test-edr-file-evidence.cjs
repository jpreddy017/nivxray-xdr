const path = require('node:path');
const fs = require('node:fs');
const assert = require('node:assert/strict');
const base = process.env.NIVX_TEST_NODE_MODULES || path.resolve(__dirname, '../apps/nivxray-xdr/node_modules');
const esbuild = require(path.join(base, 'esbuild'));
const React = require(path.join(base, 'react'));
const {act, create} = require(path.join(base, 'react-test-renderer'));
const root = path.resolve(__dirname, '..');
const pending = [], listeners = new Map();
global.window = {
  addEventListener(k, f) { listeners.set(k, f); },
  removeEventListener(k) { listeners.delete(k); },
};
global.__fileRequests = pending;
let passed = 0;
function check(condition, name) { assert(condition, name); passed++; }
const out = path.join(require('node:os').tmpdir(), `edr-file-evidence-${process.pid}.cjs`);
esbuild.buildSync({
  stdin: {contents:fs.readFileSync(path.join(root, 'apps/nivxray-xdr/src/nivxforge/files/FileEvidence.jsx'),'utf8').replace('"./fileEvidenceApi"','"file-evidence-test-api"'),
    resolveDir:path.join(root,'apps/nivxray-xdr/src/nivxforge/files'),loader:'jsx'},
  bundle: true, platform: 'node', format: 'cjs', outfile: out,
  external: ['react'], loader: {'.css': 'empty'},
  alias: {
    'react-router-dom': path.join(__dirname, 'file-evidence-test-router.cjs'),
    '@/lib/tenant': path.join(__dirname, 'file-evidence-test-tenant.cjs'),
    'file-evidence-test-api': path.join(__dirname, 'file-evidence-test-api.cjs'),
  },
});
// The bundled component and renderer must use exactly the same React instance.
process.env.NODE_PATH = base;
require('module').Module._initPaths();
const Component = require(out).default;
const flatten = (value) => value == null ? '' : typeof value === 'string' || typeof value === 'number' ? String(value)
  : Array.isArray(value) ? value.map(flatten).join('') : flatten(value.children);
const text = (tree) => flatten(tree.toJSON());
const row = {record_id:'abc',path:'C:\\tmp\\file.dll',name:'file.dll',observed_at:'2026-09-02T10:00:00Z',
  hashes:{},writer_basis:'WRITER_NOT_OBSERVED',identity_basis:'PATH_IDENTITY_ONLY',assessment:'NOT_ASSESSED'};
const page = {state:'FILE_OBSERVATIONS',observations:[row],complete:false,next_cursor:'next',issues:{}};
async function search(tree) { await act(async()=>tree.root.findByType('form').props.onSubmit({preventDefault(){}})); }
(async()=>{
  let tree;
  await act(async()=>{tree=create(React.createElement(Component,{endpointId:'ep_a'}));});
  check(text(tree).includes('Recorded file activity'), 'initial explanation rendered');
  check(pending.length===0,'no evidence query before explicit submission');
  await search(tree);
  check(pending.length===1,'one endpoint evidence request');
  check(pending[0].params.endpoint_id==='ep_a','endpoint carried to API');
  await act(async()=>pending[0].resolve(page));
  check(text(tree).includes('Hash not observed'),'missing file hash remains explicit');
  check(text(tree).includes('1 observations loaded'),'first page displayed');
  const inspect=tree.root.findAllByType('button').find(b=>b.props['aria-label']==='Inspect file.dll');
  await act(async()=>inspect.props.onClick());
  check(text(tree).includes('NOT_ASSESSED'),'no benign assessment invented');
  const older=tree.root.findAllByType('button').find(b=>b.children.includes('Continue scanning'));
  await act(async()=>older.props.onClick());
  check(pending[1].params.cursor==='next','continuation carries server cursor');
  await act(async()=>pending[1].resolve({...page,complete:true,next_cursor:null,observations:[{...row,record_id:'def'}]}));
  check(text(tree).includes('2 observations loaded'),'continuation appends observations');
  check(tree.root.findAllByType('aside').length===1,'selection survives pagination');
  await search(tree);
  const stale=pending[2];
  await act(async()=>tree.update(React.createElement(Component,{endpointId:'ep_b'})));
  await act(async()=>stale.resolve(page));
  check(!text(tree).includes('1 observations loaded'),'old endpoint response is discarded');
  await search(tree);
  await act(async()=>pending[3].reject({response:{status:403}}));
  check(text(tree).includes('not authorized'),'permission failure is distinct');
  await search(tree);
  await act(async()=>pending[4].resolve({...page,observations:[],state:'SCAN_INCOMPLETE'}));
  check(text(tree).includes('Continue scanning before concluding'),'empty partial scan is not no evidence');
  await act(async()=>listeners.get('nvx-tenant-bound')());
  check(!text(tree).includes('observations loaded'),'customer context event clears prior evidence');
  await search(tree);
  const many = Array.from({length:56}, (_, i) => ({...row, record_id:String(i), action:i % 2 ? 'file_deleted' : 'file_created'}));
  await act(async()=>pending[5].resolve({...page, complete:true, next_cursor:null, observations:many}));
  check(tree.root.findByType('tbody').findAllByType('tr').length===25, 'event history is paginated');
  await act(async()=>tree.root.findAllByType('button').find(b=>b.children.includes('Next')).props.onClick());
  check(text(tree).includes('Page 2 of 3'), 'next page updates history');
  const searchInput=tree.root.findAllByType('input').find(i=>i.props.placeholder==='Path, hash, process or computer');
  await act(async()=>searchInput.props.onChange({target:{value:'nonexistent'}}));
  check(tree.root.findByType('tbody').findAllByType('tr').length===0, 'loaded-event search filters history');
  await act(async()=>searchInput.props.onChange({target:{value:''}}));
  const host=tree.root.findAllByType('button').find(b=>b.props.className==='ft-host-label');
  await act(async()=>host.props.onClick());
  check(text(tree).includes('Related processes on ep_b'), 'computer expands associated processes');
  const zoom=tree.root.findAllByType('select').find(s=>s.findAllByType('option').some(o=>o.children.includes('Full window')));
  await act(async()=>zoom.props.onChange({target:{value:'4'}}));
  check(tree.root.findAllByType('input').some(i=>i.props.type==='range'), 'zoom enables time pan');
  check(text(tree).includes('Origin not established'), 'loaded earliest event is not attributed as entry point');
  check(text(tree).includes('Network Profile'), 'network coverage section remains available');
  await act(async()=>tree.unmount());
  console.log(`${passed} React behavior checks passed`);
})().catch(e=>{console.error(e);process.exitCode=1;}).finally(()=>fs.rmSync(out,{force:true}));

