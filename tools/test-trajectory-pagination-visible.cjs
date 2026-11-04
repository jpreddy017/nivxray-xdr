const fs = require('fs'), vm = require('vm'), assert = require('node:assert/strict');
const {buildSync} = require('esbuild');
const React = require('react');
const {create, act} = require('react-test-renderer');
const code = buildSync({stdin:{contents:fs.readFileSync(require('node:path').resolve(__dirname,'../apps/nivxray-xdr/src/nivxforge/trajectory_v3/amp/TrajectoryPage.jsx'),'utf8'),loader:'jsx'},format:'cjs',platform:'node',write:false}).outputFiles[0].text;
let cursorCalls=[], fail=false;
const page=(start,cursor)=>({data:{events:Array.from({length:200},(_,i)=>({event_iid:String(start+i)})),computer:{hostname:'VM02'},e3_preview:{older_cursor:cursor}}});
const api={get:async(_,options)=>{cursorCalls.push(options.params.before);if(fail)throw Error('timeout');return options.params.before ? page(0,null):page(200,'next');}};
const marker=name=>props=>React.createElement(name,props);
const mocks={
 'react':React,
 'react-router-dom':{useSearchParams:()=>[new URLSearchParams('t0=1793318400000&t1=1793404800000'),()=>{}]},
 '@/lib/api':{default:api},
 './theme':{C:{},CSS:'',DAY:86400000},
 './model':{DEFAULT_ON:[],presentKinds:()=>new Set(),passes:()=>true,matches:()=>true,buildModel:events=>({items:events.map(ev=>({ev})),rows:[],total:events.length,ncol:0})},
 './deeplink':{selectedFor:()=>null},
};
function req(id){let m=mocks[id];if(!m)m={__esModule:true,...Object.fromEntries(['default','ChevronDown','ChevronLeft','ChevronRight','Info','Search','X','ActivityDetails','ActivityList','NetworkSummary','AttackPanel','DeepLinkBanner','FiltersPanel','ApprovalDialog','ContextMenu'].map(k=>[k,marker(k)]))};return Object.hasOwn(m,'default')?{__esModule:true,...m}:m;}
const moduleObject={exports:{}};
const window={innerHeight:1000,setInterval:()=>1,clearInterval:()=>{},addEventListener:()=>{},removeEventListener:()=>{}};
vm.runInNewContext('(function(require,module,exports){'+code+'})',{console,window,document:{visibilityState:'visible',addEventListener:()=>{},removeEventListener:()=>{}},sessionStorage:{getItem:()=>null},ResizeObserver:class{observe(){}disconnect(){}},URLSearchParams,AbortController,performance:{now:()=>0},setTimeout})(req,moduleObject,moduleObject.exports);
const Component=moduleObject.exports.default;
const text=n=>typeof n==='string'?n:(n.children||[]).map(text).join('');
const find=(v,id)=>v.root.findByProps({'data-testid':id});
(async()=>{
 let v;await act(async()=>{v=create(React.createElement(Component,{device:'ep_test'}));});
 assert.match(text(find(v,'v3-loaded-count')),/200 events loaded.*partial history/);
 const tree=v.toJSON();
 const ids=[];function walk(n){if(!n||typeof n==='string')return;if(n.props?.['data-testid'])ids.push(n.props['data-testid']);(n.children||[]).forEach(walk);}walk(tree);
 assert.ok(ids.indexOf('v3-load-older')<ids.indexOf('v3-workspace'),'pagination must precede large workspace');
 fail=true;await act(async()=>{await find(v,'v3-load-older').props.onClick();});
 assert.match(text(find(v,'v3-loaded-count')),/200 events loaded/);
 assert.match(text(find(v,'v3-older-error')),/retained/);
 fail=false;await act(async()=>{await find(v,'v3-load-older').props.onClick();});
 assert.match(text(find(v,'v3-loaded-count')),/400 events loaded/);
 assert.doesNotMatch(text(find(v,'v3-loaded-count')),/partial/);
 assert.equal(v.root.findAllByProps({'data-testid':'v3-load-older'}).length,0);
 assert.deepEqual(cursorCalls,[undefined,'next','next']);
 v.unmount();console.log('PASS: visible pagination, partial count, failure retention, retry cursor, 200 -> 400 accumulation, exhaustion');
})().catch(e=>{console.error(e);process.exitCode=1;});

