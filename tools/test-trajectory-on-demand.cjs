const fs=require('fs'),path=require('path'),vm=require('vm'),assert=require('node:assert/strict');
const React=require('react'),{create,act}=require('react-test-renderer'),{transformSync}=require('esbuild');
const root=path.join(__dirname,'../apps/nivxray-xdr/src/nivxforge/trajectory_v3/amp');
const empty=()=>null;
const theme={C:{},HDR_H:78,LABEL_W:260,ROW_H:32,ACT_H:40};
function load(name){
 const mod={exports:{}}; const code=transformSync(fs.readFileSync(path.join(root,name),'utf8'),{loader:'jsx',format:'cjs'}).code;
 vm.runInNewContext(`(function(require,module,exports){${code}})`,{ResizeObserver:class{observe(){}disconnect(){}},window:{addEventListener(){},removeEventListener(){}},requestAnimationFrame:f=>f()})(id=>id==='react'?React:id==='./theme'?theme:id==='./model'?{fmt:String}:new Proxy({},{get:()=>empty}),mod,mod.exports);
 return mod.exports;
}
const Grid=load('Grid.jsx').default,Activity=load('Activity.jsx').ActivityList;
const item=(id,col)=>({col,ev:{event_iid:id,timestamp_instant_ms:1700000000000+col*1000},kind:{glyph:'other'},shape:'square',target:null});
const model=items=>({items,rows:[],ticks:[],ncol:items.length,total:items.length});
function box(){return {scrollLeft:0,scrollTop:0,clientWidth:800,clientHeight:400,style:{},addEventListener(){},removeEventListener(){}};}
let count=0,b=box(),tree;
const before=[item('a',0),item('b',1),item('c',2)];
const after=[item('older',0),item('a',1),item('b',2),item('c',3)];
const gp=items=>({model:model(items),items,colW:20,setColW(){},returnTo:{current:false},expanded:new Set(),height:400,onOlder:()=>count++});
act(()=>{tree=create(React.createElement(Grid,gp(before)),{createNodeMock:()=>b});});
assert.equal(count,0,'initial render must not fetch history');
b.scrollLeft=20;
act(()=>tree.root.findByProps({'data-testid':'v3-grid'}).props.onScroll({currentTarget:b}));
act(()=>tree.update(React.createElement(Grid,gp(after))));
assert.equal(b.scrollLeft,40,'same event stays at same viewport offset after prepend');
assert.equal(count,0,'layout and programmatic scrolling must not fetch');
let grid=tree.root.findByProps({'data-testid':'v3-grid'});
act(()=>grid.props.onWheel({currentTarget:b,deltaX:-10,deltaY:0}));
assert.equal(count,1);
act(()=>grid.props.onWheel({currentTarget:b,deltaX:-10,deltaY:0,ctrlKey:true}));
assert.equal(count,1,'zoom must not load history');
b.scrollLeft=200;
act(()=>grid.props.onWheel({currentTarget:b,deltaX:-10,deltaY:0}));
assert.equal(count,1,'away from older edge must not fetch');
act(()=>tree.unmount());
b=box(); count=0;
const ap=items=>({items,height:400,onOlder:()=>count++});
act(()=>{tree=create(React.createElement(Activity,ap(before)),{createNodeMock:()=>b});});
b.scrollTop=40;
act(()=>tree.update(React.createElement(Activity,ap(after))));
assert.equal(b.scrollTop,80,'activity anchor follows event identity, not old index');
act(()=>tree.root.findByProps({'data-testid':'v3-activity'}).props.onWheel({currentTarget:b,deltaY:-1}));
assert.equal(count,1);
act(()=>tree.root.findByProps({'data-testid':'v3-activity'}).props.onWheel({currentTarget:b,deltaY:1}));
assert.equal(count,1);
act(()=>tree.unmount());
// Actual model rebuild: a parent delivered on an older page resolves the child
// by process instance identity; overlapping delivery does not duplicate events.
const modelModule={exports:{}};
const modelCode=transformSync(fs.readFileSync(path.join(root,'model.js'),'utf8'),{loader:'js',format:'cjs'}).code;
vm.runInNewContext(`(function(require,module,exports){${modelCode}})`)(id=>id==='./attack'?{KILL_CHAIN:[],tacticsOf:()=>[],attackText:()=>''}:{KIND:{process_create:{glyph:'exec'}},ACTIVITY_FILTERS:[],SYSTEM_FILTERS:[]},modelModule,modelModule.exports);
const parent={event_iid:'parent-event',event_type:'process_create',process_iid:'parent-instance',image:'parent.exe',timestamp_instant_ms:1000};
const child={event_iid:'child-event',event_type:'process_create',process_iid:'child-instance',parent_process_iid:'parent-instance',image:'child.exe',timestamp_instant_ms:2000};
const partial=modelModule.exports.buildModel([child],[],'windows');
assert.equal(partial.items[0].actor,null);
const merged=modelModule.exports.buildModel([parent,child,child],[],'windows');
assert.equal(merged.total,2);
assert.equal(merged.items[1].actor.label,'parent.exe');
assert.equal(merged.parentOf.get('child-instance'),'parent-instance');
console.log('PASS: on-demand edge gestures, zoom exclusion, no eager loading, timeline and activity anchors');
