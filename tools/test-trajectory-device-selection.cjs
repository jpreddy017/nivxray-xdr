const fs=require('fs'),path=require('path'),vm=require('vm'),assert=require('node:assert/strict');
const React=require('react'),{create,act}=require('react-test-renderer'),{transformSync}=require('esbuild');
let params=new URLSearchParams(),rendered=[];
const renderer=p=>{rendered.push(p.device);return React.createElement('trajectory',p)};
const mocks={react:React,'react-router-dom':{useSearchParams:()=>[params],Link:p=>React.createElement('a',{href:p.to},p.children)},'@/nivxforge/NivXForgeConsole':{__esModule:true,default:p=>React.createElement('console',null,p.children)},'@/nivxforge/trajectory/EdrDeviceTrajectoryPage':{__esModule:true,default:renderer},'./amp/TrajectoryPage':{__esModule:true,default:renderer}};
const source=fs.readFileSync(path.join(__dirname,'../apps/nivxray-xdr/src/nivxforge/trajectory_v3/DeviceTrajectoryPage.jsx'),'utf8');
const mod={exports:{}};vm.runInNewContext(`(function(require,module,exports){${transformSync(source,{loader:'jsx',format:'cjs'}).code}})`,{URLSearchParams})(id=>mocks[id],mod,mod.exports);
for(const query of ['', 'device=','device=%20%20','legacy=1','tenant=customer-a']){
 params=new URLSearchParams(query); rendered=[];let tree;act(()=>{tree=create(React.createElement(mod.exports.default));});
 assert.deepEqual(rendered,[],'no renderer or evidence request without a device');
 assert.equal(tree.root.findByType('a').props.href,query.includes('tenant=')?'/edr/computers?tenant=customer-a':'/edr/computers');act(()=>tree.unmount());
}
for(const props of [{device:'ep-embedded',embedded:true},{}]){
 params=new URLSearchParams('device=ep-query');rendered=[];let tree;act(()=>{tree=create(React.createElement(mod.exports.default,props));});assert.deepEqual(rendered,[props.device||'ep-query']);act(()=>tree.unmount());
}
console.log('PASS: missing/blank device and legacy entry show selection; customer retained; explicit and embedded devices render');
