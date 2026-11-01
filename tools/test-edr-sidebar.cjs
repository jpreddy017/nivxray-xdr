const fs = require('fs'), path = require('path'), vm = require('vm');
const React = require('react'), {create,act} = require('react-test-renderer');
const {transformSync} = require('esbuild'), assert = require('node:assert/strict');
const root=path.resolve(__dirname,'../apps/nivxray-xdr/src/nivxforge');
const source=fs.readFileSync(path.join(root,'NivXForgeConsole.jsx'),'utf8');
const literal=source.match(/const NAV = ([\s\S]*?);\n/)[1].replace(/icon: \w+,?/g,'icon: () => null,');
const nav=Function(`return (${literal})`)();
const code=transformSync(fs.readFileSync(path.join(root,'EdrSidebar.jsx'),'utf8'),{loader:'jsx',format:'cjs'}).code;
const mod={exports:{}};
vm.runInNewContext(`(function(require,module,exports){${code}})`)(id=>id==='react'?React:{E3_DT_V3:true},mod,mod.exports);
let calls=[];let view;act(()=>{view=create(React.createElement(mod.exports.default,{nav,active:'computers',collapsed:false,onGo:p=>calls.push(p),onToggle:()=>{}}));});
for(const tab of nav.flatMap(x=>x.items)) {
  const button=view.root.findByProps({'data-testid':`nvf-nav-${tab.key}`});
  const before=calls.length;
  act(()=>button.props.onClick({preventDefault(){}}));
  if(tab.to) assert.equal(calls.at(-1),tab.to);
  else {assert.equal(calls.length,before);assert.equal(button.props['aria-disabled'],'true');}
}
assert.equal(calls.length,12);
assert.equal(view.root.findByProps({'data-testid':'nvf-nav-computers'}).props['aria-current'],'page');
act(()=>view.unmount());
console.log('PASS: 12 enabled tab clicks, five disabled capabilities, active-tab indication');
