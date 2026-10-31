// Component contract tests; real entry/workspace/V3 components, mocked API/canvas.
// Dependencies: react 18.3.1, react-test-renderer 18.3.1, esbuild 0.25.0.
const { buildSync } = require('esbuild');
const React = require('react');
const { create, act } = require('react-test-renderer');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const vm = require('node:vm');
const root = path.resolve(__dirname, '../apps/nivxray-xdr/src/nivxforge');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'edr-navigation-'));
global.__route = { endpointId: 'endpoint-A', tab: 'trajectory' };
global.__query = new URLSearchParams('device=other-device');
const sources = {
  workspace: fs.readFileSync(path.join(root, 'device/EdrDevicePage.jsx'), 'utf8'),
  entry: fs.readFileSync(path.join(root, 'trajectory_amp/DeviceTrajectoryEntry.jsx'), 'utf8'),
  v3: fs.readFileSync(path.join(root, 'trajectory_v3/DeviceTrajectoryPage.jsx'), 'utf8'),
};
function compile(source) {
  return buildSync({ stdin: { contents: source, loader: 'jsx' }, write: false,
    format: 'cjs', platform: 'node', jsx: 'transform' }).outputFiles[0].text;
}
const components = {};
const marker = name => props => React.createElement(name, props, props.children);
function mockRequire(id) {
  if (id === 'react') return React;
  if (id === 'react-router-dom') return {
    useParams: () => global.__route, useNavigate: () => () => {},
    useSearchParams: () => [global.__query, () => {}],
  };
  if (id.includes('trajectory_amp/DeviceTrajectoryEntry')) return { default: components.entry };
  if (id.includes('trajectory_v3/DeviceTrajectoryPage')) return { default: components.v3 };
  if (id.includes('trajectory/EdrDeviceTrajectoryPage')) return { default: marker('legacy-canvas') };
  if (id === './amp/TrajectoryPage') return { default: marker('v3-canvas') };
  if (id.includes('NivXForgeConsole')) return { default: marker('console-shell') };
  if (id.includes('onboardingApi')) return { getComputer: async () => ({ computer: { hostname: 'fixture' } }) };
  if (id === './flags') return { E3_DT_V3: true, E3_DT_CONTRACT_PREVIEW: false };
  return new Proxy({}, { get: (_, key) => key === '__esModule' ? true : marker(String(key)) });
}
function load(name) {
  const module = { exports: {} };
  const wrappedRequire = id => {
    const value = mockRequire(id);
    return Object.prototype.hasOwnProperty.call(value, "default") ? { __esModule: true, ...value } : value;
  };
  // esbuild's non-bundled dynamic import becomes native import: replace only
  // the two known lazy modules with Promise-resolved test module bindings.
  let code = compile(sources[name]).replace(/import\("@\/nivxforge\/trajectory_v3\/DeviceTrajectoryPage"\)/g,
    'Promise.resolve(require("@/nivxforge/trajectory_v3/DeviceTrajectoryPage"))');
  vm.runInNewContext(`(function(require,module,exports){${code}\n})`, { console })(wrappedRequire, module, module.exports);
  return module.exports.default;
}
(async () => {
  try {
    components.v3 = load('v3'); components.entry = load('entry'); components.workspace = load('workspace');
    let view;
    await act(async () => { view = create(React.createElement(components.workspace)); });
    assert.equal(view.root.findAllByType('v3-canvas').length, 1, 'computer path must use selected V3 renderer');
    assert.equal(view.root.findByType('v3-canvas').props.device, 'endpoint-A', 'path identity overrides query');
    assert.equal(view.root.findAllByType('console-shell').length, 1, 'embedded view has one shell');
    await act(async () => view.root.findByType('v3-canvas').props.onLegacy());
    assert.equal(view.root.findByType('legacy-canvas').props.device, 'endpoint-A');
    assert.equal(view.root.findByType('legacy-canvas').props.embedded, true);
    global.__route = { endpointId: 'endpoint-B', tab: 'trajectory' };
    await act(async () => view.update(React.createElement(components.workspace)));
    assert.equal(view.root.findByType('v3-canvas').props.device, 'endpoint-B', 'device change resets renderer state');
    await act(async () => view.unmount());
    await act(async () => { view = create(React.createElement(components.entry)); });
    assert.equal(view.root.findByType('v3-canvas').props.device, 'other-device', 'top tab retains query selection');
    assert.equal(view.root.findAllByType('console-shell').length, 1);
    await act(async () => view.unmount());
    console.log('PASS: computer renderer parity, device scope, single shell, legacy scope, device change, top-tab behavior');
  } finally { fs.rmSync(temp, { recursive: true, force: true }); }
})().catch(e => { console.error(e); process.exitCode = 1; });
