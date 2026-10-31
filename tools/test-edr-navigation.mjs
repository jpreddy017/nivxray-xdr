import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolveTrajectoryTarget as resolve, trajectoryDestination } from '../apps/nivxray-xdr/src/nivxforge/trajectoryTarget.mjs';
const root = new URL('../apps/nivxray-xdr/src/', import.meta.url);
const read = p => readFileSync(new URL(p, root), 'utf8');
const consoleSource = read('nivxforge/NivXForgeConsole.jsx');
const literal = consoleSource.match(/const NAV = ([\s\S]*?);\n/)[1].replace(/icon: \w+,?/g, '');
const nav = Function(`return (${literal})`)().flatMap(s => s.items);
const routes = [...read('App.jsx').matchAll(/<Route\s+path="([^"]+)"/g)].map(m => m[1]);
assert.equal(nav.length, 17);
for (const item of nav) {
  if (item.to) assert.ok(routes.includes(item.to), `${item.label} has no registered route`);
  else assert.ok(item.reason, `${item.label} must explain unavailability`);
}
console.log('PASS: all 17 sidebar destinations or unavailable reasons');
const rows = [
 {device_iid:'iid-A', endpoint_id:'ep-A', device_ref:'ref-A', hostname:'host', case_ids:['incident']},
 {device_iid:'iid-B', endpoint_id:'ep-B', device_ref:'ref-B', hostname:'host', case_ids:['incident']}
];
assert.equal(resolve(rows, {device:'ep-A'}), 'ref-A');
assert.equal(resolve(rows, {deviceIid:'iid-B'}), 'ref-B');
assert.equal(resolve(rows, {device:'host'}), null, 'ambiguous hostname must not pick first');
assert.equal(resolve(rows, {incidentId:'incident'}), null, 'multi-endpoint incident must not pick first');
assert.equal(resolve(rows, {device:'missing', incidentId:'incident'}), null, 'explicit device must not fall back');
assert.equal(resolve(rows, {deviceIid:'host'}), null, 'IID must not resolve by hostname');
assert.equal(resolve([rows[0]], {incidentId:'incident'}), 'ref-A');
assert.equal(resolve([], {device:'ep-A'}), null);
const query = new URLSearchParams('device=old&device_iid=iid-A&endpoint_id=ep-B&tenant=T&event=E&incident_id=I&t0=10&t1=20&rule=R');
const destination = new URL(trajectoryDestination(query, 'ref-A', '#evidence'), 'https://example.invalid');
for (const key of ['tenant','event','incident_id','t0','t1','rule']) assert.equal(destination.searchParams.get(key), query.get(key));
assert.equal(destination.searchParams.get('device'), 'ref-A');
assert.equal(destination.searchParams.has('device_iid'), false);
assert.equal(destination.searchParams.has('endpoint_id'), false);
assert.equal(destination.hash, '#evidence');
assert.equal(query.get('device'), 'old');
console.log('PASS: unique device resolution, ambiguity refusal, no identity fallback, context-preserving redirect');
