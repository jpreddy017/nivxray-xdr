import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ATTACK_TACTICS, CATALOGUE_VERSION } from "../../apps/nivxray-xdr/src/xdr/lib/mitre/attackNameIndex.generated.js";
import { buildLayer, layerFromStrip, validateLayer } from "../../apps/nivxray-xdr/src/xdr/lib/mitre/navigatorLayer.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const read = (p) => fs.readFileSync(path.join(ROOT, p), "utf8");

test("ONE catalogue version: backend compact == FE generated index == name_index == service path", () => {
  const svc = read("backend/services/mitre_catalogue/service.py");
  const file = svc.match(/"(enterprise_v[\d_]+\.compact\.json)"/)[1];
  const compact = JSON.parse(read(`backend/mitre_catalogue/${file}`));
  assert.equal(compact.version, CATALOGUE_VERSION);
  assert.equal(JSON.parse(read("backend/mitre_catalogue/name_index.json")).catalogue_version, CATALOGUE_VERSION);
  assert.deepEqual(ATTACK_TACTICS.map((t) => t.key), compact.tactics.map((t) => t.shortname));
  assert.match(compact.source, /mitre-attack\/attack-stix-data/);
  assert.match(compact.source_sha256, /^[0-9a-f]{64}$/);
});

test("HeatMap and Device Trajectory import the SAME generated catalogue module (no second copy)", () => {
  const heat = read("apps/nivxray-xdr/src/xdr/pages/XdrMitreHeatmap.jsx");
  const dt = read("apps/nivxray-xdr/src/nivxforge/trajectory_v3/amp/attack.js");
  // ONE shared ATT&CK authority, in a Gate-16 shared-safe namespace. XDR
  // (heatmap) and EDR (trajectory) must both import the same generated index;
  // the EDR bundle may not reach into an XDR product namespace to get it.
  for (const src of [heat, dt]) assert.match(src, /from "@\/xdr\/lib\/mitre\/attackNameIndex\.generated"/);
  assert.doesNotMatch(dt, /mitreTactics/);
  assert.doesNotMatch(heat, /"16\.1"/);
});

test("Navigator layer export: structure + versions follow the catalogue", () => {
  const strip = { catalogue_version: CATALOGUE_VERSION, label: "Observed on this device", semantics: "not a verdict", tactics: [
    { shortname: "execution", techniques: [{ technique: "T1059.001", count: 3, first_ms: 0, last_ms: 1000, types: ["Rule-mapped"], rules: ["R1"], url: "https://attack.mitre.org/techniques/T1059/001/" }] },
    { shortname: "impact", techniques: [] }] };
  const l = layerFromStrip(strip, { device: "dev_x", t0: 0, t1: 1000 });
  assert.deepEqual(validateLayer(l), []);
  assert.equal(l.versions.attack, CATALOGUE_VERSION.split(".")[0]);
  assert.equal(l.versions.layer, "4.5");
  assert.deepEqual(l.techniques.map((t) => [t.techniqueID, t.tactic, t.score]), [["T1059.001", "execution", 3]]);
  assert.ok(validateLayer(buildLayer({ name: "x", version: "19.2", techniques: [{ techniqueID: "bad", tactic: "Execution", score: "1" }] })).length >= 3);
});
