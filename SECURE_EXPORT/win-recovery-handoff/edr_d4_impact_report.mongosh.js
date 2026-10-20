// NivXForge EDR · D4 IMPACT REPORT · STRICTLY READ ONLY
//
//   mongosh "<MONGO_URL>" --file edr_d4_impact_report.mongosh.js
//
// NOT ONE write verb appears in this file — no delete, update, insert, drop,
// rename or createIndex. grep it before you run it.
//
// It produces the final deletion scope for approval:
//   1. EDR endpoints in the tenant
//   2. EDR-only delete candidates, and what D2/D3 retain
//   3. the D4 blast radius: XDR evidence DERIVED from this EDR telemetry
//   4. incidents classified EDR-ONLY / MIXED / UNKNOWN / unrelated
//   5. dependents of the EDR-ONLY incidents, DISCOVERED not assumed, each
//      tenant-checked and overlap-checked
//   6. what survives
//
// THE JOIN (deterministic, from what the code persists — no name, hash,
// timestamp or proximity matching anywhere):
//   xdr_canonical_evidence  provenance.source_kind = "sensor"
//                           provenance.trust_state = "AUTHENTICATED"
//                           provenance.collector_id       ∈ EDR endpoints
//                           additional_fields.endpoint_id ∈ EDR endpoints
//                           provenance.trace_id = originating raw_id
//   v2_shadow_observations  origin = "collector-live"
//                           collector_id / connector_id   ∈ EDR endpoints
//                           event.raw.raw_evidence_ref.collection
//                                                    = "edr_raw_events"
//   workspace_cases         endpoint_campaign.endpoint_id ∈ EDR endpoints
//                           xdr_pipeline.source_provenance.collector_id
//
// `raw_ref` is NOT usable: the EDR bridge stamps raw_ref={raw_id,collection}
// on the canonical dict, but the row persisted by xdr_pipeline.py is
// re-derived from the sensor payload and carries no pointer — verified,
// raw_ref.raw_id exists on 0 documents.
//
// CLASSIFICATION POLICY (the three D4 safety checks)
//   EDR-ONLY  every cited canonical event resolves to an EDR endpoint of
//             this tenant. Eligible for deletion.
//   MIXED     at least one cited event resolves to a NON-EDR source.
//             PRESERVED — never deleted, listed by id.
//   UNKNOWN   at least one cited event does NOT resolve (evidence row
//             absent) and none resolve foreign. PRESERVED by default and
//             listed, because "absent" is not "mine to delete".
//   unrelated not on an EDR endpoint of this tenant. Not considered.

const DB_NAME = "greeting-app-5782-test_database";
const TENANT  = "ten_e759b7288598bd882e3dcac49d";
const RAW     = "edr_raw_events";

const t = db.getSiblingDB(DB_NAME);
const has = (c) => t.getCollectionNames().includes(c);
const n = (x) => String(x).padStart(10);
const pad = (s) => String(s).padEnd(42);

print("\n================ D4 IMPACT REPORT (READ ONLY) ================");
print(`db ${DB_NAME}`);
print(`tenant ${TENANT}`);
print(`generated ${new Date().toISOString()}`);

// ───────────────── 1 · the tenant's EDR endpoints ─────────────────
const endpoints = has("edr_endpoints")
  ? t.edr_endpoints.find({ tenant_id: TENANT },
      { endpoint_id: 1, hostname: 1, event_count: 1, enrollment_state: 1 }).toArray()
  : [];
print(`\n── 1 · EDR endpoints in this tenant: ${endpoints.length}`);
for (const e of endpoints) {
  const raw = has(RAW)
    ? t[RAW].countDocuments({ tenant_id: TENANT, endpoint_ref: e.endpoint_id })
    : 0;
  print(`   ${pad(e.endpoint_id)} ${String(e.enrollment_state || "?").padEnd(10)}` +
        ` raw ${n(raw)}   counter ${e.event_count ?? "-"}   ${e.hostname || ""}`);
}
const EP = endpoints.map((e) => e.endpoint_id).filter(Boolean);

// ───────────────── 2 · EDR-only collections ─────────────────
const EDR_TELEMETRY = [
  "edr_raw_events", "edr_processing_queue", "edr_rejected_telemetry",
  "edr_acquisition_gaps", "edr_acquisition_integrity", "edr_delivery_counters",
  "edr_findings", "edr_finding_evaluations", "edr_compromise_events",
  "edr_endpoint_address_observations", "edr_response_commands",
  "edr_policy_endpoint_state", "edr_endpoint_exclusion_enforcement",
];
const EDR_IDENTITY = [
  "edr_endpoints", "edr_agent_credentials", "edr_agent_sessions",
  "edr_enrollment_tokens",
];
const EDR_KEEP = [
  "edr_policies", "edr_groups", "edr_policy_versions", "edr_exclusions",
  "edr_exclusion_sets", "edr_isolation_policy", "edr_tenant_boundary",
  "edr_connector_deployments", "edr_saved_views",
  "edr_enrollment_audit", "edr_policy_audit",
];

function group(title, names) {
  print(`\n── ${title}`);
  let sum = 0;
  for (const name of names) {
    if (!has(name)) { print(`   ${pad(name)} (absent)`); continue; }
    const scoped = t[name].countDocuments({ tenant_id: TENANT });
    const all = t[name].countDocuments({});
    sum += scoped;
    print(`   ${pad(name)} tenant ${n(scoped)}   collection ${all}`);
  }
  print(`   ${pad("SUBTOTAL")} ${n(sum)}`);
  return sum;
}

print("\n── 2 · EDR-only data (delete candidates under D1)");
let edrTotal = 0;
edrTotal += group("2a · telemetry and derived state", EDR_TELEMETRY);
edrTotal += group("2b · identity (recreated by enrolment)", EDR_IDENTITY);
group("2c · RETAINED by D2 / D3 — configuration and audit", EDR_KEEP);
print(`\n   EDR delete-candidate total: ${edrTotal}`);

// ───────────────── 3 · D4 · XDR evidence derived from EDR ─────────────────
print("\n── 3 · D4 blast radius · XDR evidence derived from EDR telemetry");

const evidenceFilter = {
  tenant_id: TENANT,
  $or: [{ "provenance.collector_id": { $in: EP } },
        { "additional_fields.endpoint_id": { $in: EP } },
        { "host.host_id": { $in: EP } }],
};
const obsFilter = {
  tenant_id: TENANT,
  $or: [{ collector_id: { $in: EP } }, { connector_id: { $in: EP } },
        { "event.raw.raw_evidence_ref.collection": RAW }],
};

let edrEvidence = 0, edrObs = 0;
if (has("xdr_canonical_evidence") && EP.length) {
  const c = t.xdr_canonical_evidence;
  edrEvidence = c.countDocuments(evidenceFilter);
  print(`   ${pad("xdr_canonical_evidence · EDR-derived")} ${n(edrEvidence)}`);
  print(`   ${pad("  …authenticated sensor rows, tenant")} ` +
        `${n(c.countDocuments({ tenant_id: TENANT, "provenance.source_kind": "sensor" }))}`);
  print(`   ${pad("xdr_canonical_evidence · tenant total")} ` +
        `${n(c.countDocuments({ tenant_id: TENANT }))}`);
  print(`   ${pad("xdr_canonical_evidence · all tenants")} ${n(c.countDocuments({}))}`);
}
if (has("v2_shadow_observations") && EP.length) {
  const o = t.v2_shadow_observations;
  edrObs = o.countDocuments(obsFilter);
  print(`   ${pad("v2_shadow_observations · EDR-derived")} ${n(edrObs)}`);
  print(`   ${pad("v2_shadow_observations · tenant total")} ` +
        `${n(o.countDocuments({ tenant_id: TENANT }))}`);
  print(`   ${pad("v2_shadow_observations · all tenants")} ${n(o.countDocuments({}))}`);
}

// ───── 3b · artefacts keyed on the evidence, not on an incident ─────
// Discovered by probing which collections carry a sensor reference
// (trace_id = raw_id, evidence_ref, collector_id). Left behind, these would
// be live references to deleted canonical evidence.
print("\n── 3b · evidence-keyed artefacts (EDR-derived)");
const EVIDENCE_KEYED_PROBE = [
  ["xdr_detection_matches", { tenant_id: TENANT, source: "sensor" }],
  ["xdr_spread_sightings", { tenant_id: TENANT, collector_id: { $in: EP } }],
  ["xdr_correlation_matches",
   { tenant_id: TENANT, trace_id: { $regex: "^raw_[0-9a-f]{24}$" } }],
];
for (const [c, f] of EVIDENCE_KEYED_PROBE) {
  if (!has(c)) { print(`   ${pad(c)} (absent)`); continue; }
  print(`   ${pad(c)} in-scope ${n(t[c].countDocuments(f))}` +
        `   tenant ${n(t[c].countDocuments({ tenant_id: TENANT }))}` +
        `   all tenants ${n(t[c].countDocuments({}))}`);
}

// ───────── 4 · incident classification · EDR-ONLY / MIXED / UNKNOWN ─────────
const edrOnly = [], mixedInc = [], unknownInc = [];
let otherInc = 0, citedResolved = 0, citedMissing = 0;
if (has("workspace_cases") && EP.length) {
  const incs = t.workspace_cases.find(
    { tenant_id: TENANT, doc_type: "xdr_incident" },
    { id: 1, incident_number: 1, title: 1, incident_state: 1,
      "xdr_pipeline.canonical_event_id": 1,
      "xdr_pipeline.source_provenance.collector_id": 1,
      "endpoint_campaign.endpoint_id": 1,
      "endpoint_campaign.detections.canonical_event_id": 1 }).toArray();

  for (const inc of incs) {
    const prov = ((inc.xdr_pipeline || {}).source_provenance) || {};
    const camp = inc.endpoint_campaign || {};
    if (!(EP.includes(camp.endpoint_id) || EP.includes(prov.collector_id))) {
      otherInc++; continue;                        // unrelated · preserved
    }
    const cids = [(inc.xdr_pipeline || {}).canonical_event_id]
      .concat((camp.detections || []).map((d) => d && d.canonical_event_id))
      .filter(Boolean);
    let foreign = 0, unknown = 0;
    for (const cid of cids) {
      const row = has("xdr_canonical_evidence")
        ? t.xdr_canonical_evidence.findOne(
            { tenant_id: TENANT, event_id: cid },
            { "provenance.collector_id": 1, "additional_fields.endpoint_id": 1,
              "host.host_id": 1 })
        : null;
      if (!row) { unknown++; citedMissing++; continue; }
      citedResolved++;
      const cc = (row.provenance || {}).collector_id;
      const ee = (row.additional_fields || {}).endpoint_id;
      const hh = (row.host || {}).host_id;
      if (!EP.includes(cc) && !EP.includes(ee) && !EP.includes(hh)) foreign++;
    }
    inc._cited = cids.length; inc._foreign = foreign; inc._unknown = unknown;
    if (foreign > 0) mixedInc.push(inc);
    else if (unknown > 0) unknownInc.push(inc);
    else edrOnly.push(inc);
  }
  print(`\n── 4 · incident classification`);
  print(`   ${pad("EDR-ONLY · eligible for deletion")} ${n(edrOnly.length)}`);
  print(`   ${pad("MIXED · PRESERVED")} ${n(mixedInc.length)}`);
  print(`   ${pad("UNKNOWN evidence · PRESERVED by default")} ${n(unknownInc.length)}`);
  print(`   ${pad("unrelated · not considered")} ${n(otherInc)}`);
  print(`   ${pad("cited events resolved / missing")} ${n(citedResolved)} / ${citedMissing}`);
  for (const i of edrOnly.slice(0, 30))
    print(`      EDR-ONLY  ${i.id}  #${i.incident_number || "-"}  ` +
          `cited ${i._cited}  ${String(i.title || "").slice(0, 45)}`);
  for (const i of mixedInc.slice(0, 30))
    print(`      MIXED     ${i.id}  #${i.incident_number || "-"}  ` +
          `foreign ${i._foreign}/${i._cited}  ${String(i.title || "").slice(0, 40)}`);
  for (const i of unknownInc.slice(0, 30))
    print(`      UNKNOWN   ${i.id}  #${i.incident_number || "-"}  ` +
          `unresolved ${i._unknown}/${i._cited}  ${String(i.title || "").slice(0, 38)}`);
}

const DEL_IDS_RAW = edrOnly.map((i) => i.id).filter(Boolean);
let DEL_IDS = DEL_IDS_RAW.slice();
const KEEP_IDS = mixedInc.concat(unknownInc).map((i) => i.id).filter(Boolean);

// ─────────── 5 · dependents · discovered, tenant-checked, overlap-checked ───────────
print(`\n── 5 · dependents of the ${DEL_IDS.length} EDR-ONLY incident(s)`);
const REF_FIELDS = ["incident_id", "case_id", "id", "parent_incident_id",
                    "promoted_incident_id", "incident_ids"];
const PAIRS = [];
if (DEL_IDS.length) {
  const probe = t.getCollectionNames().filter(
    (c) => /^(xdr_|v2_|verdict_|investigation|incidents$|canonical_)/.test(c));
  for (const c of probe) for (const f of REF_FIELDS) {
    let hit = 0;
    try { hit = t[c].countDocuments({ [f]: { $in: DEL_IDS } }); } catch (e) { continue; }
    if (hit) PAIRS.push([c, f, hit]);
  }
}

// ENTANGLEMENT PROPAGATION · a dependent citing both a deletable and a
// preserved incident would, if preserved, keep a live reference to a deleted
// incident. So the entanglement propagates: promote that incident to
// PRESERVED. Repeated to a fixpoint.
const entangled = [];
if (DEL_IDS.length && KEEP_IDS.length) {
  const proj = {};
  for (const g of REF_FIELDS) proj[g] = 1;
  for (let pass = 0; pass < 10; pass++) {
    const promote = new Set();
    for (const [c, f] of PAIRS) {
      const docs = t[c].find(
        { [f]: { $in: DEL_IDS },
          $or: REF_FIELDS.map((g) => ({ [g]: { $in: KEEP_IDS } })) },
        proj).toArray();
      for (const d of docs) if (DEL_IDS.includes(d[f])) promote.add(d[f]);
    }
    if (!promote.size) break;
    for (const id of promote) {
      entangled.push(id);
      KEEP_IDS.push(id);
      DEL_IDS = DEL_IDS.filter((x) => x !== id);
    }
  }
}
if (entangled.length) {
  print(`   ${pad("promoted to PRESERVED · entangled")} ${n(entangled.length)}`);
  for (const id of entangled.slice(0, 30)) print(`      ENTANGLED ${id}`);
  print(`   ${pad("EDR-ONLY after propagation")} ${n(DEL_IDS.length)}`);
}
if (PAIRS.length) {
  let foreignTenant = 0;
  for (const [c, f] of PAIRS) {
    const hit = t[c].countDocuments({ [f]: { $in: DEL_IDS } });
    if (!hit) { print(`   ${pad(c + " ." + f)} ${n(0)}   (all preserved)`); continue; }
    const hasTenant = t[c].countDocuments(
      { [f]: { $in: DEL_IDS }, tenant_id: { $exists: true } });
    const wrongTenant = t[c].countDocuments(
      { [f]: { $in: DEL_IDS }, tenant_id: { $exists: true, $ne: TENANT } });
    let overlap = 0;
    if (KEEP_IDS.length) {
      overlap = t[c].countDocuments(
        { [f]: { $in: DEL_IDS },
          $or: REF_FIELDS.map((g) => ({ [g]: { $in: KEEP_IDS } })) });
    }
    foreignTenant += wrongTenant;
    print(`   ${pad(c + " ." + f)} ${n(hit)}   tenant-stamped ${n(hasTenant)}` +
          `   foreign-tenant ${n(wrongTenant)}   residual-overlap ${n(overlap)}`);
  }
  print(`\n   ${pad("TOTAL foreign-tenant dependents (S2)")} ${n(foreignTenant)}`);
  if (foreignTenant) print("   >>> STOP S2: a dependent carries another tenant's id");
} else if (DEL_IDS_RAW.length) {
  print("   no dependent artefact references these incident ids");
} else {
  print("   none — no EDR-ONLY incident exists in this tenant");
}

// ───── 5b · EVIDENCE PINNING · the other direction of D4 ─────
// A preserved incident still cites canonical events, and those events still
// cite their raw rows. Deleting them would break the preserved incident
// instead of the deleted one, so they are pinned out of every sweep.
const KEEP_CEV = [];
if (KEEP_IDS.length && has("workspace_cases")) {
  for (const inc of t.workspace_cases.find(
        { tenant_id: TENANT, id: { $in: KEEP_IDS } },
        { "xdr_pipeline.canonical_event_id": 1,
          "endpoint_campaign.detections.canonical_event_id": 1 }).toArray()) {
    const camp = inc.endpoint_campaign || {};
    for (const cid of [(inc.xdr_pipeline || {}).canonical_event_id]
          .concat((camp.detections || []).map((d) => d && d.canonical_event_id))
          .filter(Boolean))
      if (!KEEP_CEV.includes(cid)) KEEP_CEV.push(cid);
  }
}
const KEEP_RAW = [];
{
  const survivingEvidence = {
    tenant_id: TENANT,
    $or: [{ event_id: { $in: KEEP_CEV } },
          { $nor: [{ $or: [{ "provenance.collector_id": { $in: EP } },
                           { "additional_fields.endpoint_id": { $in: EP } },
                           { "host.host_id": { $in: EP } }] }] }],
  };
  const survivingObs = {
    tenant_id: TENANT,
    $or: [{ canonical_event_id: { $in: KEEP_CEV } },
          { $nor: [{ $or: [{ collector_id: { $in: EP } },
                           { connector_id: { $in: EP } },
                           { "event.raw.raw_evidence_ref.collection": RAW }] }] }],
  };
  if (has("xdr_canonical_evidence"))
    for (const r of t.xdr_canonical_evidence.distinct("provenance.trace_id",
          survivingEvidence))
      if (r && !KEEP_RAW.includes(r)) KEEP_RAW.push(r);
  if (has("v2_shadow_observations"))
    for (const r of t.v2_shadow_observations.distinct(
          "event.raw.raw_evidence_ref.raw_id", survivingObs))
      if (r && !KEEP_RAW.includes(r)) KEEP_RAW.push(r);
}
print("\n── 5b · pinned out of the sweeps (cited by preserved incidents)");
print(`   ${pad("canonical events pinned")} ${n(KEEP_CEV.length)}`);
print(`   ${pad("raw events pinned")} ${n(KEEP_RAW.length)}`);
if (KEEP_CEV.length && has("xdr_canonical_evidence")) {
  const pinnedInScope = t.xdr_canonical_evidence.countDocuments(
    { $and: [evidenceFilter, { event_id: { $in: KEEP_CEV } }] });
  edrEvidence -= pinnedInScope;
  print(`   ${pad("evidence removal after pinning")} ${n(edrEvidence)}`);
}
if (KEEP_CEV.length && has("v2_shadow_observations")) {
  const pinnedObs = t.v2_shadow_observations.countDocuments(
    { $and: [obsFilter, { canonical_event_id: { $in: KEEP_CEV } }] });
  edrObs -= pinnedObs;
  print(`   ${pad("observation removal after pinning")} ${n(edrObs)}`);
}
if (KEEP_RAW.length && has(RAW)) {
  print(`   ${pad("raw removal after pinning")} ` +
        `${n(t[RAW].countDocuments({ tenant_id: TENANT, raw_id: { $nin: KEEP_RAW } }))}`);
}

// ───────────────── 6 · what survives ─────────────────
print("\n── 6 · preserved after the proposed cleanup");
for (const c of ["xdr_canonical_evidence", "v2_shadow_observations",
                 "workspace_cases", "xdr_investigations",
                 "xdr_investigation_findings", "xdr_detection_rules",
                 "xdr_detection_matches", "xdr_incidents",
                 "investigation_cases"]) {
  if (!has(c)) { print(`   ${pad(c)} (absent)`); continue; }
  const all = t[c].countDocuments({});
  let removed = 0;
  if (c === "xdr_canonical_evidence") removed = edrEvidence;
  if (c === "v2_shadow_observations") removed = edrObs;
  if (c === "workspace_cases") removed = DEL_IDS.length;
  print(`   ${pad(c)} total ${n(all)}   removal ${n(removed)}   remaining ${n(all - removed)}`);
}

print("\n── storage (the reason for all of this)");
let bytes = 0;
for (const c of EDR_TELEMETRY.concat(["xdr_canonical_evidence",
                                      "v2_shadow_observations"])) {
  if (!has(c)) continue;
  try {
    const s = t.runCommand({ collStats: c });
    bytes += (s.size || 0) + (s.totalIndexSize || 0);
    print(`   ${pad(c)} docs ${n(s.count)}   data ${((s.size || 0) / 1048576).toFixed(1)} MiB` +
          `   idx ${((s.totalIndexSize || 0) / 1048576).toFixed(1)} MiB`);
  } catch (e) { print(`   ${pad(c)} collStats unavailable`); }
}
print(`   ${pad("TOTAL data+index on these collections")} ${(bytes / 1073741824).toFixed(2)} GiB`);

print("\nREAD ONLY — nothing was modified by this script.");
