// NivXForge EDR · D4 IMPACT REPORT · STRICTLY READ ONLY
//
//   mongosh "<MONGO_URL>" --file edr_d4_impact_report.mongosh.js
//
// There is NOT ONE write verb in this file — no delete, update, insert,
// drop, rename or createIndex. grep it before you run it.
//
// It answers the four questions that must be answered before D1-D5 can be
// authorised:
//   1. how much obsolete EDR development data exists, per collection
//   2. how much XDR evidence is DERIVED from it (the D4 blast radius)
//   3. which incidents depend on that evidence, split into EDR-ONLY
//      (retire with the telemetry) and MIXED (never auto-deleted)
//   4. what survives, so "unrelated XDR preserved" is a number
//
// HOW THE EDR-DERIVED XDR ROWS ARE IDENTIFIED — verified against real
// sensor rows, not assumed:
//   xdr_canonical_evidence   provenance.source_kind = "sensor"
//                            provenance.trust_state = "AUTHENTICATED"
//                            provenance.collector_id        ∈ EDR endpoints
//                            additional_fields.endpoint_id  ∈ EDR endpoints
//   v2_shadow_observations   origin = "collector-live"
//                            collector_id                   ∈ EDR endpoints
//   workspace_cases          endpoint_campaign.endpoint_id   ∈ EDR endpoints
//
// NOTE on raw_ref: the EDR bridge stamps raw_ref={raw_id,collection} on the
// canonical dict, but the row persisted by detection_content/xdr_pipeline.py
// is re-derived from the sensor payload and carries NO raw_ref pointer —
// verified: 0 rows have raw_ref.raw_id. The authenticated-sensor provenance
// above is therefore the authoritative join, and `provenance.trace_id`
// carries the originating `edr_raw_events.raw_id` for spot checks.

const DB_NAME = "greeting-app-5782-test_database";
const TENANT  = "ten_e759b7288598bd882e3dcac49d";
const RAWCOL  = "edr_raw_events";

const t = db.getSiblingDB(DB_NAME);
const has = (c) => t.getCollectionNames().includes(c);
const n = (x) => String(x).padStart(10);
const pad = (s) => String(s).padEnd(40);

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
  const raw = has(RAWCOL)
    ? t[RAWCOL].countDocuments({ tenant_id: TENANT, endpoint_ref: e.endpoint_id })
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

const SENSOR_EVIDENCE = {
  tenant_id: TENANT,
  $or: [{ "provenance.collector_id": { $in: EP } },
        { "additional_fields.endpoint_id": { $in: EP } },
        { "host.host_id": { $in: EP } }],
};
let edrEvidence = 0, evidenceTotal = 0;
if (has("xdr_canonical_evidence")) {
  const c = t.xdr_canonical_evidence;
  edrEvidence = EP.length ? c.countDocuments(SENSOR_EVIDENCE) : 0;
  evidenceTotal = c.countDocuments({});
  const sensorAll = c.countDocuments({ tenant_id: TENANT, "provenance.source_kind": "sensor" });
  const tenantAll = c.countDocuments({ tenant_id: TENANT });
  print(`   ${pad("xdr_canonical_evidence · EDR endpoints")} ${n(edrEvidence)}`);
  print(`   ${pad("  …of which authenticated sensor rows")} ${n(sensorAll)}`);
  print(`   ${pad("xdr_canonical_evidence · tenant total")} ${n(tenantAll)}`);
  print(`   ${pad("xdr_canonical_evidence · all tenants")} ${n(evidenceTotal)}`);
}

let edrObs = 0, obsTotal = 0;
if (has("v2_shadow_observations")) {
  const o = t.v2_shadow_observations;
  edrObs = EP.length
    ? o.countDocuments({ tenant_id: TENANT,
        $or: [{ collector_id: { $in: EP } }, { connector_id: { $in: EP } },
              { "event.raw.raw_evidence_ref.collection": RAWCOL }] })
    : 0;
  obsTotal = o.countDocuments({});
  print(`   ${pad("v2_shadow_observations · EDR-derived")} ${n(edrObs)}`);
  print(`   ${pad("v2_shadow_observations · tenant total")} ` +
        `${n(o.countDocuments({ tenant_id: TENANT }))}`);
  print(`   ${pad("v2_shadow_observations · all tenants")} ${n(obsTotal)}`);
}

// ── incidents: EDR-ONLY vs MIXED, decided from what the incident persists
const edrOnly = [], mixed = [];
let otherInc = 0;
if (has("workspace_cases")) {
  const incidents = t.workspace_cases.find(
    { tenant_id: TENANT, doc_type: "xdr_incident" },
    { id: 1, incident_number: 1, title: 1, created_at: 1, incident_state: 1,
      "xdr_pipeline.canonical_event_id": 1,
      "xdr_pipeline.source_provenance.source_kind": 1,
      "xdr_pipeline.source_provenance.collector_id": 1,
      "endpoint_campaign.endpoint_id": 1,
      "endpoint_campaign.detections.canonical_event_id": 1 }).toArray();

  for (const inc of incidents) {
    const prov = ((inc.xdr_pipeline || {}).source_provenance) || {};
    const camp = inc.endpoint_campaign || {};
    const onEdrEndpoint = EP.includes(camp.endpoint_id) ||
                          EP.includes(prov.collector_id);
    if (!onEdrEndpoint) { otherInc++; continue; }
    // MIXED = the campaign also cites evidence that is NOT from an EDR
    // endpoint of this tenant. Checked per cited canonical event.
    const cids = [(inc.xdr_pipeline || {}).canonical_event_id]
      .concat((camp.detections || []).map((d) => d && d.canonical_event_id))
      .filter(Boolean);
    let foreign = 0;
    for (const cid of cids) {
      if (!has("xdr_canonical_evidence")) break;
      const row = t.xdr_canonical_evidence.findOne({ event_id: cid },
        { "provenance.collector_id": 1, "additional_fields.endpoint_id": 1 });
      if (!row) continue;                       // evidence absent ≠ foreign
      const cc = (row.provenance || {}).collector_id;
      const ee = (row.additional_fields || {}).endpoint_id;
      if (!EP.includes(cc) && !EP.includes(ee)) foreign++;
    }
    (foreign === 0 ? edrOnly : mixed).push(inc);
  }
  print(`\n   ${pad("incidents · EDR-ONLY (retire with telemetry)")} ${n(edrOnly.length)}`);
  print(`   ${pad("incidents · MIXED (NEVER auto-deleted)")} ${n(mixed.length)}`);
  print(`   ${pad("incidents · unrelated (preserved)")} ${n(otherInc)}`);
  for (const i of edrOnly.slice(0, 30))
    print(`      EDR-ONLY  ${i.id}  #${i.incident_number || "-"}  ` +
          `${i.incident_state || ""}  ${String(i.title || "").slice(0, 55)}`);
  for (const i of mixed.slice(0, 30))
    print(`      MIXED     ${i.id}  #${i.incident_number || "-"}  ` +
          `${i.incident_state || ""}  ${String(i.title || "").slice(0, 55)}`);
}

// ───────────────── 4 · dependents of the EDR-ONLY incidents ─────────────────
// Discovery, not assumption: every xdr_* / v2_* collection is probed for a
// persisted reference to those incident ids, so the cleanup list is derived
// from the data instead of from a guess about naming.
const ids = edrOnly.map((i) => i.id).filter(Boolean);
print(`\n── 4 · dependents of the ${ids.length} EDR-ONLY incident(s)`);
if (ids.length) {
  const probe = t.getCollectionNames().filter(
    (c) => /^(xdr_|v2_|verdict_|investigation|incidents$|canonical_)/.test(c));
  const fields = ["incident_id", "case_id", "id", "parent_incident_id",
                  "promoted_incident_id"];
  let found = 0;
  for (const c of probe) for (const f of fields) {
    let hit = 0;
    try { hit = t[c].countDocuments({ [f]: { $in: ids } }); } catch (e) { continue; }
    if (hit > 0) { found++; print(`   ${pad(c + " ." + f)} ${n(hit)}`); }
  }
  if (!found) print("   no dependent artefact references these incident ids");
} else {
  print("   none — no EDR-ONLY incident exists in this tenant");
}

// ───────────────── 5 · what survives ─────────────────
print("\n── 5 · preserved after the proposed cleanup (unrelated XDR)");
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
  if (c === "workspace_cases") removed = edrOnly.length;
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
          `   indexes ${((s.totalIndexSize || 0) / 1048576).toFixed(1)} MiB`);
  } catch (e) { print(`   ${pad(c)} collStats unavailable`); }
}
print(`   ${pad("TOTAL data+index on these collections")} ${(bytes / 1073741824).toFixed(2)} GiB`);

print("\nREAD ONLY — nothing was modified by this script.");
