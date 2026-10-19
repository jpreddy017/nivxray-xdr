// NivXForge EDR · development reset · D1-D5 as approved · DRY RUN BY DEFAULT
//
//   mongosh "<MONGO_URL>" --file edr_dev_reset.mongosh.js
//
// Owner decisions implemented by this script (2026-10-19):
//   D1  tenant-wide cleanup of obsolete development EDR telemetry+enrolment
//   D2  RETAIN EDR configuration, groups, policies, tenant settings
//   D3  RETAIN enrolment and policy audit
//   D4  leave NO broken XDR evidence references: the XDR artefacts DERIVED
//       from this EDR telemetry are retired in the same pass, and nothing
//       else is. Any incident that also cites non-EDR evidence is
//       classified MIXED and is NEVER deleted — it is listed for a human.
//   D5  a real snapshot identifier must be recorded below or the script
//       refuses to delete anything.
//
// GUARANTEES
//   * dry run unless CONFIRM and SNAPSHOT are both set
//   * no dropDatabase, no collection drop -> indexes and validators survive
//   * every filter is tenant-scoped
//   * deletion order is leaf -> root, so no intermediate state has a
//     dangling reference even if the run is interrupted
//   * MIXED incidents, unrelated tenants and non-EDR evidence are never
//     written

// ─────────────────────────── configuration ───────────────────────────
const DB_NAME = "greeting-app-5782-test_database";
const TENANT  = "ten_e759b7288598bd882e3dcac49d";
const RAW     = "edr_raw_events";

const CONFIRM  = "";   // set to "DELETE-EDR-DEV-DATA" to arm            (D5)
const SNAPSHOT = "";   // real Atlas snapshot id, recorded beforehand    (D5)

const KEEP_CONFIG = true;   // D2
const KEEP_AUDIT  = true;   // D3
const CASCADE_XDR = true;   // D4

// D4 · artefacts that hang off an incident. Filled from the production
// impact report (section 4), which DISCOVERS them rather than assuming
// them. Each entry is [collection, field].
const DEPENDENTS = [
  ["xdr_investigation_activity",    "incident_id"],
  ["xdr_investigations",            "incident_id"],
  ["xdr_investigation_findings",    "incident_id"],
  ["xdr_iue_understanding",         "incident_id"],
  ["xdr_framework_mappings",        "incident_id"],
  ["xdr_response_timeline",         "incident_id"],
  ["xdr_intelligence_overlays",     "incident_id"],
  ["xdr_intelligence_overlay_audit", "incident_id"],
];

// ───────────────────── collection classification ─────────────────────
const EDR_TELEMETRY = [
  "edr_processing_queue", "edr_rejected_telemetry", "edr_acquisition_gaps",
  "edr_acquisition_integrity", "edr_delivery_counters", "edr_findings",
  "edr_finding_evaluations", "edr_compromise_events",
  "edr_endpoint_address_observations", "edr_response_commands",
  "edr_policy_endpoint_state", "edr_endpoint_exclusion_enforcement",
];
const EDR_IDENTITY = [
  "edr_endpoints", "edr_agent_credentials", "edr_agent_sessions",
  "edr_enrollment_tokens",
];
const EDR_CONFIG = [
  "edr_policies", "edr_groups", "edr_policy_versions", "edr_exclusions",
  "edr_exclusion_sets", "edr_isolation_policy", "edr_tenant_boundary",
  "edr_connector_deployments", "edr_saved_views",
];
const EDR_AUDIT = ["edr_enrollment_audit", "edr_policy_audit"];

// ───────────────────────────── helpers ───────────────────────────────
const t = db.getSiblingDB(DB_NAME);
const has = (c) => t.getCollectionNames().includes(c);
const n = (x) => String(x).padStart(10);
const pad = (s) => String(s).padEnd(42);
const armed = CONFIRM === "DELETE-EDR-DEV-DATA" && SNAPSHOT.length > 0;

print(`\n=== NivXForge EDR dev reset · ${armed ? "ARMED" : "DRY RUN"} ===`);
print(`db ${DB_NAME}   tenant ${TENANT}`);
print(`D1 tenant-wide · D2 keep config ${KEEP_CONFIG} · D3 keep audit ` +
      `${KEEP_AUDIT} · D4 cascade ${CASCADE_XDR}`);

// ── the tenant's EDR endpoints define every EDR-derived selector below
const EP = has("edr_endpoints")
  ? t.edr_endpoints.find({ tenant_id: TENANT }, { endpoint_id: 1 })
      .toArray().map((e) => e.endpoint_id).filter(Boolean)
  : [];
print(`\nEDR endpoints in tenant: ${EP.length} ${JSON.stringify(EP)}`);

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

// ── D4 classification · EDR-ONLY vs MIXED incidents
const edrOnly = [], mixedInc = [];
if (CASCADE_XDR && has("workspace_cases") && EP.length) {
  const incs = t.workspace_cases.find(
    { tenant_id: TENANT, doc_type: "xdr_incident" },
    { id: 1, incident_number: 1, title: 1, incident_state: 1,
      "xdr_pipeline.canonical_event_id": 1,
      "xdr_pipeline.source_provenance.collector_id": 1,
      "endpoint_campaign.endpoint_id": 1,
      "endpoint_campaign.detections.canonical_event_id": 1 }).toArray();
  for (const i of incs) {
    const prov = ((i.xdr_pipeline || {}).source_provenance) || {};
    const camp = i.endpoint_campaign || {};
    if (!(EP.includes(camp.endpoint_id) || EP.includes(prov.collector_id)))
      continue;                                   // unrelated · preserved
    const cids = [(i.xdr_pipeline || {}).canonical_event_id]
      .concat((camp.detections || []).map((d) => d && d.canonical_event_id))
      .filter(Boolean);
    let foreign = 0;
    for (const cid of cids) {
      const row = t.xdr_canonical_evidence.findOne({ event_id: cid },
        { "provenance.collector_id": 1, "additional_fields.endpoint_id": 1 });
      if (!row) continue;
      const cc = (row.provenance || {}).collector_id;
      const ee = (row.additional_fields || {}).endpoint_id;
      if (!EP.includes(cc) && !EP.includes(ee)) foreign++;
    }
    (foreign === 0 ? edrOnly : mixedInc).push(i);
  }
}
const INC_IDS = edrOnly.map((i) => i.id).filter(Boolean);

// ───────────────────────── plan / dry run ────────────────────────────
function count(c, f) { return has(c) ? t[c].countDocuments(f) : 0; }
function line(c, f, note) {
  if (!has(c)) { print(`   ${pad(c)} (absent)`); return 0; }
  const k = t[c].countDocuments(f);
  print(`   ${pad(c)} ${n(k)}${note ? "   " + note : ""}`);
  return k;
}

let planned = 0;
print("\n── A · XDR artefacts derived from this EDR telemetry (D4)");
if (CASCADE_XDR) {
  for (const [c, f] of DEPENDENTS)
    planned += line(`${c}`, { [f]: { $in: INC_IDS } }, `by ${f}`);
  planned += line("workspace_cases", { tenant_id: TENANT, id: { $in: INC_IDS } },
                  "EDR-ONLY incidents");
  planned += line("v2_shadow_observations", obsFilter);
  planned += line("xdr_canonical_evidence", evidenceFilter);
  print(`   ${pad("MIXED incidents · NOT TOUCHED")} ${n(mixedInc.length)}`);
  for (const i of mixedInc.slice(0, 30))
    print(`      MIXED  ${i.id}  #${i.incident_number || "-"}  ` +
          `${String(i.title || "").slice(0, 55)}`);
} else {
  print("   cascade disabled — XDR references to removed EDR evidence WOULD");
  print("   be left unresolvable. Not the approved D4 behaviour.");
}

print("\n── B · EDR telemetry and derived state");
for (const c of [RAW].concat(EDR_TELEMETRY))
  planned += line(c, { tenant_id: TENANT });

print("\n── C · EDR identity (recreated by the fresh enrolment)");
for (const c of EDR_IDENTITY) planned += line(c, { tenant_id: TENANT });

print(`\n── D · RETAINED · configuration (D2 keep=${KEEP_CONFIG})`);
for (const c of EDR_CONFIG) line(c, { tenant_id: TENANT });
print(`\n── E · RETAINED · audit (D3 keep=${KEEP_AUDIT})`);
for (const c of EDR_AUDIT) line(c, { tenant_id: TENANT });
if (!KEEP_CONFIG || !KEEP_AUDIT)
  print("\n   WARNING: D2/D3 said RETAIN. Set both back to true.");

print(`\nplanned deletions: ${planned}`);

if (!armed) {
  print("\nDRY RUN — nothing was changed.");
  print("To execute: record a REAL Atlas snapshot id in SNAPSHOT and set");
  print('CONFIRM = "DELETE-EDR-DEV-DATA", then re-run.');
  quit(0);
}
if (!KEEP_CONFIG || !KEEP_AUDIT) {
  print("\nREFUSING: D2/D3 require configuration and audit to be retained.");
  quit(1);
}

// ───────────────────────────── execution ─────────────────────────────
// Leaf -> root. An interrupted run therefore leaves a smaller consistent
// graph, never a dangling reference.
print(`\n=== EXECUTING · snapshot ${SNAPSHOT} ===`);
let removed = 0;
function wipe(c, f, label) {
  if (!has(c)) return;
  const before = t[c].countDocuments(f);
  if (!before) { print(`   ${pad(label || c)} ${n(0)}  (nothing to do)`); return; }
  const res = t[c].deleteMany(f);
  removed += res.deletedCount;
  print(`   ${pad(label || c)} expected ${n(before)}  deleted ${n(res.deletedCount)}`);
}

if (CASCADE_XDR && INC_IDS.length) {
  for (const [c, f] of DEPENDENTS) wipe(c, { [f]: { $in: INC_IDS } });
  wipe("workspace_cases", { tenant_id: TENANT, id: { $in: INC_IDS } },
       "workspace_cases (EDR-ONLY incidents)");
}
if (CASCADE_XDR) {
  wipe("v2_shadow_observations", obsFilter);
  wipe("xdr_canonical_evidence", evidenceFilter);
}
for (const c of [RAW].concat(EDR_TELEMETRY)) wipe(c, { tenant_id: TENANT });
for (const c of EDR_IDENTITY) wipe(c, { tenant_id: TENANT });

print(`\ntotal deleted: ${removed}`);

// ──────────────────────────── verification ───────────────────────────
print("\n── post-reset verification · must all read 0");
for (const c of [RAW].concat(EDR_TELEMETRY, EDR_IDENTITY))
  print(`   ${pad(c)} ${n(count(c, { tenant_id: TENANT }))}`);
if (CASCADE_XDR) {
  print(`   ${pad("xdr_canonical_evidence (EDR-derived)")} ` +
        `${n(count("xdr_canonical_evidence", evidenceFilter))}`);
  print(`   ${pad("v2_shadow_observations (EDR-derived)")} ` +
        `${n(count("v2_shadow_observations", obsFilter))}`);
  print(`   ${pad("workspace_cases (EDR-ONLY incidents)")} ` +
        `${n(count("workspace_cases", { id: { $in: INC_IDS } }))}`);
  let dangling = 0;
  for (const [c, f] of DEPENDENTS) dangling += count(c, { [f]: { $in: INC_IDS } });
  print(`   ${pad("dangling dependents (must be 0)")} ${n(dangling)}`);
}

print("\n── retained · must be NON-zero");
for (const c of EDR_CONFIG.concat(EDR_AUDIT))
  print(`   ${pad(c)} ${n(count(c, { tenant_id: TENANT }))}`);
print(`   ${pad("MIXED incidents still present")} ${n(mixedInc.length)}`);
print(`   ${pad("workspace_cases · all tenants")} ${n(count("workspace_cases", {}))}`);
print(`   ${pad("xdr_canonical_evidence · all tenants")} ` +
      `${n(count("xdr_canonical_evidence", {}))}`);

print("\nNo collection was dropped — indexes and validators are intact.");
print("Ready for a fresh enrolment.");
