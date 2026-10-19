// NivXForge EDR · development reset · DRY RUN BY DEFAULT
//
//   mongosh "<MONGO_URL>" --file edr_dev_reset.mongosh.js
//
// Nothing is deleted until CONFIRM is set to the exact string below AND a
// backup/snapshot reference is recorded in SNAPSHOT. The first run prints
// what WOULD be removed, including the XDR blast radius, and exits.
//
// Guarantees of this script:
//   * no dropDatabase, no collection drops  -> indexes and validators survive
//   * every filter is tenant-scoped          -> nothing outside the tenant
//   * XDR / v2 / canonical collections are NEVER written, only COUNTED
//   * it prints before-and-after counts for every collection it touches

// ─────────────────────────── configuration ───────────────────────────
const DB_NAME  = "greeting-app-5782-test_database";
const TENANT   = "ten_e759b7288598bd882e3dcac49d";
const ENDPOINT = "ep_1989031c8c1d0085812f";

// "endpoint" = only this computer's telemetry · "tenant" = the whole tenant,
// including ep_a67be48d5b4e01d4d9e8 (1,719,950 raw events).
const SCOPE = "tenant";

// Keep the fleet's configuration (policies, groups, exclusions, boundary).
// false would also clear them and force the defaults to be re-seeded.
const KEEP_CONFIG = true;

// Append-only history of who enrolled what. Cheap, and useful after a reset.
const KEEP_AUDIT = true;

const CONFIRM  = "";   // set to "DELETE-EDR-DEV-DATA" to arm
const SNAPSHOT = "";   // Atlas snapshot id / mongodump path taken beforehand

// ───────────────────── collection classification ─────────────────────
// Derived by reading the code, not by naming: every collection below is
// referenced ONLY by edr_plane/*, routers/edr_*, services/edr/* or
// edr_trajectory/*. edr_raw_events is the one exception and is handled
// separately, because XDR reads it.
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
const EDR_CONFIG = [   // cleared only when KEEP_CONFIG === false
  "edr_policies", "edr_groups", "edr_policy_versions", "edr_exclusions",
  "edr_exclusion_sets", "edr_isolation_policy", "edr_tenant_boundary",
  "edr_connector_deployments", "edr_saved_views",
];
const EDR_AUDIT = ["edr_enrollment_audit", "edr_policy_audit"];

// READ-ONLY here. Listed so the blast radius is visible, never written.
const XDR_REFERENCING = ["xdr_canonical_evidence", "v2_shadow_observations"];

// ───────────────────────────── helpers ───────────────────────────────
const target = db.getSiblingDB(DB_NAME);   // `db` itself is never written
const armed = CONFIRM === "DELETE-EDR-DEV-DATA" && SNAPSHOT.length > 0;

function tenantFilter(name) {
  const f = { tenant_id: TENANT };
  if (SCOPE === "endpoint") {
    if (name === "edr_raw_events") f.endpoint_ref = ENDPOINT;
    else if (name !== "edr_enrollment_tokens") f.endpoint_id = ENDPOINT;
  }
  return f;
}

function report(group, names) {
  print(`\n── ${group}`);
  let total = 0;
  for (const name of names) {
    if (!target.getCollectionNames().includes(name)) { print(`   ${name.padEnd(38)} (absent)`); continue; }
    const f = tenantFilter(name);
    const scoped = target[name].countDocuments(f);
    const all = target[name].countDocuments({});
    total += scoped;
    print(`   ${name.padEnd(38)} in scope ${String(scoped).padStart(9)}   collection total ${all}`);
  }
  return total;
}

// ───────────────────────────── dry run ───────────────────────────────
print(`\n=== NivXForge EDR dev reset · ${armed ? "ARMED" : "DRY RUN"} ===`);
print(`db ${DB_NAME}   tenant ${TENANT}   scope ${SCOPE}`);

let planned = 0;
planned += report("EDR telemetry and derived state (will be removed)", EDR_TELEMETRY);
planned += report("EDR raw evidence (will be removed — read by XDR, see below)", ["edr_raw_events"]);
planned += report("EDR identity (will be removed, recreated by enrolment)", EDR_IDENTITY);
report(`EDR configuration (${KEEP_CONFIG ? "KEPT" : "will be removed"})`, EDR_CONFIG);
if (!KEEP_CONFIG) planned += report("…counted above", []);
report(`EDR audit (${KEEP_AUDIT ? "KEPT" : "will be removed"})`, EDR_AUDIT);

print("\n── XDR blast radius (READ ONLY — this script never writes these)");
for (const name of XDR_REFERENCING) {
  if (!target.getCollectionNames().includes(name)) { print(`   ${name.padEnd(38)} (absent)`); continue; }
  // the pointer is `raw_ref` = { collection, raw_id } — see
  // services/evidence_bridge.py::_raw_reference and
  // v2/ingestion/telemetry_bridge.py
  const pointed = target[name].countDocuments({ "raw_ref.collection": "edr_raw_events" });
  const anyRef = target[name].countDocuments({ "raw_ref": { $exists: true, $ne: null } });
  print(`   ${name.padEnd(38)} raw_ref -> edr_raw_events: ${String(pointed).padStart(8)}   any raw_ref: ${anyRef}`);
}
print("   NOTE: those references resolve by raw_id. Clearing edr_raw_events");
print("   leaves them unresolvable — XDR keeps working, but any case or");
print("   finding built on this telemetry will show evidence it cannot load.");
print("   Decide deliberately; this script will NOT touch them.");

print(`\nplanned deletions in scope: ${planned}`);

if (!armed) {
  print("\nDRY RUN — nothing was changed.");
  print("To execute: take an Atlas snapshot, put its id in SNAPSHOT, set");
  print('CONFIRM = "DELETE-EDR-DEV-DATA", and re-run.');
  quit(0);
}

// ───────────────────────────── execution ─────────────────────────────
print(`\n=== EXECUTING · snapshot ${SNAPSHOT} ===`);
const groups = [["telemetry", EDR_TELEMETRY], ["raw", ["edr_raw_events"]],
                ["identity", EDR_IDENTITY]];
if (!KEEP_CONFIG) groups.push(["config", EDR_CONFIG]);
if (!KEEP_AUDIT) groups.push(["audit", EDR_AUDIT]);

let removed = 0;
for (const [group, names] of groups) {
  for (const name of names) {
    if (!target.getCollectionNames().includes(name)) continue;
    const f = tenantFilter(name);
    const before = target[name].countDocuments(f);
    const res = target[name].deleteMany(f);
    removed += res.deletedCount;
    print(`   ${group.padEnd(9)} ${name.padEnd(38)} expected ${String(before).padStart(9)}  deleted ${res.deletedCount}`);
  }
}
print(`\ntotal deleted: ${removed}`);

// ──────────────────────────── verification ───────────────────────────
print("\n── post-reset verification (all must read 0 in scope)");
for (const [, names] of groups) for (const name of names) {
  if (!target.getCollectionNames().includes(name)) continue;
  print(`   ${name.padEnd(38)} ${target[name].countDocuments(tenantFilter(name))}`);
}
print("\n── preserved");
for (const name of (KEEP_CONFIG ? EDR_CONFIG : []).concat(KEEP_AUDIT ? EDR_AUDIT : [])) {
  if (!target.getCollectionNames().includes(name)) continue;
  print(`   ${name.padEnd(38)} ${target[name].countDocuments({ tenant_id: TENANT })}`);
}
print("\nindexes intact (no collection was dropped). Ready for a fresh enrolment.");
