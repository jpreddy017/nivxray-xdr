// NivXForge EDR · development reset · D1-D5 as approved · DRY RUN BY DEFAULT
//
//   mongosh "<MONGO_URL>" --file edr_dev_reset.mongosh.js
//
// Owner decisions implemented here (approved 2026-10-19):
//   D1  tenant-wide cleanup of obsolete development EDR telemetry+enrolment
//   D2  RETAIN EDR configuration, groups, policies, tenant settings
//   D3  RETAIN enrolment and policy audit
//   D4  leave NO broken XDR evidence references: the XDR artefacts DERIVED
//       from this EDR telemetry are retired in the same pass, and nothing
//       else is
//   D5  a verified restorable BACKUP reference must be recorded below or
//       nothing deletes. Emergent-managed Atlas offers no user-facing
//       snapshot, so this is the mongodump artefact + its sha256.
//
// THE THREE D4 SAFETY CHECKS
//   1. tenant-scoped dependent selectors — a dependent is only deleted when
//      it is stamped with THIS tenant or carries no tenant stamp at all. A
//      dependent carrying another tenant's id aborts the run (S2).
//   2. UNKNOWN evidence — an incident citing a canonical event that does not
//      resolve is PRESERVED, not deleted. Absent is not "mine to delete".
//   3. MIXED preservation — an incident citing any non-EDR evidence is
//      preserved, and any dependent that ALSO references a preserved
//      incident is excluded from deletion.
//
// GUARANTEES
//   * dry run unless CONFIRM and SNAPSHOT are both set
//   * no dropDatabase, no collection drop -> indexes and validators survive
//   * every filter is tenant-scoped
//   * leaf -> root order, so an interrupted run never leaves a dangling ref
//   * preserved incidents, other tenants and non-EDR evidence are never
//     written

// ─────────────────────────── configuration ───────────────────────────
const DB_NAME = "greeting-app-5782-test_database";
const TENANT  = "ten_e759b7288598bd882e3dcac49d";
const RAW     = "edr_raw_events";

const CONFIRM  = "";   // set to "DELETE-EDR-DEV-DATA" to arm            (D5)
const BACKUP   = "";   // verified backup reference, e.g.                (D5)
                       // "edr-predelete-20261020.archive.gz sha256:…"
                       // There is NO user-facing Atlas snapshot on an
                       // Emergent-managed cluster — this is the mongodump
                       // archive you took and verified yourself.

const KEEP_CONFIG = true;   // D2
const KEEP_AUDIT  = true;   // D3
const CASCADE_XDR = true;   // D4

// D4 · artefacts that hang off an incident. Filled from section 5 of the
// impact report, which DISCOVERS them rather than assuming them.
const DEPENDENTS = [
  ["xdr_investigation_activity",     "incident_id"],
  ["xdr_investigations",             "incident_id"],
  ["xdr_investigation_findings",     "incident_id"],
  ["xdr_iue_understanding",          "incident_id"],
  ["xdr_framework_mappings",         "incident_id"],
  ["xdr_response_timeline",          "incident_id"],
  ["xdr_intelligence_overlays",      "incident_id"],
  ["xdr_intelligence_overlay_audit", "incident_id"],
];
const REF_FIELDS = ["incident_id", "case_id", "id", "parent_incident_id",
                    "promoted_incident_id", "incident_ids"];

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
const armed = CONFIRM === "DELETE-EDR-DEV-DATA" && BACKUP.length > 0;

print(`\n=== NivXForge EDR dev reset · ${armed ? "ARMED" : "DRY RUN"} ===`);
print(`db ${DB_NAME}   tenant ${TENANT}`);
print(`D1 tenant-wide · D2 keep config ${KEEP_CONFIG} · D3 keep audit ` +
      `${KEEP_AUDIT} · D4 cascade ${CASCADE_XDR}`);

const EP = has("edr_endpoints")
  ? t.edr_endpoints.find({ tenant_id: TENANT }, { endpoint_id: 1 })
      .toArray().map((e) => e.endpoint_id).filter(Boolean)
  : [];
print(`\nEDR endpoints in tenant: ${EP.length} ${JSON.stringify(EP)}`);

const EV_OR = [{ "provenance.collector_id": { $in: EP } },
               { "additional_fields.endpoint_id": { $in: EP } },
               { "host.host_id": { $in: EP } }];
const OBS_OR = [{ collector_id: { $in: EP } }, { connector_id: { $in: EP } },
                { "event.raw.raw_evidence_ref.collection": RAW }];
const evidenceFilterBase = { tenant_id: TENANT, $or: EV_OR };
const obsFilterBase = { tenant_id: TENANT, $or: OBS_OR };

// ───── D4 · classify incidents: EDR-ONLY / MIXED / UNKNOWN / unrelated ─────
const edrOnly = [], mixedInc = [], unknownInc = [];
if (CASCADE_XDR && has("workspace_cases") && EP.length) {
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
    if (!(EP.includes(camp.endpoint_id) || EP.includes(prov.collector_id)))
      continue;                                    // unrelated · preserved
    const cids = [(inc.xdr_pipeline || {}).canonical_event_id]
      .concat((camp.detections || []).map((d) => d && d.canonical_event_id))
      .filter(Boolean);
    let foreign = 0, unknown = 0;
    for (const cid of cids) {
      const row = t.xdr_canonical_evidence.findOne(
        { tenant_id: TENANT, event_id: cid },
        { "provenance.collector_id": 1, "additional_fields.endpoint_id": 1,
          "host.host_id": 1 });
      if (!row) { unknown++; continue; }            // safety check 2
      const cc = (row.provenance || {}).collector_id;
      const ee = (row.additional_fields || {}).endpoint_id;
      const hh = (row.host || {}).host_id;
      if (!EP.includes(cc) && !EP.includes(ee) && !EP.includes(hh)) foreign++;
    }
    inc._cited = cids.length; inc._foreign = foreign; inc._unknown = unknown;
    if (foreign > 0) mixedInc.push(inc);            // safety check 3
    else if (unknown > 0) unknownInc.push(inc);
    else edrOnly.push(inc);
  }
}
let DEL_IDS  = edrOnly.map((i) => i.id).filter(Boolean);
const KEEP_IDS = mixedInc.concat(unknownInc).map((i) => i.id).filter(Boolean);

// Safety check 3, part two · ENTANGLEMENT PROPAGATION.
// If a dependent cites both an EDR-ONLY incident and a preserved one,
// preserving that dependent would leave a live reference to a deleted
// incident — the exact broken reference D4 forbids. So the entanglement
// propagates: the EDR-ONLY incident is promoted to PRESERVED instead.
// Repeated to a fixpoint, because each promotion can entangle more.
const entangled = [];
if (CASCADE_XDR && DEL_IDS.length && KEEP_IDS.length) {
  const proj = {};
  for (const g of REF_FIELDS) proj[g] = 1;
  for (let pass = 0; pass < 10; pass++) {
    const promote = new Set();
    for (const [c, f] of DEPENDENTS) {
      if (!has(c)) continue;
      const docs = t[c].find(
        { [f]: { $in: DEL_IDS },
          $or: REF_FIELDS.map((g) => ({ [g]: { $in: KEEP_IDS } })) },
        proj).toArray();
      for (const d of docs) {
        const v = d[f];
        if (DEL_IDS.includes(v)) promote.add(v);
      }
    }
    if (!promote.size) break;
    for (const id of promote) {
      entangled.push(id);
      KEEP_IDS.push(id);
      DEL_IDS = DEL_IDS.filter((x) => x !== id);
    }
  }
}

// Safety check 1+3 · a dependent is in scope only when it is stamped with
// THIS tenant (or unstamped) AND references no preserved incident.
function depFilter(field) {
  const f = {
    [field]: { $in: DEL_IDS },
    $and: [{ $or: [{ tenant_id: TENANT }, { tenant_id: { $exists: false } }] }],
  };
  if (KEEP_IDS.length) {
    f.$and.push({ $nor: REF_FIELDS.map((g) => ({ [g]: { $in: KEEP_IDS } })) });
  }
  return f;
}
function foreignTenantCount(c, field) {
  return has(c) ? t[c].countDocuments(
    { [field]: { $in: DEL_IDS }, tenant_id: { $exists: true, $ne: TENANT } }) : 0;
}

// ───────── EVIDENCE PINNING · the other direction of D4 ─────────
// A preserved incident (MIXED, UNKNOWN or ENTANGLED) still cites canonical
// events, and those events still cite their raw rows. Deleting them would
// break the preserved incident instead of the deleted one. So the evidence
// cited by preserved incidents — and the raw events behind it — are PINNED
// out of every sweep below.
const KEEP_CEV = [];
if (CASCADE_XDR && KEEP_IDS.length && has("workspace_cases")) {
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
// Raw events are pinned if ANY surviving tenant row still points at them —
// evidence cited by a preserved incident, and also evidence or observations
// that the EDR selectors do not claim at all (the tenant's own non-EDR rows).
// Measured, not assumed: production has 5 such evidence rows and 4 such
// observations, and if they cite a raw event it must survive.
const KEEP_RAW = [];
if (CASCADE_XDR) {
  const survivingEvidence = {
    tenant_id: TENANT,
    $or: [{ event_id: { $in: KEEP_CEV } }, { $nor: [{ $or: EV_OR }] }],
  };
  const survivingObs = {
    tenant_id: TENANT,
    $or: [{ canonical_event_id: { $in: KEEP_CEV } }, { $nor: [{ $or: OBS_OR }] }],
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

const evidenceFilter = KEEP_CEV.length
  ? { $and: [evidenceFilterBase, { event_id: { $nin: KEEP_CEV } }] }
  : evidenceFilterBase;
const obsFilter = KEEP_CEV.length
  ? { $and: [obsFilterBase, { canonical_event_id: { $nin: KEEP_CEV } }] }
  : obsFilterBase;
const rawFilter = KEEP_RAW.length
  ? { tenant_id: TENANT, raw_id: { $nin: KEEP_RAW } }
  : { tenant_id: TENANT };

// Artefacts keyed on the EVIDENCE rather than on an incident. These were
// found by probing which collections actually carry a sensor reference —
// trace_id = raw_id, evidence_ref, collector_id — not by guessing at names.
// Without them, deleting canonical evidence would strand live references.
const EVIDENCE_KEYED = [
  ["xdr_detection_matches",
   { tenant_id: TENANT, source: "sensor",
     canonical_event_id: { $nin: KEEP_CEV } }],
  ["xdr_spread_sightings",
   { tenant_id: TENANT, collector_id: { $in: EP },
     canonical_event_id: { $nin: KEEP_CEV } }],
  ["xdr_correlation_matches",
   { $and: [{ tenant_id: TENANT },
            { trace_id: { $regex: "^raw_[0-9a-f]{24}$" } },
            { trace_id: { $nin: KEEP_RAW } }] }],
];

// ───────────────────────── plan / dry run ────────────────────────────
function count(c, f) { return has(c) ? t[c].countDocuments(f) : 0; }
function line(c, f, note) {
  if (!has(c)) { print(`   ${pad(c)} (absent)`); return 0; }
  const k = t[c].countDocuments(f);
  print(`   ${pad(c)} ${n(k)}${note ? "   " + note : ""}`);
  return k;
}

let planned = 0, foreignTenant = 0, excluded = 0;
print("\n── A · XDR artefacts derived from this EDR telemetry (D4)");
if (CASCADE_XDR) {
  for (const [c, f] of DEPENDENTS) {
    if (!has(c)) { print(`   ${pad(c)} (absent)`); continue; }
    const inScope = DEL_IDS.length ? t[c].countDocuments(depFilter(f)) : 0;
    const naive = DEL_IDS.length ? t[c].countDocuments({ [f]: { $in: DEL_IDS } }) : 0;
    const wrong = DEL_IDS.length ? foreignTenantCount(c, f) : 0;
    foreignTenant += wrong; excluded += (naive - inScope);
    planned += inScope;
    print(`   ${pad(c + " ." + f)} ${n(inScope)}   referencing ${n(naive)}` +
          `   excluded ${n(naive - inScope)}   foreign-tenant ${n(wrong)}`);
  }
  planned += line("workspace_cases", { tenant_id: TENANT, id: { $in: DEL_IDS } },
                  "EDR-ONLY incidents");
  for (const [c, f] of EVIDENCE_KEYED) planned += line(c, f, "evidence-keyed");
  planned += line("v2_shadow_observations", obsFilter);
  planned += line("xdr_canonical_evidence", evidenceFilter);
  print(`\n   ${pad("PRESERVED · MIXED incidents")} ${n(mixedInc.length)}`);
  for (const i of mixedInc.slice(0, 30))
    print(`      MIXED    ${i.id}  #${i.incident_number || "-"}  ` +
          `foreign ${i._foreign}/${i._cited}  ${String(i.title || "").slice(0, 40)}`);
  print(`   ${pad("PRESERVED · UNKNOWN evidence")} ${n(unknownInc.length)}`);
  for (const i of unknownInc.slice(0, 30))
    print(`      UNKNOWN  ${i.id}  #${i.incident_number || "-"}  ` +
          `unresolved ${i._unknown}/${i._cited}  ${String(i.title || "").slice(0, 38)}`);
  print(`   ${pad("PRESERVED · entangled with a preserved")} ${n(entangled.length)}`);
  for (const id of entangled.slice(0, 30)) print(`      ENTANGLED ${id}`);
  print(`   ${pad("PINNED · evidence cited by preserved")} ${n(KEEP_CEV.length)}`);
  print(`   ${pad("PINNED · raw events behind that evidence")} ${n(KEEP_RAW.length)}`);
  print(`   ${pad("dependents excluded by the guards")} ${n(excluded)}`);
  print(`   ${pad("dependents with a FOREIGN tenant (S2)")} ${n(foreignTenant)}`);
} else {
  print("   cascade disabled — references to removed EDR evidence WOULD be");
  print("   left unresolvable. Not the approved D4 behaviour.");
}

print("\n── B · EDR telemetry and derived state");
planned += line(RAW, rawFilter, KEEP_RAW.length ? `${KEEP_RAW.length} raw pinned` : "");
for (const c of EDR_TELEMETRY)
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
  print("To execute: take and VERIFY a mongodump archive, record it in");
  print('BACKUP, set CONFIRM = "DELETE-EDR-DEV-DATA", then re-run.');
  quit(0);
}
if (!KEEP_CONFIG || !KEEP_AUDIT) {
  print("\nREFUSING: D2/D3 require configuration and audit to be retained.");
  quit(1);
}
if (foreignTenant > 0) {
  print("\nREFUSING (S2): a dependent of an EDR-ONLY incident carries another");
  print("tenant's id. Resolve that before any deletion.");
  quit(1);
}

// ───────────────────────────── execution ─────────────────────────────
print(`\n=== EXECUTING · backup ${BACKUP} ===`);
let removed = 0;
function wipe(c, f, label) {
  if (!has(c)) return;
  const before = t[c].countDocuments(f);
  if (!before) { print(`   ${pad(label || c)} ${n(0)}  (nothing to do)`); return; }
  let gone = 0;
  if (before > 200000) {
    // Chunked, so a multi-million-row sweep cannot hit a client timeout and
    // can be resumed by simply re-running: each chunk is committed.
    while (true) {
      const ids = t[c].find(f, { _id: 1 }).limit(50000).toArray().map((d) => d._id);
      if (!ids.length) break;
      gone += t[c].deleteMany({ _id: { $in: ids } }).deletedCount;
      print(`      ${pad(label || c)} ${n(gone)} / ${before}`);
    }
  } else {
    gone = t[c].deleteMany(f).deletedCount;
  }
  removed += gone;
  print(`   ${pad(label || c)} expected ${n(before)}  deleted ${n(gone)}`);
}

if (CASCADE_XDR && DEL_IDS.length) {
  for (const [c, f] of DEPENDENTS) wipe(c, depFilter(f), c + " ." + f);
  wipe("workspace_cases", { tenant_id: TENANT, id: { $in: DEL_IDS } },
       "workspace_cases (EDR-ONLY incidents)");
}
if (CASCADE_XDR) {
  for (const [c, f] of EVIDENCE_KEYED) wipe(c, f, c + " (evidence-keyed)");
  wipe("v2_shadow_observations", obsFilter);
  wipe("xdr_canonical_evidence", evidenceFilter);
}
wipe(RAW, rawFilter);
for (const c of EDR_TELEMETRY) wipe(c, { tenant_id: TENANT });
for (const c of EDR_IDENTITY) wipe(c, { tenant_id: TENANT });

print(`\ntotal deleted: ${removed}`);

// ──────────────────────────── verification ───────────────────────────
print("\n── post-reset verification · must all read 0");
print(`   ${pad(RAW + " (unpinned)")} ${n(count(RAW, rawFilter))}`);
for (const c of EDR_TELEMETRY.concat(EDR_IDENTITY))
  print(`   ${pad(c)} ${n(count(c, { tenant_id: TENANT }))}`);
if (KEEP_RAW.length)
  print(`   ${pad(RAW + " pinned, EXPECTED non-zero")} ` +
        `${n(count(RAW, { tenant_id: TENANT, raw_id: { $in: KEEP_RAW } }))}` +
        ` of ${KEEP_RAW.length}`);
if (CASCADE_XDR) {
  print(`   ${pad("xdr_canonical_evidence (EDR-derived)")} ` +
        `${n(count("xdr_canonical_evidence", evidenceFilter))}`);
  print(`   ${pad("v2_shadow_observations (EDR-derived)")} ` +
        `${n(count("v2_shadow_observations", obsFilter))}`);
  print(`   ${pad("workspace_cases (EDR-ONLY incidents)")} ` +
        `${n(count("workspace_cases", { id: { $in: DEL_IDS } }))}`);
  let dangling = 0;
  for (const [c, f] of DEPENDENTS) dangling += count(c, { [f]: { $in: DEL_IDS } });
  print(`   ${pad("dangling dependents (must be 0)")} ${n(dangling)}`);
  for (const [c, f] of EVIDENCE_KEYED)
    print(`   ${pad(c + " (evidence-keyed)")} ${n(count(c, f))}`);
}

print("\n── retained · must be NON-zero / unchanged");
for (const c of EDR_CONFIG.concat(EDR_AUDIT))
  print(`   ${pad(c)} ${n(count(c, { tenant_id: TENANT }))}`);
print(`   ${pad("preserved incidents still present")} ` +
      `${n(count("workspace_cases", { id: { $in: KEEP_IDS } }))} of ${KEEP_IDS.length}`);
if (KEEP_CEV.length)
  print(`   ${pad("pinned evidence still present")} ` +
        `${n(count("xdr_canonical_evidence", { tenant_id: TENANT, event_id: { $in: KEEP_CEV } }))}` +
        ` of ${KEEP_CEV.length}`);
print(`   ${pad("workspace_cases · all tenants")} ${n(count("workspace_cases", {}))}`);
print(`   ${pad("xdr_canonical_evidence · all tenants")} ` +
      `${n(count("xdr_canonical_evidence", {}))}`);

print("\nNo collection was dropped — indexes and validators are intact.");
print("Ready for a fresh enrolment.");
