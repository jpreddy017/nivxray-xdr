# RCA — Second & Final Inventory Pass (READ-ONLY)
Deployment: greeting-app-5782 | DB: greeting-app-5782-test_database | run_id: 4067c54d-e252-4243-a214-27a9f17715bc
TENANT = ten_e759b7288598bd882e3dcac49d
EP = ["ep_1989031c8c1d0085812f","ep_a67be48d5b4e01d4d9e8"]
Follows RCA_4067c54d-e252-4243-a214-27a9f17715bc.MD (A–G). No writes/deletes/deploy/secret changes performed.

=====================================================================
GAP 1 — EVIDENCE PINNING (which raw events must SURVIVE)
=====================================================================
H1  xdr_canonical_evidence · distinct provenance.trace_id (5 non-EDR-attributed rows) = 5 values:
      live_3eee147edfa74fa5
      live_5b8470579b8145c4
      live_6267f80b081d4ae2
      live_bfded2f28d7247d7
      live_fd512680a4ed4117

H2  v2_shadow_observations · distinct event.raw.raw_evidence_ref.raw_id (4 unmatched tenant rows) = 0 values
      (the 4 unmatched rows carry NO raw_id — field null/absent; they contribute nothing to KEEP_RAW)

H3  KEEP_RAW = union(H1, H2) non-null  => the 5 H1 values.  |KEEP_RAW| = 5
      edr_raw_events {tenant_id:TENANT, raw_id:{$nin:KEEP_RAW}} = 1,877,149   <- EXACT raw deletion count
      edr_raw_events {tenant_id:TENANT, raw_id:{$in:KEEP_RAW}}  = 0
        (derivation: tenant total edr_raw_events = 1,877,149, which EQUALS the $nin count; $in and $nin
         are exact complements over the collection, so $in = total - $nin = 0. The direct $in count
         timed out — there is NO raw_id-prefix index: events_keyset is {ingest_time,raw_id,tenant_id}
         with raw_id NOT the prefix, so a bare raw_id filter collscans 1.8M docs.)

  *** DEFECT FLAG ***  $in (0) < |KEEP_RAW| (5).
  Every one of the 5 raw ids cited by the surviving evidence rows is ABSENT from edr_raw_events.
  i.e. evidence ALREADY cites missing raw rows. Note the format mismatch: the cited ids are
  "live_*" shaped, whereas edr_raw_events raw_ids are "raw_*" shaped (see I3 regex). The planned
  delete therefore pins NOTHING (KEEP_RAW resolves to 0 existing rows) and all 1,877,149 tenant raws
  would be deleted. Owner must decide whether these 5 evidence rows are to be retained/repaired
  given they reference non-existent raw evidence.

=====================================================================
GAP 2 — EVIDENCE-KEYED ARTEFACTS
=====================================================================
I1  xdr_detection_matches  — COLLECTION DOES NOT EXIST in this DB (collection_not_found).
      in-scope / tenant-total / all-tenants / EDR-shaped subset: N/A (absent). Nothing to delete.

I2  xdr_spread_sightings   — COLLECTION DOES NOT EXIST in this DB (not in live collection list).
      in-scope / tenant-total / all-tenants / subset: N/A (absent). Nothing to delete.

I3  xdr_correlation_matches — EXISTS but GLOBALLY EMPTY:
      in-scope {tenant_id:TENANT, trace_id:/^raw_[0-9a-f]{24}$/} = 0
      tenant total {tenant_id:TENANT}                            = 0
      all tenants {}                                             = 0
      EDR-shaped subset (+canonical_event_id:/^cev_(raw_)?[0-9a-f]{24}/) = 0

I4  xdr_ingest_dedupe — EXISTS but GLOBALLY EMPTY:
      tenant {tenant_id:TENANT} = 0
      all tenants {}            = 0

=====================================================================
GAP 3 — TENANT ISOLATION AND UNSTAMPED DOCUMENTS
=====================================================================
J1  count {} (ALL tenants):
      edr_raw_events                     1,877,149
      edr_processing_queue               1,718,750
      edr_rejected_telemetry                25,992
      edr_acquisition_gaps                   2,786
      edr_acquisition_integrity                  3
      edr_delivery_counters                      6
      edr_finding_evaluations              301,549
      edr_endpoint_address_observations         29
      edr_policy_endpoint_state                  2
      edr_endpoints                              2
      edr_agent_credentials                      2
      edr_policies                               1
      edr_groups                                 1
      edr_policy_versions                        1
      edr_enrollment_audit                      14
      edr_policy_audit                       4,426

J2  count {tenant_id:{$exists:false}} (UNSTAMPED docs) — for ALL 16 collections = 0.
      No document in any of these collections lacks a tenant stamp; none would be left behind by a
      tenant-scoped delete.

J3  edr_raw_events {tenant_id:{$ne:TENANT}} = 0   (every raw event belongs to this tenant)
    edr_endpoints distinct tenant_id (all tenants) = ["ten_e759b7288598bd882e3dcac49d"] (1 value)
      => Clean isolation. Combined with J1==J2-complement, this DB is effectively single-tenant for
         the EDR collections; the all-tenant totals in J1 equal the tenant's own data.

=====================================================================
GAP 4 — EMPTY INCIDENT CASCADE
=====================================================================
K1  workspace_cases {tenant_id:TENANT, doc_type:"xdr_incident"} = 0   (re-confirmed)
K2  workspace_cases distinct doc_type {tenant_id:TENANT} = 0 values
      => the tenant holds NO workspace_cases documents of ANY doc_type (collection empty for tenant).
K3  workspace_cases {"endpoint_campaign.endpoint_id":{$in:EP}} (NO tenant filter) = 0
      => no incident about these endpoints stamped under a different tenant; no isolation defect.

  Cascade holds: 0 incidents, 0 tenant workspace_cases of any type, 0 cross-tenant endpoint incidents.
  "No MIXED, no UNKNOWN, no dependents" basis confirmed.

=====================================================================
BOTTOM LINE FOR THE OWNER
=====================================================================
1. EXACT raw deletion count = 1,877,149 (all tenant raws). KEEP_RAW pins 0 existing rows because the
   5 cited raw ids do not exist in edr_raw_events — DECISION NEEDED before authorising.
2. The 5 surviving evidence rows already dangle (cite missing raw). Decide retain vs repair vs purge.
3. Two "evidence-keyed artefact" collections (xdr_detection_matches, xdr_spread_sightings) do NOT exist.
   xdr_correlation_matches and xdr_ingest_dedupe exist but are globally empty — nothing to delete.
4. No unstamped docs anywhere (J2 all 0); clean tenant isolation (J3); empty-incident cascade holds (GAP 4).
This was a read-only inventory. No changes were made.