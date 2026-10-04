# READ-ONLY PRODUCTION CENSUS — xdr_canonical_evidence

**Mode:** report-only. No migration endpoint invoked. Zero writes. No admin credential used. No secrets returned.
**Tooling note:** all figures via read-only `mongo_query` (find / count / distinct / list_collections / list_indexes). No `explain` / `aggregate` is available in this toolset — items needing them are marked NOT OBTAINABLE.
**LIVE-DATA CAVEAT:** the collection is under active ingestion. Total observed drifted upward across reads (121,987 → 121,999 → 122,000). All counts below are instantaneous snapshots at query time, NOT a frozen total; small cross-query deltas are live inserts, not inconsistency.

## A. DATABASE IDENTITY
- Production DB name (query target, server-resolved): `greeting-app-5782-test_database` — **CONFIRMED** (matches prior report).
- Collection: `xdr_canonical_evidence`.
- First/last query wall-clock timestamps: **NOT OBTAINABLE** (the tool returns no query timestamp). Lower bound on "now": latest observed `ingest_time` = 2026-10-03T13:01:48.940257+00:00.

## B. PRODUCTION CORPUS (snapshot)
1. total documents = **121,987** (first read; later reads 121,999 / 122,000 — live drift)
2. CANDIDATE COUNT, exact STEP-35 predicate `{endpoint_id $exists:false, collector_id /^ep_/}` = **0**
3. with `additional_fields.endpoint_id` existing = **121,982**
4. missing `additional_fields.endpoint_id` = **5**
- 3 + 4 = 121,987 == total at that instant ✓

## C. CANDIDATE ELIGIBILITY BREAKDOWN (all restricted to the 5 missing-authoritative docs)
- C1 missing authoritative field (denominator) = **5**
- C2 candidate set (…AND collector_id /^ep_/ AND len>3, via `^ep_.+`) = **0**
- C3 collector_id EXISTS but NOT /^ep_/ (invalid identity) = **5**
- C4 collector_id does NOT exist = **0**
- C5 …AND host.hostname EXISTS (name-only) = **0**
- C6 …AND host object absent (host-less) = **0**
- C7 …AND host.hostname absent AND (host.host_id|device_iid|event.computer|host.ip) exists = **0** (none — so NO rows would require NEVER_IDENTITY inference; none to be touched)
- C8 endpoint_id EXISTS but NOT /^ep_/ (non-minted authoritative defect) = **0**
- Reconciliation: C2 + C3 + C4 = 0 + 5 + 0 = 5 == C1 ✓ — **no shortfall**. All 5 missing-authoritative docs carry a collector_id that is present but non-platform-minted.

## D. SAFETY CONFIRMATIONS
- authoritative identities overwritten = **0**
- evidence rows modified = **0**
- indexes changed = **0**
- collections/schema changed = **0**
- APPLY writes = **0**
- REVERT writes = **0**
- migration operations invoked = **0**
- `e3_migration_runs` records for backfill_authoritative_endpoint_identity / revert_authoritative_endpoint_identity_backfill / explain_canonical_identity_read_plan = **0** (confirmed).
  - NOTE: `e3_migration_runs` is NOT empty — it holds **3** records, but all are operation `ensure_canonical_identity_indexes` (mode apply then two report, actor admin@nivxray.com, 2026-10-03 ~11:10–11:21Z). That operation created the two `sd_canonical_*` indexes; `existing_indexes_changed:false`, `refusals:[]`. It is a DIFFERENT operation from the three named above, which each remain 0.
- `e3_migration_row_ledger` = **collection ABSENT** (count returned collection_not_found) → effectively 0.

## E. POPULATION DIFFERENCE CLASSIFICATION (evidence-only)
- Preview: 303,181 docs / 1,236 candidates. Production (this census): 121,987+ docs / **0 candidates**. Candidate count DIFFERS from 1,236 — reported, not acted upon (expected per instruction).
- E1 time ranges:
  - `event_time` min = `2026-09-18 08:38:17.563`, max = `2026-10-01T10:33:50.287033Z`. CAVEAT: `event_time` is stored in MIXED string formats (space-separated no-tz AND ISO-Z), so lexicographic sort may not be strictly chronological — treat min/max as approximate.
  - `ingest_time` min = `2026-09-18T10:01:43.850316+00:00`, max = `2026-10-03T13:01:48.940257+00:00`. `ingest_time` present on ~122,000 docs (≈all).
- E2 distinct `tenant_id` = **1** value only: `ten_e759b7288598bd882e3dcac49d`, holding the ENTIRE corpus (121,999 at read). "Top 5 tenants" is therefore a single tenant = full count; no further partition exists.
- E3 `provenance.endpoint_identity.authority` distribution: AUTHENTICATED_INGEST_BOUNDARY = **1,232**; BACKFILL_DETERMINISTIC = **0**; absent = **120,767**. (No BACKFILL_DETERMINISTIC rows → the backfill never wrote, consistent with 0 candidates and 0 backfill runs.)
- E4 `provenance.endpoint_identity.state`: RESOLVED = **1,233**; UNRESOLVED = **0**; absent = **120,767**. (RESOLVED vs authority-present differ by 1 = a live insert between the two read batches.)
- E5 TTL / expiry: **NO TTL index and NO expireAfterSeconds** on any of the 4 indexes; no expiry field evident in index metadata. → TTL does NOT explain any attrition. Beyond that, cause of the preview-vs-prod population difference: **NO EVIDENCE AVAILABLE** from read-only data (not hypothesised).

## F. QUERY-PLAN PROOF
- F1 explain for the B2 candidate predicate: **NOT OBTAINABLE** — no `explain` command in available tooling.
- F2 explain for the §d endpoint/time read (tenant_id + endpoint_id $in, sort event_time -1, limit 200): **NOT OBTAINABLE** — cannot produce winning plan / IXSCAN indexName / SORT-stage presence / COLLSCAN presence / indexBounds key order without `explain`. Observation only: an index whose key shape matches this query exists — `sd_canonical_endpointid_eventtime`, true order (tenant_id, additional_fields.endpoint_id, event_time -1).
- F3 full index list (4):
  1. `_id_` — {_id:1}
  2. `tenant_id_1_ingest_time_-1` — tenant_id(1), ingest_time(-1)  [order per index name; list_indexes rendered keys unordered]
  3. `sd_canonical_endpointid_eventtime` — TRUE order (tenant_id 1, additional_fields.endpoint_id 1, event_time -1)
  4. `sd_canonical_hostname_eventtime` — TRUE order (tenant_id 1, host.hostname 1, event_time -1)
  - No `expireAfterSeconds` on any index.
  - CAVEAT: `list_indexes` returned compound keys as unordered JSON objects (alphabetised). True compound key order for the two `sd_canonical_*` indexes is taken from the `ensure_canonical_identity_indexes` creation record in `e3_migration_runs`, which preserves it.

## BOUNDARY COMPLIANCE
- Collections read: `xdr_canonical_evidence`, `e3_migration_runs`, `e3_migration_row_ledger` (absent), plus list_collections/list_indexes metadata. No reads or writes to Behavior/shadow/KUSHU/DESKTOP-A9HGFJJ/sensors/threat-intel/UI. No document of `xdr_canonical_evidence` modified. No admin endpoint called. No secret/credential/connection string returned or requested.
