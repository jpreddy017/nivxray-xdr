# WINSEC SEMANTICS · CLEAN REPROJECTION · CONTRIBUTOR CONTRACT

Owner ruling executed in order: Account Event Ruling → Clean Reprojection →
Contributor Contract. Nothing deployed. Classification Audit View recorded
as a non-blocking evidence/provenance feature, not built.

Date 2026-06 · branch `feature/rc2-alignment`.

---

## 1 · WINSEC_SEMANTIC_AUDIT

Every entry of `WINSEC_KIND` reviewed. `event.kind` states WHAT WAS
OBSERVED; a detection is what a detection engine CONCLUDED.

| EVENT_ID | WINDOWS_MEANING | CURRENT_CANONICAL_KIND | PROPOSED / APPLIED | OBSERVATION_OR_SECURITY_CLAIM | CHANGE_REQUIRED |
|---|---|---|---|---|---|
| 4624 | An account was successfully logged on | `logon_success` | `logon_success` | OBSERVATION (the ID itself states success) | NO |
| 4625 | An account failed to log on | `logon_failure` | `logon_failure` | OBSERVATION (the ID itself states failure) | NO |
| 4634 | An account was logged off | `logon_success` | **`logoff`** | OBSERVATION | **YES — was factually wrong** |
| 4672 | Special privileges assigned to a new logon | `privilege_escalation` | **`special_privileges_assigned`** | OBSERVATION (fires on every SYSTEM logon) | **YES — was a security claim** |
| 4688 | A new process has been created | `process_create` | `process_create` | OBSERVATION | NO |
| 4697 | A service was installed in the system | `service_install` | `service_install` | OBSERVATION | NO |
| 4698 | A scheduled task was created | `scheduled_task_create` | `scheduled_task_create` | OBSERVATION | NO |
| 4700 | A scheduled task was **enabled** | `scheduled_task_create` | **`scheduled_task_enabled`** | OBSERVATION | **YES — conflated enable with create** |
| 4720 | A user account was created | **`detection`** | **`user_account_created`** | OBSERVATION | **YES — owner ruling** |
| 4732 | A member was added to a security-enabled local group | **`detection`** | **`security_group_member_added`** | OBSERVATION | **YES — owner ruling** |
| 4738 | A user account was changed | **`detection`** | **`user_account_changed`** | OBSERVATION | **YES — owner ruling** |
| 4776 | Credential validation by the NTLM package | `logon_success` | **`credential_validation`** | OBSERVATION (outcome is in `Status`, not the ID — 4776 is logged for failures too) | **YES — claimed an outcome the ID does not state** |
| 5140 | A network share object was accessed | `smb_share_access` | `smb_share_access` | OBSERVATION | NO |
| 5145 | A network share object was checked for access | `smb_share_access` | `smb_share_access` | OBSERVATION | NO |
| 5156 | WFP permitted a connection | `network_connect` | `network_connect` | OBSERVATION | NO |
| 7045 | A service was installed (System channel) | `service_install` | `service_install` | OBSERVATION | NO |
| 1102 | The audit log was cleared | **`alert`** | **`audit_log_cleared`** | OBSERVATION | **YES — was a security claim** |
| `"*"` | (dead catch-all key, unreachable from an int lookup) | `alert` | **REMOVED** | — | **YES — could only ever be revived as a default** |

7 of 17 mappings changed; 6 of those were a claim or a factual error.

**Vocabulary**: names are REUSED from the project's existing Windows
Security vocabulary (`detection_content/telemetry/windows_security_dsm.py`
`event_type`): `user_account_created`, `security_group_member_added`,
`credential_validation`, `special_privileges_assigned`, `audit_log_cleared`.
`logoff` was already recognised by the trajectory auth-lane resolver. Only
`user_account_changed` and `scheduled_task_enabled` are new, and both follow
the existing family naming. No duplicate vocabulary introduced.

**Governance**: `v2/cem/v1/schema.py::EVENT_KINDS` 41 → 50 (the 9 new /
now-used kinds, including `unclassified_telemetry`, which the classifier was
already emitting while being absent from the locked enum). The frozen count
in `tests/test_v2_framework.py` was amended deliberately, as that test asks.

**Consumer updates (minimum)**: `_AUTH_KINDS` in
`edr_plane/trajectory_window.py` and `edr_plane/trajectory/contract.py`
gained `credential_validation` so 4776 still resolves to the AUTHENTICATION
lane. Both lane maps (`v2/trajectory/schema.py`,
`services/edr/device_identity.py`) already default unknown kinds to the
`system` lane, which is where account / privilege / audit observations
belong — no change needed and none made.

### 4720_RESULT
`user_account_created`, basis `SOURCE_EVENT_ID:winsec:4720`. Actor and the
account acted upon are preserved and kept APART (`account_context.actor_*`
vs `target_user_name` / `target_user_sid`). NOT a detection.

### 4732_RESULT
`security_group_member_added`, basis `SOURCE_EVENT_ID:winsec:4732`.
`group_name`, `group_sid`, `member_sid` and `member_name` preserved —
including Windows' literal `"-"` for an unresolved member name, recorded as
delivered, not resolved and not dropped. NOT a detection.

### 4738_RESULT
`user_account_changed`, basis `SOURCE_EVENT_ID:winsec:4738`. NOT a
detection.

### WINDOWS_SECURITY_PROVIDER_RESULT — ENABLED, on source evidence

The gate is NOT keyed off the display label. `source_provider()` resolves,
in order of authority:

1. `additional_fields.winlog.provider` (sensor dialect)
2. **`raw_ref.System.Provider`** — the provider the RECORD named
3. `raw_ref.provider` / `raw_ref.Provider`
4. privileged channel (`Security` → Security-Auditing,
   `Microsoft-Windows-Sysmon/Operational` → Sysmon) — one channel, one
   possible writer
5. only then the vendor+product label, explicitly marked
   `VENDOR_PRODUCT_LABEL`

Live proof from the retained G1 evidence: Windows Security records carry
`raw_ref.System = {Provider: "Microsoft-Windows-Security-Auditing",
Channel: "Security", EventID: 4672, EventRecordID: 239166}`. The chain
**source Windows Security event → authoritative Event ID → canonical
account/group observation** is pinned per reviewed Event ID (17 cases).

On the reprojected corpus the resolved basis is
`SOURCE_STATED_PROVIDER:raw_ref.provider` for 3,295 records and
`SOURCE_STATED_PROVIDER:raw_ref.System.Provider` for 4 — **0 records fell
back to the display label.**

**Also fixed (source identity)**: the Sysmon parser/normalizer discarded the
record's own `Provider` and `EventRecordID`. They are now carried in
`raw_ref`, so `source_identity.record_id` is populated for **3,299 / 3,299**
acceptance observations. Nothing is invented: the values come from the raw
`<System>` block.

---

## 2 · CLEAN_REPROJECTION_STATUS — DONE

Script: `/app/scripts/g1_clean_reprojection.py` (`--plan` / `--apply`,
idempotent).

**Source of truth**: the BYTE-PRESERVED raw Windows Event XML retained in
`xdr_canonical_events` (3,299 records for the G1 tenant), reached from each
retained canonical evidence document through its own
`provenance.ingest.raw_envelope_ref`. This is a true raw replay, not a
projection of a projection.

**Replay path** — identical to the live ingest, minus the detection fabric:
`evtx_xml.decode_document` (same `evtx-xml-decoder/1.0.0`) → the DSM named by
the **RECORDED routing decision** (`provenance.ingest.selected_dsm_id`; the
DSM is never re-resolved by content) → its parser → its normalizer → the
FIXED `telemetry_bridge` → `v2_shadow_observations`.

`NOT_REPLAYABLE = 0`, `REPLAY_FAILURES = {}`, `WRITTEN = 3299`.

### NEW_CORPUS_IDENTITY
```
tenant_id        ten_3f7f772b353a6bbbb0ac8bc564
tenant_slug      g1-acceptance-clean   (LAB, ACTIVE)
organization_id  org_10b45e9746dd71655ecbb13287  (same ACTIVE org as G1)
device_iid       dev_f4b3fb82d7f3      (NEW identity; the source computer
                 name DESKTOP-A9HGFJJ is preserved VERBATIM in the evidence
                 — only the identity SCOPE is new)
ingest_job_id    g1-clean-reprojection-1
```

Every observation carries a `reprojection` block naming the source tenant,
the source evidence id, the raw envelope ref, the decoder id, the DSM id,
`routing_authority: RECORDED_ROUTING_DECISION`, and —
explicitly — `detection_state: DETECTION_NOT_EVALUATED` with the note
*"NOT_EVALUATED is not CLEAN"*. The acceptance corpus is canonical
OBSERVATIONS only; no detection, IOC or verdict engine has evaluated it.

### OLD_CORPUS_MUTATED — NO
```
ten_f1a5479243e901cf159e230fa0 observations   3298 before → 3298 after
ten_f1a5479243e901cf159e230fa0 kind=detection 3102 before → 3102 after
```
No update, no delete, no backfill, no reclassification, no corrected shadow
field. Every write was filtered on the new tenant and the script refuses to
run if the target equals the source.

### CLASSIFICATION_COUNTS

| SOURCE_PROVIDER | EVENT_ID | CANONICAL_KIND | CLASSIFICATION_BASIS | AUTHORITY | COUNT |
|---|---|---|---|---|---|
| Microsoft-Windows-Sysmon | 13 | `registry_value_set` | SOURCE_EVENT_ID:sysmon:13 | SOURCE_STATED_EVENT_ID | 2335 |
| Microsoft-Windows-Sysmon | 12 | `registry_create` | SOURCE_EVENT_ID:sysmon:12 | SOURCE_STATED_EVENT_ID | 766 |
| Microsoft-Windows-Sysmon | 11 | `file_create` | SOURCE_EVENT_ID:sysmon:11 | SOURCE_STATED_EVENT_ID | 107 |
| Microsoft-Windows-Sysmon | 3 | `network_connect` | SOURCE_EVENT_ID:sysmon:3 | SOURCE_STATED_EVENT_ID | 70 |
| Microsoft-Windows-Sysmon | 1 | `process_create` | SOURCE_EVENT_ID:sysmon:1 | SOURCE_STATED_EVENT_ID | 16 |
| Microsoft-Windows-Security-Auditing | 4672 | `special_privileges_assigned` | SOURCE_EVENT_ID:winsec:4672 | SOURCE_STATED_EVENT_ID | 2 |
| Microsoft-Windows-Security-Auditing | 4624 | `logon_success` | SOURCE_EVENT_ID:winsec:4624 | SOURCE_STATED_EVENT_ID | 2 |
| Microsoft-Windows-Sysmon | 22 | `dns_query` | SOURCE_EVENT_ID:sysmon:22 | SOURCE_STATED_EVENT_ID | 1 |
| | | | | **TOTAL** | **3299** |

**100 % of the corpus is classified from a SOURCE-STATED Event ID.** Zero
records were derived from populated fields, and zero were left unclassified.

Before → after on the same evidence: **3,102 `detection` → 0**.

### Acceptance ledger
```
Sysmon 12 -> registry_create                  PROVEN (766)
Sysmon 13 -> registry_value_set               PROVEN (2335)
4720 -> user_account_created                  PROVEN by contract + 17-case
4732 -> security_group_member_added           end-to-end test; NOT present
4738 -> user_account_changed                  in the G1 corpus (honest gap,
                                              not fabricated to fill a row)
UNCLASSIFIED_TO_DETECTION              = 0
UNKNOWN_TO_SECURITY_CLAIM              = 0
FALSE_COMPROMISE_FROM_CANONICAL_KIND   = 0   (no observation in the corpus
   carries a security-claim kind, so nothing can earn a compromise marker
   from its kind; `trajectory_window.compromise_authority` additionally
   still requires detection-fabric attribution or MITRE-attributed evidence)
```
The three account Event IDs are proven by contract and by the per-Event-ID
end-to-end test, NOT by the corpus: this Windows host never emitted 4720 /
4732 / 4738 during the G1 window. That is stated as a coverage gap rather
than filled.

---

## 3 · CONTRIBUTOR_CONTRACT_STATUS — DEFINED (server-side, not yet wired)

`backend/edr_plane/compromise_contract.py`. Enforces the four-way
separation: `event.kind` = observed · detection = engine conclusion ·
compromise = authoritative correlation/IOC conclusion · response state =
what response did.

Shape, as requested:
```
compromise_event_id      indicator_id            authority
derivation_basis         description             tactics[]
techniques[]             contributing_event_refs[]   evidence_refs[]
observed_at              contributors_state
```
`ContributingEventRef = {event_iid, contribution_basis, stated_by,
evidence_ref?}`.

Refusals at construction time:

* `authority` must be one of `DETECTION_FABRIC_ATTRIBUTION`,
  `MITRE_ATTRIBUTED_EVIDENCE`, `IOC_CORRELATION_ENGINE`. A telemetry kind,
  a UI, or an analyst assumption is not an authority.
* 19 `FORBIDDEN_BASES` rejected case-insensitively —
  `TEMPORAL_PROXIMITY`, `SAME_PID`, `SAME_PROCESS_NAME`, `SAME_LANE`,
  `UI_PROXIMITY`, `ADJACENT_IN_RENDER`, `INFERRED`, `GUESS`, …
* a contributor named by a DIFFERENT mechanism than the one that raised the
  compromise is refused (`CONTRIBUTOR_AUTHORITY_MISMATCH`).
* a raw dict cannot be smuggled in as a contributor — only validated
  `ContributingEventRef` instances are accepted.
* duplicates refused; empty description refused; MITRE ids validated
  (`Tnnnn[.nnn]`, `TAnnnn`) rather than accepted as prose.
* **missing provenance stays missing**: `contributors_state` is either
  `CONTRIBUTORS_PROVEN_BY_AUTHORITY` (non-empty, every member stated) or
  `CONTRIBUTORS_NOT_PROVEN_BY_AUTHORITY` (empty). Proven-and-empty and
  listed-and-disclaimed are both refused, so DT2-3c's contributor emphasis
  is disabled by data rather than by a client-side opinion.

Two real producers, and no others:

* `from_detection_derivation()` — only a `DETECTION_MATCHED` derivation.
  `DETECTION_EVALUATED_NO_MATCH` and `DETECTION_NOT_EVALUATED` are refused,
  so a detection GAP can become neither a compromise nor a clean claim.
  Contributors are exactly the subject observation plus the derivation's own
  `evidence_ids` — a derivation naming nothing extra proves exactly ONE
  contributor.
* `from_mitre_attributed_evidence()` — the observation's own technique
  attribution speaks for exactly one observation, so it can prove exactly
  one contributor. A wider set is not expressible.

NOT wired into any route yet, and no compromise has been persisted.

---

## TESTS

| Suite | Result |
|---|---|
| `tests/edr/test_winsec_semantics.py` (new) | **87 passed** |
| `tests/edr/test_compromise_contributor_contract.py` (new) | **68 passed** |
| `tests/edr/test_event_id_propagation.py` | 97 passed |
| `tests/test_w1_sysmon_field_preservation.py` + `test_d18_registry_evidence.py` | 55 passed |
| `tests/test_v2_framework.py` (EVENT_KINDS governance) | amended count green |
| whole `tests/edr` + d19 + registry-disambiguation | **1316 passed, 3 skipped, 7 failed** |

### SECURITY_REGRESSIONS — NONE
The same 7 failures as before this work, all PRE-EXISTING and unrelated
(`test_p0_f13_5_detection_handoff.py` ×5 and
`test_p0_a2_adversarial_live.py` ×1 reproduce at HEAD with the patch
stashed; `test_p0_f7_live_api.py` passes in isolation and is a live-DB xdist
flake). Zero new ruff findings in the touched files.

### EVIDENCE_INTEGRITY
* historical corpus byte-untouched (counts asserted before and after);
* acceptance corpus traceable to raw bytes: source evidence id + raw
  envelope ref + decoder id + DSM id + record id on every row;
* the acceptance corpus is explicitly `DETECTION_NOT_EVALUATED`.

**FINDING (reported, not redesigned):** `event.iid` is a CONTENT hash, so it
is NOT a unique observation identity — 2,250 of these 3,299 distinct Windows
records hash identically (same registry key, same image, same millisecond).
The first reprojection pass de-duplicated on it and silently dropped them;
the script now keys idempotency on the unique source evidence id, and the
corpus is complete at 3,299. The historical corpus has the same collision
property. Flagged for owner review — evidence identity is a separate
decision from this step.

---

## Ledger
```
CODE_CHANGED = YES
  backend/v2/ingestion/canonical.py            (WinSec semantics, basis,
                                                persisted source identity)
  backend/v2/ingestion/telemetry_bridge.py     (provider gate, record id,
                                                sid dialect, account ctx)
  backend/v2/cem/v1/schema.py                  (EVENT_KINDS 41 -> 50)
  backend/detection_content/telemetry/sysmon_dsm.py  (Provider +
                                                EventRecordID preserved)
  backend/edr_plane/trajectory_window.py       (_AUTH_KINDS)
  backend/edr_plane/trajectory/contract.py     (_AUTH_KINDS)
  backend/edr_plane/compromise_contract.py     (NEW)
  backend/tests/test_v2_framework.py           (governance count)
  backend/tests/edr/test_winsec_semantics.py            (NEW)
  backend/tests/edr/test_compromise_contributor_contract.py (NEW)
  scripts/g1_clean_reprojection.py             (NEW)

DATA_CHANGED = YES, ADDITIVE ONLY
  + 1 tenant registry row (g1-acceptance-clean)
  + 3299 observations in the NEW acceptance tenant
  0 rows of the historical corpus touched

DEPLOYED = NO
DT2_3C_STATUS = NOT STARTED (awaiting owner go-ahead)
CLASSIFICATION_AUDIT_VIEW = RECORDED AS A BACKLOG FEATURE, NOT BUILT
```

## Open items for the owner
1. **Sysmon proxy mappings** (outside the approved WinSec scope, pinned by a
   shrink-only test): Sysmon **255 → `alert`** is the one remaining
   security-claim kind produced from a known Event ID. Adjacent semantic
   proxies worth the same review: 2 (FileCreateTime → `file_write`), 4
   (Sysmon service state changed → `process_exit`), 9 (RawAccessRead →
   `file_write`), 14 (RegistryRename → `registry_delete`), 24
   (ClipboardChange → `file_write`), 25 (ProcessTampering →
   `process_access`).
2. **`event.iid` is not a unique observation identity** (finding above).
3. **Go-ahead for DT2-3c**, and whether to wire the contributor contract
   into `GET /api/edr/endpoints/{id}/trajectory` first.
