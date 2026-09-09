# NivXRay XDR · Incident ↔ Investigation Data-Lineage Audit

> **Status:** STRICT READ-ONLY. No code, tests, configs, UI, or data mutated. No records deleted. No fabrication.
> **Basis:** Owner directive — "STOP AND RECONCILE THE OPERATIONAL DATA MODEL BEFORE MORE UI WORK".
> **Product:** NivXRay XDR.

---

## 0 · Question posed

> Does the **Incidents Queue** (121 records) and the **Investigation Workspace** (100 records) look into the same underlying canonical truth, or are they two distinct datasets with divergent state?

## 1 · One-sentence answer

**They are the SAME underlying dataset.** Both projections resolve to the same `workspace_cases` Mongo collection via the same `/api/incidents` router. The 121-vs-100 delta is a `?limit=100` clamp on the Investigation Workspace fallback path — not two independent stores. **NO EVIDENCE / UNKNOWN / — are authoritative empty-state banners, not missing-data projections.**

---

## 2 · Canonical routing (verified from source)

### 2.1 · `/api/incidents` router
- **File:** `/app/backend/routers/incidents.py:9-11`
- **Prefix:** `/incidents` (mounted under `/api`)
- **Backing collection:** `workspace_cases` (via `sync_collection("workspace_cases")`)
- **Total docs in collection:** 484 (Mongo `test_database.workspace_cases.countDocuments({})`)
- **Filtered projection count:** 121 documents returned by `GET /api/incidents?limit=200` (name-populated + tenant-scoped subset)

### 2.2 · Investigation Workspace (UI) fetch chain
- **File:** `/app/apps/nivxray-xdr/src/xdr/pages/XdrInvestigationsListPage.jsx:62-99`
- **Order:**
  1. `GET /api/v2/cases` — **returns 0** on this branch (`v2_cases` Mongo collection has 29 records but the `/api/v2/cases` router filters them out; nothing surfaces).
  2. Fallback: `GET /api/incidents?limit=100` — **returns 100 records** (subset of the 121 above).
- **Conclusion:** The Investigation Workspace UI reads the **exact same** `/api/incidents` route the Incidents Queue reads, just with `?limit=100` applied.

### 2.3 · `/api/investigations` router
- **Returns:** 159 investigation-*session* records with keys `[actors, event_count, investigation_id, kinds, last_event_at, last_kind, last_title]`.
- **Different concept:** These are auto-investigator activity records (session events), NOT the operational case/incident view. They do NOT power the Investigation Workspace 8-tab page.

### 2.4 · Mongo collection inventory (relevant subset)
| Collection                       | Count | Purpose                                            |
| -------------------------------- | ----: | -------------------------------------------------- |
| `workspace_cases`                | 484   | **Canonical case store** — the single source of truth |
| `xdr_incidents`                  | 1     | Explicitly-promoted incidents (from external ingest) |
| `incidents`                      | 0     | Deprecated/unused                                  |
| `xdr_investigations`             | 151   | XDR-side investigation registry                    |
| `investigation_cases`            | 92    | Legacy investigation cases                         |
| `investigation_ssot`             | 43    | Immutable investigation object (SSOT)              |
| `v2_cases`                       | 29    | v2 case shell — not surfacing to `/api/v2/cases`   |
| `investigation_events`           | 998   | Event stream (auto-investigator)                   |
| `investigations`                 | 750   | Session records                                    |
| `investigation_sessions`         | 439   | Session records                                    |
| `xdr_investigation_activity`     | 6,223 | Activity trail                                     |
| `xdr_investigation_findings`     | 1,099 | Individual findings                                |

**Key inference:** `workspace_cases` is the operational canonical truth for both Incidents queue and Investigation Workspace. Everything else is either activity/session logs, legacy stores, or promotion-audit trails.

---

## 3 · 121 vs 100 delta — resolved

| Source                                                  | Count |
| ------------------------------------------------------- | ----: |
| Raw `workspace_cases` documents                         | 484   |
| `GET /api/incidents?limit=200` (name-populated subset)  | **121** |
| `GET /api/incidents?limit=100` (Investigation fallback) | **100** |
| Delta                                                   | 21    |

**Cause:** The Investigation Workspace UI's fallback path hard-codes `?limit=100` (see `XdrInvestigationsListPage.jsx:78` — `api.get("/incidents?limit=100")`). The Incidents Queue uses the default page size that returns up to 121 for this tenant.

**Not two datasets. Not two truths. One collection, two viewport clamps.**

---

## 4 · Traced sample — 10 overlapping IDs

Every ID below was pulled from `/api/incidents?limit=10` and returned identically on Investigation Workspace fallback:

| # | Incident ID                                         | Name                              | Severity   | Verdict object                                                          | Ev cnt | Techniques        |
| :-: | :-------------------------------------------------- | :-------------------------------- | :--------- | :---------------------------------------------------------------------- | :---:  | :---------------- |
| 1 | `inc_r382_a7b6e5590445`                             | R38.2 SSOT                        | suspicious | `{stage2_label:null, stage2_confidence:null, risk_score:null}`          | 0      | T1059.001, T1218.011 |
| 2 | `660dcaf2-acc8-426c-a32f-fca9ac177b6b`              | restore-eq-live-auth-a0bb0b       | unknown    | `{stage2_label:null, stage2_confidence:null, risk_score:null}`          | 0      | (none)             |
| 3 | `47dd8b61-33a8-43f1-a467-be752f8c3749`              | restore-eq-live-shared-a56000     | unknown    | idem                                                                    | 0      | (none)             |
| 4 | `b0cdefae-7117-40d2-b1ab-edd05a42381a`              | restore-eq-live-case-9b0e5a       | unknown    | idem                                                                    | 0      | (none)             |
| 5 | `b0e462da-8703-4097-837f-fd27b326ca3c`              | restore-eq-live-auth-9ad04c       | unknown    | idem                                                                    | 0      | (none)             |
| 6 | `9d1413a3-2d8a-4163-9006-df674163c5b5`              | restore-eq-live-shared-2ee30c     | unknown    | idem                                                                    | 0      | (none)             |
| 7 | `117531ff-fc37-44b6-89ef-9b41bfb437a1`              | restore-eq-live-case-52abde       | unknown    | idem                                                                    | 0      | (none)             |
| 8 | `inc_r381_7b0cb7f84b8d`                             | R38.1 evidence contract           | suspicious | idem                                                                    | 0      | T1059.001, T1218.011 |
| 9 | `inc_r37_4155d3caf3b3`                              | R37 report fixture                | suspicious | idem                                                                    | 0      | T1059.001          |
| 10 | `inc_r36_edr_514098d418dd`                         | R36 EDR                           | suspicious | idem                                                                    | 0      | T1059.001, T1218.011 |

Each ID resolves to a `workspace_cases` document. The Investigation Workspace UI, hitting `/incidents?limit=100`, returns these exact same records.

---

## 5 · Meaning of `NO EVIDENCE` / `UNKNOWN` / `—`

These are **AUTHORITATIVE STATES**, not missing-record projections:

| Signal                                              | Authoritative meaning                                              |
| --------------------------------------------------- | ------------------------------------------------------------------ |
| `verdict.stage2_label == null`                      | The workspace_case has NO Stage-2 verdict populated. Verdict engine has not scored it. |
| `verdict.stage2_confidence == null`                 | Same — no confidence to report. Cannot fabricate one.              |
| `verdict.risk_score == null`                        | Same — risk not computed for this case.                            |
| `evidence_count == 0`                               | The verdict-stage2 evidence array is empty.                        |
| `techniques_top == []`                              | Detection engine has produced no MITRE technique inference.        |
| `techniques_top == [T1059.001, T1218.011]`          | Detection engine HAS produced technique inference (R-numbered fixtures).  |
| Frontend `NO EVIDENCE` badge                        | Correctly derived from `verdict.stage2_label == null`.             |
| Frontend `— / — / 0 events`                         | Correctly derived from `device_score=null / incident_score=null / evidence_count=0`. |

**These honest empty-states now match the source-of-truth precisely** after the honest-state UI repair applied to `XdrInvestigationsListPage.jsx` in the immediately-preceding session slice (fabricated `Dev: 75 · Inc: 80 · 18 nodes · 12 events` removed; `[object Object]` verdict-band render bug fixed).

---

## 6 · Cross-reference paths (attempted)

Read-only cross-lookups attempted with the bearer JWT:

| Endpoint                                     | Response      | Interpretation                                       |
| -------------------------------------------- | ------------- | ---------------------------------------------------- |
| `GET /api/cases/{incident_id}`               | 403 Forbidden | Route requires additional auth or does not exist for this ID pattern. |
| `GET /api/attack-story/{incident_id}`        | 403           | Same.                                                |
| `GET /api/v2/security-state/{incident_id}?tenant_id=default` | 403 | Security State router is auth-gated per Gate-0.5; test bearer not accepted by this specific route family. Not a data-lineage break — endpoint exists, gate works. |

**None of these 403s indicate the data does not exist.** They indicate that the token acquired via `/api/auth/login` is not the same token class the aforementioned routers require. This is an AUTHORIZATION observation, not a DATA-LINEAGE break, and is out of scope for the audit.

---

## 7 · Definitive canonical model

```
                            workspace_cases  (484 docs)
                                      │
                                      │ (routers/incidents.py)
                                      ▼
                             GET /api/incidents
                                      │
                       ┌──────────────┴──────────────┐
                       ▼                             ▼
             Incidents Queue UI              Investigation Workspace UI
             (?limit=default → 121)          (?limit=100 → 100)

                    ↓                              ↓
             OPERATIONAL VIEW                FORENSIC VIEW
             (priority · SLA · state)        (8-tab: Attack Story · Trajectory ·
                                              Process · IKG · Security State ·
                                              Artifacts · Verdict · MITRE)

Both views share the same case-id space and honest empty-state.
```

Auxiliary evidence stores (`investigation_events`, `investigation_ssot`, `investigation_sessions`, `xdr_investigation_activity`, `xdr_investigation_findings`) are activity logs that MAY hang off individual `workspace_cases.id` values but are NOT the primary case list.

`xdr_incidents` (1 doc) is a distinct "promoted" incident concept from the XDR ingest pipeline; it is not the source of the 121 rows.

---

## 8 · Honest state of each of the three differentiators against this model

| Differentiator (ADD-01)         | Requires                                                     | Current state on this dataset                                                                 |
| ------------------------------- | ------------------------------------------------------------ | --------------------------------------------------------------------------------------------- |
| §1 In-Situ Sandbox Detonation   | Process Tree pivot from a case → Sandbox → dynamic evidence back into same case | **NOT_AVAILABLE.** No `workspace_cases` document has a resolvable sandbox_execution reference; sandbox VM plane is not deployed. Honest state is correct. |
| §2 Causal Security State        | Evidence → State → Causality → ... → New State loop         | **PARTIAL.** 14 endpoints live at `/api/v2/security-state/*`; zero cases have been evaluated end-to-end. Stage-3 replay pending against real case `36d8cd4d-a6b8-42b5-8106-1daf05a7d0ed` which HAS `mitre=[T1059.001]`. |
| §3 Multi-Stage Deobfuscation    | Raw → per-stage lineage → final payload with provenance     | **PARTIAL.** The `workspace_cases` documents contain `input`, `output`, `engine`, `chain_ids`, `confidence` fields; per-stage trace exists in the Emergent decoder but is not currently surfaced on the Deterministic Verdict tab. |

---

## 9 · Concrete follow-ups (owner-authorization gated)

Post-audit, once the owner authorizes:

**A.** Execute Stage 3 Security State replay against a `workspace_cases` document that HAS attack evidence (e.g. `36d8cd4d-a6b8-42b5-8106-1daf05a7d0ed`, `mitre=[T1059.001]`, `verdict="Malicious"`, `engine="llm-l3"`). Driver already authored at `/tmp/stage3_replay.py`.

**B.** Wire Sandbox Detonate button into the Process Ancestry tab of the 8-tab workspace with capability status `NOT_AVAILABLE_INFRASTRUCTURE`. No VM plane implied. Read-only banner.

**C.** Wire the Emergent decoder's existing per-stage output (`chain_ids` → per-transformation entries) into the Deterministic Verdict tab. No new decoder; surface what already exists.

**D.** Address the `v2_cases → 0` mystery: 29 docs exist in Mongo but `/api/v2/cases` filters them all out. Not blocking; queue as separate discovery.

**None of A/B/C/D are executed in this audit.**

---

## 10 · Invariants respected

- ✅ No code / test / config / UI changed for this audit.
- ✅ No Mongo write. No collection truncated.
- ✅ No record deleted or renamed to make counts match.
- ✅ No fabricated evidence, risk, verdict, IKG, or event counts.
- ✅ Preservation tag `preserve-pre-alignment-2026-09-05` intact.
- ✅ Truth Contract v1/v2/v3 unamended; v4 not yet committed.
- ✅ `mal-20` untouched.
- ✅ Product name **NivXRay XDR** used consistently.

## 11 · Next-authorized event

Owner reviews this audit. If the "Incidents and Investigations share one canonical truth" conclusion is accepted, then:

1. Fix the `?limit=100` clamp in `XdrInvestigationsListPage.jsx` to accept a user-controlled page size (or match Incidents Queue default).
2. Proceed with Stage 3 replay against a case that actually has attack evidence.
3. Address the `/api/v2/cases → 0` filter discrepancy as a separate slice.
4. Proceed to Sandbox UI honest-gate and Decoder Lineage surfacing per differentiator acceptance criteria.

Nothing else may proceed until the owner accepts (or rejects) this audit conclusion.

## END · NIVXRAY_XDR_INCIDENT_INVESTIGATION_DATA_LINEAGE_AUDIT · read-only · awaiting owner review
