# NivXRay XDR · P0-1 · CASE / INCIDENT STORE RECONCILIATION

> **Mode:** STRICT READ-ONLY. No data deleted, migrated or modified. No code changed. `git status` after delivery shows Markdown artifacts only.
> **Authorised by owner** as the prerequisite artifact for the P0-1 Case Store Decision. Implementation is **NOT** authorised by this document.
> **Branch:** `feature/rc2-alignment` @ `869f7336`. **Date:** 2026-09-05.
> **Rule:** NO EVIDENCE → NO CLAIM. Every count below is a live `count_documents()` against the running Mongo instance.

---

# 0 · HEADLINE: A CORRECTION TO MY OWN AUDIT (read this first)

The master audit (§G, **DEV-3**) stated:

> *"Three parallel case stores. `workspace_cases` (484) is the analyst-facing legacy store; `xdr_incidents` (1) is the canonical pipeline output; `v2_cases` (35) is a third."*

**This is WRONG on the most important point and is hereby corrected.**

`xdr_incidents` is **not** the canonical pipeline output. The canonical pipeline writes incidents **into `workspace_cases`**:

```python
# backend/detection_content/xdr_incident.py:26
INCIDENT_COLLECTION   = "workspace_cases"
# backend/detection_content/xdr_incident.py:114
await db[INCIDENT_COLLECTION].insert_one(dict(doc))
```

And the codebase already **declares** `workspace_cases` authoritative, in three independent places written at different times:

| Declaration | Source |
|---|---|
| *"Creates a real record in the SSOT collection `workspace_cases` (**already the authoritative case store per `routers/incidents.py`**)"* | `detection_content/xdr_incident.py:5-7` |
| *"Canonical Incident API — projects `workspace_cases` into the … **`workspace_cases` remains the sole authoritative record**"* | `routers/incidents.py:1-7` |
| *"No RC5 collection appears here. **v2 storage is fully separate.**"* | `v2/case_engine/schema.py:8` |

**Therefore the P0-1 problem is not "which of three stores wins".** The authoritative store was already decided and is already implemented consistently. The real problem is different, and narrower:

> **`workspace_cases` is one collection carrying three mutually-exclusive document shapes**, and one of the shapes that downstream code reads (`verdict_stage2`) **exists on zero documents**.

This changes the P0-1 work from a *store migration* (high risk) to a *document-type discriminator + one dead-projection fix* (low risk). The corrected finding is restated as **DEV-3′** in §7.

---

# 1 · THE THREE COLLECTIONS — WHAT EACH ACTUALLY IS

| Collection | Live docs | What it actually is | Authoritative for | Declared separate? |
|---|---|---|---|---|
| **`workspace_cases`** | **484** | **The incident/case SSOT.** Written by the canonical XDR pipeline AND by the artifact-analysis path. Read by 48 non-test modules | **Incidents** (the XDR plane) | — it *is* the authority |
| **`xdr_incidents`** | **1** | **BYO-EDR vendor promotion store.** Cortex-XDR-only. One row per *vendor* incident promoted from third-party ingest | Vendor-side incident identity mirroring | Yes — separate ID namespace (`INC-CORTEX-…` / `xdr_incident_id`) |
| **`v2_cases`** | **35** | **v2 Case Engine parent rows.** Deliberately isolated storage per frozen ARCHITECTURE_v2 §5 | v2 artifact/analysis cases | **Yes, explicitly** (`v2/case_engine/schema.py:8`) |

**These are not three competitors. They are one authority, one vendor mirror, and one deliberately-isolated subsystem.**

---

# 2 · `workspace_cases` — DOCUMENT-SHAPE CENSUS (live, exact)

```
total                                              484
├─ has `xdr_pipeline`   (XDR pipeline incident)     198
├─ has `ssot`           (analysis/SSOT case)        209
├─ has BOTH                                           0   ← mutually exclusive
└─ has NEITHER                                       77
```

Cross-checks:

| Predicate | Docs |
|---|---|
`incident_state` present | **198** |
`incident_priority` present | **197** |
`id` matches `^inc_` | **199** |
`tenant_id` present | **199** |
`input` present (analyzer-case field) | **285** |
`user_email` present | **304** |
**`verdict_stage2` present** | **0** ⟵ **see §5** |

### Shape A — XDR pipeline incident (198 docs)

Written by `detection_content/xdr_incident.py:114`. Exact field set (`xdr_incident.py:74-113`):

```
id (inc_<20hex>) · tenant_id · created_at · updated_at
incident_state · incident_state_history[] · incident_priority · priority_label
verdict_card{verdict, confidence, reason, engine}
xdr_pipeline{engine_id, engine_version, trace_id, canonical_event_id, iue_id,
             detection_rule_id, ice_matches[], veee{}, source_provenance{}}
title
```

Live sample:
```json
{"id":"inc_5c3cc3a9e4354d039c47","tenant_id":"default","incident_state":"new",
 "incident_priority":"P3",
 "verdict_card":{"verdict":"suspicious","confidence":60,
   "reason":"verdict derived from detection(+45) + iue.severity_hint(+15)",
   "engine":"nivxray::xdr::veee"},
 "title":"Suspicious — sig 2027865 → 10.1.2.3"}
```
Full provenance chain is intact: `trace_id ← integration ← collector ← dsm ← parser ← normalizer ← canonical_event_id ← iue_id ← detection_rule_id ← ice_match_ids ← veee_engine_id` (`xdr_incident.py:14-17`).

### Shape B — Analysis / SSOT case (209 docs with `ssot`, 285 with `input`)

Observed field set on a live doc:
```
id · name · user_email · created_at · updated_at
input · input_len · output · output_len
engine · verdict · verdict_card · confidence · confidence_backfilled_at
iocs · lolbas · mitre · chain_ids · reached_shellcode · reinvestigated_at
ssot (209 docs)
```
This is the artifact-analysis case (decoder/analyzer lineage), **not** an XDR incident. It has `verdict` and `verdict_card` but **no** `incident_state`, **no** `xdr_pipeline`, **no** `tenant_id`.

### Shape C — 77 docs with neither `ssot` nor `xdr_pipeline`

Analysis cases predating the SSOT bundle (they hold `input`/`output`/`verdict` but no `ssot`). **Not incidents.** Classification confidence: MEDIUM — see U-1.

### Consequence

`GET /api/incidents` and every dashboard lens read `workspace_cases`. The incident-vs-analysis distinction is currently made **implicitly, by field presence**, per-reader, with no shared discriminator. `services/dashboard_lenses.py:21-32` documents the fields it honours (`incident_state`, `incident_assignee`, `incident_priority`, `incident_severity`, `high_fidelity`, `customer_engaged`, `on_hold_reason`, `on_hold_until`, `sla_due_at`) — all of which exist **only on Shape A**. So lenses de-facto filter to the 197-198 incidents. **The counts are honest; the schema contract is not explicit.**

---

# 3 · EXHAUSTIVE WRITER TRACE

## 3.1 · `workspace_cases` — WRITERS (complete, non-test)

| # | Writer | file:line | Operation | Shape | Notes |
|---|---|---|---|---|---|
| W1 | **XDR pipeline incident materialiser** | `detection_content/xdr_incident.py:114` | `insert_one` | **A** | The canonical incident creator. Gated: VEEE label ∈ {MALICIOUS, SUSPICIOUS} **and** score ≥ `INCIDENT_MIN_SCORE` (default **55**, `xdr_incident.py:27`). Refusal returns `created=False` + explicit `reason` + `honesty_note` |
| W2 | Closed-loop | `detection_content/xdr_closed_loop.py:362` | `update_one` | A | closure/loop state |
| W3 | Verdict Stage-2 | `routers/verdict_stage2.py:114`, `:181` | `update_one` | B | **would write `verdict_stage2`; 0 docs currently carry it** — see §5 |
| W4 | Telemetry router | `routers/telemetry.py:68` | `update_one` | A/B | telemetry attach |
| W5 | Golden-case seeder | `tools/seed_golden_case.py:95` | `insert_one` | B | tooling |
| W6 | Narrative backfill script | `scripts/backfill_narrative_enrichment.py:220` | `update_one` | B | one-off script |
| W7 | Server startup guard | `server.py:742` | conditional insert | B | *"only inserts when `workspace_cases` lacks the frozen case id"* — idempotent Sample1 guard |
| W8 | Incident lifecycle API | `routers/incidents.py:871`, `:894`, `:953` | `update_one` | A | state / assignee / field updates |
| W9 | Queue bulk ops | `routers/xdr_queue_ops.py` → `/api/xdr/incidents/bulk/{assign,state}` | `update_one` | A | bulk assign / state |

**Writer count: 9 paths. Exactly ONE creates XDR incidents (W1).** No competing incident creator exists.

## 3.2 · `xdr_incidents` — WRITERS (complete)

| # | Writer | file:line | Operation |
|---|---|---|---|
| W10 | Cortex promotion | `detection_content/xdr_cortex_promotion.py:164` | `insert_one` |
| W11 | Cortex promotion (merge into existing) | `detection_content/xdr_cortex_promotion.py:178` | `update_one` |
| W12 | Cortex actions router | `routers/xdr_cortex_actions.py:187` | `update_one` |

**Only the Cortex/BYO-EDR path writes here.** `xdr_cortex_promotion.py:28-30` states: *"`xdr_incidents` — one row per promoted incident; `xdr_incident_promotion_audit` — append-only decision trail."*

## 3.3 · `v2_cases` — WRITERS (complete)

| # | Writer | file:line | Operation |
|---|---|---|---|
| W13 | v2 cases router | `v2/routers/cases.py:95` | `insert_one` |
| W14 | v2 cases router (soft delete) | `v2/routers/cases.py:122` | `update_one` → `status: "deleted"` |
| W15 | v2 seed | `v2/seed/__init__.py:78`, `:105` | `update_one … upsert=True` |
| W16 | v2 ingest `_upsert_case` | `v2/routers/ingest.py:75` (called `:136`) | `update_one … upsert=True` |

Guard evidence: `security_state/tests/phase5_shadow_tests.py:399` asserts `not f.startswith("v2_cases")` — i.e. an existing test **forbids** Security State from writing authoritative `v2_cases`. The isolation is actively defended.

---

# 4 · EXHAUSTIVE READER TRACE

## 4.1 · `workspace_cases` — 48 non-test modules, 107 distinct reference sites

**Engines (13)** — `detection_content/`: `xdr_incident.py`, `xdr_investigation.py:314`, `xdr_closed_loop.py:262`, `xdr_closure_classification.py:169`, `xdr_response_decision.py:54`, `xdr_response_fabric.py:68`, `xdr_threat_family.py:144`, `xdr_attack_chain_graph.py:233`, `xdr_framework_mapping.py:360`, `xdr_evidence_traversal.py:101,143,267`, `xdr_executive_summary.py:318`

**Routers (18)** — `incidents.py:29` (`_col = sync_collection("workspace_cases")`), `xdr_dashboard.py`, `xdr_mss.py`, `xdr_queue_ops.py`, `edr.py:26`, `incident_summary.py`, `incident_threat_model.py`, `attack_graph.py`, `attack_story.py`, `narration.py`, `cases.py`, `die.py`, `documents.py`, `mitre_catalogue.py`, `autonomous_investigator.py`, `content_supply_chain.py`, `telemetry.py`, `verdict_stage2.py`

**Services (12)** — `services/`: `iue/service.py:50` (`INCIDENTS_COLLECTION`), `iue/artifacts.py:155`, `investigator/orchestrator.py:44`, `investigator/capabilities/historical.py:6`, `investigator/capabilities/network_identity_file.py:64,162,342,437` (cross-incident IOC pivots on `iocs.ip`, `iocs.domain`, `iocs.hash`, `iocs.user`), `attack_story/service.py:32`, `attack_graph/service.py:43`, `attack_evidence/service.py:152`, `threat_model/service.py:40`, `report/service.py:463`, `evidence_inspector/service.py:95`, `dashboard_lenses.py:21`, `ssot_store.py:12-15`

**Infrastructure (5)** — `deps.py:226`, `server.py:742`, `privacy.py`, `canonical/ssot/store.py:9` (*"read from and not written to. `workspace_cases.ssot` is not touched"*), `tools/sample1_sanity_check.py`

**Reader count: 48 modules.** This is the single largest coupling surface in the backend and the strongest argument **against** migrating away from `workspace_cases`.

## 4.2 · `xdr_incidents` — READERS

`detection_content/xdr_cortex_promotion.py:136` (dedup lookup), `routers/xdr_cortex_actions.py:55`. **2 modules. No dashboard, no incident API, no investigation engine reads it.**

## 4.3 · `v2_cases` — READERS

`v2/routers/cases.py` (16 `/api/v2/cases/{case_id}/*` paths), `v2/routers/ingest.py`, `v2/routers/ingestion.py`, `v2/seed/`. **Confined to the `v2/` package**, exactly as `v2/case_engine/schema.py:8` requires.

---

# 5 · NEW P1 FINDING · `verdict_stage2` IS READ BUT NEVER WRITTEN

| Fact | Evidence |
|---|---|
`verdict_stage2` present on | **0 of 484** `workspace_cases` docs (live `count_documents`) |
`/api/edr/detections` derives from it | `routers/edr.py:3-8` — *"Detections is a READ-ONLY projection derived from `workspace_cases.verdict_stage2.evidence[]`"* |
Test asserts that provenance string | `tests/canonical/incidents/test_incident_summary.py:46` → `assert row["provenance"] == "workspace_cases.verdict_stage2.evidence[]"` |
Also asserted | `tests/canonical/edr/test_edr_projections.py:71`, `tests/canonical/ssot/test_ssot_isolation.py:399` |
Writers that would populate it | `routers/verdict_stage2.py:114`, `:181` |

**Conclusion:** `/api/edr/detections` and the `verdict_stage2`-sourced part of `/api/incidents/{id}/summary` are **structurally always empty** in the current database. The projection code is correct; the source field has no data. This is honest-empty, not fabricated — but it means the EDR "detections" surface audited in CAT-13 is emptier than that report implied.

**Severity: P1.** **Not authorised for fix here** — recorded for the owner's decision. The likely resolution is that the pipeline-created Shape-A incident writes `verdict_card` (`xdr_incident.py:88-93`, *"Additive verdict record (compatible with verdict_stage2 shape)"*) but **never** `verdict_stage2`, so pipeline incidents are invisible to every `verdict_stage2` reader.

---

# 6 · INCIDENT-IDENTITY MAP

| Namespace | Format | Owner | Live docs | Cross-links |
|---|---|---|---|---|
`workspace_cases.id` (incident) | `inc_<20 hex>` | `xdr_incident.py:69` | 199 | → `xdr_pipeline.canonical_event_id` → `xdr_canonical_evidence.event_id`; → `xdr_pipeline.iue_id` → `xdr_iue_understanding`; → `xdr_pipeline.ice_matches[]` → `xdr_correlation_matches.match_id`; → `xdr_pipeline.trace_id` |
`workspace_cases.id` (analysis case) | UUID4 / seeded slug | analyzer path | ~285 | → `chain_ids`, `iocs`, `lolbas`, `mitre` |
`xdr_incidents.nivx_incident_id` | `INC-CORTEX-<12 hex>` | `xdr_cortex_promotion.py` | 1 | → `evidence_event_ids[]` → `xdr_canonical_evidence` (`cev-cortex-…`); → `source_integration_id` |
`xdr_incidents.xdr_incident_id` | vendor-native (e.g. `INC-777`) | Cortex XDR | 1 | vendor mirror |
`v2_cases._id` | `case_<slug>` (e.g. `case_dfir_bumblebee_akira_2026`) | v2 case engine | 35 | → `v2_case_events` (empty), `v2_artifact_store` (15) |

**Critical gap in the identity map:** there is **no link field** between `xdr_incidents.nivx_incident_id` and any `workspace_cases.id`. A Cortex-promoted vendor incident and a NivXRay pipeline incident describing the same activity **cannot currently be joined**. Both reference `xdr_canonical_evidence` event IDs, so the join is *derivable* through canonical evidence — but it is not materialised anywhere.

---

# 7 · CORRECTED DEVIATION · DEV-3′

> **DEV-3′ (replaces DEV-3).** `workspace_cases` is the correctly-and-consistently-implemented incident SSOT. The defect is that it stores **three mutually-exclusive document shapes (198 / 209 / 77) with no explicit type discriminator**, and that a field read by three downstream projections (`verdict_stage2`) is written by **zero** live documents. `xdr_incidents` and `v2_cases` are **not** competitors — they are a vendor mirror and a deliberately-isolated subsystem, both correctly scoped.
> **Severity: P1** (downgraded from P0 — no ambiguity of authority exists).
> **Residual P0:** none in this category. The P0-1 gate can be closed by **decision + documentation**, not by migration.

---

# 8 · EVIDENCE-BACKED RECOMMENDATION (owner retains the decision)

## Recommendation: **Option 1 — Ratify `workspace_cases` as authoritative. Add a discriminator. Migrate nothing.**

| | Option 1 · Ratify `workspace_cases` (**RECOMMENDED**) | Option 2 · Migrate incidents to `xdr_incidents` | Option 3 · Migrate to `v2_cases` |
|---|---|---|---|
| Code churn | **Near zero.** Add an explicit `doc_type` discriminator; document the contract | **48 reader modules** must be rewritten | 48 readers + breaks the `v2` isolation contract |
| Data migration | **None** | 199 incidents + re-key 285 analysis cases | 199 incidents + 285 analysis cases |
| Contradicts existing code declarations | **No** — it ratifies what 3 source files already declare | **Yes** — contradicts `xdr_incident.py:5-7`, `incidents.py:1-7` | **Yes** — violates `v2/case_engine/schema.py:8` and the `phase5_shadow_tests.py:399` guard |
| Breaks provenance chain | No | High risk: `xdr_pipeline` envelope must be re-homed | High risk |
| Breaks dashboard honesty invariant | No | Yes — all 10 lenses in `dashboard_lenses.py` are keyed to `workspace_cases` fields | Yes |
| Effort | **XS** | **XL** | **XL** |
| Risk | **LOW** | **HIGH** | **HIGH** |

### Why Option 1 is the evidence-led answer

1. **Authority is already unambiguous in code**, declared independently in `xdr_incident.py`, `routers/incidents.py` and `v2/case_engine/schema.py`. Choosing anything else would mean overruling three consistent existing declarations with zero evidence that they are wrong.
2. **Exactly one writer creates XDR incidents** (`xdr_incident.py:114`), and it is gated and provenance-complete. There is no write-race to resolve.
3. **48 reader modules** already treat it as the SSOT. Migration cost is concentrated entirely on the readers, and buys nothing.
4. `xdr_incidents` has **2 readers and 1 doc** and a *separate ID namespace by design* — it is a vendor mirror, and mirrors are supposed to be separate.
5. `v2_cases` isolation is **actively defended by a test**. Breaking it would break a guard someone deliberately installed.

### What Option 1 actually requires (scoping only — NOT authorised)

| Step | Change | Risk |
|---|---|---|
| 1 | Add an explicit `doc_type` field (`xdr_incident` / `analysis_case`) written by new documents; derive it for existing docs at read time from `xdr_pipeline`/`ssot`/`input` presence. **No backfill required for correctness** | LOW |
| 2 | Publish the discriminator contract in `docs/` so all 48 readers share one rule instead of 48 implicit ones | NONE |
| 3 | Decide the `verdict_stage2` question (§5): either have the pipeline write `verdict_stage2` alongside `verdict_card`, or re-point `routers/edr.py` at `verdict_card`. **One or the other — not both** | LOW |
| 4 | Materialise the missing `xdr_incidents ↔ workspace_cases` link (§6) via shared `canonical_event_id`, so vendor and native incidents are joinable | LOW |
| 5 | Classify the 77 Shape-C documents (U-1) before any future retention policy is applied to them | NONE (read-only) |

**Explicitly NOT recommended:** deleting the 285 analysis cases, deleting the 77 Shape-C docs, or collapsing analysis cases into incidents. They are legitimate records of a different type in a shared collection — a **naming/contract** problem, not a data problem.

---

# 9 · UNKNOWN

| # | Unknown | Why unresolvable read-only |
|---|---|---|
| U-1 | ~~Exact nature of the **77** docs with neither `ssot` nor `xdr_pipeline`~~ **RESOLVED 2026-09-05** by key-signature analysis of all 77: **76 carry `input`+`output`+`engine`+`verdict` → deterministically `analysis_case` (rule R3)**; **1** (`inc_r381_empty`, keys `id, mitre, tenant_id, title, user_email`) has no discriminating field → `unclassified`, classification withheld. See `NIVXRAY_XDR_P0_1_P0_2_DELIVERY_EVIDENCE.md` §A.3 | **CLOSED** |
| U-2 | Whether the 285 analysis cases are production records or accumulated test/demo data | Not determinable from schema |
| U-3 | ~~Why 199 docs match `^inc_` but only 198 carry `xdr_pipeline`~~ **RESOLVED 2026-09-05**: the extra document is **`inc_r381_empty`**, a test fixture occupying the `inc_` namespace with no `xdr_pipeline`, no `ssot` and no `input`. It is the single `unclassified` document and was deliberately left un-backfilled | **CLOSED** |
| U-4 | Whether `routers/verdict_stage2.py` has ever executed successfully in this environment | `verdict_stage2` on 0 docs suggests no, but a wipe cannot be ruled out |
| U-5 | Whether the single `xdr_incidents` row is a live promotion or an end-to-end test artifact. `description: "end-to-end"`, `host: legion5`, `user: codex` strongly suggest a **test** — not asserted as fact | — |

---

# 10 · AUDIT INTEGRITY

Read-only confirmed: `git status` after delivery lists Markdown artifacts only. No Mongo write, no index creation, no code edit, no config change. `mal-20` untouched. Truth Contract unamended. No implementation performed or authorised by this document.

## END · P0-1 Case Store Reconciliation · awaiting owner decision on §8
