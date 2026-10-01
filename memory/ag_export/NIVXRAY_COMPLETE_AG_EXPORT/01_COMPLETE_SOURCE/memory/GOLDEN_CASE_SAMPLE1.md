# GOLDEN DIAGNOSTIC CASE — CANONICAL INVESTIGATION CONVERGENCE

**Case name**: `Sample1`
**Purpose**: Objective acceptance test for the canonical investigation architecture. This case is preserved untouched as the architectural canary. Any future implementation of ADR-005 D1–D10 MUST cause the same input to flow through the canonical investigation lifecycle and produce evidence-backed downstream projections, replacing every empty/generic field recorded below.

**Status**: FROZEN — READ-ONLY. Do not modify, delete, re-investigate, or overwrite this case. Do not attach shadow observations to it. Do not migrate it. Do not archive it.

**Companion documents**:
- `/app/memory/IUE_ARCHITECTURE_TRACE.md`
- `/app/memory/IUE_INVESTIGATION_SSOT_RECONCILIATION.md`
- `/app/memory/adr/0005-canonical-investigation-architecture.md`
- `/app/memory/adr/0005-owner-decision-matrix.md`
- `/app/memory/GOLDEN_CASE_SAMPLE1.snapshot.json` (raw MongoDB document snapshot, 79 903 bytes)

---

## 1. Identity

| Field | Value |
|---|---|
| Case ID | `3db79c4a-088b-4df7-b65a-f68b367b7677` |
| Case name | `Sample1` |
| Owner (user_email) | `admin@nivxray.com` |
| Created at | `2026-08-10T04:57:27.520418+00:00` (UTC) |
| Updated at | `2026-08-10T04:57:27.520418+00:00` (UTC) |
| Reinvestigated at | `2026-08-10T04:57:27.520418+00:00` (UTC) |
| Persisted engine label | `engine = "convergence"` |
| Storage collection | `workspace_cases` (Mongo) |
| SSOT shape (persisted) | die-Canonical (see §5) |
| SSOT schema version | `1.0` |
| Determinism fingerprint (sha256 of persisted doc, `_id` excluded) | `5b4337d5a9fc05923bd3090f1270268ae8eef7af2ccf06f4e8d8492bf908261d` |
| Snapshot file | `/app/memory/GOLDEN_CASE_SAMPLE1.snapshot.json` |

---

## 2. Workspace entry point and actual route taken

| Layer | Path taken by Sample1 today |
|---|---|
| UI action | Analyst uploaded `Sample.docx` (40 786 bytes ZIP archive), Workspace paste field received a synthesised binary-file marker (`[BINARY FILE — Sample.docx] Size: 40786 bytes …`), then clicked **Save Case** |
| Frontend endpoint | `POST /api/cases/save` |
| Router | `backend/routers/cases.py::save_case` |
| Actual pipeline invoked | `backend/routers/ops.py::decode_smart` (the `/api/decode/smart` handler) |
| IUE call sites hit | IUE-1 (`nivxforge.investigation.input_understanding.understand`) — **post-hoc metadata stamp only** on `cio.metadata.input_understanding`. `route` field emitted but not consumed. |
| MDR pipeline invoked | **NO** — `v2/jobs/pipeline.py::run_investigation_with_progress` was never called |
| Wave 1 shadow attached | **NO** — no `verdict_shadow` record produced (see §7) |
| Bytes-native handling | **NO** — DOCX bytes were substituted with a synthesised text descriptor before ingestion |
| Vendor/binary classifier | **NOT ON PATH** — IUE-4 (`services/uil/classifier.py`) not invoked |
| Multi-artefact detector | **NOT ON PATH** — IUE-3 (`v2/investigation/iu/engine.py`) not invoked |
| Artefact decomposition | Partial — via IDA (`ssot.investigation_object.ida` = dict[4], `artifacts` = list[3]); did not enter recursion |

**Route classification** (per `IUE_ARCHITECTURE_TRACE.md` §5.1): **`IUE-stamp only` + `bypasses MDR`**.

---

## 3. Persisted case — actual state of investigation surfaces

Empty/absent fields the analyst is missing on the Workspace view:

| Investigation surface | Persisted value | Consumer expected |
|---|---|---|
| IOCs — URLs | `[]` | Non-empty when text contains URLs |
| IOCs — IPs | `[]` | Non-empty when text contains IPv4/IPv6 |
| IOCs — Domains | `[]` | Non-empty when text contains hostnames |
| IOCs — Emails | `[]` | Non-empty when text contains addresses |
| IOCs — MD5 | 2 entries (`7d2b361f20c7042d71636fee1118beb9`, `9beb8111eef63617d2407c02f163b2d7`) | These are ZIP-member digests of `Sample.docx`, NOT investigation-derived IOCs |
| IOCs — SHA1 | 2 entries (`961d0f8f064d0a7ecac08da4f80a5ad75af64805`, `50846fa57da5a08f4ad80cace7a0d460f8f0d169`) | Same as above — archive metadata, not evidence |
| IOCs — SHA256 | 2 entries (`3915b712…`, `7a326847…`) | Same as above |
| IOCs — Bitcoin addresses | `[]` | — |
| MITRE ATT&CK mapping | `[]` (top-level AND inside `ssot.investigation_object.mitre` AND inside `investigation_summary.mitre_techniques`) | Techniques with per-technique evidence pointers |
| LOLBAS | `[]` (top-level AND inside `ssot.investigation_object.lolbas`) | Detected LOLBAS binaries with evidence |
| Attack Chain (`chain_ids`) | `[None, None, None]` — three empty stage slots | Ordered stages with per-stage evidence and MITRE mapping |
| Attack Story | Absent (`investigation_summary.attack_story = []`) | Structured narrative sections with evidence pointers |
| Observed behaviours | `[]` | Non-empty when process/file/network events are extracted |
| Inferred objectives | `[]` | Intent-derived attacker goals |
| Kill chain lanes | `{}` (empty) | Populated lanes across MITRE tactics |
| Recommendations (evidence-backed) | Not present in SSOT | Per-technique remediations tied to detected evidence |

Recommendations that ARE shown to the analyst (screenshotted by the owner):
```
IMMEDIATE
  • Isolate the affected host from the network
  • Preserve volatile memory (collect memory image)
  • Preserve event logs and endpoint telemetry
THREAT HUNTING
  • Baseline unusual parent-child process trees on impacted hosts
CONTAINMENT
  • Disable involved user accounts and rotate credentials
  • Review lateral movement paths from the affected host
  • Monitor DNS beaconing over the following 72 hours
  • Review recently-created scheduled tasks and services
```

Provenance of the above block: **static generic fallback template** emitted by `services/die/analyst_narrative.py` when the underlying investigation has no MITRE / no LOLBAS / no evidence-graph to derive from. The generator has no evidence to specialise against, so it returns the same list for every case where the deeper pipeline never ran.

---

## 4. Fields MISSING from the persisted case (that MDR would have produced)

```
ssot.investigation_model      → MISSING
ssot.investigation_narrative  → MISSING
ssot.investigation_report     → MISSING
ssot.mdr_investigation        → MISSING
ssot.executive_card           → MISSING
ssot.attack_story             → MISSING
ssot.ikg / evidence_graph     → MISSING
ssot.verdict_shadow           → MISSING   ← case did NOT enter Wave 1
ssot.recommendations          → MISSING   ← evidence-driven recs never generated
ssot.mitigation(s)            → MISSING
```

Consequence: the Workspace UI has no source of MITRE data, no source of an evidence-driven attack chain, no source of executive-card text, no source of evidence-driven recommendations, and no source of an analyst narrative other than the generic template. This is architectural, not a UI bug.

---

## 5. What IS present in the persisted case (the die-Canonical SSOT)

`ssot` (schema version `"1.0"`) keys present:

| Key | Type/size | Notes |
|---|---|---|
| `analysis` | dict[10] | DIE analyze envelope — commands, semantic AST, intent hooks (all empty for this input) |
| `analyst_narrative` | dict[7] | Static generic narrative (see §3) |
| `chain` | list[3] | Three-stage decode chain, all empty terminals |
| `decode_confidence` | 82 | Decoder self-report — high because "no more to peel" is a confident state |
| `decode_trace` | list[3] | Per-stage decode trace |
| `decode_winner_engine` | `"chain (3 stages)"` | Chain declared the winner |
| `inline_story_preproc` | dict[7] | Preprocessor stages |
| `investigation_mode` | `True` | Flag only |
| `investigation_object` | dict[29] | die-Canonical container (see §6) |
| `lolbas` | list[0] | Empty |
| `mitre` | list[0] | Empty |
| `predicted_tree` | `None` | Process-tree predictor not populated |
| `reached_shellcode` | `False` | — |
| `steps` | list[3] | Same three stages |
| `understanding` | dict[18] | IUE-2 style understanding — but as a stamped result, not the driver |
| `version` | dict[4] | Schema versions |

Not present: `investigation_model`, `investigation_narrative`, `investigation_report`, `mdr_investigation`, `executive_card`, `attack_story`, `ikg`, `evidence_graph`, `verdict_shadow`.

---

## 6. `ssot.investigation_object` — die-Canonical container inventory

29 fields present. Every investigation-content field is empty:

```
acquired_document        dict[23]   ← DOCX metadata + extraction stats
acquisition_plan         list[7]    ← IDA acquisition steps
artifact_summary         dict[1]
artifacts                list[3]    ← three sub-artefacts identified
behaviour                dict[2]
commands                 list[0]    ← EMPTY
confidence               dict[4]
dkp                      list[0]    ← EMPTY (Decoder Knowledge Pack)
document_profile         dict[0]    ← EMPTY
engines_selected         list[7]
engines_skipped          list[5]
explanation_coverage     dict[4]
explanations             list[0]    ← EMPTY
health                   dict[5]
ice                      dict[12]
ida                      dict[4]
incident                 dict[12]
input                    dict[1]
intent                   dict[9]
iocs                     dict[0]    ← EMPTY
lolbas                   list[0]    ← EMPTY
metadata                 dict[9]
mitre                    list[0]    ← EMPTY
narrative                dict[7]    ← generic template
plan                     list[10]   ← IUE-2 style plan (10 steps)
preprocessor             dict[7]
profiling                dict[5]
report_extraction        dict[0]    ← EMPTY
understanding            dict[18]
```

Notably, `investigation_object.plan` shows the die-Canonical **did** compute an IUE-2 style ten-step plan — but the executor produced empty outputs for every substantive step, because DOCX ingestion via `decode_smart` does not invoke the analyzers that produce IOCs/MITRE/LOLBAS/commands/dkp/explanations from document text.

---

## 7. Wave 1 shadow observation store — Sample1 is absent

Verified against `verdict_shadow_observations` collection:

| Total records | 2 |
| Sample1 record present | **NO** |
| Latest 2 records | `2026-08-10T03:30:23Z` (`shadow_engine=canonical-v2-verdict-1.0`), `2026-08-10T02:16:17Z` (`shadow_engine=canonical-v2-verdict-1.0`) |
| Sample1 saved at | `2026-08-10T04:57:27Z` — later than both existing observations |

Confirmation: Wave 1 shadow attach lives inside `v2/jobs/pipeline.py::run_investigation_with_progress`. Because MDR was never invoked for Sample1, no shadow record was produced.

---

## 8. Exact execution path that produced this state

```
[Analyst uploads Sample.docx via Workspace]
   │
   ▼
Frontend paste field receives synthesised text descriptor:
   "[BINARY FILE — Sample.docx] Size: 40786 bytes …"
   │
   ▼
POST /api/cases/save
   │
   ▼ backend/routers/cases.py::save_case
   │   detects output is "blank" → decides to reinvestigate before persisting
   │
   ▼ calls routers/ops.py::decode_smart
   │
   ▼ decode_smart pipeline (as documented in IUE_ARCHITECTURE_TRACE §5.5):
   │
   ├─▶ ingress_gate (vendor-JSON normaliser — not applicable)
   ├─▶ atomic_ioc_guard (not applicable)
   ├─▶ deterministic_best_decode → chain (3 stages, empty terminals)
   ├─▶ CIM compose
   ├─▶ CIO compose
   │       └─▶ IUE-1 (nivxforge) — POST-HOC metadata stamp only
   │             (route field emitted; NEVER READ)
   ├─▶ verdict refresh → verdict=Partial, confidence=25
   └─▶ OSINT enrich (no IOCs to enrich)
   │
   ▼ Result persisted to workspace_cases:
   │   engine="convergence"
   │   ssot.version="1.0" (die-Canonical shape)
   │   ssot.investigation_object populated but empty of content
   │   NO investigation_model, NO Wave 1 attach
   │
   ▼ Workspace UI renders:
   │   • Verdict card:            Partial · 25
   │   • IOCs section:            hashes only (from archive)
   │   • MITRE section:           empty
   │   • LOLBAS section:          empty
   │   • Attack Chain section:    empty stages
   │   • Attack Story:            missing
   │   • Executive Summary:       missing
   │   • Recommendations:         GENERIC TEMPLATE FALLBACK
   │       (from services/die/analyst_narrative.py static block)
   └─▶ [Analyst screenshots the generic recs and flags the case]
```

---

## 9. Expected canonical investigation surfaces (from ADR-005 §4)

Under the canonical lifecycle defined by ADR-005 §7, the same input MUST reach:

```
[Any surface (Workspace paste / Save Case / Reinvestigate / Docs / Auto-Investigate / EDR/SIEM/OT)]
        │
        ▼
EntryAdapter    → bytes-safe raw + filename + mime_hint + source_channel
        │
        ▼
InputHealth     → structural checks (documented in ssot.input_health)
        │
        ▼
IUE (D1)        → IUEDecision{input_profile, intent, capabilities,
                              confidence_matrix, plan, dispatch_policy, provenance}
        │
        ▼
Executor        → runs the plan (or DAG per D4); attaches every step's
                  output to evidence_graph with mandatory Provenance (D3);
                  invokes RECURSIVE_DISCOVERY (D6) for embedded artefacts
        │
        ▼
Canonical Investigation SSOT (D2)
   authoritative tier                projection tier
   ──────────────────                 ─────────────────
   evidence_graph                     activity{processes,files,network,
   reasoning_steps                                  registry,auth}
   iue_decision                       iocs (typed)
   execution_trace                    threat_intel
   input_raw / input_profile /        attck (with per-technique evidence
   input_health                              pointers)
   artifacts[] (recursive via         attack_chain (ordered stages)
              ssot_ref per D6)        attack_story (structured)
   provenance (per entry)             analyst_summary (structured)
                                      executive_summary (structured)
                                      recommendations (per-technique,
                                                       evidence-tied)
                                      reports.{stix,sigma,yara,navigator,mdr}
                                      timeline
        │
        ▼
Downstream consumers read ONLY from the SSOT (ADR-005 §9); no consumer
re-parses raw input, no consumer synthesises its own MITRE/attack_chain/
verdict from raw text.
```

---

## 10. Acceptance test — what "fixed" looks like against Sample1

When the canonical investigation architecture (ADR-005 D1–D10 decided,
implementation sequence executed) is in place, **re-investigating
Sample.docx MUST produce a case where**:

| Surface | Current state | Post-canonical acceptance |
|---|---|---|
| Persisted engine label | `"convergence"` | `"canonical-v1"` or equivalent — reflecting the canonical lifecycle |
| SSOT shape | die-Canonical (v1.0) | Canonical Investigation SSOT (per D2) — either two-tier (authoritative + projection) or single canonical shape depending on D2 outcome |
| `iocs.urls / ips / domains / emails` | `[]` | Populated where present in DOCX text; empty where genuinely absent — **each with provenance** |
| `iocs.hashes` | Archive-member digests only | Investigation-derived hashes with provenance pointers to the evidence node that produced them |
| `mitre` | `[]` | Non-empty when the executor produces evidence for a technique; each technique carries an `evidence_ids[]` back-pointer |
| `lolbas` | `[]` | Non-empty when a LOLBAS binary is referenced in decoded text; each entry carries evidence |
| `attack_chain` | `[None, None, None]` | Ordered `Stage[]` with per-stage `evidence_ids[]`, `technique_ids[]`, `timestamp` |
| `attack_story` | Missing | Structured, deterministic (not LLM) — sections tied to evidence graph nodes |
| `executive_summary` | Missing | 5-question answer card, deterministic, evidence-pointered |
| `analyst_summary` | Generic template | Structured, evidence-tied — with pointers into `evidence_graph` |
| `recommendations` | Generic template | Per-technique remediations tied to detected evidence; no fallback template unless the SSOT genuinely has no MITRE (in which case the fact "no MITRE" is itself recorded with provenance) |
| Wave-N shadow attach | Absent | Present, **labelled with `source_ssot_shape` + `source_path`** per ADR-005 §10 |
| Reasoning steps | Not surfaced | Full ReasoningStep stream (D3) — replay + audit + analyst-visible |
| Determinism | N/A (each rerun differs subtly) | Same input + same engine versions ⇒ byte-identical SSOT (canonical JSON has stable sha256) |
| Recursive discovery | None | `Sample.docx` → embedded artefacts → child SSOTs by `ssot_ref` (D6) |

If any of the above criteria are not met after the canonical lifecycle
is implemented, **the implementation is incomplete** — regardless of
what other cases pass. Sample1 is the architectural canary.

---

## 11. Rules governing this case going forward

- **R-G1**: Sample1 (case ID `3db79c4a-088b-4df7-b65a-f68b367b7677`) MUST NOT be deleted, migrated, re-saved, or re-investigated in place.
- **R-G2**: Any future implementation acceptance test SHALL re-ingest the same input (`Sample.docx`) as a NEW case; the ORIGINAL Sample1 record remains the pre-canonical baseline for diff comparisons.
- **R-G3**: Any change to the golden case in the DB (drift, accidental update, migration side-effect) MUST be treated as a regression.
- **R-G4**: The determinism fingerprint `5b4337d5a9fc05923bd3090f1270268ae8eef7af2ccf06f4e8d8492bf908261d` (sha256 of the persisted doc excluding `_id`) SHALL be verifiable at any time by re-running the snapshot procedure documented in `/app/memory/GOLDEN_CASE_SAMPLE1.snapshot.json`.
- **R-G5**: No shadow observation SHALL be back-attached to this case retroactively.
- **R-G6**: No route change, no adapter, no migration, no scoring change may take effect against `case_id = 3db79c4a-088b-4df7-b65a-f68b367b7677` until D1/D2/D3/D4/D6/D7/D10 are decided and the implementation sequence explicitly targets it as an acceptance test.

---

## 12. Non-actions taken during this freeze

- No code changes.
- No route changes.
- No database modifications (only READ queries).
- No Wave 1 modifications.
- No shadow attach.
- No case reinvestigation.
- No SSOT migration.

**Read-only freeze recorded. Awaiting owner decisions on D1/D2/D3/D4/D6/D7/D10 per `/app/memory/adr/0005-owner-decision-matrix.md`.**
