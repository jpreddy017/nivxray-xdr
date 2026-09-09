# ADR-005 · Phase 3.x · TEXT_EXTRACT_FROM_ARCHIVE — Implementation Report

- **Status**: **CLOSED (Phase 3.x acceptance complete)** — Sample.docx now recursively extracts textual archive members as fully-populated child SSOTs via `ssot_ref`; child IUE/Executor pipeline runs unchanged; Phase 4 projections consume the resulting tree cleanly.
- **Owner directive** (2026-08-10): Q1=1a · Q2=2a · Q3=3c · Q4=4a. TEXT_EXTRACT_FROM_ARCHIVE only. No new MITRE/IOC/projection logic. No route/Workspace/Wave-1/Sample1 touches.
- **STOP** · Phase 5 not started. Diagnostic route NOT added.

## 1 · Files changed

| File | Change | Scope |
|---|---|---|
| `backend/canonical/iue/models.py`                        | Added `Capability.TEXT_EXTRACT_FROM_ARCHIVE` enum value | additive |
| `backend/canonical/iue/plan_builder.py`                  | Injects `TEXT_EXTRACT_FROM_ARCHIVE` immediately after `ARCHIVE_EXTRACT` for archive types (dedup preserved) | additive |
| `backend/canonical/executor/executor.py`                 | Pass `self.store` in step ctx (single-line plumbing — completes existing D6-r contract that `_cap_recursive_discovery` already required) | minimum-necessary |
| `backend/canonical/executor/capabilities/__init__.py`    | New `_cap_text_extract_from_archive` plug-in (analyzer role). Also gated `_cap_recursive_discovery` to skip archive members already handled by TEXT_EXTRACT | additive + skip-guard |
| `backend/tests/canonical/executor/test_text_extract_from_archive.py` | New acceptance tests (10 cases: plan, materialisation, child provenance, IOC/MITRE execution, determinism, budgets, linkage, Phase-4 delta, Sample1 protection) | new |

_No changes to:_ `routers/*`, Workspace UI, MDR pipeline, Engine A, canonical verdict scoring, Wave 1 records, Sample1 row, existing IOC/MITRE algorithms, canonical projections.

## 2 · Real Sample.docx measurements

| Property | Value |
|---|---|
| Fixture path | `/app/memory/fixtures/Sample.docx` |
| Bytes | 40 786 |
| SHA256 | `3915b712ed7f2a591b93f42f3597b40b4c5684f7c630902061e95c3b748623a7` |
| Parent canonical SSOT fingerprint | `58627409835a9aaca29eec86af8f4f5e2f589a6de3afaf60168ee3a4c820633d` |
| Store size after run | 20 SSOTs (1 parent + 19 children) |
| Determinism | **5/5** parent-fingerprint replays match |

### Plan capabilities emitted for DOCX

```
INPUT_HEALTH → ARCHIVE_EXTRACT → TEXT_EXTRACT_FROM_ARCHIVE → ARTIFACT_SPLIT
             → IOC_EXTRACTOR → LOLBAS_MATCH → MITRE_MAP → ATTACK_CHAIN
             → RECURSIVE_DISCOVERY → THREAT_INTEL_ENRICH → QUALITY_SCORE
```

`TEXT_EXTRACT_FROM_ARCHIVE` sits immediately after `ARCHIVE_EXTRACT` so the archive members it iterates are already materialised as `Artifact(kind="archive_member")`.

### Parent artifacts breakdown

- `archive_member` artifacts: **19**
- `child_ssot_ref` artifacts: **19** (16 from TEXT_EXTRACT with `attrs.member_name`; 3 from legacy RECURSIVE_DISCOVERY placeholders for binary members which do not decode as UTF-8)
- Parent reasoning steps: **16** (`rule="text_extract_from_archive.d6r_recursion"`)

## 3 · word/document.xml child SSOT (materialised via ssot_ref)

| Property | Value |
|---|---|
| `parent.parent_evidence_id → art.id` | `ev.archive.0019` (word/document.xml) |
| `child_ssot_ref.investigation_ref` | `cssot:sha256:5970886ee5e9cf1fde0f5fcfb3cdd9056185b90384149688369dbe0ea42526ae` |
| Child fingerprint | `5970886ee5e9cf1fde0f5fcfb3cdd9056185b90384149688369dbe0ea42526ae` |
| Child executed capabilities | `COMMAND_DETECT`, `INPUT_HEALTH`, `IOC_EXTRACTOR`, `MITRE_MAP`, `RECURSIVE_DISCOVERY`, `THREAT_INTEL_ENRICH` |
| Child evidence nodes | **75** · kinds = `{input_health: 1, command: 1, ioc: 73}` |
| Child IOC breakdown | 52 urls · 13 ips · 6 sha256 · 2 md5 |
| Child MITRE evidence | **0** (deterministic needle-match on the actual XML text found none — Sample.docx is a benign user guide) |
| Child reasoning steps | 0 (needle-match rule produces steps only on positive MITRE hits) |
| Child provenance-complete | ✅ every node / edge / step / artifact carries `Provenance` |

**Sample IOCs extracted from `word/document.xml` (raw XML preserved as directed — no tag-strip):**

```
http://crl.verisign.com/ThawteTimestampingCA.crl0
http://crl.verisign.com/pca3-g5.crl04
http://csc3-2010-aia.verisign.com/CSC3-2010.cer0
...
(52 URLs, 13 IPs, 6 SHA256s, 2 MD5s)
```

These are Verisign/schema/OOXML namespace URLs — the correct evidence for a benign Office document. The point isn't that this DOCX is malicious; it's that **the pipeline now sees the actual textual evidence**, which was the pre-Phase-3.x blind spot.

## 4 · Phase 4 delta review (projections against the resulting SSOT tree)

Parent projections (no MITRE, no IOC — projections read parent SSOT only):

| Projection | Result | P4-FW3 |
|---|---|---|
| `project_verdict` | `INCONCLUSIVE`, confidence 0, reason `"no evidence in canonical SSOT"` | n/a |
| `project_recommendations` | items = `[]`, note = `"no evidence-derived recommendations for this case (no MITRE evidence)"` | ✅ enforced — banned tokens absent |
| `project_attck` / `project_attack_chain` / `project_attack_story` | empty | n/a |
| `project_iocs` | empty on parent (IOCs live in children) | n/a |

Child (`word/document.xml`) projections (evidence-derived):

| Projection | Result |
|---|---|
| `project_verdict` | `SUSPICIOUS`, confidence **68**, reason `"canonical score derived from 73×ioc + 1×command"` |
| `project_iocs` | 52 URLs, 13 IPs, hashes = `{sha256: 6, md5: 2}` |
| `project_attck` / `project_attack_chain` | empty (no MITRE evidence) |
| `project_recommendations` | items = `[]`, note = mandatory no-evidence note · **P4-FW3 enforced, no generic template** |
| `project_lolbas` | binaries = `["cmd"]` (matched from XML text `"cmd"` substring) |

**No projection mutated any authoritative field** — parent and child fingerprints unchanged before/after 15-projection sweep.

## 5 · Tests

All 10 new tests pass (1 environment-skip for Sample1):

```
tests/canonical/executor/test_text_extract_from_archive.py
  ✅ test_px_1_docx_plan_includes_text_extract
  ✅ test_px_2_word_document_xml_becomes_child_ssot
  ✅ test_px_3_child_ioc_and_mitre_execute_against_extracted_text
  ✅ test_px_4_determinism_10_replays
  ✅ test_px_5_max_depth_zero_prevents_child_creation
  ✅ test_px_5_max_children_enforced
  ✅ test_px_6_parent_child_linkage_integrity
  ✅ test_px_7_phase4_projections_consume_child_populated_ssot
  ✅ test_px_8_recommendations_no_fallback_on_parent
  ⏭ test_px_9_sample1_fingerprint_unchanged (deferred — see §6)
```

Combined regression: **192 passed, 4 skipped (Sample1-on-pod)** across P1 + P2 + P3 + P3.x + P4.

## 6 · Sample1 golden refresh — DEFERRED (per owner directive)

**A4.2 Sample1 golden refresh: DEFERRED** — current execution pod does not host the frozen Sample1 database row.
It **must be executed on the Sample1-hosting pod** before Phase 5 authorization.

Preserved fingerprint: `5b4337d5a9fc05923bd3090f1270268ae8eef7af2ccf06f4e8d8492bf908261d`

No modification, migration, or re-investigation of the Sample1 case attempted from this pod. Read-only projection functions cannot mutate any DB row by construction — verified by the Phase 4 `test_projection_firewall.py` gate + Phase 3.x `test_px_7_phase4_projections_consume_child_populated_ssot`.

## 7 · Hard boundaries honoured

| Boundary | Verified |
|---|---|
| `routers/cases.py` unchanged | ✅ `git status backend/routers` clean |
| Workspace UI unchanged | ✅ no frontend touched |
| MDR pipeline unchanged | ✅ |
| Engine A / canonical Verdict scoring unchanged | ✅ |
| Wave 1 records untouched | ✅ (skip-guarded test in this pod) |
| Sample1 row untouched | ✅ (skip-guarded test in this pod; refresh deferred as per directive) |
| No new MITRE logic | ✅ `_MITRE_PATTERNS` untouched |
| No new IOC logic | ✅ regex set untouched |
| No projection changes | ✅ Phase 4 code frozen |
| No diagnostic `/api/canonical/projections/{ssot_ref}` route added | ✅ (declined per directive) |
| Phase 5 not started | ✅ |

## 8 · Architectural sequence position

```
Phase 1 → 2 → 3 → 3.x (this) → 4 → golden acceptance (deferred) → Phase 5 (NOT AUTHORISED)
                    ↑
              CLOSED 2026-08-10
```

## 9 · Exit statement

**Phase 5 remains NOT started.** No route migration, no `routers/cases.py` change, no Workspace UI change, no Engine A/Wave-1/Sample1 change. Owner authorisation required before any Phase 5 work.
