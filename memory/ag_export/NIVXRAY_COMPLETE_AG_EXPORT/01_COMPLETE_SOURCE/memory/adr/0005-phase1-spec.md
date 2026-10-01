# ADR-005 · Phase 1 Specification — Canonical IUE Composer

- **Status**: **AUTHORISED for implementation** (owner 2026-08-10)
- **Prerequisite artefacts**: ADR-005 design + owner decisions + migration map + implementation sequence (all approved 2026-08-10)
- **Governance amendments applied**: Amendment 1 (5-input-class coverage), Amendment 2 (semantic vs. byte identity), Amendment 3 (Phase 10 rollback wording)
- **Gate**: Design → Implement → Tests → Sample.docx NEW-case acceptance → Determinism → Owner sign-off → **STOP** for review
- **Sample1 record**: NEVER modified (R-G1..R-G6, IX-1). Any reference to "Sample.docx" below means a NEW ingestion of the file, not the persisted Sample1 case.

---

## 1. Scope (from owner authorisation, verbatim)

### Allowed in Phase 1
- New Composer module
- Adapters around existing IUE sub-classifiers (IUE-2, IUE-3, IUE-4, IUE-5) + pre-IUE InputHealth
- Canonical `IUE.classify(...)` public API
- `IUEDecision` output object (per ADR-005 §3.2)
- Deterministic tests
- Provenance envelope (D3-z) on every emitted evidence
- Unit + integration tests
- `Sample.docx` as a NEW test input

### NOT allowed in Phase 1
- ❌ Route changes (no router file modified)
- ❌ Workspace UI changes
- ❌ `routers/cases.py` changes
- ❌ Engine A changes
- ❌ Canonical Verdict scoring changes
- ❌ Wave 1 changes
- ❌ Canonical SSOT authoritative-tier work (Phase 2 territory)
- ❌ Deleting or deprecating any existing IUE
- ❌ MDR pipeline changes
- ❌ Attack Story / MITRE / Recommendations changes
- ❌ ADR-004 Step 2 work

---

## 2. Deliverables

| Path | Purpose |
|---|---|
| `backend/canonical/__init__.py` | Package marker |
| `backend/canonical/iue/__init__.py` | Public API — `classify()`, `IUEDecision` |
| `backend/canonical/iue/models.py` | `IUEDecision`, `InputProfile`, `IUEEvidence`, `PlanStep`, `ConfidenceMatrix`, `Capability`, `DispatchPolicy`, `Provenance` |
| `backend/canonical/iue/composer.py` | `classify(RawInput, Context?) -> IUEDecision` |
| `backend/canonical/iue/plan_builder.py` | Deterministic plan + dispatch emission |
| `backend/canonical/iue/determinism.py` | Canonical-JSON serialiser + sha256 fingerprint |
| `backend/canonical/iue/adapters/input_health.py` | Wraps `services/die/input_health.py` |
| `backend/canonical/iue/adapters/bytes_magic.py` | Wraps `services/uil/classifier.py` (IUE-4) |
| `backend/canonical/iue/adapters/text_structure.py` | Wraps `services/die/input_understanding.py` classification (IUE-2) |
| `backend/canonical/iue/adapters/language_detector.py` | Wraps `v2/investigation/iu/engine.py` (IUE-3) |
| `backend/canonical/iue/adapters/multi_artefact.py` | Wraps IUE-3 multi-artefact aggregation |
| `backend/canonical/iue/adapters/artefact_decomp.py` | Wraps IUE-5 (`services/ida/input_classifier.py`) |
| `backend/canonical/iue/adapters/intent.py` | Wraps `services/die/intent.py` |
| `backend/tests/canonical/iue/*.py` | Unit + integration + contract + determinism + amendment-1 5-class + no-network + Sample.docx tests |

**Constraints**:
- Adapters are **read-only wrappers** around existing sub-classifiers. Adapters MUST NOT modify the wrapped modules. Adapters translate the wrapped module's output into `IUEEvidence` + normalised typed emit.
- Composer MUST NOT execute any decoding, IOC extraction, MITRE mapping, or artefact acquisition. It classifies, profiles, plans, dispatches. (ADR-005 §3.4)
- All I/O forbidden. No network. No filesystem writes. No DB writes. (INV-2 determinism)

## 3. Contract summary (from ADR-005 §3.2)

```
classify(RawInput{bytes | str, filename?, mime_hint?, source_channel?},
         Context?) -> IUEDecision {
    input_health,            # InputHealth output
    input_profile,           # {primary_type, embedded[], input_kind, encoding, size, byte_signature, filename?}
    intent,                  # {label, confidence, evidence_ids[]}
    capabilities,            # List[Capability] ordered
    plan,                    # List[PlanStep{engine, action, reason, required, expected_output_kind}]
    confidence_matrix,       # 6 named axes
    dispatch_policy,         # strict_ordered | parallel_where_safe | dag
    provenance,              # {engine="canonical.iue.composer", version, at, upstream_evidence_ids[]}
    next_engine_hint,        # analyst one-liner
    evidence,                # List[IUEEvidence]
    determinism_hash,        # sha256 of canonical JSON
}
```

Determinism rule: same `(bytes | str | filename | mime_hint | source_channel)` tuple ⇒ identical `determinism_hash`.

## 4. Adapter contracts

Each adapter exposes one function:
```
def <sub>_evidence(raw: RawInput) -> List[IUEEvidence]
```
returning an ordered list of `IUEEvidence{source, observation, confidence, rationale, meta, provenance}` entries. No side effects; no reliance on network; no mutation of the wrapped module.

The composer aggregates all evidence, applies the tie-breaking rule (§5), and produces `IUEDecision`.

## 5. Tie-breaking rule (deterministic)

When two sub-classifiers emit conflicting `primary_type`:
1. `input_health.blocking=true` short-circuits — primary_type stays as sub-classifier evidence but `IUEDecision.intent.label = "blocked_by_health"` and plan is `[HEALTH_INVESTIGATE, MANUAL_REVIEW]`.
2. Otherwise: **highest confidence wins**.
3. Confidence tie: **fixed sub-classifier priority order** (documented in `composer.py::_TIE_BREAK_ORDER`):
   ```
   bytes_magic  > text_structure  > language_detector  > multi_artefact
   ```
4. All non-winning types with confidence ≥ 40 join `input_profile.embedded[]`.
5. `evidence[]` is sorted by `(-confidence, sub_classifier_priority)` for stability.

Every step above is a pure function of the inputs — no clock reads, no random, no environment lookups.

## 6. Plan builder rule

`PlanStep[]` is emitted by a lookup table `_PLAN_BY_TYPE: primary_type -> List[PlanStep]`, then augmented by per-embedded-type steps. Dispatch policy is `strict_ordered` in Phase 1 (parallel_where_safe / dag deferred to Phase 3 executor design). Rationale: Phase 1 must be provably deterministic; parallel scheduling is Phase 3's problem.

## 7. Tests / gates for Phase 1

Located in `backend/tests/canonical/iue/`.

| Test | File | Gate |
|---|---|---|
| T1.1 sub-classifier composition | `test_composer_composition.py` | ✅ green |
| T1.2 determinism (20 inputs × 100 replays) | `test_composer_determinism.py` | fingerprints stable |
| T1.3 contract vs. ADR-005 §3.2 | `test_composer_contract.py` | schema complete |
| T1.4 provenance envelope | `test_composer_provenance.py` | every evidence has envelope |
| T1.5 tie-breaking | `test_composer_tiebreak.py` | rule §5 deterministic |
| T1.6 no-network | `test_composer_no_network.py` | passes under socket-guard |
| **T1.7 (Amendment 1) 5-input-class** | `test_composer_amendment1_inputs.py` | all 5 classes prove real IUE-2/3/4/5 participation via provenance |

Amendment 1 acceptance table:

| Class | Fixture | Must-see participation |
|---|---|---|
| raw text | PowerShell EncodedCommand (base64) | IUE-2 classification + IUE-3 language detection in provenance |
| raw bytes | 128-byte MZ PE header | IUE-4 bytes_magic in provenance (only IUE with byte support) |
| DOCX | `Sample.docx` bytes | IUE-4 (magic=DOCX) + IUE-5 artefact_decomp in provenance |
| multi-artefact | `wmic /... cmd /c "powershell -e <base64>"` | IUE-3 multi-artefact `embedded[]` non-empty |
| malformed | 40% control-char + truncated encoding | InputHealth reports anomaly; UNKNOWN with evidence; no exception |

## 8. Sample.docx NEW-case acceptance (Phase 1 gate)

- **A1.1** Ingest `Sample.docx` bytes through composer only (no route). Assert:
  - `input_profile.primary_type == DOCX`
  - `input_health` populated
  - `intent` populated with non-generic label
  - `plan[]` non-empty
  - `dispatch[]` includes at minimum `ARCHIVE_EXTRACT`, `ARTIFACT_SPLIT`, `IOC_EXTRACTOR`, `MITRE_MAP`
  - `confidence_matrix` populated on all 6 axes
  - `determinism_hash` reproducible across 100 replays
  - `provenance` shows IUE-4 + IUE-5 both participated
- **A1.2** Sample1 original record fingerprint verified unchanged — `5b4337d5a9fc05923bd3090f1270268ae8eef7af2ccf06f4e8d8492bf908261d`.

## 9. Explicit exclusions

- Phase 1 does NOT populate the canonical SSOT (Phase 2).
- Phase 1 does NOT execute the plan (Phase 3).
- Phase 1 does NOT compute a verdict (Phase 9).
- Phase 1 does NOT expose a route.
- Phase 1 does NOT change the behaviour of any existing route.

## 10. Exit condition

1. All tests T1.1..T1.7 green.
2. A1.1, A1.2 verified.
3. Phase 1 report produced at `/app/memory/adr/0005-phase1-report.md` summarising:
   - Files added
   - Test results
   - Sample.docx acceptance outcome
   - Determinism proof (hash of the DOCX ingestion)
   - Sample1 fingerprint re-verification
4. **STOP.** Await owner review before Phase 2 is authorised.
