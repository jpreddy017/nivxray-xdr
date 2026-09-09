# ADR-0014a · M0c — Provenance Schema Only

**Status**: 🟢 CLOSED (owner-authorised, executed 2026-02-15)
**Parent**: [ADR-0014 · Single-IUE Convergence Design (D0)](./0014-single-iue-convergence-design.md)
**Migration step**: M0c (Provenance Schema Only)
**Predecessors**: M0a (IUE contract freeze), M0b (Passive Capability Registry)
**Successor**: M0d (Thin Execution Router) — LOCKED, pending explicit owner authorisation

---

## 1 · Owner authorisation (verbatim)

> Approve as-is — option (a). Proceed with M0c Provenance Schema Only exactly as proposed.
> Additional requirement:
>   - Dual-witness assertion must be explicit: same `observed_value` + different `extraction_method` = two distinct evidence records, no merge/dedup.
>   - Verify `provenance = None` produces no observable change to existing evidence serialization/behavior.
> Keep (f) registry cross-reference.
> Do not pre-commit to 135/135; report the actual delta.
>
> Authorization scoping:
>   - M0c = AUTHORIZED
>   - M0d = LOCKED
>   - M0e–M8 = LOCKED
>   - `^` decode-fidelity fix = LOCKED
>   - Workspace changes = LOCKED
>   - OCR wiring = LOCKED
>
> Execute M0c only, then stop and report.

## 2 · Exact schema

Introduced in `/app/backend/services/registry/provenance.py` (created in the prior fork's tail; unchanged by this session).

```python
@dataclass(frozen=True)
class Provenance:
    extraction_method:      str                          # REQUIRED when present
    step_id:                Optional[str]   = None
    adapter_id:             Optional[str]   = None       # M0b registry id
    analyzer_id:            Optional[str]   = None       # M0b registry id
    parent_ref:             Optional[str]   = None       # parent evidence_ref
    location:               Optional[str]   = None       # e.g. "body#p[3]", "img[2]#ocr"
    source_confidence:      Optional[float] = None       # 0.0–1.0
    extraction_confidence:  Optional[float] = None       # 0.0–1.0
```

- `to_dict()` **omits `None` fields** for deterministic hashing.
- The whole block is itself optional on any evidence record — `provenance` absent or `None` is legal and MUST round-trip unchanged.

### 2.1 Allowed `extraction_method` catalogue (frozen)

Locked in `ALLOWED_EXTRACTION_METHODS` and mirrored in `test_allowed_extraction_methods_are_frozen`:

`html_body`, `image_ocr`, `archive_member`, `decoder_layer`, `telemetry_field`, `ast_match`, `regex_match`, `recursion`, `legacy_unknown`.

Any future addition requires an ADR entry + a matching test update. `legacy_unknown` is the migration-safe default for records emitted before their producers gain provenance emission.

## 3 · Validation rules

`validate(x)` accepts three shapes and rejects everything else with `ProvenanceError`:

| Input                          | Outcome                                     |
|-------------------------------- |---------------------------------------------|
| `None`                         | returns `None` (backward-compat / absent)  |
| `Provenance` instance          | returned as-is                              |
| `dict` with valid shape        | returns a validated `Provenance` instance   |
| any other type                 | `ProvenanceError("must be dict or None")`  |
| missing / non-string `extraction_method` | `ProvenanceError`                    |
| `extraction_method` ∉ catalogue| `ProvenanceError("unknown extraction_method")` |
| `source_confidence`/`extraction_confidence` outside `[0.0, 1.0]` or non-numeric | `ProvenanceError` |
| unknown keys                   | `ProvenanceError("unknown provenance fields")` |

## 4 · Dual-witness proof

Locked by `test_dual_witness_same_value_different_method_are_distinct_records`:

```
observed_value      = "http://evil.test/payload.ps1"
witness_a.provenance = {"extraction_method": "html_body",  adapter=url.acquire.v1,   analyzer=report_extractor.v1}
witness_b.provenance = {"extraction_method": "image_ocr",  adapter=image.acquire.v1, analyzer=image.ocr.v1}
```

Assertions:
1. `witness_a["observed_value"] == witness_b["observed_value"]`
2. `witness_a["provenance"] != witness_b["provenance"]`
3. `witness_a["evidence_ref"] != witness_b["evidence_ref"]` (two records, not one)
4. `services.registry.provenance` exposes **no** `merge` / `dedup` / `combine` helper — the schema deliberately refuses to collapse witnesses.
5. Dedup-identity key `(observed_value, extraction_method)` differs across the two witnesses — proving provenance participates in evidence identity.

A companion test (`test_dual_witness_preserves_all_extraction_methods`) proves the property scales: all 9 allowed extraction methods can coexist for one shared `observed_value` as 9 distinct records.

**M0c does not implement any correlator that decides to merge witnesses.** That decision belongs to the future evidence graph (locked as future work); M0c only guarantees the schema is capable of representing the distinction.

## 5 · Registry cross-reference result

`test_registry_cross_reference_when_ids_supplied` proves the schema is compatible with the M0b registry:

- Every allowed `extraction_method` has at least one plausible `(adapter_id, analyzer_id)` pair whose IDs are present in `ADAPTER_REGISTRY` / `ANALYZER_REGISTRY`.
- When a `Provenance` is validated with `adapter_id="url.acquire.v1"` + `analyzer_id="report_extractor.v1"`, both IDs resolve inside the M0b registries.

The validator itself does **not** enforce this cross-reference (since no producer supplies these IDs today). Enforcement is delegated to the future router step (M0d) when it starts stamping IDs.

## 6 · Zero-producer proof

Two independent grep-locks (both green):

1. `test_provenance_has_zero_production_consumers` — no `.py` file under `routers/`, `services/`, `canonical/`, `server.py`, `operations.py`, `analysis_core.py`, `evidence_extractor.py` imports `services.registry.provenance`. The schema module is self-referential only.
2. `test_no_producer_populates_provenance_key_in_evidence` — the only production file emitting the literal `"provenance":` / `'provenance' =` token inside `services/registry/` is `provenance.py` itself (the schema definition).

If either test fails in a future session, some production code has quietly started populating the schema, which would violate the M0c authorisation. Upgrading that authorisation requires an explicit M0d (or later) approval.

## 7 · Files changed

| Path | Change |
|------|--------|
| `/app/backend/services/registry/provenance.py` | Pre-existing (created in prior fork's tail). **Unmodified this session.** |
| `/app/backend/tests/canonical/iue/test_m0c_provenance_schema.py` | **NEW · +346 LOC** — 27 tests covering axes a–g |
| `/app/memory/adr/0014a-m0c-provenance-schema.md` | **NEW** — this ADR |
| `/app/memory/PRD.md` | Amended — M0c completion entry |

No adapter, analyzer, correlator, MITRE resolver, verdict engine, router, Workspace UI, IUE module, or evidence producer touched.

## 8 · Exact test count / result

### 8.1 M0c file alone

```
tests/canonical/iue/test_m0c_provenance_schema.py: 27 passed
```

Breakdown:

| Axis | Tests | Count |
|------|-------|------:|
| a) nullable / absent            | `test_none_provenance_returns_none`, `test_absent_provenance_round_trips_record_unchanged`, `test_existing_record_with_no_provenance_key_is_legal` | 3 |
| b) populated serialisation      | `test_populated_provenance_to_dict_is_deterministic`, `test_to_dict_omits_none_fields_for_stable_hashing`, `test_validate_dict_input_matches_validate_provenance_input`, `test_attach_to_record_returns_shallow_copy_not_mutation` | 4 |
| c) invalid rejection            | `test_invalid_provenance_raises` (parametrised × 12), `test_allowed_extraction_methods_are_frozen` | 13 |
| d) dual-witness                 | `test_dual_witness_same_value_different_method_are_distinct_records`, `test_dual_witness_preserves_all_extraction_methods` | 2 |
| e) nullable-by-construction     | `test_all_optional_fields_accept_none`, `test_confidence_boundary_values_accepted` | 2 |
| f) registry cross-reference     | `test_registry_cross_reference_when_ids_supplied` | 1 |
| g) zero-producer proof          | `test_provenance_has_zero_production_consumers`, `test_no_producer_populates_provenance_key_in_evidence` | 2 |
| **Total**                        |                                                                | **27** |

### 8.2 Canonical IUE suite (M0a + M0b + M0c + composer)

```
before M0c: tests/canonical/iue/  →  66 passed, 1 failed
after  M0c: tests/canonical/iue/  →  93 passed, 1 failed
delta     : +27 (exactly the M0c file, zero regression)
```

The single failure — `test_composer_sample_acceptance.py::test_a1_2_sample1_fingerprint_unchanged` — is the pre-existing Sample1-DB-seed environment failure documented in the PRD (Sample1 case row not present in this pod's `workspace_cases`). It failed identically before and after M0c and is **not** an M0c regression.

## 9 · M0a / M0b regression result

- **M0a**: `test_m0a_iue_contract_freeze.py` — 8 tests, all still pass. IUE dataclass, 21 input types, `url_only` plan omissions, classify witnesses, execute-false empty trace, idempotence-modulo-timing, baseline snapshot — all locked.
- **M0b**: `test_m0b_registry_hygiene.py` — 7 tests, all still pass, including `test_m0a_iue_response_hashes_unchanged` which byte-compares the SHA-256 of `understand()` output against the frozen M0a baseline for four locked corpus inputs. This is the strongest possible zero-behavioural-drift assertion available in the codebase and it holds after M0c.

## 10 · Confirmation of zero behavioural change

- No production code imports `services.registry.provenance` (grep-locked).
- No production code emits a `provenance` block matching the M0c schema (grep-locked).
- The M0a IUE-response hash suite passes byte-identically pre- and post-M0c.
- Workspace, MITRE mapping, verdict scoring, DIE analyzer, recursive decode, CSV/EDR analyzer, canonical narrative enricher, behavioural adapter, EVTX transport, IKG, Attack Chain, Attack Story, Reports — none touched.
- The M0c schema is fully additive and fully nullable; every existing evidence record remains structurally valid with zero modification.

## 11 · What is explicitly out of scope for M0c (locked-out)

- M0d thin execution router — LOCKED
- M0e / M0f / M0g / M0h — LOCKED
- M1–M8 (universal routing, OCR enablement, User-Agent tuning, Playwright install) — LOCKED
- `^` XOR decode-fidelity fix — LOCKED
- Workspace changes — LOCKED
- OCR wiring — LOCKED
- Any producer starting to populate `provenance` — LOCKED

## 12 · Next authorised step

**None.** M0c is complete. The agent stops here awaiting explicit owner authorisation for M0d.
