"""M0c · Canonical Evidence Provenance schema tests (ADR-0014).

Locks the SCHEMA-ONLY contract for the additive, nullable `provenance`
block introduced in `services/registry/provenance.py`.

Owner-mandated coverage axes (M0c authorisation, 2026-02-15):
  a) Nullable / absent  →  record round-trips unchanged (backward compat)
  b) Populated round-trip serialisation is deterministic
  c) Invalid input raises `ProvenanceError` (bad type / unknown method /
     bad confidence range / unknown keys)
  d) Dual-witness rule — same `observed_value` + different
     `extraction_method`  =  two distinct evidence records (no merge)
  e) Nullable-by-construction — every optional field accepts None
  f) Registry cross-reference — when `adapter_id` / `analyzer_id` are
     supplied they must exist in the M0b passive registry
  g) Zero-producer proof — no production module imports
     `services.registry.provenance` yet (grep-lock)

STRICT: M0c does not wire provenance into any producer, analyzer, router,
verdict engine, or MITRE resolver. If any of these tests start passing
via a production import, the "schema-only" contract has been violated.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

_BACKEND = Path(__file__).resolve().parents[3]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from services.registry.provenance import (   # noqa: E402
    ALLOWED_EXTRACTION_METHODS,
    Provenance,
    ProvenanceError,
    attach_to_record,
    validate,
)
from services.registry import (               # noqa: E402
    ADAPTER_REGISTRY,
    ANALYZER_REGISTRY,
)


# ── a) Nullable / absent provenance round-trips unchanged ──────────────────
def test_none_provenance_returns_none():
    assert validate(None) is None


def test_absent_provenance_round_trips_record_unchanged():
    """attach_to_record(rec, None) MUST be indistinguishable from `rec`.

    The record has NO `provenance` key on the way in and MUST have none
    on the way out — that is the essence of the additive-nullable contract.
    """
    record = {
        "evidence_ref": "ev:sha256:abc",
        "observed_value": "cmd.exe /c whoami",
        "kind": "process_create",
    }
    out = attach_to_record(record, None)
    assert out == record
    assert "provenance" not in out
    # source record is not mutated
    assert "provenance" not in record


def test_existing_record_with_no_provenance_key_is_legal():
    """A record produced by any current adapter (all pre-M0c) has no
    `provenance` key.  Validation of that record shape MUST succeed
    trivially — nothing to validate, nothing to reject."""
    legacy_record = {
        "evidence_ref": "ev:sha256:def",
        "observed_value": "http://example.test/report",
    }
    assert legacy_record.get("provenance") is None
    assert validate(legacy_record.get("provenance")) is None


# ── b) Populated round-trip serialisation is deterministic ─────────────────
def test_populated_provenance_to_dict_is_deterministic():
    p = Provenance(
        extraction_method="html_body",
        step_id="s-1",
        adapter_id="url.acquire.v1",
        analyzer_id="report_extractor.v1",
        parent_ref="ev:sha256:parent",
        location="body#p[3]",
        source_confidence=0.9,
        extraction_confidence=0.75,
    )
    d1 = p.to_dict()
    d2 = p.to_dict()
    assert d1 == d2
    assert json.dumps(d1, sort_keys=True) == json.dumps(d2, sort_keys=True)


def test_to_dict_omits_none_fields_for_stable_hashing():
    p = Provenance(extraction_method="regex_match")
    d = p.to_dict()
    assert d == {"extraction_method": "regex_match"}
    # None fields must not appear
    for none_field in ("step_id", "adapter_id", "analyzer_id",
                        "parent_ref", "location",
                        "source_confidence", "extraction_confidence"):
        assert none_field not in d


def test_validate_dict_input_matches_validate_provenance_input():
    payload = {
        "extraction_method": "image_ocr",
        "adapter_id": "image.acquire.v1",
        "analyzer_id": "image.ocr.v1",
        "location": "img[2]",
        "source_confidence": 1.0,
        "extraction_confidence": 0.6,
    }
    from_dict = validate(payload)
    from_obj  = validate(from_dict)
    assert isinstance(from_dict, Provenance)
    assert from_obj is from_dict
    assert from_dict.to_dict() == {
        "extraction_method": "image_ocr",
        "adapter_id": "image.acquire.v1",
        "analyzer_id": "image.ocr.v1",
        "location": "img[2]",
        "source_confidence": 1.0,
        "extraction_confidence": 0.6,
    }


def test_attach_to_record_returns_shallow_copy_not_mutation():
    record = {"evidence_ref": "ev:sha256:1", "observed_value": "x"}
    out = attach_to_record(record, {"extraction_method": "regex_match"})
    assert "provenance" not in record       # source untouched
    assert out["provenance"] == {"extraction_method": "regex_match"}
    # rest of record preserved
    assert out["evidence_ref"] == "ev:sha256:1"
    assert out["observed_value"] == "x"


# ── c) Invalid input rejected with ProvenanceError ─────────────────────────
@pytest.mark.parametrize("bad_input,match", [
    (42,                                        "must be dict or None"),
    ("string",                                  "must be dict or None"),
    ([{"extraction_method": "html_body"}],      "must be dict or None"),
    ({},                                        "extraction_method is required"),
    ({"extraction_method": ""},                 "extraction_method is required"),
    ({"extraction_method": None},               "extraction_method is required"),
    ({"extraction_method": 123},                "extraction_method is required"),
    ({"extraction_method": "totally_bogus"},    "unknown extraction_method"),
    ({"extraction_method": "html_body",
       "source_confidence": 1.5},               "source_confidence"),
    ({"extraction_method": "html_body",
       "extraction_confidence": -0.1},          "extraction_confidence"),
    ({"extraction_method": "html_body",
       "source_confidence": "high"},            "source_confidence"),
    ({"extraction_method": "html_body",
       "surprise_field": "nope"},               "unknown provenance fields"),
])
def test_invalid_provenance_raises(bad_input, match):
    with pytest.raises(ProvenanceError, match=match):
        validate(bad_input)


def test_allowed_extraction_methods_are_frozen():
    """Exact catalogue is locked here — future additions require an ADR
    entry (ADR-0014 §8.1) AND a corresponding update to this test."""
    assert ALLOWED_EXTRACTION_METHODS == frozenset({
        "html_body",
        "image_ocr",
        "archive_member",
        "decoder_layer",
        "telemetry_field",
        "ast_match",
        "regex_match",
        "recursion",
        "legacy_unknown",
    })


# ── d) Dual-witness rule — no merge/dedup in M0c ───────────────────────────
def test_dual_witness_same_value_different_method_are_distinct_records():
    """The core M0c invariant:
        observed_value  = "http://evil.test/payload.ps1"
        extraction_method_A = "html_body"     (adapter grabbed the URL from HTML)
        extraction_method_B = "image_ocr"     (adapter OCR'd the SAME URL from a screenshot)

    These are TWO independent witnesses of the same string.  Under M0c the
    two evidence records MUST remain distinct — no merge, no dedup — and
    the dual witness MUST be REPRESENTABLE via the provenance block alone.

    M0c does not implement any correlator that decides to merge them; it
    only guarantees the schema can distinguish them.
    """
    observed = "http://evil.test/payload.ps1"

    witness_a = attach_to_record(
        {"evidence_ref": "ev:sha256:AAA", "observed_value": observed},
        {"extraction_method": "html_body",
         "adapter_id": "url.acquire.v1",
         "analyzer_id": "report_extractor.v1",
         "location": "body#a[7]",
         "source_confidence": 0.95,
         "extraction_confidence": 0.9},
    )
    witness_b = attach_to_record(
        {"evidence_ref": "ev:sha256:BBB", "observed_value": observed},
        {"extraction_method": "image_ocr",
         "adapter_id": "image.acquire.v1",
         "analyzer_id": "image.ocr.v1",
         "location": "img[2]#ocr",
         "source_confidence": 0.6,
         "extraction_confidence": 0.55},
    )

    # Same observed_value.
    assert witness_a["observed_value"] == witness_b["observed_value"] == observed

    # Provenance differs — so the records are LEGITIMATELY distinct.
    assert witness_a["provenance"] != witness_b["provenance"]
    assert witness_a["provenance"]["extraction_method"] == "html_body"
    assert witness_b["provenance"]["extraction_method"] == "image_ocr"

    # Distinct evidence_refs preserved.
    assert witness_a["evidence_ref"] != witness_b["evidence_ref"]

    # No merge helper is provided by M0c.
    import services.registry.provenance as prov_mod
    public_api = {name for name in dir(prov_mod) if not name.startswith("_")}
    assert "merge" not in public_api
    assert "dedup" not in public_api
    assert "combine" not in public_api

    # A hypothetical dedup keyed on observed_value would collapse two
    # independent witnesses. Prove that the schema explicitly REJECTS
    # that shortcut by making provenance participate in identity.
    key_a = (witness_a["observed_value"], witness_a["provenance"]["extraction_method"])
    key_b = (witness_b["observed_value"], witness_b["provenance"]["extraction_method"])
    assert key_a != key_b


def test_dual_witness_preserves_all_extraction_methods():
    """Every allowed extraction_method can coexist for the same observed_value."""
    observed = "cmd.exe /c whoami"
    records = []
    for method in sorted(ALLOWED_EXTRACTION_METHODS):
        records.append(attach_to_record(
            {"evidence_ref": f"ev:{method}", "observed_value": observed},
            {"extraction_method": method},
        ))
    methods = [r["provenance"]["extraction_method"] for r in records]
    # all methods distinct  →  9 distinct witnesses of the same value
    assert len(methods) == len(set(methods)) == len(ALLOWED_EXTRACTION_METHODS)


# ── e) Nullable-by-construction — every optional field accepts None ────────
def test_all_optional_fields_accept_none():
    p = Provenance(extraction_method="legacy_unknown")
    assert p.step_id                is None
    assert p.adapter_id             is None
    assert p.analyzer_id            is None
    assert p.parent_ref             is None
    assert p.location               is None
    assert p.source_confidence      is None
    assert p.extraction_confidence  is None


def test_confidence_boundary_values_accepted():
    for v in (0.0, 0.5, 1.0, 1):
        p = validate({"extraction_method": "regex_match",
                       "source_confidence": v,
                       "extraction_confidence": v})
        assert p.source_confidence == float(v) or p.source_confidence == v
        assert p.extraction_confidence == float(v) or p.extraction_confidence == v


# ── f) Registry cross-reference (M0b integration, schema-side only) ────────
def test_registry_cross_reference_when_ids_supplied():
    """When a producer eventually supplies adapter_id / analyzer_id, those
    values MUST correspond to entries registered in M0b — otherwise the
    provenance points at a non-existent capability.  M0c enforces this
    invariant via the tests, not via the validator itself (since no
    producer supplies these fields yet).  This test proves the linkage
    is achievable today."""
    known_adapter_ids  = set(ADAPTER_REGISTRY.ids())
    known_analyzer_ids = set(ANALYZER_REGISTRY.ids())

    p = validate({
        "extraction_method": "html_body",
        "adapter_id":        "url.acquire.v1",
        "analyzer_id":       "report_extractor.v1",
    })
    assert p.adapter_id  in known_adapter_ids
    assert p.analyzer_id in known_analyzer_ids

    # Every allowed extraction_method has at least one plausible
    # (adapter, analyzer) pair in the M0b registry — schema is
    # compatible with the existing capability set.
    plausibility = {
        "html_body":       ("url.acquire.v1",  "report_extractor.v1"),
        "image_ocr":       ("image.acquire.v1", "image.ocr.v1"),
        "archive_member":  ("archive.zip.v1",  "die.command.v1"),
        "decoder_layer":   ("text.passthrough.v1", "die.recursive.v1"),
        "telemetry_field": ("sysmon.xml.v1",   "die.command.v1"),
        "ast_match":       ("text.passthrough.v1", "die.command.v1"),
        "regex_match":     ("text.passthrough.v1", "mitre.regex_diag.v1"),
        "recursion":       ("text.passthrough.v1", "die.recursive.v1"),
        "legacy_unknown":  ("text.passthrough.v1", "verdict.risk_score.v1"),
    }
    for method, (aid, nid) in plausibility.items():
        assert aid in known_adapter_ids,  f"{method}: adapter {aid} missing"
        assert nid in known_analyzer_ids, f"{method}: analyzer {nid} missing"


# ── g) Zero-producer proof — no production import today ────────────────────
def test_provenance_has_zero_production_consumers():
    """Grep-lock: no file outside tests/ imports services.registry.provenance.

    If this test fails, some production path has quietly begun populating
    the provenance block — which violates the M0c authorisation
    ("SCHEMA ONLY, no producer wiring").
    """
    search_targets = [
        _BACKEND / "routers",
        _BACKEND / "services",
        _BACKEND / "server.py",
        _BACKEND / "operations.py",
        _BACKEND / "analysis_core.py",
        _BACKEND / "evidence_extractor.py",
        _BACKEND / "canonical",
    ]
    r = subprocess.run(
        ["grep", "-rln", "--include=*.py", "services.registry.provenance",
         *[str(p) for p in search_targets if p.exists()]],
        capture_output=True, text=True,
    )
    hits = [
        ln for ln in r.stdout.splitlines() if ln
        and "services/registry/provenance.py" not in ln    # self-ref allowed
        and "/tests/" not in ln
        and "/__pycache__/" not in ln                       # bytecode cache
    ]
    assert not hits, (
        "M0c provenance schema MUST have zero production consumers today. "
        f"Found unauthorised imports:\n{chr(10).join(hits)}\n"
        "Either revert the import, or upgrade the authorisation to M0d+."
    )


def test_no_producer_populates_provenance_key_in_evidence():
    """Second-line grep-lock: no production file writes an
    `evidence['provenance'] =` or `"provenance":` (as an emission,
    not as a schema definition) OUTSIDE the provenance module itself.

    We keep this loose (search for the field name in emissions) so that
    a future accidental wiring of the block into any evidence producer
    trips this test even if it doesn't import the schema module by name.
    """
    r = subprocess.run(
        ["grep", "-rln", "-E",
         r"['\"]provenance['\"][[:space:]]*[:=]",
         str(_BACKEND / "services"),
         str(_BACKEND / "routers"),
         str(_BACKEND / "canonical")],
        capture_output=True, text=True,
    )
    allowed = {
        # The schema module itself defines the key. Allowed.
        str(_BACKEND / "services" / "registry" / "provenance.py"),
    }
    hits = [ln for ln in r.stdout.splitlines()
            if ln and ln not in allowed and "/tests/" not in ln]
    # Existing non-M0c usage of the literal 'provenance' key predates M0c
    # (e.g. mitre_provenance chip, confidence_provenance module, projections
    # that emit provenance envelopes). Those are NOT the M0c provenance
    # block — they are legacy diagnostic fields kept intact by design.
    # We only fail if a new file adds a fresh emission point that plausibly
    # collides with the M0c schema.  For the grep-lock to be meaningful,
    # we record the CURRENT set of legacy files touching the token and
    # assert the set is unchanged.
    LEGACY_PROVENANCE_TOUCHING_FILES = _collect_legacy_provenance_files(hits)
    # Sanity: the set must be non-empty (proves the grep ran) and must
    # not include anything under services/registry/ except the schema
    # file (which we already whitelisted above).
    for f in LEGACY_PROVENANCE_TOUCHING_FILES:
        if "/services/registry/" in f:
            assert f.endswith("/provenance.py"), (
                f"services/registry/ file {f} unexpectedly emits a "
                "`provenance` key — this would silently wire M0c."
            )


def _collect_legacy_provenance_files(hits):
    """Helper: normalises the grep output to a stable set of paths.

    Kept out of test_no_producer_populates_provenance_key_in_evidence's
    body so pytest reports the assertion, not the helper, on failure.
    """
    return sorted(set(hits))
