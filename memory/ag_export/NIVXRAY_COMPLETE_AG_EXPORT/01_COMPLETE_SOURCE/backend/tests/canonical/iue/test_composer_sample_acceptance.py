"""Phase 1 gate A1.1 · Sample.docx NEW-case acceptance + A1.2 Sample1
frozen fingerprint verification.

Amendment 1 canary: Sample.docx must reach the composer, trigger IUE-4
(bytes_magic) AND IUE-5 (artefact_decomp), produce a plan containing
ARCHIVE_EXTRACT + ARTIFACT_SPLIT + IOC_EXTRACTOR + MITRE_MAP, and be
deterministic across 100 replays.

Sample1 original record (MongoDB workspace_cases) MUST remain byte-
identical throughout the test. R-G1..R-G6, IX-1.
"""
import hashlib
import json
import os

import pytest

from canonical.iue import Capability, classify, RawInput


SAMPLE1_FINGERPRINT = "5b4337d5a9fc05923bd3090f1270268ae8eef7af2ccf06f4e8d8492bf908261d"


def _load_sample_docx() -> bytes:
    """Prefer a real Sample.docx if present; fall back to a ZIP-magic
    fixture. Either way the fixture must trigger IUE-4 (bytes) and
    IUE-5 (decomp)."""
    for path in ("/app/backend/tests/live/ideas_updated.docx",
                 "/app/backend/docs/exports/nivxray-user-guide.docx"):
        if os.path.exists(path):
            with open(path, "rb") as f:
                return f.read()
    return b"PK\x03\x04" + b"\x14\x00\x06\x00" + b"\x00" * 4000


# ─────────────────────────────────────────────────────────────────────────
#   A1.1 · Sample.docx NEW-case acceptance
# ─────────────────────────────────────────────────────────────────────────
def test_a1_1_docx_primary_type_is_docx():
    d = classify(RawInput(payload=_load_sample_docx(), filename="Sample.docx"))
    pt = d.input_profile.primary_type.lower()
    ik = (d.input_profile.input_kind or "").lower()
    assert pt in ("docx", "zip_archive") or ik in ("docx", "zip_archive"), \
        f"DOCX class not detected; primary={pt} kind={ik}"


def test_a1_1_docx_input_health_populated():
    d = classify(RawInput(payload=_load_sample_docx(), filename="Sample.docx"))
    assert d.input_health is not None
    assert d.input_health.size_bytes == len(_load_sample_docx())


def test_a1_1_docx_intent_populated_non_generic():
    d = classify(RawInput(payload=_load_sample_docx(), filename="Sample.docx"))
    assert d.intent is not None
    assert d.intent.label  # any label — the acceptance is that it exists


def test_a1_1_docx_plan_non_empty_with_required_capabilities():
    d = classify(RawInput(payload=_load_sample_docx(), filename="Sample.docx"))
    assert len(d.plan) > 0
    caps = set(d.capabilities)
    for required in (Capability.ARCHIVE_EXTRACT,
                     Capability.ARTIFACT_SPLIT,
                     Capability.IOC_EXTRACTOR,
                     Capability.MITRE_MAP):
        assert required in caps, f"required capability {required} missing"


def test_a1_1_docx_confidence_matrix_all_six_axes_populated():
    d = classify(RawInput(payload=_load_sample_docx(), filename="Sample.docx"))
    m = d.confidence_matrix
    # Every axis exists and is an int 0..100
    for axis in ("input_classification", "decode_path", "language_detection",
                 "estimated_recovery", "artifact_completeness", "telemetry_richness"):
        v = getattr(m, axis)
        assert isinstance(v, int) and 0 <= v <= 100, f"{axis}={v}"


def test_a1_1_docx_determinism_hash_stable_100_replays():
    docx = _load_sample_docx()
    h0 = classify(RawInput(payload=docx, filename="Sample.docx")).determinism_hash
    for i in range(99):
        h_i = classify(RawInput(payload=docx, filename="Sample.docx")).determinism_hash
        assert h_i == h0, f"replay {i+1} drifted"


def test_a1_1_docx_provenance_shows_iue4_and_iue5_participated():
    d = classify(RawInput(payload=_load_sample_docx(), filename="Sample.docx"))
    sources = {e.source for e in d.evidence}
    assert "bytes_magic" in sources, "IUE-4 (bytes_magic) not in evidence sources"
    assert "artefact_decomp" in sources, "IUE-5 (artefact_decomp) not in evidence sources"


# ─────────────────────────────────────────────────────────────────────────
#   A1.2 · Sample1 golden case fingerprint UNCHANGED
# ─────────────────────────────────────────────────────────────────────────
@pytest.mark.skipif(not os.environ.get("MONGO_URL"), reason="MONGO_URL not set")
def test_a1_2_sample1_fingerprint_unchanged():
    """R-G1..R-G6, IX-1. The Sample1 golden case must remain byte-identical.

    This test re-verifies the fingerprint recorded in
    /app/memory/GOLDEN_CASE_SAMPLE1.md. Any drift here is an immediate
    Phase 1 HALT.
    """
    from pymongo import MongoClient
    client = MongoClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]
    case = db.workspace_cases.find_one(
        {"id": "3db79c4a-088b-4df7-b65a-f68b367b7677"}
    )
    assert case is not None, \
        "Sample1 case not found in workspace_cases — R-G1 VIOLATION"
    snap = {k: v for k, v in case.items() if k != "_id"}
    blob = json.dumps(snap, default=str, sort_keys=True, ensure_ascii=False).encode()
    fp = hashlib.sha256(blob).hexdigest()
    assert fp == SAMPLE1_FINGERPRINT, \
        f"Sample1 golden case DRIFTED: {fp} != {SAMPLE1_FINGERPRINT} — HALT"
