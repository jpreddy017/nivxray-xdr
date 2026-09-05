"""T1-D · SSOT write · ``canonical_bytes`` + ``compute_checksum`` golden.

Freezes the deterministic canonical-JSON serialisation used by the
content-addressable SSOT store.  The checksum is the true byte-identity
contract: any Stage-1 change that alters the serialisation of an
identical SSOT payload will flip this hash and fail the test.
"""
from __future__ import annotations

import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[3]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from tests.canonical.stage1_goldens._harness import compare_or_capture


def _fixture_ssot():
    """Deterministic SSOT payload – ordering intentionally scrambled
    so ``sort_keys=True`` in ``canonical_bytes`` is exercised."""
    return {
        "report_extraction": {
            "commands": [
                {"normalized_command": "powershell -enc AAAA",
                 "mitre": ["T1059.001"]},
            ],
            "mitre_techniques": [
                {"id": "T1059.001", "name": "PowerShell",
                 "tactic": "execution"},
            ],
            "threat_actors": [{"name": "TestActor"}],
        },
        "document_profile": {"vendor": "Test", "title": "T1D"},
        "input": {"raw": "https://test.example.gov/advisory/t1d"},
        "acquired_document": {
            "ok": True, "url": "https://test.example.gov/advisory/t1d",
            "engine": "trafilatura",
        },
        "understanding": {"input_type": "threat_report_url",
                           "confidence": 0.9},
    }


def test_t1_d_canonical_bytes_stable():
    from services.ssot_store import canonical_bytes, compute_checksum
    ssot = _fixture_ssot()
    payload_bytes = canonical_bytes(ssot)
    checksum = compute_checksum(ssot)

    # canonical_bytes MUST be deterministic across calls.
    assert canonical_bytes(ssot) == payload_bytes

    frozen = {
        "canonical_bytes_len": len(payload_bytes),
        "canonical_bytes_sample_prefix": payload_bytes[:200].decode(
            "utf-8", errors="replace"),
        "checksum": checksum,
    }
    compare_or_capture("t1_d_canonical_bytes", frozen)


def test_t1_d_checksum_ignores_persisted_at():
    """``canonical_bytes`` scrubs the persisted_at / checksum /
    investigation_id / ssot_ref keys before hashing.  Adding these
    fields MUST NOT change the checksum."""
    from services.ssot_store import compute_checksum
    a = _fixture_ssot()
    b = dict(a)
    b["persisted_at"] = "2026-02-14T12:00:00Z"
    b["checksum"] = "deadbeef"
    b["investigation_id"] = "ignored"
    b["ssot_ref"] = {"id": "x", "checksum": "y"}

    assert compute_checksum(a) == compute_checksum(b), (
        "SSOT content-addressing regressed — extra volatile fields "
        "changed the deterministic checksum."
    )
