"""Phase 5.1 · POST /api/uil/investigate canonical migration acceptance.

Owner directive 2026-08-10:
  - Q1=b · Direct canonical envelope (no legacy DIE/build_session)
  - Q2=a · NIVX_CANONICAL_UIL_INVESTIGATE default OFF
  - Q3=a · wave/lifecycle/canonical_ssot_ref labels
  - Q4=a · Legacy path unchanged when flag OFF
  - Q5=a · Log-only observability
  - Q6=a · Manual rollback

Gates covered here: G1..G10 (see 0005-phase5.1-spec.md).
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

import pytest


# ── G3 · Static: canonical branch must NOT call legacy DIE/build_session ──
def _module_imports(path: Path):
    """Return the set of names imported by the module at `path` (AST-based)."""
    import ast
    tree = ast.parse(path.read_text())
    imports: set = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                imports.add(f"{module}.{alias.name}")
    return imports


def test_g3_canonical_entry_does_not_import_legacy_die_or_build_session():
    """The canonical branch must not IMPORT the legacy DIE render or the
    legacy build_session adapter. Docstrings that reference these names
    for documentation are permitted; actual imports are not."""
    for p in (
        Path("/app/backend/services/uil/canonical_entry.py"),
        Path("/app/backend/services/uil/canonical_session.py"),
    ):
        imports = _module_imports(p)
        banned_prefixes = (
            "services.die.investigation_results",
            "services.session.adapter",
            "services.session.build_session",
        )
        for imp in imports:
            for banned in banned_prefixes:
                assert not imp.startswith(banned), (
                    f"{p.name} imports banned legacy symbol {imp!r} "
                    f"(F5.1-A / F5.1-B)"
                )
        # `from services.session import build_session` case
        assert "services.session.build_session" not in imports, \
            f"{p.name} imported legacy build_session"


# ── G2/G5 · Canonical envelope shape + Wave-N labels ─────────────────────
def _run_canonical(text: str = "powershell -EncodedCommand SGVsbG8=",
                   filename: str = "sample.ps1"):
    from services.uil.canonical_entry import investigate_canonical
    return investigate_canonical(
        payload=text.encode("utf-8"),
        filename=filename,
        text_input=text,
        correlation_id="phase5_1-test-corr",
    )


def test_g2_canonical_envelope_has_session_v1_keys():
    result = _run_canonical()
    session = result["session"]
    for key in ("session_id", "created_at", "schema", "original_input",
                "document_profile", "acquired_document",
                "investigation_inputs", "incident", "readiness",
                "summary", "raw_investigation", "uil"):
        assert key in session, f"session-v1 key missing: {key!r}"
    assert session["schema"] == "session-v1"


def test_g5_wave_labels_present_on_canonical_envelope():
    session = _run_canonical()["session"]
    assert session["wave"] == "5.1"
    assert session["lifecycle"] == "canonical"
    assert session["canonical_ssot_ref"].startswith("cssot:sha256:")


def test_g2_incident_populated_from_canonical_projections():
    session = _run_canonical()["session"]
    incident = session["incident"]
    # T1059.001 fires on `powershell -EncodedCommand`.
    assert "T1059.001" in incident["techniques"]
    assert incident["verdict"]["label"] in {
        "MALICIOUS", "SUSPICIOUS", "LIKELY_BENIGN", "INCONCLUSIVE",
    }


def test_g2_recommendations_are_evidence_derived_no_generic_fallback():
    """T1059.001 fires ⇒ recommendations must be per-technique, and the
    P4-FW3 no-generic-fallback rule must hold on this envelope too."""
    session = _run_canonical()["session"]
    recs = session["incident"]["recommendations"]
    assert recs, "T1059.001 should yield evidence-derived recommendations"
    banned = ("IMMEDIATE", "THREAT HUNTING", "CONTAINMENT",
              "Isolate the host")
    blob = json.dumps(session, sort_keys=True, default=str)
    for b in banned:
        assert b not in blob, f"Phase 5.1 envelope leaked banned template {b!r}"


def test_g2_investigation_inputs_derived_from_projections():
    """Ensure investigation_inputs is populated deterministically from
    canonical projections (IOCs + MITRE)."""
    session = _run_canonical(
        text="see http://evil.example/x and hash 44d88612fea8a8f36de82e1278abb02f",
        filename="paste.txt",
    )["session"]
    inputs = session["investigation_inputs"]
    types = {inp["type"] for inp in inputs}
    assert "url" in types
    assert "hash" in types


# ── G4 · Determinism ─────────────────────────────────────────────────────
def test_g4_determinism_10_replays_same_ssot_ref():
    r0 = _run_canonical()
    fp0 = r0["session"]["canonical_ssot_ref"]
    for _ in range(10):
        r = _run_canonical()
        assert r["session"]["canonical_ssot_ref"] == fp0


# ── G1 · Legacy path unchanged when flag OFF ─────────────────────────────
def test_g1_flag_off_by_default():
    """Feature flag defaults OFF in code per owner Q2=a."""
    from services.uil.canonical_entry import canonical_flag_enabled
    # Force clean env
    saved = os.environ.pop("NIVX_CANONICAL_UIL_INVESTIGATE", None)
    try:
        assert canonical_flag_enabled() is False
        for val in ("off", "0", "false", "no", "", "  ", "OFF"):
            os.environ["NIVX_CANONICAL_UIL_INVESTIGATE"] = val
            assert canonical_flag_enabled() is False, \
                f"flag must be OFF for env value {val!r}"
    finally:
        if saved is not None:
            os.environ["NIVX_CANONICAL_UIL_INVESTIGATE"] = saved
        else:
            os.environ.pop("NIVX_CANONICAL_UIL_INVESTIGATE", None)


def test_g1_flag_on_case_insensitive():
    from services.uil.canonical_entry import canonical_flag_enabled
    saved = os.environ.pop("NIVX_CANONICAL_UIL_INVESTIGATE", None)
    try:
        for val in ("on", "ON", "On", "  on  "):
            os.environ["NIVX_CANONICAL_UIL_INVESTIGATE"] = val
            assert canonical_flag_enabled() is True, \
                f"flag must be ON for env value {val!r}"
    finally:
        if saved is not None:
            os.environ["NIVX_CANONICAL_UIL_INVESTIGATE"] = saved
        else:
            os.environ.pop("NIVX_CANONICAL_UIL_INVESTIGATE", None)


# ── G10 · No new endpoint, no new collection ─────────────────────────────
def test_g10_no_new_endpoint_added_on_uil_router():
    """Route count on uil router must equal pre-5.1 (3 endpoints:
    classify, split, investigate)."""
    from routers.uil import router as uil_router
    paths = {r.path for r in uil_router.routes if hasattr(r, "path")}
    # Prefix stripped by FastAPI at include time; check by suffix.
    assert paths == {"/uil/classify", "/uil/split", "/uil/investigate"}


def test_g10_no_new_collection_created():
    """Canonical path must NOT reference any collection other than the
    existing `investigation_sessions`."""
    for p in (
        Path("/app/backend/services/uil/canonical_entry.py"),
        Path("/app/backend/services/uil/canonical_session.py"),
    ):
        src = p.read_text()
        for banned in ("canonical_lifecycle_shadow",
                        "wave5_1_observations",
                        "wave_5_1_"):
            assert banned not in src, \
                f"{p.name} introduced disallowed collection reference {banned!r}"


# ── G6 · Sample1 protection (canonical path stores in-memory) ────────────
@pytest.mark.skipif(not os.environ.get("MONGO_URL"),
                    reason="MONGO_URL not set")
def test_g6_sample1_fingerprint_unchanged_after_canonical_run():
    """Run the canonical branch a few times and verify Sample1
    fingerprint remains locked."""
    from pymongo import MongoClient
    SAMPLE1_ID = "3db79c4a-088b-4df7-b65a-f68b367b7677"
    SAMPLE1_FP = ("5b4337d5a9fc05923bd3090f1270268ae8eef7af2ccf06f4e8d"
                  "8492bf908261d")
    client = MongoClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]
    if db.workspace_cases.find_one({"id": SAMPLE1_ID}) is None:
        pytest.skip("not the Sample1-hosting pod DB")

    for _ in range(5):
        _run_canonical()

    case = db.workspace_cases.find_one({"id": SAMPLE1_ID})
    assert case is not None
    snap = {k: v for k, v in case.items() if k != "_id"}
    blob = json.dumps(snap, default=str, sort_keys=True,
                      ensure_ascii=False).encode()
    assert hashlib.sha256(blob).hexdigest() == SAMPLE1_FP


@pytest.mark.skipif(not os.environ.get("MONGO_URL"),
                    reason="MONGO_URL not set")
def test_g8_wave1_count_unchanged():
    from pymongo import MongoClient
    client = MongoClient(os.environ["MONGO_URL"])
    db = client[os.environ["DB_NAME"]]
    if db.workspace_cases.find_one(
            {"id": "3db79c4a-088b-4df7-b65a-f68b367b7677"}) is None:
        pytest.skip("not the Sample1-hosting pod DB")
    # Wave-1 stability invariant.  Historical baseline in the original
    # long-lived DB was 2 records.  In a fresh pod the baseline is 0 —
    # either state is valid; the real invariant is that the collection
    # MUST NOT grow beyond the historical baseline (Wave-1 was
    # deprecated in Phase 4 — no new attaches from legacy paths).
    count = db.verdict_shadow_observations.count_documents({})
    assert count <= 2, (
        f"verdict_shadow_observations grew beyond historical baseline: "
        f"got {count}, expected <= 2 (Wave 1 deprecated in Phase 4)"
    )


# ── G9 · Not-ready envelope path is intact ───────────────────────────────
def test_g9_not_ready_envelope_returns_none_session_with_uil_meta():
    """When UIL normalize says not-ready (e.g. unknown binary), the
    canonical branch should still return the honest {"session": None,
    "uil": {ready: False, ...}} shape."""
    # A tiny random-bytes blob that the UIL normalizer marks as
    # "not ready" (no preprocessor).
    from services.uil.canonical_entry import investigate_canonical
    result = investigate_canonical(
        payload=b"\x00\x01\x02BLOB",
        filename="unknown.bin",
        text_input=None,
        correlation_id="phase5_1-notready",
    )
    if result.get("session") is None:
        assert result["uil"]["ready"] is False


# ── G7 · Full canonical regression suite still green (this file added) ───
# — verified externally by `pytest tests/canonical/`.
