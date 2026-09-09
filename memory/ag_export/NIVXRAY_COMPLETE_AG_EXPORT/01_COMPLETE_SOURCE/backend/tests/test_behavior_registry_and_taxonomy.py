"""P0.11 · Behavior Registry + traceability BROKEN_AT_* taxonomy."""
from __future__ import annotations

from fastapi.testclient import TestClient

from server import app
from services.ida.behavior_registry import build_registry
from services.ida.projections.mitre import BEHAVIOR_TO_MITRE


client = TestClient(app)


# ══════════════════════════════════════════════════════════════════
# Behavior Registry
# ══════════════════════════════════════════════════════════════════
def test_registry_covers_entire_behavior_vocabulary():
    reg = build_registry()
    assert set(reg.keys()) == set(BEHAVIOR_TO_MITRE.keys())


def test_every_registry_entry_has_deterministic_derived_fields():
    reg = build_registry()
    for btype, spec in reg.items():
        assert spec.id == btype
        assert spec.canonical_name
        # Projections must match the frozen maps.
        assert spec.projections["mitre"] == list(
            BEHAVIOR_TO_MITRE.get(btype, ()))
        # Consumers are the fixed downstream set.
        assert "services.ida.projections.mitre.project_to_mitre" \
            in spec.consumers
        # Producers non-empty (every vocab entry has at least one
        # code path that emits it).
        assert spec.producers


def test_supporting_rules_populated_when_mitre_overlaps():
    reg = build_registry()
    # T1490 is referenced by ransomware recovery rules — so
    # shadow_copy_deletion must list them.
    assert any("erad." in r or "rec." in r
                   for r in reg["shadow_copy_deletion"].supporting_rules)


def test_registry_endpoint_returns_list():
    r = client.get("/api/behaviors/registry")
    assert r.status_code == 200
    body = r.json()
    assert body["schema_version"] == "1.0"
    assert body["count"] == len(build_registry())
    assert body["behaviors"]


def test_registry_endpoint_returns_single_entry():
    r = client.get("/api/behaviors/registry/shadow_copy_deletion")
    assert r.status_code == 200
    body = r.json()
    assert body["behavior"]["id"] == "shadow_copy_deletion"
    assert "T1490" in body["behavior"]["projections"]["mitre"]


def test_registry_endpoint_404_for_unknown():
    r = client.get("/api/behaviors/registry/does_not_exist_9999")
    assert r.status_code == 404


# ══════════════════════════════════════════════════════════════════
# BROKEN_AT_* taxonomy on traceability
# ══════════════════════════════════════════════════════════════════
def test_traceability_uses_broken_at_taxonomy():
    """Every broken chain must carry ``broken_at`` in the fixed
    BROKEN_AT_* vocabulary (per user directive · 2026-02-05)."""
    from scripts.corpus_validation import run_corpus
    import json, pathlib
    manifest = json.loads(pathlib.Path("corpus/manifest.json")
                                 .read_text(encoding="utf-8"))
    r = run_corpus(manifest)
    allowed = {
        "BROKEN_AT_BEHAVIOR", "BROKEN_AT_PROJECTION",
        "BROKEN_AT_RULE", "BROKEN_AT_RECOMMENDATION",
        "BROKEN_AT_POLICY", "BROKEN_AT_UI",
    }
    for case in r["per_case"]:
        for br in case["traceability"]["broken_chains"]:
            assert br["broken_at"] in allowed, (
                f"unknown broken_at value: {br['broken_at']!r}")
            assert br["last_successful"], "missing last_successful"
            assert br["reason"], "missing reason"
