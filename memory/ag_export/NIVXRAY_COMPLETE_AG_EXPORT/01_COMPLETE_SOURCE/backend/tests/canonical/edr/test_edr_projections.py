"""EDR projection contract tests · Slice 2 · P0.

Locks:
  - Detections are a READ-ONLY projection of
    ``workspace_cases.verdict_stage2.evidence[]`` (no native detection
    engine exists in the repo, verified 2026-08-29).
  - Every projected detection surfaces ``detected_by`` explicitly.
  - Process Tree reuses the existing canonical Activity Inventory.
    An incident with no timeline attached returns an honest
    ``no_matching_evidence`` reason — never a fabricated tree.
"""
from __future__ import annotations

import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[3]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from routers.edr import (  # noqa: E402
    _project_detections, _project_process_tree, _RULE_SEVERITY,
)


# ── Helpers ──────────────────────────────────────────────────────────
def _case_with_stage2():
    return {
        "id":         "case-xyz-1",
        "user_email": "analyst@nivxray.com",
        "created_at": "2026-08-29T10:00:00+00:00",
        "verdict_stage2": {
            "label": "malicious",
            "risk_score": 92,
            "confidence_bucket": "high",
            "evidence": [
                {"rule_id": "CMD-OBFUSCATION",       "weight": 30},
                {"rule_id": "PROC-SUSPICIOUS-PARENT", "weight": 25,
                    "process": "powershell.exe"},
                {"rule_id": "MITRE-IMPACT",          "weight": 20},
            ],
        },
        "ssot": {
            "investigation_object": {
                "host": "HOST-001",
            },
        },
    }


# ── Detections ───────────────────────────────────────────────────────
def test_detections_empty_when_no_stage2():
    rows = _project_detections({"id": "c1"})
    assert rows == []


def test_detections_project_from_stage2_evidence():
    rows = _project_detections(_case_with_stage2())
    assert len(rows) == 3
    for r in rows:
        # Contract: every row surfaces these operational fields.
        for k in ("detection_id", "detection", "rule_id", "detected_by",
                    "detection_source", "severity", "device",
                    "user", "disposition", "incident_id",
                    "evidence_ref"):
            assert k in r
        # Contract: detected_by is human-readable and identifies the
        # engine that produced the row (never blank, never faked).
        assert r["detected_by"] == "NivXRay Verdict Engine · Stage-2"
        # Contract: provenance points back to the source array.
        assert r["detection_source"] == "workspace_cases.verdict_stage2.evidence[]"
        assert r["evidence_ref"]["type"] == "stage2_rule_evidence"
        assert r["incident_id"] == "case-xyz-1"


def test_detections_severity_map_from_known_rules():
    rows = _project_detections(_case_with_stage2())
    by_rule = {r["rule_id"]: r for r in rows}
    assert by_rule["CMD-OBFUSCATION"]["severity"]     == _RULE_SEVERITY["CMD-OBFUSCATION"]
    assert by_rule["MITRE-IMPACT"]["severity"]        == _RULE_SEVERITY["MITRE-IMPACT"]


def test_detections_carry_incident_context():
    rows = _project_detections(_case_with_stage2())
    for r in rows:
        assert r["device"] == "HOST-001"
        assert r["user"]   == "analyst@nivxray.com"
        assert r["disposition"] == "malicious"


# ── Process Tree ─────────────────────────────────────────────────────
def test_process_tree_empty_when_no_timeline():
    """Case with no attached timeline → honest empty tree."""
    tree = _project_process_tree({"id": "c1", "ssot": {}})
    assert tree["reason"] == "no_matching_evidence"
    assert tree["nodes"]  == []
    assert tree["roots"]  == []


def test_process_tree_when_timeline_attached_returns_ok():
    """Case WITH a canonical timeline attached returns a real tree
    projected from services.activity.ActivityInventory (SSOT)."""
    doc = {
        "id": "c2",
        "user_email": "analyst@nivxray.com",
        "tenant_id":  "acme",
        "ssot": {"timeline": {
            "events": [
                {"event_id": "e1", "timestamp": "2026-06-15T14:30:00+00:00",
                    "process": "explorer.exe", "user": "user1",
                    "host": "HOST-001", "action": "execute",
                    "provenance_chain": ["iue.intake:e1"]},
                {"event_id": "e2", "timestamp": "2026-06-15T14:30:15+00:00",
                    "process": "powershell.exe", "parent_process": "explorer.exe",
                    "user": "user1", "host": "HOST-001", "action": "execute",
                    "provenance_chain": ["iue.intake:e2"]},
            ]}},
    }
    tree = _project_process_tree(doc)
    assert tree["reason"] == "ok"
    assert tree["source"] == "services.activity.ActivityInventory"
    assert len(tree["nodes"]) >= 2
    # Each node has the pivot metadata required by the UI.
    for n in tree["nodes"]:
        assert "entity_id" in n
        assert "process"   in n
        assert "pivots"    in n
        assert n["pivots"]["trajectory"] == "/edr/trajectory"
