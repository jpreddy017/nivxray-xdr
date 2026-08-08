"""P0.7 · Behavior Provenance Endpoint + CI invariant on rule library.

Locks two contracts:
    1. ``POST /api/investigation/behaviors/explain`` returns the
       stable Evidence → Behavior → Projection → Recommendation
       graph.  Response schema is versioned (``schema_version``)
       and does not leak internals like ``behaviors_full``.
    2. No RecommendationRule in ``services/mitigation/evidence_driven/
       rule_library.py`` may inspect raw Evidence fields
       (``output_text``, ``processes``, ``commands``, ``files``,
       ``registry_keys``).  Rules can only read the projected
       semantic fields (``behaviors``, ``impacts``,
       ``mitre_techniques``) plus the structured IOC bags.
"""
from __future__ import annotations

import ast
import pathlib
from typing import List

from fastapi.testclient import TestClient

from server import app


client = TestClient(app)


# ══════════════════════════════════════════════════════════════════
# Behavior Provenance Endpoint · public contract
# ══════════════════════════════════════════════════════════════════
def test_endpoint_returns_stable_schema_and_projection_chain():
    payload = {
        "behaviors": [
            {"behavior_type": "shadow_copy_deletion",
             "label":         "Shadow copy deletion",
             "source":        "command_classifier",
             "source_ref":    "body.line.37",
             "provenance":    "command_execution",
             "confidence":    "deterministic",
             "evidence":      {"command": "vssadmin delete shadows /all"}},
            {"behavior_type": "data_encryption_for_impact",
             "label":         "Ransomware family: Medusa",
             "source":        "malware_lookup",
             "source_ref":    "malware:Medusa",
             "provenance":    "malware_reference",
             "confidence":    "deterministic",
             "evidence":      {"malware_family": "Medusa"}},
        ]
    }
    r = client.post("/api/investigation/behaviors/explain", json=payload)
    assert r.status_code == 200, r.text
    body = r.json()

    # ── Stable versioned schema ────────────────────────────────
    assert body["schema_version"] == "1.0"
    assert "behaviors" in body
    assert "verdict"   in body
    assert "summary"   in body
    # Internal names must NOT leak
    assert "behaviors_full" not in body

    # ── Each behavior carries full projection chain ────────────
    for b in body["behaviors"]:
        assert set(b.keys()) >= {
            "id", "behavior_type", "label", "source", "provenance",
            "confidence", "evidence", "observed_at",
            "projections", "recommendations",
        }
        assert set(b["projections"].keys()) == {
            "mitre", "kill_chain", "impacts"
        }
        assert isinstance(b["recommendations"], list)

    # ── Semantics · vssadmin should project to T1490/impact ──
    shadow = next(b for b in body["behaviors"]
                   if b["behavior_type"] == "shadow_copy_deletion")
    assert "T1490"                in shadow["projections"]["mitre"]
    assert "impact"               in shadow["projections"]["kill_chain"]
    assert "recovery_inhibited"   in shadow["projections"]["impacts"]
    # ── Recommendations attributed to shadow_copy_deletion ────
    # (erad.protect_shadow_copies + rec.restore_backups fire when
    # impact / recovery_inhibited is present).
    assert "erad.protect_shadow_copies" in shadow["recommendations"]

    # ── Summary aggregates ────────────────────────────────────
    assert "impact"             in body["summary"]["kill_chain"]
    assert "recovery_inhibited" in body["summary"]["impacts"]
    assert "T1490"              in body["summary"]["mitre"]
    assert "T1486"              in body["summary"]["mitre"]


def test_endpoint_rejects_missing_behavior_type():
    r = client.post("/api/investigation/behaviors/explain",
                        json={"behaviors": [{"label": "no type"}]})
    assert r.status_code == 400


def test_endpoint_ignores_unknown_fields_on_input():
    """Strict allowlist — extra fields on caller input are dropped,
    not blindly passed to Behavior constructor."""
    r = client.post(
        "/api/investigation/behaviors/explain",
        json={"behaviors": [{
            "behavior_type": "shadow_copy_deletion",
            "label":         "Shadow copy deletion",
            "source":        "command_classifier",
            "provenance":    "command_execution",
            "malicious_extra_field": "attacker attempt to inject",
        }]},
    )
    assert r.status_code == 200


def test_endpoint_deterministic_and_idempotent():
    payload = {
        "behaviors": [{
            "behavior_type": "shadow_copy_deletion",
            "label":         "Shadow copy deletion",
            "source":        "command_classifier",
            "provenance":    "command_execution",
        }]
    }
    a = client.post("/api/investigation/behaviors/explain",
                       json=payload).json()
    b = client.post("/api/investigation/behaviors/explain",
                       json=payload).json()
    assert a == b


def test_endpoint_empty_behaviors_yields_empty_summary():
    r = client.post("/api/investigation/behaviors/explain",
                        json={"behaviors": []})
    assert r.status_code == 200
    body = r.json()
    assert body["behaviors"]           == []
    assert body["summary"]["mitre"]    == []
    assert body["summary"]["impacts"]  == []
    assert body["summary"]["kill_chain"] == []


# ══════════════════════════════════════════════════════════════════
# CI invariant · rules may not inspect raw Evidence fields
# ══════════════════════════════════════════════════════════════════
_BANNED_RAW_EVIDENCE_ATTRS = {
    "output_text", "processes", "commands", "files", "registry_keys",
}


def _find_ctx_attr_reads(source: str) -> List[str]:
    """Walk the AST and find every ``<name>.<attr>`` access to the
    banned raw-evidence attribute set.  Used to prove no rule
    inspects raw evidence via ``c.output_text``, ``c.processes``,
    etc.
    """
    hits: List[str] = []
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            if node.attr in _BANNED_RAW_EVIDENCE_ATTRS:
                # Only flag if the value being attribute-accessed is
                # a plain Name (heuristic for ``c.output_text``, not
                # e.g. ``self.foo.output_text`` inside CaseContext).
                if isinstance(node.value, ast.Name):
                    hits.append(f"{node.value.id}.{node.attr}"
                                f" @ line {node.lineno}")
    return hits


def test_ci_invariant_no_rule_inspects_raw_evidence():
    """Per user directive · 2026-02-05:

        "No Recommendation Rule may inspect raw Evidence.  Only
        Recommendation → Behavior → Projection is allowed."

    Concrete check: no attribute read of the form
    ``<var>.output_text|processes|commands|files|registry_keys`` may
    appear in the rule library.  Rules must consume the projected
    semantic fields (``behaviors``, ``impacts``,
    ``mitre_techniques``) plus structured IOC bags (``ips``,
    ``urls``, ``domains``).
    """
    src = pathlib.Path(
        "services/mitigation/evidence_driven/rule_library.py"
    ).read_text(encoding="utf-8")
    hits = _find_ctx_attr_reads(src)
    assert not hits, (
        "CI invariant violation — rule_library.py inspects raw "
        "evidence attribute(s):\n  " + "\n  ".join(hits) +
        "\nRules must read projected semantic fields (behaviors, "
        "impacts, mitre_techniques) or structured IOCs (ips, urls, "
        "domains) — not raw Evidence.")
