"""
P4 · MITRE Consistency Diagnostic · regression tests
─────────────────────────────────────────────────────

Locks the shape and semantics of the diagnostic emitted by
``services.diagnostics.mitre_consistency.check`` — the developer
tool that verifies the three ATT&CK panels agree with each other.

The diagnostic is READ-ONLY.  These tests never mutate payloads;
they only assert on the report structure.
"""
from __future__ import annotations

from services.diagnostics.mitre_consistency import check


# ══════════════════════════════════════════════════════════════════
# Shape / defaults
# ══════════════════════════════════════════════════════════════════
def test_empty_payload_returns_ok_report_with_all_checks_present():
    r = check({})
    # No data → nothing to disagree.  Report is ok.
    assert r["ok"] is True
    assert r["schema_version"] == "1.0"
    ids = {c["check"] for c in r["checks"]}
    assert ids == {"B2M", "M2C", "C2M", "ORPH", "DUP", "LANE"}
    # Counts are all zero.
    for v in r["counts"].values():
        assert v == 0


def test_report_is_deterministic():
    payload = {"summary_narrative": {"behavior_summary": ["whoami discovery"]}}
    a = check(payload)
    b = check(payload)
    assert a == b


# ══════════════════════════════════════════════════════════════════
# B2M · behavior_summary → MITRE
# ══════════════════════════════════════════════════════════════════
def test_b2m_flags_unbridged_behavior_bullet():
    payload = {"summary_narrative": {
        "behavior_summary": ["Something that is not in the bridge dictionary"]
    }}
    r = check(payload)
    b2m = next(c for c in r["checks"] if c["check"] == "B2M")
    assert not b2m["ok"]
    assert "Something that is not in the bridge dictionary" in b2m["items"]


def test_b2m_passes_when_every_bullet_bridges_to_mitre():
    payload = {"summary_narrative": {
        # These match _PURPOSE_TO_MITRE entries.
        "behavior_summary": ["Current-user discovery", "PowerShell in-memory execution"],
    }}
    r = check(payload)
    b2m = next(c for c in r["checks"] if c["check"] == "B2M")
    assert b2m["ok"], b2m


# ══════════════════════════════════════════════════════════════════
# M2C · mitre_summary → clusters
# ══════════════════════════════════════════════════════════════════
def test_m2c_flags_summary_technique_missing_from_clusters():
    payload = {"summary_narrative": {
        "mitre_summary": [{"tactic": "Execution",
                              "techniques": [{"id": "T1053.005"}]}],
    }, "incident": {"behaviors": []}}
    r = check(payload)
    m2c = next(c for c in r["checks"] if c["check"] == "M2C")
    assert not m2c["ok"]
    assert "T1053.005" in m2c["items"]


def test_m2c_passes_when_technique_is_in_a_cluster():
    payload = {
        "summary_narrative": {
            "mitre_summary": [{"tactic": "Execution",
                                  "techniques": [{"id": "T1053.005"}]}],
        },
        "incident": {"behaviors": [
            {"id": "b1", "mitre": [{"id": "T1053.005", "tactic": "execution"}]},
        ]},
    }
    r = check(payload)
    m2c = next(c for c in r["checks"] if c["check"] == "M2C")
    assert m2c["ok"], m2c


# ══════════════════════════════════════════════════════════════════
# C2M · clusters → mitre_summary
# ══════════════════════════════════════════════════════════════════
def test_c2m_flags_cluster_technique_missing_from_summary():
    payload = {
        "summary_narrative": {"mitre_summary": []},
        "incident": {"behaviors": [
            {"id": "b1", "mitre": [{"id": "T1105", "tactic": "command_and_control"}]},
        ]},
    }
    r = check(payload)
    c2m = next(c for c in r["checks"] if c["check"] == "C2M")
    assert not c2m["ok"]
    assert "T1105" in c2m["items"]


# ══════════════════════════════════════════════════════════════════
# ORPH · symmetric-difference indicator
# ══════════════════════════════════════════════════════════════════
def test_orph_flags_orphan_when_only_one_panel_has_the_tech():
    payload = {
        "summary_narrative": {"mitre_summary": [
            {"tactic": "Execution", "techniques": [{"id": "T1053.005"}]},
        ]},
        "incident": {"behaviors": []},
    }
    r = check(payload)
    orph = next(c for c in r["checks"] if c["check"] == "ORPH")
    assert not orph["ok"]
    assert "T1053.005" in orph["items"]


# ══════════════════════════════════════════════════════════════════
# DUP · duplicate technique inside a tactic
# ══════════════════════════════════════════════════════════════════
def test_dup_flags_repeated_technique_in_same_tactic():
    payload = {"summary_narrative": {"mitre_summary": [
        {"tactic": "Execution",
             "techniques": [{"id": "T1053.005"}, {"id": "T1053.005"}]},
    ]}}
    r = check(payload)
    dup = next(c for c in r["checks"] if c["check"] == "DUP")
    assert not dup["ok"]
    assert any("T1053.005" in x for x in dup["items"])


# ══════════════════════════════════════════════════════════════════
# LANE · declared tactic must be implied by ≥1 technique
# ══════════════════════════════════════════════════════════════════
def test_lane_flags_declared_tactic_not_implied_by_any_technique():
    payload = {"incident": {"behaviors": [
        # Cluster declares "Impact" but its only technique T1053.005
        # resolves to Execution.  LANE should flag it.
        {"id": "bad-lane",
             "mitre_tactics": ["Impact", "Execution"],
             "mitre":         [{"id": "T1053.005", "tactic": "execution"}]},
    ]}}
    r = check(payload)
    lane = next(c for c in r["checks"] if c["check"] == "LANE")
    assert not lane["ok"]
    assert any("bad-lane" in x for x in lane["items"])


def test_lane_passes_when_declared_tactics_are_all_implied():
    payload = {"incident": {"behaviors": [
        {"id": "ok",
             "mitre_tactics": ["Execution"],
             "mitre":         [{"id": "T1053.005", "tactic": "execution"}]},
    ]}}
    r = check(payload)
    lane = next(c for c in r["checks"] if c["check"] == "LANE")
    assert lane["ok"], lane


# ══════════════════════════════════════════════════════════════════
# Read-only guarantee
# ══════════════════════════════════════════════════════════════════
def test_check_is_pure_no_mutation():
    payload = {
        "summary_narrative": {
            "behavior_summary": ["Current-user discovery"],
            "mitre_summary":    [{"tactic": "Discovery",
                                     "techniques": [{"id": "T1033"}]}],
        },
        "incident": {"behaviors": [
            {"id": "b1", "mitre": [{"id": "T1033", "tactic": "discovery"}]},
        ]},
    }
    import copy
    snap = copy.deepcopy(payload)
    _ = check(payload)
    assert payload == snap


# ══════════════════════════════════════════════════════════════════
# Happy path — all checks green on a consistent payload
# ══════════════════════════════════════════════════════════════════
def test_consistent_payload_all_checks_green():
    payload = {
        "summary_narrative": {
            "behavior_summary": ["Current-user discovery",
                                     "PowerShell in-memory execution"],
            "mitre_summary":    [
                {"tactic": "Discovery",
                     "techniques": [{"id": "T1033"}]},
                {"tactic": "Execution",
                     "techniques": [{"id": "T1059.001"}]},
            ],
        },
        "incident": {"behaviors": [
            {"id": "b1",
                 "mitre_tactics": ["Discovery"],
                 "mitre":         [{"id": "T1033", "tactic": "discovery"}]},
            {"id": "b2",
                 "mitre_tactics": ["Execution"],
                 "mitre":         [{"id": "T1059.001", "tactic": "execution"}]},
        ]},
    }
    r = check(payload)
    assert r["ok"] is True, [c for c in r["checks"] if not c["ok"]]
