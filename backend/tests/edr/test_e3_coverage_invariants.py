"""E3 · the coverage invariants. These are what stop dead rules.

Three defects motivated this file, all found by measurement:

1. `DET-CR-002` (T1003.003) gated on the literal string `ntds.dit`, so
   it could not fire on its OWN positive fixture — real NTDS theft via
   `ntdsutil "ac i ntds" "ifm" "create full <dir>"` never names the file.
2. A rule can pass its flat Sysmon-shaped fixture and still be DEAD on
   canonical evidence. Rule tests that only use the raw dialect cannot
   see that.
3. A rule can be perfectly correct and still be undetectable because the
   telemetry it needs is not collected. That is a SENSOR fact and must
   not be reported as a rule failure.
"""
from __future__ import annotations

import sys

import pytest

sys.path.insert(0, "/app/backend")

from detection_content.library.registry import (                # noqa: E402
    RUNTIME_DETECTION_RULES,
)
from detection_content.xdr_pipeline import evaluate_detection   # noqa: E402

sys.path.insert(0, "/app/backend/scripts")
from e3_coverage_matrix import (                                # noqa: E402
    NON_ENDPOINT_PLATFORMS,
    NOT_A_WINDOWS_ENDPOINT_SOURCE,
    TELEMETRY_BRIDGE,
    _canonical_control,
    _is_canonical_shaped,
)

RULES = list(RUNTIME_DETECTION_RULES)
IDS = [r.rule_id for r in RULES]


def _fires(rule, ev) -> bool:
    return any(m.get("rule_id") == rule.rule_id
               for m in (evaluate_detection(ev).get("detections") or []))


# ── A · every rule must satisfy its OWN fixtures ─────────────────────
@pytest.mark.parametrize("rule", RULES, ids=IDS)
def test_every_rule_satisfies_its_own_fixtures(rule):
    assert rule.fixtures, f"{rule.rule_id} declares no fixture"
    for fx in rule.fixtures:
        got = bool(rule.predicate(fx.event))
        assert got is bool(fx.should_match), (
            f"{rule.rule_id} ({rule.technique_id}) fixture "
            f"{fx.name!r}: expected {fx.should_match}, got {got} — "
            f"{str(fx.event)[:160]}")


# ── B · a rule that fires on the raw dialect must fire on the
#        CANONICAL dialect too, or it is dead in production ──────────
@pytest.mark.parametrize("rule", RULES, ids=IDS)
def test_a_rule_that_fires_on_raw_also_fires_on_canonical(rule):
    for fx in rule.fixtures:
        if not fx.should_match:
            continue
        if not _fires(rule, dict(fx.event)):
            continue                       # covered by test A
        assert _fires(rule, _canonical_control(dict(fx.event))), (
            f"{rule.rule_id} fires on its raw fixture but NOT on canonical "
            f"evidence — it is DEAD in production. fixture {fx.name!r}")


# ── C · no rule may fire on ordinary benign Windows telemetry ────────
BENIGN = [
    {"Image": "C:\\Windows\\System32\\svchost.exe",
     "CommandLine": "svchost.exe -k netsvcs -p -s Schedule",
     "ParentImage": "C:\\Windows\\System32\\services.exe"},
    {"Image": "C:\\Windows\\explorer.exe", "CommandLine": "explorer.exe"},
    {"Image": "C:\\Windows\\System32\\taskhostw.exe",
     "CommandLine": "taskhostw.exe",
     "ParentImage": "C:\\Windows\\System32\\svchost.exe"},
]


@pytest.mark.parametrize("rule", RULES, ids=IDS)
def test_no_rule_fires_on_benign_windows_telemetry(rule):
    for ev in BENIGN:
        assert not _fires(rule, ev), (
            f"{rule.rule_id} FALSE POSITIVE on benign {ev['Image']}")
        assert not _fires(rule, _canonical_control(dict(ev))), (
            f"{rule.rule_id} FALSE POSITIVE on canonical benign "
            f"{ev['Image']}")


# ── D · the vocabulary bridge must stay complete and truthful ────────
def test_every_declared_telemetry_requirement_is_mapped_or_declared():
    unmapped = set()
    for rule in RULES:
        for req in (rule.telemetry_requirements or []):
            if req not in TELEMETRY_BRIDGE \
                    and req not in NOT_A_WINDOWS_ENDPOINT_SOURCE:
                unmapped.add(req)
    assert not unmapped, (
        "these telemetry requirements have no canonical mapping and are not "
        f"declared out of scope, so coverage cannot be measured: {unmapped}")


def test_the_bridge_never_claims_a_field_outside_a_canonical_group():
    groups = {"process", "registry", "file", "network", "identity",
              "security", "authentication", "host"}
    for req, br in TELEMETRY_BRIDGE.items():
        for field in br["fields"]:
            assert field.split(".")[0] in groups, (req, field)


# ── E · the specific defect that started this ────────────────────────
def test_ntds_extraction_is_detected_without_the_filename():
    rule = next(r for r in RULES if r.rule_id == "DET-CR-002")
    for cmd in ('ntdsutil "ac i ntds" "ifm" "create full C:\\temp" q q',
                'ntdsutil.exe "activate instance ntds" "ifm" '
                '"create full C:\\x"'):
        assert rule.predicate({"CommandLine": cmd}), cmd
    # and it still must not fire on simply LOOKING at the directory
    assert not rule.predicate({"CommandLine": "dir C:\\Windows\\NTDS"})
    assert not rule.predicate({"CommandLine": "ntdsutil /?"})


# ── F · shape detection must not rebuild an already-canonical fixture
def test_an_already_canonical_fixture_is_used_as_is():
    canon = {"event_type": "registry_event",
             "registry": {"key_path": "HKLM\\...\\Run", "action": "set_value"}}
    assert _is_canonical_shaped(canon)
    assert _canonical_control(canon) == canon
    flat = {"Image": "powershell.exe", "CommandLine": "powershell -enc AAA"}
    assert not _is_canonical_shaped(flat)
    assert _canonical_control(flat)["process"]["command_line"] == \
        "powershell -enc AAA"


# ── G · out-of-scope platforms are out of SCOPE, not failures ────────
def test_non_endpoint_platforms_are_declared_not_blamed():
    assert "linux" in NON_ENDPOINT_PLATFORMS
    assert "identity" in NON_ENDPOINT_PLATFORMS
    for rule in RULES:
        plat = getattr(rule.platform, "value", str(rule.platform)).lower()
        assert plat in NON_ENDPOINT_PLATFORMS or plat == "windows", plat
