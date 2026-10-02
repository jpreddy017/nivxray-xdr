"""Regression: the OLD AmpEventDetails MITRE box and the NEW DT-V3 MitreBox show identical attributions for the same E1 row.
Old component logic (AmpEventDetails.jsx L114-115): tactics = event.mitre filtered /^TA/i, techniques = the rest."""
import pytest

from edr_trajectory import attack

ROWS = [
    {"mitre": ["T1059.001", "T1027"], "mitre_basis": "RULE_DECLARED_BY_MATCHED_DETECTION", "findings": [{"rule_id": "R1", "attck": ["T1059.001", "T1027"]}]},
    {"mitre": ["TA0002", "T1059"], "mitre_basis": "RULE_DECLARED_BY_MATCHED_DETECTION"},
    {"mitre": ["T1003.001", "T1021.002", "TA0006", "TA0008"], "mitre_basis": "TI_DERIVED"},
    {"mitre": ["T1086"], "mitre_basis": "HEURISTIC_TEXT_PATTERN"},
    {"mitre": ["T1071.001"], "mitre_basis": "SOURCE_NORMALIZER_TAG_NOT_VALIDATED_DETECTION"},
    {"mitre": [], "mitre_basis": "NOT_ATTRIBUTED"},
    {},
]


def old_box(ev):
    m = ev.get("mitre") or []
    return sorted(x.upper() for x in m if x.upper().startswith("TA")), sorted(x.upper() for x in m if not x.upper().startswith("TA"))


@pytest.mark.parametrize("row", ROWS)
def test_old_and_new_render_identical_attributions(row):
    tacs, techs = old_box(row)
    a = attack.annotate_row(row)
    if not tacs and not techs:
        assert a is None  # both components show the same ◇ empty states
        return
    assert sorted(a["tactic_ids"]) == tacs
    assert sorted(t["technique"] for t in a["techniques"]) == techs  # same ids; revoked ones surfaced, not dropped
