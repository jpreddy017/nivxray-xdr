"""ATT&CK adapter over E1 attribution + rule-mapping lint against the vendored official catalogue."""
import json
import pathlib
import re
import sys

from edr_trajectory import attack
from services.mitre_catalogue import get_catalogue

ROOT = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools" / "e3ui"))
import mitre_mapping_diff  # noqa: E402

#: Known E1 mapper drift vs ATT&CK v19.2, documented in docs/e3/DT_MITRE_ATTRIBUTION_INVENTORY.md (E1 items, not changed by E3).
KNOWN_E1_RETIRED = {
    "v2/ingestion/mitre_map.py": {"T1562.001"},
    "operations.py": {"T1070.001", "T1562", "T1562.001", "T1562.004", "T1562.008"},
    "engine/detectors/mitre_mapper.py": {"T1562", "T1562.001", "T1562.006"},
    "canonical/projections/attck.py": {"T1070.001", "T1562.001", "T1562.004"},
}


def test_one_catalogue_version_backend_frontend():
    fe = (ROOT / "apps/nivxray-xdr/src/xdr/mitre/attackNameIndex.generated.js").read_text()
    assert attack.version() == get_catalogue().version == re.search(r'CATALOGUE_VERSION = "([\d.]+)"', fe).group(1)
    assert [t["shortname"] for t in attack.tactics()] == [t["key"] for t in json.loads(re.search(r"ATTACK_TACTICS = (\[.*?\]);", fe, re.S).group(1))]


def test_annotate_row_uses_e1_fields_and_catalogue():
    row = {"mitre": ["T1059.001", "T1027"], "mitre_basis": "RULE_DECLARED_BY_MATCHED_DETECTION",
           "findings": [{"rule_id": "R1", "attck": ["T1059.001", "T1027"], "severity": "high", "confidence": 0.9}]}
    a = attack.annotate_row(row)
    assert a["type"] == "Rule-mapped" and a["severity"] == "high"
    assert [t["technique"] for t in a["techniques"]] == ["T1027", "T1059.001"]
    assert a["tactics"] == ["execution", "stealth"]  # official kill-chain order; v19 Stealth
    assert attack.annotate_row({"mitre": [], "mitre_basis": "NOT_ATTRIBUTED"}) is None
    assert attack.annotate_row({"mitre": ["T1071.001"], "mitre_basis": "SOURCE_NORMALIZER_TAG_NOT_VALIDATED_DETECTION"})["type"] == "Heuristic"


def test_revoked_is_surfaced_not_dropped():
    t = attack.technique("T1086")
    assert t["status"] == "revoked" and t["replacement"] == "T1059.001" and t["display"].startswith("revoked → T1059.001")
    assert attack.technique("T9999")["status"] == "unknown"


def test_rule_mapping_lint():
    res = mitre_mapping_diff.scan()
    assert res["sources"]["edr_trajectory/artifacts_overlay.py"]["issues"] == []
    retired = {rel: {i["technique"] for i in s["issues"] if i["status"] != "active"} for rel, s in res["sources"].items()}
    assert {k: v for k, v in retired.items() if v} == KNOWN_E1_RETIRED, "new revoked/deprecated ids in E1 mappers — update the inventory doc"


def test_device_summary_detections_only_by_default():
    rows = [{"event_iid": "a", "ms": 1, "mitre": ["T1059.001"], "mitre_basis": "RULE_DECLARED_BY_MATCHED_DETECTION", "findings": [{"rule_id": "R", "attck": ["T1059.001"], "severity": "HIGH"}]},
            {"event_iid": "b", "ms": 2, "mitre": ["T1071.001"], "mitre_basis": "SOURCE_NORMALIZER_TAG_NOT_VALIDATED_DETECTION"}]
    s = attack.device_summary(rows, None, None, ms_of=lambda r: r["ms"])
    seen = {x["technique"] for c in s["tactics"] for x in c["techniques"]}
    assert seen == {"T1059.001"} and len(s["tactics"]) == len(get_catalogue().tactics)
    s2 = attack.device_summary(rows, None, None, ms_of=lambda r: r["ms"], include_heuristic=True)
    assert {x["technique"] for c in s2["tactics"] for x in c["techniques"]} == {"T1059.001", "T1071.001"}
