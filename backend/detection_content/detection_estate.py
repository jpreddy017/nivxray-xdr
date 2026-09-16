"""DCR-1 · honest accounting of the authored detection estate.

"98 authored rules, 0 firing" was arithmetically true and materially
misleading: the store also holds MITRE technique descriptions (reference
content with no predicate), mirrors of correlation rules that already fire on
the correlation engine, authoring-gate test fixtures, and duplicate copies of
one rule. Counting those as authored detections overstates both the estate and
the gap.

Nothing is moved or deleted here — the records stay exactly where they are and
are reported in their own buckets.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List

#: Titles written to exercise the authoring gates, not to detect anything.
_FIXTURE_TITLES = {"proprietary demo", "lifecycle test",
                   "gate refusal candidate", "dry-run test"}
_FIXTURE_SOURCES = {"testvendor", "somewhere"}

REFERENCE = "mitre_reference"
CORRELATION = "correlation_mirror"
FIXTURE = "test_fixture"
DETECTION = "authored_detection"


def classify(doc: Dict[str, Any]) -> str:
    source = str(doc.get("source") or "").lower()
    upstream = str(doc.get("upstream_id") or "")
    title = str(doc.get("title") or "").strip().lower()
    rule_type = str(doc.get("rule_type") or "").lower()
    lane = str(doc.get("lane") or "").lower()
    if source == "mitre att&ck" or upstream.startswith("attack_") \
            or rule_type == "attack_technique":
        return REFERENCE
    if source == "nivxray-correlation" or upstream.startswith("cor_") \
            or rule_type == "correlation" or lane == "correlation":
        return CORRELATION
    if source in _FIXTURE_SOURCES or title in _FIXTURE_TITLES:
        return FIXTURE
    return DETECTION


def estate(docs: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    buckets: Dict[str, List[Dict[str, Any]]] = {REFERENCE: [], CORRELATION: [],
                                                FIXTURE: [], DETECTION: []}
    for d in docs:
        buckets[classify(d)].append(d)
    seen: Dict[str, int] = {}
    distinct, duplicates = [], []
    for d in buckets[DETECTION]:
        key = str(d.get("title") or d.get("upstream_id") or d.get("id"))
        seen[key] = seen.get(key, 0) + 1
        (distinct if seen[key] == 1 else duplicates).append(d)
    return {
        "store_rules_counted": sum(len(v) for v in buckets.values()),
        "authored_detections_distinct": len(distinct),
        "authored_detection_duplicate_copies": len(duplicates),
        "mitre_reference_entries": len(buckets[REFERENCE]),
        "correlation_mirrors": len(buckets[CORRELATION]),
        "test_fixtures": len(buckets[FIXTURE]),
        "duplicate_titles": sorted({str(d.get("title")) for d in duplicates}),
        "accounting_note": (
            "Only `authored_detections_distinct` is a detection denominator. "
            "MITRE entries are reference content with no predicate, "
            "correlation mirrors already fire on the correlation engine, and "
            "fixtures exist to exercise the authoring gates. No record was "
            "moved, edited or deleted to produce this count."),
    }
