"""IUE understanding — THIN CONSOLIDATOR (STEP 3 §2.6 · STEP 5 §6).

Hard rule (STEP 3 §8 risk 8 + STEP 5 §6 residual risk 6):
  This module MUST remain a thin dispatcher.  Any structured-event →
  MITRE / semantic mapping delegates to existing owners:
    - services.die.input_understanding.understand   (text)
    - services.die.canonical                         (canonical field → MITRE)
    - services.mitigation.evidence_driven.*          (posture normalisation)

The 40-LOC ceiling on functional code below is enforced by
``tests/canonical/iue/lane_a/test_iue_understanding_thin.py``.
"""
from __future__ import annotations

from typing import Any, Iterable, List, Mapping


def understand_structured(events: Iterable) -> Mapping[str, Any]:
    """Convert LogicalEvents into a partial ``report_extraction`` fragment.

    Only produces the additive Lane-A keys documented in STEP 3 §3.5.
    Existing report_extraction keys (commands, mitre_techniques, iocs,
    behaviors, threat_actors, malware_families, …) are populated by the
    existing IDA path when present — this module DOES NOT re-implement
    that logic.  Delegation is the contract.
    """
    lst: List[dict] = []
    total_records = 0
    for ev in events:
        lst.append(ev.to_dict())
        total_records += ev.count
    return {
        "logical_events": lst,
        "logical_event_count": len(lst),
        "logical_record_total": total_records,
    }
