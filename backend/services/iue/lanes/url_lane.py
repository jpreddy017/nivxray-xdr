"""Lane-B orchestrator · URL / domain → canonical LogicalEvents.

Owner directive:
    URL → intake → IDA acquisition → parsing → normalization →
          aggregation → IUE → LogicalEvent → EVIDENCE tab / SSOT / ICE

Reuses:
  - services/ida/acquisition.acquire_url       (unchanged)
  - services/iue/collectors/url_collector      (thin wrapper)
  - services/iue/parsers/acquired_url_parser   (thin iterator)
  - services/iue/normalizers/field_map         (shared with Lane A)
  - services/iue/aggregator                    (shared with Lane A)
  - services/iue/understanding                 (thin consolidator)

Preserves Fix 1's ``acquisition_failed`` envelope on failure — the
returned wire fragment carries ``report_extraction_fragment.source =
"acquisition_failed"`` and the ``acquisition_failure`` dict byte-for-byte
identical to what ``services/die/investigation_results.render`` emits
today.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from ..intake import intake, IntakeDecision
from ..failure import IUEFailure
from ..collectors.url_collector import collect_url, URLRawPayload
from ..parsers.acquired_url_parser import iter_records
from ..normalizers.field_map import normalize
from ..aggregator import aggregate
from ..understanding import understand_structured


def _fix1_report_extraction(acquired: Dict[str, Any]) -> Dict[str, Any]:
    """Reproduce Prev-mode's Fix 1 ``report_extraction`` envelope
    byte-for-byte from an AcquiredResource dict.

    Contract (grep-verified against services/die/investigation_results.py
    lines 478–505):
        - source                = "acquisition_failed"
        - status                = "acquisition_failed"
        - evidence_source_url   = acquired.url
        - acquisition_failure   = { … full acquired dict … }
        - error                 = acquired.error_detail or fallback msg
    """
    return {
        "source":                "acquisition_failed",
        "status":                "acquisition_failed",
        "evidence_source_url":   acquired.get("url"),
        "evidence_source":       f"acquisition_failed:{acquired.get('error_code') or 'unknown'}",
        "acquisition_failure":   acquired,
        "error": acquired.get("error_detail")
                  or f"URL acquisition failed: {acquired.get('error_code') or 'unknown'}",
        # Empty additive keys so downstream consumers that iterate
        # get uniform shape regardless of success/failure.
        "commands":            [],
        "command_investigations": [],
        "investigation_summary": {},
        "mitre_techniques":    [],
        "body_artifacts":      [],
        "threat_actors":       [],
        "malware_families":    [],
        "behaviors":           [],
        "iocs":                {},
    }


def analyze_url(url: str,
                 *, session_ctx=None,
                 tenant_id=None,
                 allow_prev_fallback: bool = True) -> Dict[str, Any]:
    """Full Lane-B pipeline.  Returns the T2 wire contract, extended
    with the AcquiredResource dict so downstream consumers keep parity
    with Fix 1 semantics."""
    # 1. Intake
    decision = intake(url, session_ctx=session_ctx, tenant_id=tenant_id,
                        allow_prev_fallback=allow_prev_fallback)
    if isinstance(decision, IUEFailure):
        return {"intake_decision": None, "iue_failure": decision.to_dict()}

    # Intake will assign lane="url" for any URL that IDA classifies as
    # a URL kind.  Non-URL inputs are rejected here — Lane B is scoped
    # to URLs.
    if decision.lane != "url":
        return {
            "intake_decision": decision.to_dict(),
            "iue_failure": IUEFailure(
                status="terminal", stage="intake",
                error_code="intake_unknown_kind",
                message=f"Lane B accepts URL inputs only; got lane={decision.lane}",
                recoverable=False,
                input_id=decision.input_id, tenant_id=decision.tenant_id,
            ).to_dict(),
        }

    # 2. Collect (via existing acquisition; Fix 1 preserved on failure)
    collect_result = collect_url(url,
                                    input_id=decision.input_id,
                                    tenant_id=decision.tenant_id,
                                    upstream=decision.provenance)
    # Failure path — collect_url returns (IUEFailure, acquired_dict) tuple
    # when the acquisition succeeded technically but ok=False.
    if isinstance(collect_result, tuple):
        failure, acquired_dict = collect_result
        return {
            "intake_decision":            decision.to_dict(),
            "iue_failure":                failure.to_dict(),
            "acquired_document":          acquired_dict,
            "logical_events":             [],
            "malformed":                  [],
            "report_extraction_fragment": _fix1_report_extraction(acquired_dict),
        }
    if isinstance(collect_result, IUEFailure):
        return {
            "intake_decision":            decision.to_dict(),
            "iue_failure":                collect_result.to_dict(),
            "logical_events":             [],
            "malformed":                  [],
            "report_extraction_fragment": {},
        }

    raw: URLRawPayload = collect_result

    # 3. Parse → 4. Normalize → 5. Aggregate → 6. Understand
    parsed = list(iter_records(raw))
    ok_r = [p for p in parsed if p.parse_status == "ok"]
    bad_r = [p for p in parsed if p.parse_status != "ok"]
    normalized = [normalize(p) for p in ok_r]
    events = aggregate(normalized)
    fragment = understand_structured(events)

    return {
        "intake_decision":            decision.to_dict(),
        "raw_payload":                raw.to_dict(),
        "acquired_document":          raw.acquired,
        "logical_events":             [ev.to_dict() for ev in events],
        "malformed":                  [p.to_dict() for p in bad_r],
        "report_extraction_fragment": fragment,
    }
