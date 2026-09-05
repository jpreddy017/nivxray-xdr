"""Lane-C orchestrator · File / Artifact → canonical LogicalEvents.

Owner directive:
    Artifact upload → Artifact Router → existing artifact-specific
    analyzer → canonical artifact evidence → LogicalEvent(lane="artifact")
    → IUE / T2 wire → existing StructuredEvidenceTab (pure projection)

Reuses:
  - services.iue.collectors.file_collector.collect_file  (thin dispatch wrapper)
  - services.iue.parsers.artifact_parser.iter_records    (primary + child records)
  - services.iue.normalizers.field_map.normalize         (shared with Lane A/B)
  - services.iue.aggregator.aggregate                    (shared with Lane A/B)
  - services.iue.understanding.understand_structured     (shared consolidator)

STAGE-1 rules honoured:
  - Static analysis only.  No execution, no sandbox, no network.
  - Artifact-first identification (via the existing
    ``services.artifact_intelligence`` dispatcher registry).
  - Same T2 wire contract as Lane A / Lane B — the frontend does not
    change to consume this lane.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from ..failure import IUEFailure
from ..collectors.file_collector import collect_file, FileRawPayload
from ..parsers.artifact_parser import iter_records
from ..normalizers.field_map import normalize
from ..aggregator import aggregate
from ..understanding import understand_structured
from ..intake import IntakeDecision
from .._prov import intake_prov
from ..tenancy import resolve_tenant


def _hash_input_bytes(payload: bytes) -> str:
    import hashlib
    return hashlib.sha256(payload).hexdigest()[:16]


def _file_intake_decision(payload: bytes,
                            filename: str,
                            *, session_ctx: Optional[dict],
                            tenant_id: Optional[str],
                            allow_prev_fallback: bool) -> Any:
    """Produce an ``IntakeDecision`` (or ``IUEFailure``) for a file
    input.  This does NOT re-run string classifiers — files are
    committed at the endpoint layer.
    """
    tenant = tenant_id or resolve_tenant(
        session_ctx, allow_prev_fallback=allow_prev_fallback)
    if not tenant:
        return IUEFailure(
            status="terminal", stage="intake",
            error_code="tenant_context_missing",
            message="Prod-mode requires a tenant_id",
            recoverable=False,
            input_id=_hash_input_bytes(payload), tenant_id="",
        )
    input_id = _hash_input_bytes(payload)
    reasons = [f"filename:{filename or '<unnamed>'}"]
    return IntakeDecision(
        kind="binary_artifact",
        lane="file",
        confidence=0.95,
        reasons=reasons,
        ida_class=None,
        iue_type=None,
        input_id=input_id,
        tenant_id=tenant,
        parent_input_id=None,
        discovery_depth=0,
        flag_state="on",
        provenance=intake_prov(own_id=input_id),
    )


def _artifact_report_fragment(raw: FileRawPayload,
                                events: list,
                                fragment: Dict[str, Any]) -> Dict[str, Any]:
    """Extend the standard `understand_structured` fragment with a
    small artifact-specific summary block that the Workspace UI
    projects natively (StructuredEvidenceTab already knows how to
    render `report_extraction_fragment`).
    """
    disp = raw.artifact_dispatch or {}
    hashes = disp.get("hashes") or {}
    # A single compact artifact summary.  No verdict, no correlation.
    artifact_summary = {
        "artifact_type":        disp.get("artifact_type") or "unknown",
        "display_name":         disp.get("display_name") or "Unknown Artifact",
        "confidence":           disp.get("confidence") or 0,
        "detected_by":          disp.get("detected_by") or "",
        "capability_available": bool(disp.get("capability_available")),
        "fallback_reason":      disp.get("fallback_reason"),
        "file_name":            raw.filename,
        "file_size":            disp.get("size") or len(raw.bytes_ or b""),
        "file_mime":            raw.mime,
        "sha256":               (hashes.get("sha256") or "").lower(),
        "md5":                  (hashes.get("md5") or "").lower(),
        "sha1":                 (hashes.get("sha1") or "").lower(),
    }
    extended = dict(fragment or {})
    extended["artifact_summary"] = artifact_summary
    extended["source"] = "lane_c_file"
    return extended


def analyze_file(payload_bytes: bytes,
                  filename: str,
                  *, mime: str = "application/octet-stream",
                  session_ctx: Optional[dict] = None,
                  tenant_id: Optional[str] = None,
                  allow_prev_fallback: bool = False) -> Dict[str, Any]:
    """Full Lane-C pipeline.  Returns the T2 wire contract.

    Response shape (matches Lane A/B):
        {
          "intake_decision":            IntakeDecision.to_dict(),
          "raw_payload":                FileRawPayload.to_dict(),
          "logical_events":             list[LogicalEvent.to_dict()],
          "malformed":                  list[ParsedRecord.to_dict()],
          "report_extraction_fragment": {…, artifact_summary: {…}},
        }
    """
    # 1. Intake — commits lane="file", tenancy, provenance.
    decision = _file_intake_decision(payload_bytes, filename,
                                        session_ctx=session_ctx,
                                        tenant_id=tenant_id,
                                        allow_prev_fallback=allow_prev_fallback)
    if isinstance(decision, IUEFailure):
        return {"intake_decision": None, "iue_failure": decision.to_dict()}

    # 2. Collect — size cap + artifact_intelligence.dispatch()
    raw = collect_file(payload_bytes,
                         filename=filename,
                         mime=mime,
                         input_id=decision.input_id,
                         tenant_id=decision.tenant_id,
                         upstream=decision.provenance)
    if isinstance(raw, IUEFailure):
        return {
            "intake_decision": decision.to_dict(),
            "iue_failure":     raw.to_dict(),
        }

    # 3. Parse (primary + child records)
    parsed = list(iter_records(raw))
    ok_r = [p for p in parsed if p.parse_status == "ok"]
    bad_r = [p for p in parsed if p.parse_status != "ok"]

    # 4. Normalize → 5. Aggregate → 6. Understand
    normalized = [normalize(p) for p in ok_r]
    events = aggregate(normalized)
    fragment = understand_structured(events)
    fragment = _artifact_report_fragment(raw, events, fragment)

    return {
        "intake_decision":            decision.to_dict(),
        "raw_payload":                raw.to_dict(),
        "logical_events":             [ev.to_dict() for ev in events],
        "malformed":                  [p.to_dict() for p in bad_r],
        "report_extraction_fragment": fragment,
    }
