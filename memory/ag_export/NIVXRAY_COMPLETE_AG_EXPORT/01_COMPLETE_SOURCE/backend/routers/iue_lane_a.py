"""Lane-A analyze router — POST /api/iue/lane-a/analyze.

Feature-flag-gated (`IUE_STRUCTURED_LANE=on`) endpoint that accepts
raw NDJSON / JSON / CSV / XML bytes and returns the T2-frozen wire
contract (IntakeDecision · RawPayload · LogicalEvents · malformed ·
report_extraction_fragment).

The frontend Analyst Workspace vertical slice consumes THIS shape —
which is identical to the T2 golden fixture.  No new fields; no
verdict calculation; no MITRE inference; no correlation.

If the flag is off, the endpoint returns 503 so the frontend renders
a clear "structured lane disabled" state rather than silently
demoting to raw_text.
"""
from __future__ import annotations

import os
from typing import Optional

from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Depends

from deps import get_current_user


router = APIRouter(prefix="/iue/lane-a", tags=["iue-lane-a"])


def _flag_on() -> bool:
    return os.environ.get("IUE_STRUCTURED_LANE", "off").lower() == "on"


@router.get("/status")
def status():
    """Return whether Lane A is currently enabled and its config caps."""
    from services.iue import security as sec
    return {
        "enabled": _flag_on(),
        "flag": os.environ.get("IUE_STRUCTURED_LANE", "off"),
        "caps": {
            "max_raw_bytes": sec.MAX_RAW_BYTES,
            "max_record_count": sec.MAX_RECORD_COUNT,
            "max_record_bytes": sec.MAX_RECORD_BYTES,
        },
    }


@router.post("/analyze")
async def analyze(
    file: Optional[UploadFile] = File(default=None),
    mime: Optional[str] = Form(default=None),
    parser: str = Form(default="ndjson"),
    user=Depends(get_current_user),
):
    """Analyse an uploaded structured-log artefact.

    Parameters
    ----------
    file   : multipart file upload (bytes)
    mime   : optional MIME hint (falls back to file.content_type)
    parser : ndjson | json | csv | xml
    """
    if not _flag_on():
        raise HTTPException(
            status_code=503,
            detail={
                "error": "iue_structured_lane_disabled",
                "hint": "Set IUE_STRUCTURED_LANE=on to enable Lane A.",
            },
        )

    if file is None:
        raise HTTPException(
            status_code=400,
            detail={"error": "missing_file"},
        )

    payload = await file.read()
    resolved_mime = mime or file.content_type or "application/octet-stream"
    parser = (parser or "ndjson").lower()
    if parser not in {"ndjson", "json", "csv", "xml"}:
        raise HTTPException(
            status_code=400,
            detail={"error": "unsupported_parser",
                     "supported": ["ndjson", "json", "csv", "xml"]},
        )

    # Lazy imports — the IUE package only loads when the flag is on.
    from services.iue.intake import intake
    from services.iue.collectors.log_collector import collect
    from services.iue.normalizers.field_map import normalize
    from services.iue.aggregator import aggregate
    from services.iue.understanding import understand_structured
    from services.iue.failure import IUEFailure

    if parser == "ndjson":
        from services.iue.parsers.ndjson_parser import iter_records
    elif parser == "json":
        from services.iue.parsers.json_parser import iter_records
    elif parser == "csv":
        from services.iue.parsers.csv_parser import iter_records
    else:
        from services.iue.parsers.xml_parser import iter_records

    # 1. Intake — auth is present (Depends above), so we thread the
    # user's tenant into session_ctx and DISALLOW the __prev_public__
    # fallback in production paths (SEC-002).
    session_ctx = {"tenant_id": (user or {}).get("tenant_id")
                                    or (user or {}).get("email")
                                    or (user or {}).get("sub")}
    decision = intake(payload, session_ctx=session_ctx,
                        allow_prev_fallback=False)
    if isinstance(decision, IUEFailure):
        return {
            "intake_decision": None,
            "iue_failure": decision.to_dict(),
        }

    # 2. Collect
    raw = collect(payload, mime=resolved_mime,
                    input_id=decision.input_id,
                    tenant_id=decision.tenant_id,
                    upstream=decision.provenance)
    if isinstance(raw, IUEFailure):
        return {
            "intake_decision": decision.to_dict(),
            "iue_failure": raw.to_dict(),
        }

    # 3. Parse → 4. Normalize → 5. Aggregate → 6. Understand
    parsed = list(iter_records(raw))
    ok_r = [p for p in parsed if p.parse_status == "ok"]
    bad_r = [p for p in parsed if p.parse_status != "ok"]
    normalized = [normalize(p) for p in ok_r]
    events = aggregate(normalized)
    fragment = understand_structured(events)

    return {
        "intake_decision": decision.to_dict(),
        "raw_payload":     raw.to_dict(),
        "logical_events":  [ev.to_dict() for ev in events],
        "malformed":       [p.to_dict() for p in bad_r],
        "report_extraction_fragment": fragment,
    }
