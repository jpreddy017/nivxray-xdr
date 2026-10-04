"""Provider-neutral file status. Detection, reputation and assessment are SEPARATE.
No keys, no network: only the own-engine detections and injected test providers exist."""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

REPUTATION_STATES = ("MALICIOUS", "CLEAN", "NO_HIT", "UNKNOWN", "PROVIDER_ERROR", "RATE_LIMITED", "OUTAGE")
EVIDENCE_REQUIRED = ("MALICIOUS", "CLEAN")


def reputation(state: str, *, provider: str, at: str | None, evidence: list[dict[str, Any]] | None = None,
               detail: str | None = None) -> dict[str, Any]:
    s = state if state in REPUTATION_STATES else "UNKNOWN"
    ev = list(evidence or [])
    note = detail
    if s in EVIDENCE_REQUIRED and not ev:
        note = f"{s} claimed without evidence; recorded as UNKNOWN"
        s = "UNKNOWN"
    return {"state": s, "provider": provider, "assessed_at": at, "evidence": ev, "detail": note,
            "is_clean": s == "CLEAN", "provenance": {"provider": provider, "timestamp": at}}


class ProviderFailure(Exception):
    def __init__(self, state: str, detail: str = "") -> None:
        super().__init__(detail)
        self.state = state if state in ("PROVIDER_ERROR", "RATE_LIMITED", "OUTAGE") else "PROVIDER_ERROR"


Lookup = Callable[[str], dict[str, Any]]


def file_status(sha256: str, *, detections: list[dict[str, Any]], providers: dict[str, Lookup],
                now_iso: str | None) -> dict[str, Any]:
    """`detections` = own-engine detection records for this hash (a detection is not a verdict)."""
    reps: list[dict[str, Any]] = []
    for name, fn in sorted(providers.items()):
        try:
            r = fn(sha256)
            reps.append(reputation(r.get("state", "UNKNOWN"), provider=name, at=r.get("at") or now_iso,
                                   evidence=r.get("evidence"), detail=r.get("detail")))
        except ProviderFailure as f:
            reps.append(reputation(f.state, provider=name, at=now_iso, detail=str(f) or f.state))
        except Exception as ex:  # noqa: BLE001
            reps.append(reputation("PROVIDER_ERROR", provider=name, at=now_iso, detail=type(ex).__name__))
    if not reps:
        reps.append(reputation("UNKNOWN", provider="none_configured", at=now_iso,
                               detail="no reputation provider is enabled in E3; UNKNOWN is not CLEAN"))
    return {"subject": {"sha256": sha256}, "schema": "e3.dt.file_status.v1",
            "detections": [{"detection_id": d.get("detection_id"), "rule": d.get("rule"), "at": d.get("at"),
                            "engine": d.get("engine", "nivxforge-own"), "is_verdict": False} for d in detections],
            "detection_state": "DETECTED" if detections else "NO_DETECTION",
            "reputation": reps,
            "assessment": {"state": "UNASSESSED", "basis": "no analyst or engine assessment recorded"},
            "statement": "NO_DETECTION, NO_HIT and UNKNOWN are not CLEAN; a detection is not a malicious verdict."}
