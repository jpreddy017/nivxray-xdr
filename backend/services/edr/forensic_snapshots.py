"""Forensic snapshots · on-demand, read-only collection from one endpoint.

One job is one command on the existing response plane
(`edr_plane/response.py`), so a snapshot inherits the same guarantees as a
containment action: the job id is the command id, the request is bound to the
authorized customer and endpoint, the sensor claims only its own commands under
its own session, and a redelivered result returns the ORIGINAL job unchanged.

What this must never do is answer "what was running" from stored telemetry.
Historical polling records which processes were FIRST OBSERVED; it cannot
establish the set that existed at capture time. A snapshot is therefore only
ever the sensor's own fresh read, and an endpoint whose sensor cannot perform
one reports `CAPABILITY_UNAVAILABLE` rather than being answered from history.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from edr_plane import response as resp

ACTION = "COLLECT_PROCESS_SNAPSHOT"

#: A sensor claims within one poll interval and a /proc walk is fast. Past
#: this, a job that never came back is reported as TIMED_OUT rather than left
#: reading as though it were still running.
TIMEOUT_SECONDS = 180

#: Derived job status. The underlying command state is kept alongside it so
#: nothing is hidden behind the friendlier word.
QUEUED = "QUEUED"
RUNNING = "RUNNING"
COMPLETED_WITH_ROWS = "COMPLETED_WITH_ROWS"
COMPLETED_ZERO_ROWS = "COMPLETED_ZERO_ROWS"
FAILED = "FAILED"
CAPABILITY_UNAVAILABLE = "CAPABILITY_UNAVAILABLE"
TIMED_OUT = "TIMED_OUT"

STATUS_MEANING = {
    QUEUED: "recorded and waiting for the sensor to claim it; nothing has run",
    RUNNING: "claimed by the endpoint; the capture has not reported back yet",
    COMPLETED_WITH_ROWS: "the sensor captured and returned process rows",
    COMPLETED_ZERO_ROWS: ("the capture ran and returned NO rows — this is an "
                          "empty result, not a failure, and not a timeout"),
    FAILED: "the sensor attempted the capture and it did not complete",
    CAPABILITY_UNAVAILABLE: ("this sensor build cannot collect on demand. "
                             "Nothing was captured, and history was NOT used "
                             "to answer in its place"),
    TIMED_OUT: (f"no result arrived within {TIMEOUT_SECONDS}s. The job is not "
                f"lost — it is unanswered, and nothing is claimed about the "
                f"endpoint's state"),
}


#: What Cisco's Orbital-backed snapshot collects, and what ours does. AMP's
#: catalog query returns loaded modules, logged-in users, open network ports,
#: wireless networks and shell history; this sensor collects processes only.
#: The sections are listed either way, because an analyst comparing the two
#: consoles must be able to see the difference rather than infer it from an
#: absence.
SECTIONS = (
    ("Running processes", True,
     "pid, name and executable path from one /proc walk at capture time"),
    ("Logged-in users", False, "not collected by this sensor"),
    ("Open network ports", False,
     "not collected on demand; connections are not collected at all"),
    ("Loaded modules", False, "not collected by this sensor"),
    ("Wireless networks", False, "not collected by this sensor"),
    ("Shell history", False, "not collected by this sensor"),
    ("Scheduled tasks and services", False, "not collected by this sensor"),
    ("Memory image", False,
     "never collected; a snapshot is metadata, not a memory dump"),
)

#: Nothing deletes a snapshot here. Cisco's console keeps one for two days;
#: this preview keeps every job until its database is cleared, and says so
#: rather than implying a retention policy it does not run.
RETENTION_NOTE = ("No retention job runs in this preview: every snapshot and "
                  "its rows are kept until the database is cleared. Cisco's "
                  "console keeps a snapshot for two days.")


def sections(row_count: Optional[int]) -> List[Dict[str, Any]]:
    return [{"section": name,
             "state": "COLLECTED" if ok else "NOT_COLLECTED",
             "rows": row_count if ok else None,
             "note": note} for name, ok, note in SECTIONS]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse(ts: Optional[str]) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(str(ts)) if ts else None
    except ValueError:
        return None


def _status(doc: Dict[str, Any], now: Optional[datetime] = None) -> str:
    state = str(doc.get("state") or "")
    result = doc.get("sensor_result") or {}
    if state in ("REQUESTED", "AUTHORIZED", "DISPATCHED"):
        started = _parse(doc.get("requested_at"))
        if started and (now or _now()) - started > timedelta(
                seconds=TIMEOUT_SECONDS):
            return TIMED_OUT
        return RUNNING if state == "DISPATCHED" else QUEUED
    if state == "CAPABILITY_UNAVAILABLE":
        return CAPABILITY_UNAVAILABLE
    if state in ("EXECUTED", "VERIFIED"):
        rows = (result.get("evidence") or {}).get("rows") or []
        return COMPLETED_WITH_ROWS if rows else COMPLETED_ZERO_ROWS
    return FAILED


def _job(doc: Dict[str, Any], *, rows: bool = False,
         now: Optional[datetime] = None) -> Dict[str, Any]:
    result = doc.get("sensor_result") or {}
    ev = result.get("evidence") or {}
    status = _status(doc, now)
    out = {
        "job_id": doc.get("command_id"),
        "tenant_id": doc.get("tenant_id"),
        "endpoint_id": doc.get("endpoint_id"),
        "requested_by": doc.get("requested_by"),
        "requested_at": doc.get("requested_at"),
        "dispatched_at": doc.get("dispatched_at"),
        "reported_at": result.get("at"),
        "capture_started_at": ev.get("capture_started_at"),
        "capture_finished_at": ev.get("capture_finished_at"),
        "row_count": ev.get("row_count") if ev else None,
        "status": status,
        "status_meaning": STATUS_MEANING[status],
        "command_state": doc.get("state"),
        "detail": result.get("detail"),
        "sensor_version": ev.get("sensor_version"),
        "collection_basis": ev.get("collection_basis"),
        "not_observed": ev.get("not_observed"),
    }
    if rows:
        out["rows"] = ev.get("rows") or []
        out["rows_truncated"] = bool(ev.get("rows_truncated"))
        out["sections"] = sections(ev.get("row_count") if ev else None)
        out["retention_note"] = RETENTION_NOTE
    return out


async def request(db, *, tenant_id: str, endpoint_id: str, requested_by: str,
                  reason: str = "", authority: Optional[Dict] = None) -> Dict:
    """Record the request. Nothing is captured here — the endpoint does that."""
    cmd = await resp.request_action(
        db, tenant_id=tenant_id, endpoint_id=endpoint_id, action=ACTION,
        target={}, reason=reason or "analyst-requested process snapshot",
        requested_by=requested_by, authority=authority)
    return {**_job(cmd), "honesty_note": (
        "The job is recorded, not captured. Until the endpoint reports, this "
        "says nothing about what is running on it.")}


async def list_jobs(db, *, tenant_id: str, endpoint_id: Optional[str] = None,
                    limit: int = 50) -> Dict[str, Any]:
    q: Dict[str, Any] = {"tenant_id": tenant_id, "action": ACTION}
    if endpoint_id:
        q["endpoint_id"] = endpoint_id
    cur = db[resp.COLLECTION].find(q, projection={"_id": 0}).sort(
        "requested_at", -1).limit(max(1, min(limit, 200)))
    now = _now()
    jobs: List[Dict[str, Any]] = [_job(d, now=now) async for d in cur]
    return {"ok": True, "tenant_id": tenant_id, "endpoint_id": endpoint_id,
            "jobs": jobs, "count": len(jobs),
            "timeout_seconds": TIMEOUT_SECONDS,
            "collection_basis": (
                "Every row comes from a fresh read on the endpoint at capture "
                "time. Stored telemetry is never used to answer a snapshot.")}


async def get_job(db, *, tenant_id: str, job_id: str) -> Optional[Dict]:
    """One job WITH its rows, readable only inside its own customer."""
    doc = await db[resp.COLLECTION].find_one(
        {"tenant_id": tenant_id, "action": ACTION, "command_id": job_id},
        projection={"_id": 0})
    return _job(doc, rows=True) if doc else None
