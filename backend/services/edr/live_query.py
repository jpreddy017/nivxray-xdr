"""Live Query · one read-only question, answered by the endpoint now.

Version one asks exactly one thing: *which running processes on this computer
match this exact name, right now*. It is a COLLECTION, not a search of stored
telemetry — polling records when a process was first observed, which cannot
answer what is running at this moment.

One query is one command on the existing response plane, so the query id is the
command id, the request is bound to the acting customer and endpoint, a sensor
claims only its own commands, and a redelivered result returns the original
query unchanged.

The honest limit that shapes the result: Linux stores a process name in
`/proc/<pid>/comm`, which the kernel truncates to 15 characters. A longer name
is therefore compared on its first 15 characters, and the answer says so rather
than letting a truncated comparison read as an exact one.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from edr_plane import response as resp

ACTION = "LIVE_QUERY_PROCESS_NAME"
QUESTION = "Which running processes match this exact name on this computer now?"

#: /proc/<pid>/comm is TASK_COMM_LEN - 1 characters.
COMM_MAX = 15

TIMEOUT_SECONDS = 180

QUEUED = "QUEUED"
RUNNING = "RUNNING"
COMPLETED_WITH_MATCHES = "COMPLETED_WITH_MATCHES"
COMPLETED_NO_MATCHES = "COMPLETED_NO_MATCHES"
FAILED = "FAILED"
CAPABILITY_UNAVAILABLE = "CAPABILITY_UNAVAILABLE"
TIMED_OUT = "TIMED_OUT"

STATUS_MEANING = {
    QUEUED: "recorded and waiting for the sensor to claim it; nothing has run",
    RUNNING: "claimed by the endpoint; the query has not reported back yet",
    COMPLETED_WITH_MATCHES: "the endpoint ran the query and found matches",
    COMPLETED_NO_MATCHES: ("the endpoint ran the query and NOTHING matched. "
                           "That is an answer — the process is not running "
                           "under this name right now — not a failure and not "
                           "a timeout"),
    FAILED: "the endpoint attempted the query and it did not complete",
    CAPABILITY_UNAVAILABLE: ("this sensor build cannot answer a live query. "
                             "Nothing was asked of the endpoint, and stored "
                             "telemetry was NOT used in its place"),
    TIMED_OUT: (f"no answer arrived within {TIMEOUT_SECONDS}s. The query is "
                f"unanswered; nothing is claimed about what is running"),
}


class QueryError(Exception):
    def __init__(self, code: str, reason: str, http: int = 400):
        self.code, self.reason, self.http = code, reason, http
        super().__init__(reason)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _parse(ts: Optional[str]) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(str(ts)) if ts else None
    except ValueError:
        return None


def normalise(name: str) -> Dict[str, Any]:
    """What will actually be compared, and whether that is the whole name."""
    raw = (name or "").strip()
    if not raw:
        raise QueryError("EMPTY_PROCESS_NAME",
                         "a live query needs a process name to match; nothing "
                         "was asked of the endpoint")
    if len(raw) > 255:
        raise QueryError("PROCESS_NAME_TOO_LONG",
                         "a process name longer than 255 characters cannot "
                         "name a Linux process")
    compared = raw[:COMM_MAX]
    return {"requested": raw, "compared": compared,
            "truncated": compared != raw,
            "basis": (f"Linux truncates /proc/<pid>/comm to {COMM_MAX} "
                      f"characters, so this matches on {compared!r}"
                      if compared != raw else
                      f"exact match on /proc/<pid>/comm ({compared!r})")}


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
        return COMPLETED_WITH_MATCHES if rows else COMPLETED_NO_MATCHES
    return FAILED


def _view(doc: Dict[str, Any], *, rows: bool = False,
          now: Optional[datetime] = None) -> Dict[str, Any]:
    result = doc.get("sensor_result") or {}
    ev = result.get("evidence") or {}
    target = doc.get("target") or {}
    status = _status(doc, now)
    out = {
        "query_id": doc.get("command_id"),
        "tenant_id": doc.get("tenant_id"),
        "endpoint_id": doc.get("endpoint_id"),
        "requested_by": doc.get("requested_by"),
        "requested_at": doc.get("requested_at"),
        "dispatched_at": doc.get("dispatched_at"),
        "reported_at": result.get("at"),
        # The question and its target travel with every answer, so an analyst
        # can see exactly what was checked and on which computer.
        "question": QUESTION,
        "process_name": target.get("process_name"),
        "name_compared": target.get("name_compared"),
        "name_truncated": bool(target.get("name_truncated")),
        "match_basis": target.get("match_basis"),
        "collected_at": ev.get("collected_at"),
        "match_count": ev.get("match_count") if ev else None,
        "processes_examined": ev.get("processes_examined") if ev else None,
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
    return out


async def run(db, *, tenant_id: str, endpoint_id: str, process_name: str,
              requested_by: str, authority: Optional[Dict] = None) -> Dict:
    """Record the question. The endpoint answers it; nothing is answered here."""
    name = normalise(process_name)
    cmd = await resp.request_action(
        db, tenant_id=tenant_id, endpoint_id=endpoint_id, action=ACTION,
        target={"process_name": name["requested"],
                "name_compared": name["compared"],
                "name_truncated": name["truncated"],
                "match_basis": name["basis"]},
        reason=f"live query · process name {name['requested']!r}",
        requested_by=requested_by, authority=authority)
    return {**_view(cmd), "honesty_note": (
        "The question is recorded, not answered. Until the endpoint reports, "
        "this says nothing about what is running on it.")}


async def list_queries(db, *, tenant_id: str,
                       endpoint_id: Optional[str] = None,
                       limit: int = 50) -> Dict[str, Any]:
    q: Dict[str, Any] = {"tenant_id": tenant_id, "action": ACTION}
    if endpoint_id:
        q["endpoint_id"] = endpoint_id
    cur = db[resp.COLLECTION].find(q, projection={"_id": 0}).sort(
        "requested_at", -1).limit(max(1, min(limit, 200)))
    now = _now()
    rows: List[Dict[str, Any]] = [_view(d, now=now) async for d in cur]
    return {"ok": True, "tenant_id": tenant_id, "endpoint_id": endpoint_id,
            "question": QUESTION, "queries": rows, "count": len(rows),
            "timeout_seconds": TIMEOUT_SECONDS,
            "collection_basis": (
                "Every answer comes from a fresh read on the endpoint when the "
                "query was claimed. Stored telemetry is never searched to "
                "answer a live query.")}


async def get_query(db, *, tenant_id: str, query_id: str) -> Optional[Dict]:
    doc = await db[resp.COLLECTION].find_one(
        {"tenant_id": tenant_id, "action": ACTION, "command_id": query_id},
        projection={"_id": 0})
    return _view(doc, rows=True) if doc else None
