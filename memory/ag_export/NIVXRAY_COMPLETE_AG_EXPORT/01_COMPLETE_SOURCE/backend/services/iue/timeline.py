"""Attack Story Timeline — deterministic projection over Lane A/B/C
canonical LogicalEvents.

Architectural contract (owner directive):
    Evidence first → canonical evidence → correlation/SSOT →
    **investigation story (THIS module)** → intent/objectives → verdict.

  - PURE projection: does NOT do correlation, does NOT synthesise
    events, does NOT invent relationships.  All correlation belongs
    to ICE / SSOT layers upstream.
  - Consumes ``LogicalEvent[]`` dicts (the T2 wire ``logical_events``
    field emitted by Lane A / Lane B / Lane C).  Any lane whose
    canonical events pass through the shared aggregator can feed
    the timeline without further changes.
  - Deterministic sort key: ``canonical.event.timestamp`` (bucketed
    to 1 s by the aggregator) → falls back to ``first_seen``.
  - Events without any usable timestamp are surfaced in a separate
    ``untimed_events`` bucket so the analyst still sees them.
  - Cross-lane fuse = strict union + sort. No cross-lane grouping,
    no cross-lane semantic reunification.  ICE does that later.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence, Tuple


# ── Canonical field keys the timeline projects (Lane A/B/C shared) ──
_TS_KEY       = "canonical.event.timestamp"
_ACTION_KEY   = "canonical.event.action"
_CATEGORY_KEY = "canonical.event.category"
_SRC_IP_KEY   = "canonical.source.ip"
_SRC_HOST_KEY = "canonical.source.host"
_SRC_USER_KEY = "canonical.source.user"
_DST_IP_KEY   = "canonical.destination.ip"
_DST_DOM_KEY  = "canonical.destination.domain"
_DST_URL_KEY  = "canonical.destination.url"
_DST_HOST_KEY = "canonical.destination.host"
_DST_PORT_KEY = "canonical.destination.port"
_PROC_NAME    = "canonical.process.name"
_PROC_PARENT  = "canonical.process.parent"
_PROC_CMD     = "canonical.process.command_line"
_FILE_PATH    = "canonical.file.path"
_FILE_NAME    = "canonical.file.name"
_FILE_MIME    = "canonical.file.mime"
_FILE_SIZE    = "canonical.file.size"
_FILE_SHA256  = "canonical.file.hash.sha256"
_FILE_MD5     = "canonical.file.hash.md5"
_FILE_SHA1    = "canonical.file.hash.sha1"
_ART_TYPE     = "canonical.artifact.type"
_ART_NAME     = "canonical.artifact.display_name"
_ART_KIND     = "canonical.artifact.child_kind"
_ART_VAL      = "canonical.artifact.child_value"


def _sort_key(event: Dict[str, Any]) -> Tuple[int, str, str]:
    """Deterministic sort key for a projected timeline event.

    Priority:  (has_canonical_ts?, ts_or_first_seen, event_id)
    - has_canonical_ts=0 wins over has_canonical_ts=1, so timestamped
      events sort first.
    - Ties are broken by event_id (stable across replays).
    """
    ts = event.get("timestamp") or ""
    prio = 0 if event.get("timestamp_source") == "canonical" else 1
    return (prio, ts or event.get("first_seen") or "", event.get("event_id") or "")


def _destination_summary(cf: Dict[str, Any]) -> Optional[str]:
    """Return the highest-fidelity destination string available.

    Port is appended ONLY when the destination is a host/ip — URLs
    already encode their port and appending it would break routing.
    """
    url = cf.get(_DST_URL_KEY)
    if url:
        return str(url)
    for k in (_DST_DOM_KEY, _DST_HOST_KEY, _DST_IP_KEY):
        v = cf.get(k)
        if v:
            port = cf.get(_DST_PORT_KEY)
            return f"{v}:{port}" if port else str(v)
    return None


def _artifact_ref(cf: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Compose a compact artifact reference (Lane C primary/child records)."""
    art_type = cf.get(_ART_TYPE)
    if not art_type:
        return None
    ref: Dict[str, Any] = {"type": art_type}
    if cf.get(_ART_NAME):
        ref["display_name"] = cf[_ART_NAME]
    if cf.get(_FILE_NAME):
        ref["file_name"] = cf[_FILE_NAME]
    if cf.get(_FILE_SHA256):
        ref["sha256"] = cf[_FILE_SHA256]
    if cf.get(_FILE_SIZE):
        ref["size"] = cf[_FILE_SIZE]
    if cf.get(_ART_KIND):
        ref["child_kind"] = cf[_ART_KIND]
        ref["child_value"] = cf.get(_ART_VAL)
    return ref


def _file_ref(cf: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """File reference (raw log path/hash — NOT artifact identity)."""
    if not (cf.get(_FILE_PATH) or cf.get(_FILE_SHA256)
            or cf.get(_FILE_MD5) or cf.get(_FILE_SHA1)):
        return None
    ref: Dict[str, Any] = {}
    for k, out_k in (
        (_FILE_PATH,   "path"),
        (_FILE_NAME,   "name"),
        (_FILE_SHA256, "sha256"),
        (_FILE_MD5,    "md5"),
        (_FILE_SHA1,   "sha1"),
        (_FILE_MIME,   "mime"),
    ):
        v = cf.get(k)
        if v:
            ref[out_k] = v
    return ref or None


def _project_event(le: Dict[str, Any], lane: str) -> Dict[str, Any]:
    """Convert a single LogicalEvent dict → TimelineEvent dict."""
    cf = le.get("canonical_fields") or {}
    ts = cf.get(_TS_KEY)
    if ts:
        timestamp, ts_source = str(ts), "canonical"
    else:
        timestamp, ts_source = le.get("first_seen") or "", "first_seen"

    prov = le.get("provenance") or {}
    upstream = list(prov.get("upstream_evidence_ids") or [])

    return {
        "event_id":         le.get("event_id"),
        "lane":             lane,
        "input_id":         le.get("input_id"),
        "tenant_id":        le.get("tenant_id"),
        "source_file_id":   le.get("source_file_id"),
        "timestamp":        timestamp or None,
        "timestamp_source": ts_source if timestamp else None,
        "first_seen":       le.get("first_seen"),
        "last_seen":        le.get("last_seen"),
        "count":            le.get("count", 1),
        "action":           cf.get(_ACTION_KEY),
        "category":         cf.get(_CATEGORY_KEY),
        "host":             cf.get(_SRC_HOST_KEY),
        "user":             cf.get(_SRC_USER_KEY),
        "actor_ip":         cf.get(_SRC_IP_KEY),
        "destination":      _destination_summary(cf),
        "process":          cf.get(_PROC_NAME),
        "parent_process":   cf.get(_PROC_PARENT),
        "command_line":     cf.get(_PROC_CMD),
        "file_ref":         _file_ref(cf),
        "artifact_ref":     _artifact_ref(cf),
        "provenance_chain": upstream,
        "canonical_fields": dict(cf),
    }


def project_lane(lane_wire: Dict[str, Any],
                  *, lane_hint: Optional[str] = None) -> List[Dict[str, Any]]:
    """Project a single lane's T2 wire fragment into timeline events.

    ``lane_hint`` overrides the ``intake_decision.lane`` value when
    supplied (useful for tests / custom callers).
    """
    if not isinstance(lane_wire, dict):
        return []
    events = lane_wire.get("logical_events") or []
    if not isinstance(events, list):
        return []
    lane = lane_hint or (
        (lane_wire.get("intake_decision") or {}).get("lane") or "unknown"
    )
    return [_project_event(le, lane) for le in events
            if isinstance(le, dict)]


def fuse(lane_wires: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Fuse multiple lane wires into ONE deterministic timeline.

    Returns:
        {
          "events":         list[TimelineEvent],   # timestamped, sorted
          "untimed_events": list[TimelineEvent],   # no timestamp available
          "event_count":    int,
          "untimed_count":  int,
          "span_start":     ISO-str | None,
          "span_end":       ISO-str | None,
          "lanes":          list[str],              # distinct lanes present
          "hosts":          list[str],
          "users":          list[str],
          "meta": {
            "projection":   "attack_story_timeline",
            "note":         "Read-only projection over canonical LogicalEvents. "
                            "No correlation, no inference, no invented events.",
          }
        }
    """
    all_events: List[Dict[str, Any]] = []
    lanes = set()
    for wire in (lane_wires or []):
        if not isinstance(wire, dict):
            continue
        lane_events = project_lane(wire)
        all_events.extend(lane_events)
        for e in lane_events:
            if e.get("lane"):
                lanes.add(e["lane"])

    # Partition timestamped vs untimed.
    timed:    List[Dict[str, Any]] = []
    untimed:  List[Dict[str, Any]] = []
    for e in all_events:
        if e.get("timestamp"):
            timed.append(e)
        else:
            untimed.append(e)

    timed.sort(key=_sort_key)
    untimed.sort(key=lambda e: (e.get("event_id") or ""))

    hosts = sorted({e["host"] for e in timed + untimed if e.get("host")})
    users = sorted({e["user"] for e in timed + untimed if e.get("user")})

    return {
        "events":         timed,
        "untimed_events": untimed,
        "event_count":    len(timed),
        "untimed_count":  len(untimed),
        "span_start":     timed[0]["timestamp"] if timed else None,
        "span_end":       timed[-1]["timestamp"] if timed else None,
        "lanes":          sorted(lanes),
        "hosts":          hosts,
        "users":          users,
        "meta": {
            "projection": "attack_story_timeline",
            "note":       ("Read-only projection over canonical "
                           "LogicalEvents from Lane A/B/C. No "
                           "correlation, no inference, no invented "
                           "events."),
        },
    }


__all__ = ["project_lane", "fuse"]
