"""Query/Hunt add-on · MVP (2026-08-11).

Read-only *additive* filter capability on top of the same canonical
investigation evidence the Timeline MVP consumes.  The Query/Hunt
result set is a SCOPED sub-view of the same events — never a
parallel investigation, never a new detection engine.

Contract:

    · Consumes the same `highconf_events` + P0.2 evidence chain the
      Timeline MVP consumes.
    · Filters are inclusive (all supplied constraints must match).
    · Filters are stringly-typed and case-insensitive on host/user;
      MITRE / hash / action / category matched exactly (analyst
      intent is unambiguous).
    · The output row shape is IDENTICAL to a Timeline event so
      Timeline / Table / (future) Process Tree / (future) Graph
      views can consume the same records.
    · Does NOT mutate the underlying investigation.  A Query call
      followed by a fresh investigation call MUST produce byte-
      identical Workspace output — enforced by test.
    · No fabricated relationships; the projection uses only fields
      the raw input already exposed.

Filter dictionary keys (all optional):

    host / src_host           str  — substring, case-insensitive
    user                      str  — substring, case-insensitive
    action                    str  — exact match, case-insensitive
    category                  str  — substring, case-insensitive
    process / file_name       str  — substring, case-insensitive
    parent / parent_process   str  — substring, case-insensitive
    file_path                 str  — substring, case-insensitive
    file_hash                 str  — exact match, case-insensitive
    mitre                     str  — exact MITRE technique id (T####)
    event_type                str  — substring, case-insensitive
    date_from / date_to       ISO-8601 string  — inclusive range
    confidence                str  — one of high / medium / low
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from services.die.timeline_projection import project_timeline


# ─────────────────────────────────────────────────────────────────
#  Filter helpers — each accepts (event, criterion) and returns
#  True when the event satisfies the constraint (or the constraint
#  is empty).
# ─────────────────────────────────────────────────────────────────
def _icontains(hay: Optional[str], needle: str) -> bool:
    if not needle:
        return True
    return needle.strip().lower() in (hay or "").lower()


def _iequals(a: Optional[str], b: str) -> bool:
    if not b:
        return True
    return (a or "").strip().lower() == b.strip().lower()


def _matches(event: Dict[str, Any], f: Dict[str, Any]) -> bool:
    if not _icontains(event.get("host"),           f.get("host") or f.get("src_host") or ""):
        return False
    if not _icontains(event.get("user"),           f.get("user") or ""):
        return False
    # Action lives at the end of event_type ("<category>.<action>")
    action_want = (f.get("action") or "").strip().lower()
    if action_want:
        et = (event.get("event_type") or "").lower()
        suffix = et.rsplit(".", 1)[-1]
        if action_want != suffix and action_want not in et:
            return False
    if not _icontains(event.get("event_type"),     f.get("category") or ""):
        return False
    if not _icontains(event.get("process"),        f.get("process") or f.get("file_name") or ""):
        return False
    if not _icontains(event.get("parent_process"), f.get("parent") or f.get("parent_process") or ""):
        return False
    # file_path lives inside file_context.path (dict) — flatten for matching.
    fp = (event.get("file_context") or {}).get("path") or ""
    if not _icontains(fp,                          f.get("file_path") or ""):
        return False
    fh = (event.get("file_context") or {}).get("sha256") or ""
    if f.get("file_hash") and not _iequals(fh, f["file_hash"]):
        return False
    # MITRE filter — event must cite the exact technique id.
    mitre_want = (f.get("mitre") or "").strip().upper()
    if mitre_want:
        ids = {m.get("id","").upper() for m in (event.get("mitre") or []) if isinstance(m, dict)}
        if mitre_want not in ids:
            return False
    if not _icontains(event.get("event_type"),     f.get("event_type") or ""):
        return False
    if f.get("confidence"):
        if not _iequals(event.get("confidence"), f["confidence"]):
            return False
    # date range — inclusive.  ISO-8601 strings sort lexicographically.
    ts = event.get("timestamp") or ""
    df = (f.get("date_from") or "").strip()
    dt = (f.get("date_to") or "").strip()
    if df and ts < df:
        return False
    if dt and ts > dt:
        return False
    return True


def _clean_filters(raw: Dict[str, Any]) -> Dict[str, str]:
    """Retain only string filters with non-empty values, canonicalised."""
    out: Dict[str, str] = {}
    if not isinstance(raw, dict):
        return out
    for k, v in raw.items():
        if v is None:
            continue
        if isinstance(v, (int, float)):
            v = str(v)
        if isinstance(v, str) and v.strip():
            out[str(k)] = v.strip()
    return out


# ─────────────────────────────────────────────────────────────────
#  Public projection entry point.
# ─────────────────────────────────────────────────────────────────
def run_query(raw_text: str,
              investigation_object: Dict[str, Any],
              filters: Dict[str, Any]) -> Dict[str, Any]:
    """Return the scoped Query/Hunt result envelope.

    Envelope:

        {
          "results":          [ ...events matching all filters, same
                                 shape as Timeline events... ],
          "event_count":      int,     # after filtering
          "total_available":  int,     # before filtering
          "span_start":       ISO ts | None,
          "span_end":         ISO ts | None,
          "matched_hosts":    [ ... ],
          "matched_users":    [ ... ],
          "filters_applied":  { …echoed cleaned filters… },
          "meta": {
            "projection":  "workspace_query_hunt_mvp",
            "note":        "Read-only scoped sub-view of the canonical "
                           "investigation evidence.  Not a new detection engine.",
          }
        }
    """
    base = project_timeline(raw_text or "", investigation_object or {})
    all_events: List[Dict[str, Any]] = list(base.get("events") or [])
    clean = _clean_filters(filters or {})

    matched = [e for e in all_events if _matches(e, clean)]
    matched.sort(key=lambda e: e.get("timestamp") or "")

    hosts = sorted({e["host"] for e in matched if e.get("host")})
    users = sorted({e["user"] for e in matched if e.get("user")})

    return {
        "results":         matched,
        "event_count":     len(matched),
        "total_available": len(all_events),
        "span_start":      matched[0]["timestamp"] if matched else None,
        "span_end":        matched[-1]["timestamp"] if matched else None,
        "matched_hosts":   hosts,
        "matched_users":   users,
        "filters_applied": clean,
        "meta": {
            "projection": "workspace_query_hunt_mvp",
            "note":       ("Read-only scoped sub-view of the canonical "
                           "investigation evidence.  Not a new "
                           "detection engine.  Every returned row is "
                           "traceable to its evidence_ref."),
        },
    }


__all__ = ["run_query", "_matches", "_clean_filters"]
