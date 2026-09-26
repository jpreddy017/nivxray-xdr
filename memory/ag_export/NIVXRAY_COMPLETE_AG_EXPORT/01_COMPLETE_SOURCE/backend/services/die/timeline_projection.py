"""Workspace Timeline Graph · MVP (2026-08-11).

Read-only projection of the existing canonical investigation evidence
into a chronologically-ordered event list for the Workspace Timeline
panel.

Design constraints (owner directive, super-high-caution):

    · MUST NOT modify the existing `/api/die/investigation-results`
      payload, P0.2 evidence chain, P0.3 firewall, Sample1, or the
      shared investigation pipeline.
    · MUST be a projection — never invent events or relationships.
    · Only events that carry a real timestamp are emitted.  Narrative
      MITRE mentions (no timestamp) do NOT appear in the timeline;
      they remain visible via the existing MITRE panels.
    · Every emitted event carries the evidence_ref from the same
      P0.2-gated evidence chain the Workspace already renders.

Long-term architectural target (implementation deferred):

    RAW LOGS / ALERTS / EDR
              ↓
      Canonical Events
              ↓
      Evidence Objects  ────►  Timeline (this module)
              ↓
     Correlation / IKG
              ↓
      Workspace Timeline Graph

For MVP, the sole source of timestamped events is
`object.csv_edr.highconf_events` from `csv_edr_analyzer.analyze()`.
When future adapters (Sysmon / EVTX / CrowdStrike / Defender) feed
the same canonical event bag, this projection will pick them up
automatically without further changes.
"""
from __future__ import annotations

import csv
import io
from typing import Any, Dict, List, Optional


# Fields the analyst UI can display when present. `None` where the
# CSV/EDR row didn't supply the field.  We NEVER synthesise a value.
_EVENT_KEYS = (
    "timestamp",
    "source",
    "event_type",
    "host",
    "user",
    "process",
    "parent_process",
    "command_line",
    "file_context",
    "network_context",
    "registry_context",
    "event_or_rule",
    "evidence_ref",
    "mitre",
    "confidence",
)


# ─────────────────────────────────────────────────────────────────
#  CSV re-parse — purely local; does NOT mutate the shared
#  csv_edr_analyzer or the investigation payload.
# ─────────────────────────────────────────────────────────────────
def _index_csv_rows_by_row_key(raw_text: str) -> Dict[str, Dict[str, str]]:
    """Second-pass CSV read to expose fields the shared analyzer
    processed internally but did not propagate into highconf_events
    (user, parent_process, file_path).

    Returns a dict keyed by `date|host|category|file` because that
    combination uniquely identifies a highconf event row.  A row
    without a `date` column is skipped.
    """
    out: Dict[str, Dict[str, str]] = {}
    if not raw_text or "\n" not in raw_text:
        return out
    try:
        reader = csv.reader(io.StringIO(raw_text))
        header = next(reader, None)
        if not header:
            return out
    except Exception:
        return out

    # Match the canonical csv_edr header names (subset — same names
    # csv_edr_analyzer uses so we stay aligned).
    idx: Dict[str, Optional[int]] = {
        "date":      None, "src_host": None, "user": None,
        "file_name": None, "parent_file_name": None,
        "file_path": None, "action":   None, "category": None,
    }
    for i, name in enumerate(header):
        key = (name or "").strip().lower().replace(" ", "_")
        if key in idx and idx[key] is None:
            idx[key] = i

    if idx["date"] is None:
        return out  # no timestamp column → nothing to project

    for row in reader:
        if not row:
            continue
        def cell(k: str) -> str:
            i = idx.get(k)
            if i is None or i >= len(row):
                return ""
            return (row[i] or "").strip()
        date = cell("date")
        if not date:
            continue
        key = f'{date}|{cell("src_host")}|{cell("category")}|{cell("file_name")}'
        out[key] = {
            "user":             cell("user"),
            "parent_process":   cell("parent_file_name"),
            "file_path":        cell("file_path"),
            "action":           cell("action"),
        }
    return out


# ─────────────────────────────────────────────────────────────────
#  Evidence lookup — pull the P0.2 evidence chain the augmenter
#  already computed for each technique.
# ─────────────────────────────────────────────────────────────────
def _evidence_index(obj: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Build {mitre_id → first evidence record}.  We use the FIRST
    record because timeline events are per-row and we want a stable
    click-through to a citable evidence chain.  Additional evidence
    records remain available via the existing MITRE panels.
    """
    ev: Dict[str, Dict[str, Any]] = {}
    for t in (obj.get("mitre") or []):
        if not isinstance(t, dict):
            continue
        tid = t.get("id")
        records = t.get("evidence") or []
        if not tid or not records:
            continue
        if isinstance(records, list) and isinstance(records[0], dict):
            ev[tid] = records[0]
    return ev


def _mitre_index(obj: Dict[str, Any]) -> Dict[str, str]:
    return {t.get("id"): t.get("name", "")
            for t in (obj.get("mitre") or []) if isinstance(t, dict)}


# ─────────────────────────────────────────────────────────────────
#  Projection — the single entry point.
# ─────────────────────────────────────────────────────────────────
def project_timeline(raw_text: str, investigation_object: Dict[str, Any]) -> Dict[str, Any]:
    """Project the investigation object into a Workspace Timeline
    envelope.  Returns:

        {
          "events":       [ ...timeline events sorted by timestamp... ],
          "event_count":  int,
          "span_start":   ISO timestamp | None,
          "span_end":     ISO timestamp | None,
          "hosts":        [distinct host strings],
          "users":        [distinct user strings],
          "sources":      [distinct source names],
          "meta": {
            "projection":  "workspace_timeline_mvp",
            "note":        "Read-only projection; narrative-only techniques"
                           " have no timestamp and are intentionally omitted.",
          }
        }
    """
    if not isinstance(investigation_object, dict):
        return _empty()

    csv_edr = investigation_object.get("csv_edr") or {}
    highconf = csv_edr.get("highconf_events") or []
    if not isinstance(highconf, list) or not highconf:
        return _empty()

    enrich = _index_csv_rows_by_row_key(raw_text or "")
    ev_by_tid = _evidence_index(investigation_object)
    name_by_tid = _mitre_index(investigation_object)

    events: List[Dict[str, Any]] = []
    hosts, users, sources = set(), set(), set()

    for hc in highconf:
        if not isinstance(hc, dict):
            continue
        ts = (hc.get("date") or "").strip()
        if not ts:
            continue                       # no timestamp → not eligible
        host = (hc.get("host") or "").strip() or None
        cat  = (hc.get("category") or "").strip()
        action = (hc.get("action") or "").strip()
        fn   = (hc.get("file") or "").strip() or None
        fh   = (hc.get("hash") or "").strip()
        tid  = (hc.get("technique") or "").strip() or None

        key = f"{ts}|{host or ''}|{cat}|{fn or ''}"
        extra = enrich.get(key) or {}

        ev_record = ev_by_tid.get(tid) if tid else None
        mitre_refs = []
        if tid:
            mitre_refs = [{"id": tid, "name": name_by_tid.get(tid, "")}]

        event = {
            "timestamp":       ts,
            "source":          "csv_edr_analyzer",
            "event_type":      _event_type(cat, action),
            "host":            host,
            "user":            (extra.get("user") or None),
            "process":         fn,
            "parent_process":  (extra.get("parent_process") or None),
            "command_line":    None,     # not present in SEP-style CSV EDR
            "file_context":    _file_context(fn, fh, extra.get("file_path")),
            "network_context": None,     # not present in SEP-style CSV EDR
            "registry_context": None,    # not present in SEP-style CSV EDR
            "event_or_rule":   (ev_record.get("event_or_rule")
                                if ev_record else _event_type(cat, action)),
            "evidence_ref":    (ev_record.get("evidence_ref")
                                if ev_record else None),
            "mitre":           mitre_refs,
            "confidence":      _confidence(action, ev_record),
        }
        events.append(event)
        if host:  hosts.add(host)
        if event["user"]:  users.add(event["user"])
        sources.add(event["source"])

    # Sort chronologically by timestamp string (ISO-8601 sortable).
    events.sort(key=lambda e: e["timestamp"])

    return {
        "events":      events,
        "event_count": len(events),
        "span_start":  events[0]["timestamp"] if events else None,
        "span_end":    events[-1]["timestamp"] if events else None,
        "hosts":       sorted(hosts),
        "users":       sorted(users),
        "sources":     sorted(sources),
        "meta": {
            "projection": "workspace_timeline_mvp",
            "note":       ("Read-only projection over highconf_events "
                           "+ canonical evidence chain. Narrative-only "
                           "techniques (no timestamp) are intentionally "
                           "omitted."),
        },
    }


def _empty() -> Dict[str, Any]:
    return {
        "events":      [],
        "event_count": 0,
        "span_start":  None,
        "span_end":    None,
        "hosts":       [],
        "users":       [],
        "sources":     [],
        "meta": {
            "projection": "workspace_timeline_mvp",
            "note":       "No timestamped events available in the "
                          "current investigation.",
        },
    }


def _event_type(category: str, action: str) -> str:
    """Compose a stable event_type string from category + action."""
    cat = (category or "").strip().lower().replace(" ", "_")
    act = (action or "").strip().lower()
    if not cat and not act:
        return "unspecified"
    if not cat:
        return f"unspecified.{act}"
    if not act:
        return cat
    return f"{cat}.{act}"


def _file_context(name: Optional[str], sha256: str, path: Optional[str]) -> Optional[Dict[str, str]]:
    ctx: Dict[str, str] = {}
    if name:            ctx["name"]   = name
    if sha256:          ctx["sha256"] = sha256
    if path:            ctx["path"]   = path
    return ctx or None


def _confidence(action: str, ev_record: Optional[Dict[str, Any]]) -> str:
    """Confidence heuristic — never a lookup that could invent value.

    - 'block' / 'quarantine' / 'remove' / 'clean' from an EDR are the
       strongest signal → high.
    - 'detect' → medium.
    - Anything else defaults to the evidence record's confidence, or
       'low' when unspecified.
    """
    a = (action or "").strip().lower()
    if a in ("block", "quarantine", "remove", "clean"):
        return "high"
    if a == "detect":
        return "medium"
    if ev_record and ev_record.get("confidence"):
        return str(ev_record["confidence"])
    return "low"


__all__ = ["project_timeline", "_EVENT_KEYS"]
