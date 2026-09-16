"""Lane-B acquired-URL parser.

Yields ParsedRecords from an ``URLRawPayload``:
  - 1 primary record for the acquired document itself
  - 0..N records for discovered outbound links (each is a candidate
    for recursive re-entry via services/iue/recurse.py — NOT parsed
    here)

This parser does NOT run the existing IDA extraction (MITRE / IOCs /
threat actors / etc.).  That path remains untouched.  Lane B produces
only the CANONICAL wire contract expected by the EVIDENCE tab —
extraction stays with IDA.
"""
from __future__ import annotations

from typing import Iterator
from urllib.parse import urlparse

from ._errors import malformed_record, ok_record
from ._types import ParsedRecord


def _host_of(url: str) -> str:
    try:
        return urlparse(url or "").hostname or ""
    except Exception:
        return ""


def iter_records(raw) -> Iterator[ParsedRecord]:
    """Yield ParsedRecords derived from ``raw.acquired`` (AcquiredResource
    dict).  ``raw`` MUST be a URLRawPayload; other shapes yield a single
    malformed record."""
    acquired = getattr(raw, "acquired", None)
    if not isinstance(acquired, dict):
        yield malformed_record(raw=raw, parser_name="acquired_url",
                                 offset=0, error="not a URLRawPayload")
        return

    url = acquired.get("final_url") or acquired.get("url") or ""
    host = _host_of(url)
    title = acquired.get("title") or ""
    sitename = acquired.get("sitename") or host
    article_chars = int(acquired.get("article_chars") or 0)
    engine = acquired.get("engine") or ""

    # ── Primary record — the acquired URL itself ─────────────────
    yield ok_record(
        raw=raw, parser_name="acquired_url", offset=0,
        raw_fields={
            "action":     "url_acquire",
            "category":   "url",
            "url":        url,
            "dest_host":  host,          # → canonical.destination.host
            "sitename":   sitename,      # → canonical.destination.domain
            "title":      title,
            "engine":     engine,
            "status":     acquired.get("status_code"),
            "article_chars": article_chars,
            "duration_ms":   acquired.get("duration_ms"),
        },
    )

    # ── Discovered outbound links ─────────────────────────────────
    # Emitted as separate ParsedRecords so the aggregator can group
    # them per (host, action).  Recursive re-entry (fetching them) is
    # NOT performed here — callers may pass each link back through
    # services/iue/recurse.py::recurse() → intake() to walk the tree.
    links = acquired.get("outbound_links") or []
    seen: set = set()
    for i, link in enumerate(links, start=1):
        if not isinstance(link, str) or not link:
            continue
        link_host = _host_of(link)
        # De-duplicate at parse time so we don't emit a ParsedRecord
        # per identical link; aggregation would still collapse them,
        # but this saves memory on very link-heavy pages.
        key = (link_host, link)
        if key in seen:
            continue
        seen.add(key)
        yield ok_record(
            raw=raw, parser_name="acquired_url", offset=i,
            raw_fields={
                "action":     "url_discovered",
                "category":   "network",
                "url":        link,
                "dest_host":  link_host,   # → canonical.destination.host
                "parent_url": url,
            },
        )
