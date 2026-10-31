"""Newest-first cursor paging. The RC8 'oldest N of the window' behaviour is impossible here:
the first page is always the newest evidence, and every older event is reachable by cursor."""
from __future__ import annotations

import base64
import json
from typing import Any

PAGE_DEFAULT = 200
PAGE_MAX = 500


class BadCursor(ValueError):
    pass


def _enc(d: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).decode()


def _dec(c: str) -> dict[str, Any]:
    try:
        d = json.loads(base64.urlsafe_b64decode(c.encode()).decode())
        return {"t": int(d["t"]), "id": str(d["id"]), "as_of": d.get("as_of")}
    except Exception as ex:
        raise BadCursor("cursor is not a valid e3 trajectory cursor") from ex


def _key(ev: dict[str, Any]):
    return (ev["observed_ms"], ev["event_id"])


def page_newest_first(events: list[dict[str, Any]], page_size: int = PAGE_DEFAULT,
                      cursor: str | None = None, as_of_ms: int | None = None) -> dict[str, Any]:
    """Order: observed_ms DESC, event_id DESC (total order → no dup/loss at page boundaries).

    `as_of` freezes the session on ingested_ms, so an event delivered late during paging cannot
    slip in above an already-returned boundary; a new session (no cursor) includes it.
    """
    size = max(1, min(int(page_size or PAGE_DEFAULT), PAGE_MAX))
    cur = _dec(cursor) if cursor else None
    as_of = cur["as_of"] if cur else as_of_ms
    placed = [e for e in events if e.get("observed_ms") is not None]
    unplaced = len(events) - len(placed)
    if as_of is not None:
        placed = [e for e in placed if e.get("ingested_ms") is None or e["ingested_ms"] <= as_of]
    placed.sort(key=_key, reverse=True)
    if cur:
        bound = (cur["t"], cur["id"])
        placed = [e for e in placed if _key(e) < bound]
    items = placed[:size]
    more = len(placed) > size
    nxt = _enc({"t": items[-1]["observed_ms"], "id": items[-1]["event_id"], "as_of": as_of}) if more and items else None
    return {"order": "NEWEST_FIRST", "page_size": size, "items": items, "has_more": more, "next_cursor": nxt,
            "as_of": as_of, "remaining_older": max(0, len(placed) - size), "unplaced_without_observed_at": unplaced}
