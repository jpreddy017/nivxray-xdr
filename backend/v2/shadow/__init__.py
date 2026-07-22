"""NivXRay v2 · Shadow observation sink.

Entry point that turns a raw command-line input into a persisted
CEM v1 event in the dedicated `v2_shadow_observations` collection.

**Read-only w.r.t. RC5.** This module:
  • Never imports from `engine.*`.
  • Never calls any RC5 endpoint.
  • Never writes to any RC5 collection.
  • Never runs unless `NIVX_FLAG_ADAPTERS` is `shadow` or `enabled`.

Callers (v2 tests / future v2 endpoints) opt in explicitly. RC5
paths are unaware this module exists.
"""
from __future__ import annotations

import hashlib
from typing import Any

from v2.adapters.base import Source
from v2.adapters.command_line import CommandLineAdapter
from v2.case_engine.schema import COLLECTIONS
from v2.cem.v1.schema import CanonicalEvent
from v2.flags import get as get_flag
from v2.normalization.command_line_normalizer import CommandLineNormalizer


def observe(text: str, *, case_id: str = "shadow-case-default") -> CanonicalEvent | None:
    """Return a CEM event for `text`, or None when the flag is off.

    Pure function: no I/O, no side effects, safe to call anywhere.
    """
    if not get_flag("ADAPTERS").observable():
        return None
    adapter = CommandLineAdapter()
    src = Source(kind="bytes", ref=text)
    raw_events = list(adapter.stream(src))
    if not raw_events:
        return None
    norm = CommandLineNormalizer()
    events = list(norm.normalize(raw_events[0], case_id=case_id))
    return events[0] if events else None


async def persist(db: Any, event: CanonicalEvent) -> str | None:
    """Persist a shadow-observation to its dedicated collection.

    Refuses to run unless `NIVX_FLAG_ADAPTERS` is `shadow` or
    `enabled`. Returns the inserted document id (or None if skipped).

    Writes go ONLY to `v2_shadow_observations` — never to any RC5
    collection. Deterministic input_sha256 lets us dedupe repeat
    observations without loading the whole collection into memory.
    """
    if not get_flag("ADAPTERS").observable():
        return None
    doc = {
        "adapter":       event.adapter,
        "cem_version":   "v1",
        "case_id":       event.case_id,
        "captured_at":   event.ts,
        "kind":          event.kind,
        "process_iid":   event.process_iid,
        "artefacts_iids":list(event.artefacts_iids),
        "input_sha256":  event.raw.get("sha256"),
        "event":         event.to_dict(),
    }
    # Ensure indexes exist on the shadow collection specifically —
    # cheap and idempotent. Full ensure_indexes() runs only when
    # CASE_ENGINE flag is on; we do the minimum here regardless.
    coll = db[COLLECTIONS["shadow_observations"]]
    await coll.create_index([("input_sha256", 1)], name="shadow_input_sha")
    await coll.create_index([("adapter", 1), ("captured_at", -1)], name="shadow_adapter_ts")
    result = await coll.insert_one(doc)
    return str(result.inserted_id)


__all__ = ["observe", "persist"]
