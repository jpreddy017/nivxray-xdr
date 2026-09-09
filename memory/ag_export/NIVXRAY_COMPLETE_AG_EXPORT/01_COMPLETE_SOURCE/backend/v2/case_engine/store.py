"""Case Engine · storage bootstrap.

`ensure_indexes(db)` materialises the v2 collection indexes. It is
NEVER auto-called at import time. Callers must first verify that
CASE_ENGINE feature-flag is at least SHADOW.
"""
from __future__ import annotations

import logging
from typing import Any

from v2.case_engine.schema import COLLECTIONS, INDEX_SPECS
from v2.flags import get as get_flag

log = logging.getLogger(__name__)


async def ensure_indexes(db: Any, *, force: bool = False) -> dict[str, int]:
    """Create every v2 index; idempotent.

    Refuses to run unless `CASE_ENGINE` flag is SHADOW or ENABLED,
    or `force=True` is explicitly passed (test-only escape hatch).

    Returns `{collection_name: index_count_created}`.
    """
    if not force:
        flag = get_flag("CASE_ENGINE")
        if flag.disabled():
            log.info("v2.case_engine: CASE_ENGINE flag disabled — skipping ensure_indexes()")
            return {}

    created: dict[str, int] = {}
    for coll_name, specs in INDEX_SPECS.items():
        coll = db[coll_name]
        n = 0
        for spec, opts in specs:
            await coll.create_index(spec, **opts)
            n += 1
        created[coll_name] = n
    return created


def coll_name(kind: str) -> str:
    """Resolve logical name → real Mongo collection name."""
    if kind not in COLLECTIONS:
        raise KeyError(f"Unknown v2 collection kind: {kind!r}")
    return COLLECTIONS[kind]
