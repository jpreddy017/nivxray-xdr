"""Assembly over an EvidenceProvider: one place where the contracts are combined for the API."""
from __future__ import annotations

from functools import cache
from typing import Any

from .actions import ApprovalStore, StatusLog
from .contracts import iso, require_tenant
from .fixtures import BUILDERS
from .providers import (
    STORE_CANONICAL,
    STORE_SHADOW,
    ListCollection,
    MergedProvider,
    MongoStoreProvider,
)
from .timeline import lateness

SEED_SHADOW = "e3_dt_seed_shadow_observations"        # E3-namespaced SYNTHETIC seed collections only
SEED_CANONICAL = "e3_dt_seed_canonical_evidence"


@cache
def scenario(sid: str) -> dict[str, Any]:
    if sid not in BUILDERS:
        raise KeyError(sid)
    return BUILDERS[sid]()


def scenario_meta(sid: str) -> dict[str, Any]:
    s = scenario(sid)
    return {k: s[k] for k in ("scenario_id", "tenant_id", "device_id", "label", "description", "reference_at")} | {
        "counts": {"shadow_docs": len(s["shadow"]), "canonical_docs": len(s["canonical"])}}


def provider_for(sid: str, source: str = "merged", db: Any = None) -> Any:
    s = scenario(sid)
    if source.startswith("mongo"):
        if db is None:
            raise ValueError("mongo source is not configured in this process")
        sh, ca = MongoStoreProvider(db[SEED_SHADOW], STORE_SHADOW), MongoStoreProvider(db[SEED_CANONICAL], STORE_CANONICAL)
    else:
        sh = MongoStoreProvider(ListCollection(s["shadow"]), STORE_SHADOW)
        ca = MongoStoreProvider(ListCollection(s["canonical"]), STORE_CANONICAL)
    return {"shadow": sh, "canonical": ca, "mongo_shadow": sh, "mongo_canonical": ca}.get(
        source, MergedProvider([sh, ca]))


async def load(sid: str, tenant_id: str, device_id: str, *, source: str = "merged", db: Any = None,
               t0: int | None = None, t1: int | None = None) -> dict[str, Any]:
    t = require_tenant(tenant_id)
    p = provider_for(sid, source, db)
    evs = await p.events(t, device_id, t0, t1)
    for e in evs:
        e["lateness"] = lateness(e)
    s = scenario(sid)
    return {"events": evs, "suppressed_duplicates": getattr(p, "last_suppressed", 0),
            "provenance": {"scenario_id": sid, "label": s["label"], "source": source,
                           "stores": [STORE_SHADOW, STORE_CANONICAL] if source in ("merged", "mongo") else [source],
                           "authority": "NOT_SELECTED (E1 decision)", "reference_at": iso(s["reference_ms"])}}


def status_log_for(sid: str) -> StatusLog:
    s, log = scenario(sid), StatusLog()
    for r in s["status_events"]:
        log.append(tenant_id=s["tenant_id"], subject=r["subject"], kind=r["kind"], state=r["state"],
                   recorded_at=r["recorded_at"], references_event_id=r["references"], provenance=r["provenance"])
    return log


APPROVALS = ApprovalStore()


def window(sid: str, t0: int | None, t1: int | None) -> list[int]:
    ref = scenario(sid)["reference_ms"]
    return [t0 if t0 is not None else ref - 86_400_000, t1 if t1 is not None else ref]
