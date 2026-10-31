"""G-41 · the plan proof for the Device Trajectory paging read.

`observation_us` only pays for itself if THE INDEX SUPPLIES THE ORDER. Without
the compound index the server selects on identity and then sorts in memory —
the same blocking sort that made a bounded `LIMIT` return the wrong newest N,
just with a correct key. So the index is not the deliverable; the PLAN is.

The filter and sort come from `production_adapter.branch_query`, the very
function the read itself calls, so this proves the shape production executes
rather than a hand-written imitation of it. A plan proof against a
reconstructed query proves nothing.

This lives in its own module, like `identity_backfill`'s explain, so
`migration_control` can keep its guarantee of issuing no database command at
all. The ONE command here is an `explain`, and it writes nothing.
"""
from __future__ import annotations

from typing import Any, Dict, List

from edr_plane import identity_backfill as ib
from edr_plane.canonical_index_contract import (CANONICAL_COLLECTION,
                                                TARGET_TEMPORAL_INDEXES)
from edr_trajectory import production_adapter as pa
from edr_trajectory.production_adapter import TEMPORAL_SELECT_KEY

OP_EXPLAIN_TEMPORAL_READ_PLAN = "explain_canonical_temporal_read_plan"

HOLD_NO_SAMPLE = "NO_SAMPLE_FOR_BRANCH"

#: One day of microseconds — a window shape an analyst actually asks for.
_WINDOW_US = 86_400_000_000


def _checks(plan: Dict[str, Any], spec: Dict[str, Any]) -> Dict[str, Any]:
    stages = ib._stages(plan)
    bounds = ib._bounds(plan)
    return {
        "index_expected": spec["name"],
        "index_used": ib._index_name(plan),
        "stages": stages,
        "index_bounds_key_order": bounds,
        "contract_key_order": [k for k, _ in spec["key"]],
        "checks": {
            "ixscan_present": "IXSCAN" in stages,
            "index_name_matches": ib._index_name(plan) == spec["name"],
            "no_collscan": "COLLSCAN" not in stages,
            #: a SORT stage means the index did NOT supply the order and the
            #: server is sorting in memory — the exact failure G-41 exists to
            #: remove, so it is never tolerated
            "no_blocking_sort": "SORT" not in stages,
            "key_order_matches_contract": bounds == [k for k, _ in spec["key"]],
        },
    }


async def op_explain_temporal_read_plan(db, *, mode: str,
                                        run_id: str = "") -> Dict[str, Any]:
    """Prove BOTH identity branches, in all three shapes the read executes:
    first page, resume cursor and bounded window. Read-only in every mode."""
    coll = db[CANONICAL_COLLECTION]
    #: keyed by the STORE identity, not the collection variable: the store is
    #: what declares a comparable temporal key
    time_key = TEMPORAL_SELECT_KEY[pa.STORE_CANONICAL]
    tiebreak = pa.TEMPORAL_TIEBREAK_KEY
    out: Dict[str, Any] = {"collection": CANONICAL_COLLECTION, "mode": mode,
                           "temporal_key": time_key, "tiebreak": tiebreak,
                           "branches": []}
    verdicts: List[bool] = []
    for spec in TARGET_TEMPORAL_INDEXES:
        field = spec["identity_field"]
        sample = await coll.find_one(
            {field: {"$exists": True, "$ne": None}, time_key: {"$exists": True}},
            {field: 1, "tenant_id": 1, time_key: 1})
        if not sample:
            out["branches"].append({"identity_field": field,
                                    "hold": HOLD_NO_SAMPLE, "ok": False})
            verdicts.append(False)
            continue
        ref: Any = sample
        for part in field.split("."):
            ref = (ref or {}).get(part)
        flt = {"tenant_id": sample.get("tenant_id"), field: {"$in": [ref]}}
        at = int(sample[time_key])

        shapes: Dict[str, Any] = {}
        for label, kwargs in (("first_page", {}),
                              ("resume_cursor", {"upper_bound": at}),
                              ("bounded_window", {"lo": at - _WINDOW_US,
                                                  "hi": at})):
            q, sort = pa.branch_query(flt, time_key, comparable=True,
                                      tiebreak=tiebreak, **kwargs)
            plan = await db.command({"explain": {"find": CANONICAL_COLLECTION,
                                                 "filter": q,
                                                 "sort": dict(sort),
                                                 "limit": 200},
                                     "verbosity": "executionStats"})
            shape = _checks(plan, spec)
            shape["sort"] = [list(s) for s in sort]
            shape["tenant_predicate_present"] = "tenant_id" in q
            shape["identity_predicate_present"] = field in q
            shape["ok"] = (all(shape["checks"].values())
                           and shape["tenant_predicate_present"]
                           and shape["identity_predicate_present"])
            verdicts.append(shape["ok"])
            shapes[label] = shape
        out["branches"].append({"identity_field": field, "role": spec["role"],
                                "shapes": shapes,
                                "ok": all(s["ok"] for s in shapes.values())})
    out["ok"] = bool(verdicts) and all(verdicts)
    return out


OPERATIONS = {OP_EXPLAIN_TEMPORAL_READ_PLAN: op_explain_temporal_read_plan}
