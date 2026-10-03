"""The canonical §d read's REQUIRED index specification — a declared contract.

Production measurement (Step 34C, read-only deployer diagnose) established that
`xdr_canonical_evidence` carries only `_id_` and
`tenant_id_1_ingest_time_-1 = {ingest_time: -1, tenant_id: 1}`. The §d bounded
read selects on ONE declared identity field at a time and orders by
`event_time` newest-first, so neither existing index can both select a branch
and supply its order: those branches can only be answered by scanning and then
sorting in memory.

This module states, as a contract rather than as a runbook sentence, the index
each declared canonical identity branch needs. It is DERIVED from the existing
authorities — `ENDPOINT_KEYED_STORES`, `TENANT_PARTITIONED_STORES` and
`OBSERVATION_TIME_KEY` — so a new identity field cannot be queried without its
index specification appearing here, and the key order cannot drift away from the
query shape without the guard test failing.

Key order is the query shape, not a preference:
  1. the tenant partition first, as an EQUALITY prefix — a canonical read may
     never widen the customer, and the equality prefix is also what keeps the
     following range/sort index-served;
  2. the identity field second (an `$in` over the validated alias set);
  3. `event_time` DESCENDING last, so the index itself provides the
     newest-first order and no blocking in-memory sort is needed.

NOTHING HERE CREATES AN INDEX. This module is a declaration; applying it to any
database is a separate, owner-authorized action.
"""
from __future__ import annotations

from typing import Any, Dict, List, Tuple

from edr_plane import canonical_identity_contract as idc
from edr_trajectory.production_adapter import OBSERVATION_TIME_KEY
from services.edr.endpoint_query import (ENDPOINT_KEYED_STORES,
                                         TENANT_PARTITIONED_STORES)

CANONICAL_COLLECTION = "xdr_canonical_evidence"

#: Short, stable suffixes so an index name never depends on field punctuation.
_SUFFIX: Dict[str, str] = {
    "provenance.collector_id": "collector",
    "host.host_id": "hostid",
    "host.hostname": "hostname",
}

#: Production's current index set, as MEASURED on 2026-06 (names + key only).
PRODUCTION_INDEXES_MEASURED: Tuple[Tuple[str, Tuple[Tuple[str, int], ...]], ...] = (
    ("_id_", (("_id", 1),)),
    ("tenant_id_1_ingest_time_-1", (("ingest_time", -1), ("tenant_id", 1))),
)


def _specs() -> List[Dict[str, Any]]:
    partition = TENANT_PARTITIONED_STORES[CANONICAL_COLLECTION]
    time_key = OBSERVATION_TIME_KEY[CANONICAL_COLLECTION]
    out: List[Dict[str, Any]] = []
    for field in ENDPOINT_KEYED_STORES[CANONICAL_COLLECTION]:
        out.append({
            "collection": CANONICAL_COLLECTION,
            "identity_field": field,
            "name": f"sd_canonical_{_SUFFIX[field]}_eventtime",
            "key": ((partition, 1), (field, 1), (time_key, -1)),
            "unique": False,
            "partial": None,
        })
    return out


#: The index specification the canonical §d branches require. Declaration only.
REQUIRED_CANONICAL_INDEXES: Tuple[Dict[str, Any], ...] = tuple(_specs())


def missing_against(existing_keys: List[Tuple[Tuple[str, int], ...]],
                    required: Tuple[Dict[str, Any], ...] = None
                    ) -> List[Dict[str, Any]]:
    """Which required specs are absent from a given index set. Read-only."""
    have = {tuple(k) for k in existing_keys}
    return [s for s in (required or REQUIRED_CANONICAL_INDEXES)
            if s["key"] not in have]


# ── Step 34E · the TARGET contract (declaration only, not applied) ────────
#
# One hard key plus one bounded legacy NAME branch, replacing three derived
# identity branches. `host.host_id` disappears as an addressing field because
# measurement showed it is a byte-identical copy of the authoritative field
# whenever that field exists (0 disagreeing rows) and is otherwise a hostname.

TARGET_CANONICAL_INDEXES: Tuple[Dict[str, Any], ...] = (
    {"collection": CANONICAL_COLLECTION,
     "identity_field": idc.AUTHORITATIVE_FIELD,
     "name": "sd_canonical_endpointid_eventtime",
     "key": ((TENANT_PARTITIONED_STORES[CANONICAL_COLLECTION], 1),
             (idc.AUTHORITATIVE_FIELD, 1),
             (OBSERVATION_TIME_KEY[CANONICAL_COLLECTION], -1)),
     "role": "AUTHORITATIVE_ENDPOINT_IDENTITY",
     "unique": False, "partial": None},
    {"collection": CANONICAL_COLLECTION,
     "identity_field": idc.LEGACY_NAME_FIELD,
     "name": "sd_canonical_hostname_eventtime",
     "key": ((TENANT_PARTITIONED_STORES[CANONICAL_COLLECTION], 1),
             (idc.LEGACY_NAME_FIELD, 1),
             (OBSERVATION_TIME_KEY[CANONICAL_COLLECTION], -1)),
     "role": "LEGACY_NAME_COMPATIBILITY_ONLY",
     "unique": False, "partial": None},
)
