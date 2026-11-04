"""Case Engine · MongoDB collection + index specifications.

Frozen v1 layout per /app/memory/ARCHITECTURE_v2.md §5. This module
is pure data — importing it has no runtime side-effect. Indexes are
materialised via `store.ensure_indexes(db)`, which must ONLY be
invoked when a v2 code path decides to bring storage online.

No RC5 collection appears here. v2 storage is fully separate.
"""
from __future__ import annotations

from typing import Any

# ─── Collection names ────────────────────────────────────────────────
COLLECTIONS: dict[str, str] = {
    "cases":              "v2_cases",
    "events":             "v2_case_events",
    "entities":           "v2_case_entities",
    "relationships":      "v2_case_relationships",
    "behaviors":          "v2_case_behaviors",
    "reports":            "v2_case_reports",
    "enrichment_cache":   "v2_enrichment_cache",
    "audit_log":          "v2_audit_log",
    "artifacts":          "v2_artifact_store",
    "shadow_observations":"v2_shadow_observations",  # Phase 2b sink
}

# ─── Index specifications ────────────────────────────────────────────
# Each entry: (collection, [(spec, options), ...])
# `spec` is a list of (field, direction) tuples per PyMongo convention.
# `options` is a dict passed to `create_index(**options)`.
INDEX_SPECS: dict[str, list[tuple[list[tuple[str, int]], dict[str, Any]]]] = {
    COLLECTIONS["cases"]: [
        ([("created_at", -1)],          {"name": "cases_created_desc"}),
        ([("created_by", 1)],           {"name": "cases_by_user"}),
        ([("status", 1)],               {"name": "cases_status"}),
        ([("tags", 1)],                 {"name": "cases_tags"}),
    ],
    COLLECTIONS["events"]: [
        ([("case_id", 1), ("ts", 1)],                             {"name": "events_case_ts"}),
        ([("case_id", 1), ("kind", 1), ("ts", 1)],                {"name": "events_case_kind_ts"}),
        ([("case_id", 1), ("device_iid", 1), ("ts", 1)],          {"name": "events_case_device_ts"}),
        ([("case_id", 1), ("process_iid", 1), ("ts", 1)],         {"name": "events_case_process_ts"}),
        ([("case_id", 1), ("adapter", 1), ("sequence", 1)],       {"name": "events_case_adapter_seq"}),
    ],
    COLLECTIONS["entities"]: [
        ([("case_id", 1), ("kind", 1)],                           {"name": "entities_case_kind"}),
        ([("case_id", 1), ("correlation_key", 1)],                {"name": "entities_case_corrkey", "sparse": True}),
        ([("iid", 1)],                                            {"name": "entities_iid_unique", "unique": True}),
    ],
    COLLECTIONS["relationships"]: [
        ([("case_id", 1), ("src_iid", 1)],                        {"name": "rel_case_src"}),
        ([("case_id", 1), ("dst_iid", 1)],                        {"name": "rel_case_dst"}),
        ([("case_id", 1), ("kind", 1)],                           {"name": "rel_case_kind"}),
    ],
    COLLECTIONS["behaviors"]: [
        ([("case_id", 1), ("technique_iid", 1)],                  {"name": "behaviors_case_tech"}),
        ([("case_id", 1), ("detector", 1)],                       {"name": "behaviors_case_detector"}),
    ],
    COLLECTIONS["reports"]: [
        ([("case_id", 1), ("generated_at", -1)],                  {"name": "reports_case_generated"}),
    ],
    COLLECTIONS["enrichment_cache"]: [
        ([("ttl_expires_at", 1)],                                 {"name": "enrichment_ttl", "expireAfterSeconds": 0}),
        ([("kind", 1), ("value", 1)],                             {"name": "enrichment_lookup"}),
    ],
    COLLECTIONS["audit_log"]: [
        ([("case_id", 1), ("ts", -1)],                            {"name": "audit_case_ts"}),
        ([("actor", 1), ("ts", -1)],                              {"name": "audit_actor_ts"}),
    ],
    COLLECTIONS["artifacts"]: [
        ([("case_id", 1), ("sha256", 1)],                         {"name": "artifacts_case_sha"}),
        ([("sha256", 1)],                                         {"name": "artifacts_sha256"}),
    ],
    COLLECTIONS["shadow_observations"]: [
        ([("adapter", 1), ("captured_at", -1)],                   {"name": "shadow_adapter_ts"}),
        ([("input_sha256", 1)],                                   {"name": "shadow_input_sha"}),
    ],
}


def summary() -> dict[str, Any]:
    """Introspection helper — used by tests and health endpoints."""
    return {
        "collections": COLLECTIONS,
        "index_count": {c: len(specs) for c, specs in INDEX_SPECS.items()},
    }
