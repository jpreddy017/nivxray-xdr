"""R3 · resolving a DETECTION back to its CANONICAL OBSERVATION.

Only AUTHORITATIVE references are used, in a fixed order:

1. `canonical_event_id` — the identifier the evidence authority minted
   (`canonical_bridge.canonical_event_id`). This is the PRIMARY path and
   newly produced evidence must resolve here.
2. the LEGACY pipeline-minted form (`cev_<raw_id>_pl`) — kept only so
   historical detections, which carry that reference, still resolve.
3. `raw_event_id` → `event.provenance.ingest_job_id` — the raw event id
   the canonical evidence carries in its own provenance.

No timestamp, PID, hostname, process name or "nearest event" matching.
Every resolution reports WHICH reference it used, so a regression in the
primary identifier is measurable instead of being hidden by a fallback
that quietly keeps working.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

OBSERVATIONS = "v2_shadow_observations"

PRIMARY = "canonical_event_id"
LEGACY = "legacy_pipeline_canonical_event_id"
RAW = "raw_event_id"
#: Ordered, so "was the primary used?" is answerable by position.
ORDER = (PRIMARY, LEGACY, RAW)

FORM_AUTHORITY = "CANONICAL_AUTHORITY_MINTED"
FORM_LEGACY = "LEGACY_PIPELINE_MINTED"
FORM_ABSENT = "NO_CANONICAL_REFERENCE"
FORM_UNRECOGNISED = "UNRECOGNISED_FORM"

UNRESOLVED_NO_REFERENCE = "NO_AUTHORITATIVE_REFERENCE_CARRIED"
UNRESOLVED_NOT_FOUND = "REFERENCED_OBSERVATION_NOT_FOUND"


def reference_form(canonical_event_id: Optional[str]) -> str:
    """Which minting scheme produced this reference. String inspection
    only — it classifies the reference, it never resolves anything."""
    ref = (canonical_event_id or "").strip()
    if not ref:
        return FORM_ABSENT
    if ref.startswith("cev_raw_") and ref.endswith("_pl"):
        return FORM_LEGACY
    if ref.startswith("cev_") and ref.rsplit("_", 1)[-1].isdigit():
        return FORM_AUTHORITY
    return FORM_UNRECOGNISED


def legacy_reference(raw_event_id: Optional[str]) -> Optional[str]:
    """The legacy pipeline form for a raw event id, for READS only."""
    raw_id = (raw_event_id or "").strip()
    return f"cev_{raw_id}_pl" if raw_id else None


async def resolve(db: Any, *, tenant_id: str,
                  canonical_event_id: Optional[str],
                  raw_event_id: Optional[str],
                  projection: Optional[Dict[str, Any]] = None
                  ) -> Dict[str, Any]:
    """Find the canonical observation a detection refers to.

    The tenant is part of every query, so a reference can only ever
    resolve inside its own tenant — a cross-tenant identifier simply does
    not resolve, and it is never disclosed that it exists elsewhere.
    """
    proj = projection or {"_id": 0, "event.process": 1, "event.kind": 1,
                          "canonical_event_id": 1, "epistemic_state": 1}
    primary = (canonical_event_id or "").strip() or None
    legacy = legacy_reference(raw_event_id)
    attempts: list[Dict[str, Any]] = []
    obs = None
    resolved_via = None

    candidates = ((PRIMARY, {"canonical_event_id": primary} if primary
                   else None),
                  (LEGACY, {"canonical_event_id": legacy}
                   if legacy and legacy != primary else None),
                  (RAW, {"event.provenance.ingest_job_id": raw_event_id}
                   if raw_event_id else None))
    for name, query in candidates:
        if query is None:
            attempts.append({"reference": name, "attempted": False,
                             "reason": "no such reference was carried"})
            continue
        found = await db[OBSERVATIONS].find_one(
            {"tenant_id": tenant_id, **query}, proj)
        attempts.append({"reference": name, "attempted": True,
                         "found": bool(found),
                         "value": next(iter(query.values()))})
        if found:
            obs, resolved_via = found, name
            break

    return {
        "observation": obs,
        "resolved_via": resolved_via,
        "is_fallback": bool(resolved_via) and resolved_via != PRIMARY,
        "canonical_event_id_form": reference_form(primary),
        "attempts": attempts,
        "unresolved_reason": (
            None if obs else
            (UNRESOLVED_NO_REFERENCE if not (primary or raw_event_id)
             else UNRESOLVED_NOT_FOUND)),
    }
