"""
NivXRay MITRE ATT&CK Catalogue routes.

Serves the versioned ATT&CK Enterprise catalogue (203 techniques
+ 453 sub-techniques for v16.1) and the honest coverage
projection built by scanning every incident's canonical evidence.

Contract — endpoints:
    GET /api/mitre/catalogue           — flat catalogue, all rows
    GET /api/mitre/catalogue/coverage  — tactic → parent → sub-tech,
                                              with real observation counts

Honesty guarantees (owner rule):
    · Only techniques with an observation in an incident's
      `mitre[]` or `verdict_stage2.evidence[]` list are marked
      OBSERVED.  Everything else is NO_EVIDENCE / coverage-gap.
    · Parent aggregate_count = parent observations + sum(sub
      observations).  Sub-techniques stay NO_EVIDENCE if they
      themselves have no evidence, regardless of the parent.
    · No fabricated risk / confidence / severity is emitted here;
      those live in AttackTechniqueEvidence.
"""
from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, Depends

from deps import get_current_user, db
from services.mitre_catalogue import (
    get_catalogue, resolve_coverage,
)


router = APIRouter()
ATTACK_ID_RE = re.compile(r"\b(T\d{4})(?:\.(\d{3}))?\b")


def _iter_technique_ids(inc: dict[str, Any]):
    """Yield every canonical `T####` / `T####.###` id observed on
    an incident.  Sources scanned (all governed):
      · `incident.mitre[]`               — detection engine attribution
      · `incident.verdict_stage2.evidence[]`
      · `incident.evidence[]`

    Resolution rules — honesty preserved:
      1. Real `T####` regex hit anywhere in a candidate field wins.
      2. Otherwise the value is passed through the catalogue's
         `resolve_name()`.  If the NAME is a real published ATT&CK
         technique/sub-technique we emit that canonical id.
      3. Everything else is IGNORED.  We never invent an id.
    """
    cat = get_catalogue()

    def _resolve(val: Any):
        if val is None:
            return
        s = str(val)
        m = ATTACK_ID_RE.search(s)
        if m:
            base = m.group(1)
            yield (f"{base}.{m.group(2)}" if m.group(2) else base)
            return
        # Name fallback — catalogue-published names only.
        resolved = cat.resolve_name(s)
        if resolved:
            yield resolved

    for m in (inc.get("mitre") or []):
        if isinstance(m, dict):
            for f in ("technique_id", "technique", "id",
                                "attack_id", "external_id",
                                "name", "technique_name"):
                yield from _resolve(m.get(f))
        else:
            yield from _resolve(m)

    for lane in ("evidence",):
        for e in inc.get(lane) or []:
            if isinstance(e, dict):
                for f in ("technique_id", "attack_id",
                                    "external_id", "technique_name",
                                    "name"):
                    yield from _resolve(e.get(f))

    v2 = (inc.get("verdict_stage2") or {}).get("evidence") or []
    for e in v2:
        if isinstance(e, dict):
            for f in ("technique_id", "attack_id", "external_id",
                                "technique_name", "name"):
                yield from _resolve(e.get(f))


async def _build_observations() -> tuple[dict[str, int], dict[str, list[str]]]:
    """Sum observations across every workspace_cases incident.

    Every distinct (incident, technique_id) pair counts once — a
    single incident that emits `T1059.001` fifteen times still
    contributes exactly 1 observation to the coverage view.  This
    keeps parent aggregate counts honest and prevents a chatty
    parser from inflating heatmap heat.

    Returns `(counts, incidents_by_technique)` so the coverage
    resolver can also report which real incidents observed a
    given technique (preserved from the previous heatmap so the
    right-hand "Incidents observed" panel keeps working).
    """
    counts: dict[str, int] = {}
    incidents_by_tech: dict[str, list[str]] = {}
    async for inc in db["workspace_cases"].find(
        {}, {"mitre": 1, "evidence": 1, "verdict_stage2": 1, "id": 1},
    ):
        seen: set[str] = set()
        for ext in _iter_technique_ids(inc):
            seen.add(ext)
        iid = inc.get("id")
        for ext in seen:
            counts[ext] = counts.get(ext, 0) + 1
            if iid:
                incidents_by_tech.setdefault(ext, []).append(iid)
    return counts, incidents_by_tech


# --------------------------------------------------------------------
@router.get("/mitre/catalogue")
async def get_catalogue_flat(user=Depends(get_current_user)):
    cat = get_catalogue()
    return {
        "catalogue":    "mitre-attack-enterprise",
        "version":      cat.version,
        "source":       cat.source,
        "generated_at": cat.generated_at,
        "tactics":      cat.tactics,
        "techniques":   cat.techniques,
        "stats":        cat.stats,
    }


@router.get("/mitre/catalogue/coverage")
async def get_catalogue_coverage(user = Depends(get_current_user)):
    """Full ATT&CK Enterprise coverage: parent + sub-techniques,
    joined with real incident observations."""
    counts, incidents_by_tech = await _build_observations()
    projection = resolve_coverage(counts)
    # Attach the incident ids that observed each technique — this
    # is what powers the right-side "Incidents observed" panel
    # (never fabricated; only real ids from workspace_cases).
    for tactic in projection["tactics"]:
        for parent in tactic["techniques"]:
            parent["incident_ids"] = list(
                incidents_by_tech.get(parent["external_id"]) or [])
            for sub in parent["subs"]:
                sub["incident_ids"] = list(
                    incidents_by_tech.get(sub["external_id"]) or [])
    return projection
