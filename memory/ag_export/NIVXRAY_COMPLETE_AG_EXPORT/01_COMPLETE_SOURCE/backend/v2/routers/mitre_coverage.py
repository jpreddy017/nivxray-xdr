"""v2/routers/mitre_coverage.py · MITRE ATT&CK coverage endpoint (R1.1).

GET /api/v2/cases/{case_id}/mitre/coverage
    Returns the deterministic coverage of MITRE ATT&CK techniques /
    tactics observed in the case's canonical events. Zero RC5 imports.

The response shape is stable so the frontend can render a coverage
heatmap without another schema migration when new detectors land.
"""
from __future__ import annotations
from typing import Any
from collections import Counter
from fastapi import APIRouter, Depends, HTTPException
from deps import require_admin, db as _db
from v2.flags import get as get_flag

router = APIRouter(prefix="/v2/cases", tags=["v2-mitre"])


# Minimal technique → tactic map for the DFIR chain we ship out of the
# box. Kept intentionally small; a full ATT&CK matrix belongs in a
# separate module the frontend can fetch once per session.
_TECHNIQUE_TO_TACTIC = {
    "T1082":     "discovery",
    "T1018":     "discovery",
    "T1033":     "discovery",
    "T1069":     "discovery",
    "T1087":     "discovery",
    "T1087.002": "discovery",
    "T1135":     "discovery",
    "T1590.002": "reconnaissance",
    "T1136":     "persistence",
    "T1136.002": "persistence",
    "T1098.007": "persistence",
    "T1547":     "persistence",
    "T1219":     "command_and_control",
    "T1572":     "command_and_control",
    "T1003":     "credential_access",
    "T1003.001": "credential_access",
    "T1003.003": "credential_access",
    "T1552":     "credential_access",
    "T1552.001": "credential_access",
    "T1059":     "execution",
    "T1059.001": "execution",
    "T1218":     "defense_evasion",
    "T1218.007": "defense_evasion",
    "T1218.011": "defense_evasion",
    "T1490":     "impact",
    "T1486":     "impact",
    "T1489":     "impact",
}


@router.get("/{case_id}/mitre/coverage")
async def mitre_coverage(case_id: str, _: dict = Depends(require_admin)) -> dict[str, Any]:
    """Compute MITRE technique + tactic counts for a case."""
    if not get_flag("TRAJECTORY_ENGINE").observable():
        raise HTTPException(status_code=503, detail="trajectory engine disabled")

    from v2.case_engine.schema import COLLECTIONS
    coll = _db[COLLECTIONS["shadow_observations"]]
    tech_counter: Counter[str] = Counter()
    tactic_counter: Counter[str] = Counter()
    total = 0

    cursor = coll.find({"case_id": case_id}, sort=[("captured_at", 1)])
    async for row in cursor:
        ev = row.get("event") or {}
        techs = ev.get("mitre") or []
        if not techs:
            continue
        total += 1
        for t in techs:
            tech_counter[t] += 1
            tactic = _TECHNIQUE_TO_TACTIC.get(t, "unmapped")
            tactic_counter[tactic] += 1

    return {
        "ok": True,
        "case_id": case_id,
        "events_with_mitre": total,
        "techniques": [
            {"id": t, "count": n} for t, n in tech_counter.most_common()
        ],
        "tactics": [
            {"id": t, "count": n} for t, n in tactic_counter.most_common()
        ],
    }
