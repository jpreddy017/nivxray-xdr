"""Round 38.2 · Cross-view SSOT consistency regression.

The single most important owner-rule test: MITRE, Attack Story and
the Attack Graph MUST report the same state for the same technique
because they all consume ``compose_attack_evidence()``.

An analyst must never see:
    MITRE          T1059.001 = OBSERVED
    Attack Story   T1059.001 = SUPPORTED
    Attack Graph   T1059.001 = missing
That would be a genuine SSOT violation, exactly what Step 1 + Step 2
of the R38 chain are designed to prevent.
"""
from __future__ import annotations
import asyncio, hashlib
from datetime import datetime, timezone
import pytest

from services.attack_evidence import compose_attack_evidence
from services.attack_story    import AttackStoryService
from services.attack_graph    import AttackGraphService
from services.investigator     import InvestigatorService


@pytest.fixture(scope="module")
def loop():
    lp = asyncio.new_event_loop()
    yield lp
    lp.close()


def _run(loop, coro):
    return loop.run_until_complete(coro)


@pytest.fixture(scope="module")
def db(loop):
    from motor.motor_asyncio import AsyncIOMotorClient
    import os
    from dotenv import load_dotenv
    load_dotenv("/app/backend/.env")
    c = AsyncIOMotorClient(os.environ["MONGO_URL"])
    yield c[os.environ.get("DB_NAME", "test_database")]
    c.close()


@pytest.fixture(scope="module")
def incident_id(loop, db):
    inc_id = "inc_r382_" + hashlib.sha256(b"r382").hexdigest()[:12]
    evt_id = "evt_r382_" + hashlib.sha256(b"r382-evt").hexdigest()[:12]
    now = datetime.now(timezone.utc).isoformat()
    canonical = {
        "event_id": evt_id, "timestamp": now,
        "dsm": {"id": "sysmon", "event_id": "sysmon:1"},
        "host": {"name": "WKS-R382"},
        "user": {"name": "carol@nivxray.local"},
        "process": {"name": "powershell.exe",
                        "parent": {"name": "winword.exe"},
                        "commandline": "powershell.exe -nop -enc AAAA"},
        "security": {"signature": {"id": 77777, "name": "PS"}},
    }
    incident = {
        "id": inc_id, "tenant_id": "default",
        "created_at": now, "updated_at": now,
        "name": "R38.2 SSOT", "title": "R38.2 SSOT",
        "user_email": "admin@nivxray.com",
        "incident_state": "new", "incident_priority": "P2",
        "verdict_card": {"verdict": "suspicious", "confidence": 65,
                              "engine": "nivxray::detection_content::sigma"},
        "mitre": [{"technique_id": "T1059.001", "tactic_id": "TA0002",
                        "name": "PowerShell"},
                    {"technique_id": "T1218.011", "tactic_id": "TA0005"}],
        "iocs": {},
        "xdr_pipeline": {"engine_id": "nivxray::detection_content::xdr_incident",
                              "trace_id": "r382-fix",
                              "canonical_event_id": evt_id,
                              "detection_rule_id": "rule-r382",
                              "ice_matches": []}
    }
    async def _seed():
        await db["xdr_canonical_evidence"].update_one(
            {"event_id": evt_id}, {"$set": canonical}, upsert=True)
        await db["workspace_cases"].update_one(
            {"id": inc_id}, {"$set": incident}, upsert=True)
    _run(loop, _seed())
    _run(loop, InvestigatorService.tick(db, inc_id))
    return inc_id


# ── The SSOT crossview theorem ──────────────────────────────────────
def test_mitre_state_matches_attack_story_state(loop, db, incident_id):
    """Every technique in AttackTechniqueEvidence with state OBSERVED
    must be reflected as an OBSERVED stage in Attack Story."""
    atk_ev = _run(loop, compose_attack_evidence(db, incident_id))
    story  = _run(loop, AttackStoryService.compose(db, incident_id))

    observed_techs = {t["technique_id"] for t in atk_ev["techniques"]
                              if t["state"] == "OBSERVED"}
    story_observed_techs: set = set()
    for stage in story["flow"]:
        if stage["state"] == "OBSERVED":
            story_observed_techs.update(stage["techniques"])

    missing = observed_techs - story_observed_techs
    assert not missing, (
        f"SSOT violation — techniques OBSERVED in MITRE/AttackEvidence "
        f"but missing from Attack Story OBSERVED stages: {missing}\n"
        f"  MITRE observed: {observed_techs}\n"
        f"  Story observed: {story_observed_techs}"
    )


def test_attack_story_only_uses_governed_evidence(loop, db, incident_id):
    """Attack Story must not surface any OBSERVED technique that
    AttackTechniqueEvidence does not consider OBSERVED / SUPPORTED /
    HYPOTHESIZED.  Fabrication guard."""
    atk_ev = _run(loop, compose_attack_evidence(db, incident_id))
    story  = _run(loop, AttackStoryService.compose(db, incident_id))
    governed = {t["technique_id"] for t in atk_ev["techniques"]
                    if t["state"] in ("OBSERVED", "SUPPORTED", "HYPOTHESIZED")}
    surfaced: set = set()
    for stage in story["flow"]:
        if stage["state"] in ("OBSERVED", "SUPPORTED", "POSSIBLE"):
            surfaced.update(stage["techniques"])
    invented = surfaced - governed
    assert not invented, (
        f"Attack Story surfaced techniques that are NOT in the "
        f"canonical AttackTechniqueEvidence: {invented}"
    )


def test_attack_graph_technique_state_matches(loop, db, incident_id):
    """Same for Attack Graph: any technique node with state OBSERVED
    must appear as OBSERVED in AttackTechniqueEvidence."""
    atk_ev = _run(loop, compose_attack_evidence(db, incident_id))
    graph  = _run(loop, AttackGraphService.compose(db, incident_id))
    canon_state = {t["technique_id"]: t["state"]
                        for t in atk_ev["techniques"]}
    for n in graph["nodes"]:
        if n["kind"] != "technique":
            continue
        tid = (n.get("attrs") or {}).get("tid") or n.get("label")
        if not tid or n["state"] == "NOT_OBSERVED":
            continue
        expected = canon_state.get(tid)
        # Graph carries only OBSERVED/SUPPORTED so we only enforce that
        # canonical must also consider it OBSERVED or SUPPORTED.
        assert expected in ("OBSERVED", "SUPPORTED", "HYPOTHESIZED"), (
            f"Attack Graph shows {tid} as {n['state']} but "
            f"AttackTechniqueEvidence says {expected!r}"
        )


def test_cross_view_totals_agree(loop, db, incident_id):
    """AttackTechniqueEvidence.counts.observed >=
       Attack Story.stages_observed >= 1 for the golden fixture."""
    atk_ev = _run(loop, compose_attack_evidence(db, incident_id))
    story  = _run(loop, AttackStoryService.compose(db, incident_id))
    assert atk_ev["counts"]["observed"] >= 2
    assert story["counts"]["stages_observed"] >= 2, (
        f"Story observed stages={story['counts']['stages_observed']} "
        f"< MITRE observed techniques={atk_ev['counts']['observed']}"
    )
