"""
Round 18 · Mitigation & Exclusion Intelligence
──────────────────────────────────────────────

Validates the knowledge-layer risk model:
  * enrich_recommendation attaches risk_analysis ONLY when the
    suggested_action is an exclusion.
  * Ordinary mitigations (ISOLATE_ENDPOINT, IP_BLOCK,
    COLLECT_FORENSIC_SNAPSHOT, OSINT_ENRICH_*) come back UNCHANGED.
  * Every risk model entry declares Detection Method, Affected Engine,
    Exclusion Type, Scope, Visibility Impact, Security Risk, Safer
    Alternative, Approval Policy.
  * HIGH / CRITICAL bands must carry a warning_banner. Threat-name
    exclusions must require DUAL_APPROVAL.
  * The synthesizer integrates the enricher — end-to-end recos for
    an exclusion candidate ship with `risk_band` populated and recos
    for ordinary mitigations do NOT carry `risk_band`.
"""
from __future__ import annotations
import asyncio, os, uuid
import pytest
from dotenv import load_dotenv
load_dotenv("/app/backend/.env")
from motor.motor_asyncio import AsyncIOMotorClient

from detection_content.xdr_mitigation_intelligence import (
    enrich_recommendation, enrich_all, is_exclusion, risk_model_for,
    EXCLUSION_ACTIONS, summary,
    LOW, MEDIUM, HIGH, CRITICAL,
)
from detection_content.xdr_recommendation_synthesis import (
    synthesize, _GUIDANCE, APPLICABLE, CAPABILITY_UNAVAILABLE,
)


# ── Fixtures ────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def loop():
    lp = asyncio.new_event_loop(); yield lp; lp.close()


@pytest.fixture(scope="module")
def db(loop):
    c = AsyncIOMotorClient(os.environ["MONGO_URL"])
    yield c[os.environ.get("DB_NAME", "test_database")]; c.close()


def _run(loop, coro): return loop.run_until_complete(coro)


# ── Guardrail · risk applies only to exclusions ─────────────────

def test_ordinary_mitigations_are_never_risk_tagged():
    """ISOLATE_ENDPOINT / IP_BLOCK / COLLECT_FORENSIC_SNAPSHOT /
    OSINT_* are NOT exclusions — risk_analysis must not be attached."""
    for aid in ("ENDPOINT_ISOLATE", "IP_BLOCK",
                        "COLLECT_FORENSIC_SNAPSHOT",
                        "OSINT_ENRICH_IP", "OSINT_ENRICH_DOMAIN",
                        "OSINT_ENRICH_HASH", "IOC_ADD_WATCHLIST"):
        assert not is_exclusion(aid), aid
        reco = {"id": "x", "suggested_action": aid, "target_entity": {}}
        out = enrich_recommendation(dict(reco))
        assert "risk_analysis" not in out, \
            f"{aid} must not receive a risk block"
        assert "risk_band" not in out, \
            f"{aid} must not receive a risk band"


def test_all_registered_exclusions_have_a_risk_model():
    """Every action listed in EXCLUSION_ACTIONS must have a
    corresponding risk model (except placeholders)."""
    # WILDCARD_EXCLUSION_ADD is declared in the model but no synthesizer
    # candidate emits it yet — still, the model MUST exist so future
    # candidates can rely on it.
    modelled = {"APPLICATION_ALLOW_LIST_ADD", "PROCESS_EXCLUSION_ADD",
                     "PATH_EXCLUSION_ADD", "WILDCARD_EXCLUSION_ADD",
                     "THREAT_EXCLUSION_ADD"}
    assert modelled.issubset(EXCLUSION_ACTIONS)
    for aid in modelled:
        m = risk_model_for(aid)
        assert m is not None, aid
        for field in ("exclusion_type", "scope", "detection_method",
                            "affected_engine", "visibility_impact",
                            "security_risk", "safer_alternative",
                            "approval_policy"):
            assert m.get(field), f"{aid}.{field} must not be blank"


# ── Locked bands per PRD §Round 18 ──────────────────────────────

def test_risk_bands_match_prd_lock():
    assert risk_model_for("APPLICATION_ALLOW_LIST_ADD")["security_risk"] == MEDIUM
    assert risk_model_for("PROCESS_EXCLUSION_ADD")["security_risk"]      == HIGH
    assert risk_model_for("PATH_EXCLUSION_ADD")["security_risk"]         == HIGH
    assert risk_model_for("THREAT_EXCLUSION_ADD")["security_risk"]       == CRITICAL


def test_high_and_critical_have_warning_banner():
    for aid in ("PROCESS_EXCLUSION_ADD", "PATH_EXCLUSION_ADD",
                        "WILDCARD_EXCLUSION_ADD", "THREAT_EXCLUSION_ADD"):
        m = risk_model_for(aid)
        assert m["warning_banner"], f"{aid} must carry a warning banner"
        assert m["security_risk"] in (HIGH, CRITICAL), aid


def test_medium_band_has_no_warning_banner():
    m = risk_model_for("APPLICATION_ALLOW_LIST_ADD")
    assert m["warning_banner"] is None
    assert m["security_risk"] == MEDIUM


def test_threat_exclusion_requires_dual_approval():
    m = risk_model_for("THREAT_EXCLUSION_ADD")
    assert m["approval_policy"] == "DUAL_APPROVAL"


def test_exclusion_enrichment_shape():
    reco = {"id": "reco-x", "suggested_action": "PATH_EXCLUSION_ADD",
                 "target_entity": {"kind": "path",
                                              "value": "C:\\Program Files\\Vendor"}}
    out = enrich_recommendation(dict(reco))
    ra = out["risk_analysis"]
    assert out["risk_band"] == HIGH
    assert ra["exclusion_type"] == "Path Exclusion"
    assert ra["scope"]           == "filesystem_subtree"
    assert "TETRA" in ra["affected_engine"]
    assert "hash-scoped" in ra["safer_alternative"].lower() \
        or "hash" in ra["safer_alternative"].lower()
    assert ra["warning_banner"].startswith("HIGH RISK")
    assert ra["analyst_decision"] is None


# ── Synthesizer integration ─────────────────────────────────────

def test_synthesizer_attaches_risk_only_to_exclusion_candidates():
    """Build a plausible context and verify risk_band presence pattern."""
    context = {
        "state": "READY",
        "entities": [
            {"kind": "ipv4",        "value": "203.0.113.42", "role": "destination",
              "origin": "network.dst.ip"},
            {"kind": "hash",        "value": "a" * 64, "role": "artifact",
              "origin": "file.hash"},
            {"kind": "path",        "value": "C:\\Program Files\\PCAppStore",
              "role": "artifact", "origin": "file.path"},
            {"kind": "process",     "value": "PCAppStore.exe",
              "role": "artifact", "origin": "process.image"},
            {"kind": "threat_name", "value": "PUA.Win.Adware.PCAppStore",
              "role": "trigger", "origin": "security.signature.name"},
        ],
    }
    threat_family  = {"family": "PUA_ADWARE", "confidence": "MEDIUM"}
    recos = synthesize(context, threat_family, [], [], [])
    assert recos, "synthesizer must emit recommendations for this context"

    for r in recos:
        aid = r["suggested_action"]
        if is_exclusion(aid):
            assert "risk_analysis" in r, f"{aid} missing risk_analysis"
            assert r["risk_band"] in (LOW, MEDIUM, HIGH, CRITICAL,
                                                     "UNKNOWN"), r
            # Locked pairings.
            if aid == "APPLICATION_ALLOW_LIST_ADD":
                assert r["risk_band"] == MEDIUM
            if aid == "PROCESS_EXCLUSION_ADD":
                assert r["risk_band"] == HIGH
            if aid == "PATH_EXCLUSION_ADD":
                assert r["risk_band"] == HIGH
            if aid == "THREAT_EXCLUSION_ADD":
                assert r["risk_band"] == CRITICAL
        else:
            assert "risk_analysis" not in r, \
                f"{aid} is not an exclusion — must not carry risk_analysis"
            assert "risk_band" not in r, aid


def test_all_four_exclusion_candidates_emitted_for_full_pua_context():
    context = {
        "state": "READY",
        "entities": [
            {"kind": "hash",        "value": "a" * 64, "role": "artifact",
              "origin": "file.hash"},
            {"kind": "path",        "value": "C:\\Program Files\\Vendor",
              "role": "artifact", "origin": "file.path"},
            {"kind": "process",     "value": "vendor.exe",
              "role": "artifact", "origin": "process.image"},
            {"kind": "threat_name", "value": "PUA/Adware.Vendor",
              "role": "trigger", "origin": "security.signature.name"},
        ],
    }
    recos = synthesize(context, {"family": "PUA_ADWARE"}, [], [], [])
    emitted_actions = {r["suggested_action"] for r in recos
                                if is_exclusion(r["suggested_action"])}
    assert emitted_actions == {"APPLICATION_ALLOW_LIST_ADD",
                                            "PROCESS_EXCLUSION_ADD",
                                            "PATH_EXCLUSION_ADD",
                                            "THREAT_EXCLUSION_ADD"}, emitted_actions


def test_no_exclusion_candidates_without_entities():
    """If evidence yields no hash/path/process/threat_name entities,
    zero exclusion recommendations must be emitted."""
    context = {
        "state": "READY",
        "entities": [
            {"kind": "ipv4", "value": "203.0.113.42", "role": "destination",
              "origin": "network.dst.ip"},
        ],
    }
    recos = synthesize(context, {"family": "PUA_ADWARE"}, [], [], [])
    exclusion_recos = [r for r in recos
                                if is_exclusion(r["suggested_action"])]
    assert exclusion_recos == [], \
        "no exclusion entity → no exclusion recommendation"


def test_exclusions_capability_reports_honest_unavailable():
    """Round 13 honest-state: no EDR adapter is wired, so every
    exclusion action must report CAPABILITY_UNAVAILABLE."""
    context = {
        "state": "READY",
        "entities": [
            {"kind": "hash", "value": "b" * 64, "role": "artifact",
              "origin": "file.hash"},
        ],
    }
    recos = synthesize(context, {"family": "MALWARE"}, [], [], [])
    hashes = [r for r in recos if r["suggested_action"]
                    == "APPLICATION_ALLOW_LIST_ADD"]
    assert hashes, "hash entity must produce the allow-list candidate"
    for r in hashes:
        assert r["applicability"] == CAPABILITY_UNAVAILABLE
        # …but the RISK MODEL is still attached (independent of runtime
        # capability — the analyst still needs to see the trade-off).
        assert "risk_analysis" in r
        assert r["risk_band"] == MEDIUM


# ── End-to-end via closed-loop recompute ────────────────────────

def test_e2e_pipeline_includes_risk_analysis_on_recompute(loop, db):
    """
    Full pipeline recompute — verify the two Round 18 architectural
    guardrails hold end-to-end:

      1. Ordinary mitigations MUST NOT carry risk_analysis.
      2. Family-filter honesty: the Golden Snort event classifies as
         **C2**.  Exclusion candidates in _GUIDANCE are scoped to
         PUA/MALWARE/UNKNOWN families ONLY (per Round 18 model —
         analysts should never be nudged toward allow-listing C2).
         The pipeline MUST therefore emit ZERO exclusion candidates
         for the Snort golden event.
    """
    from detection_content.xdr_pipeline import process_event_through_pipeline
    from detection_content.collector_runtime import GOLDEN_SNORT_EVENT

    r = _run(loop, process_event_through_pipeline(
        db, dict(GOLDEN_SNORT_EVENT), str(uuid.uuid4()),
        integration_id="integration-snort-ref",
        collector_id="collector-snort-ref"))
    loop_out = r.get("closed_loop") or {}
    all_recos = ((loop_out.get("recommendations") or {})
                        .get("synthesized") or [])
    assert all_recos, "pipeline must produce synthesized recommendations"

    exclusions = [x for x in all_recos
                        if is_exclusion(x["suggested_action"])]
    ordinaries = [x for x in all_recos
                        if not is_exclusion(x["suggested_action"])]

    # Family = C2 → zero exclusion candidates (honest family filter).
    assert loop_out.get("threat_family") == "C2", loop_out.get("threat_family")
    assert exclusions == [], \
        "C2 family must NOT surface exclusion candidates"
    # Ordinary mitigations must have arrived intact.
    assert ordinaries, "C2 incident must still produce ordinary mitigations"
    for reco in ordinaries:
        assert "risk_analysis" not in reco
        assert "risk_band" not in reco


# ── Summary endpoint ────────────────────────────────────────────

def test_summary_declares_knowledge_layer():
    s = summary()
    assert s["not_an_engine"] is True
    assert s["role"] == "KNOWLEDGE_LAYER"
    assert set(s["exclusion_actions"]) == EXCLUSION_ACTIONS
