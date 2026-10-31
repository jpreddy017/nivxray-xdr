"""Round 44 · Cockpit UX Audit + Lock — invariant regression.

This suite pins the *architectural invariants* the R44 audit locked
in.  Each test guards one owner rule against future drift.  The
audit itself is a report artefact (see
``/app/memory/COCKPIT_AUDIT_R44.md``); this file is the machine
guardrail.
"""
from __future__ import annotations
import asyncio, hashlib, os, re
from datetime import datetime, timezone
import pytest
from dotenv import load_dotenv

from services.attack_graph        import AttackGraphService
from services.evidence_inspector  import resolve as inspector_resolve
from services.attack_evidence     import compose_attack_evidence
from services       import report as report_svc


APP_ROOT = "/app"


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
    load_dotenv("/app/backend/.env")
    c = AsyncIOMotorClient(os.environ["MONGO_URL"])
    yield c[os.environ.get("DB_NAME", "test_database")]
    c.close()


@pytest.fixture(scope="module")
def incident_id(loop, db):
    inc_id = "inc_r44_" + hashlib.sha256(b"r44").hexdigest()[:12]
    evt_id = "evt_r44_" + hashlib.sha256(b"r44-evt").hexdigest()[:12]
    now = datetime.now(timezone.utc).isoformat()
    canonical = {
        "event_id": evt_id, "timestamp": now,
        "dsm": {"id": "sysmon"},
        "host": {"name": "WKS-R44"},
        "user": {"name": "jane@nivxray.local"},
        "process": {"name": "powershell.exe",
                        "parent": {"name": "winword.exe"},
                        "commandline": "powershell.exe -nop -w hidden -enc AAAA"},
        "security": {"signature": {"id": 44, "name": "PS"}, "severity": 2},
    }
    incident = {
        "id": inc_id, "tenant_id": "default",
        "created_at": now, "updated_at": now,
        "title": "R44 audit fixture",
        "user_email": "admin@nivxray.com",
        "incident_state": "in_progress", "incident_priority": "P2",
        "verdict_card": {"verdict": "suspicious", "engine": "sigma"},
        "mitre": [{"technique_id": "T1059.001", "tactic_id": "TA0002",
                        "name": "PowerShell"}],
        "xdr_pipeline": {"canonical_event_id": evt_id, "ice_matches": [],
                              "detection_rule_id": "rule-r44",
                              "trace_id": "r44"},
    }
    async def _seed():
        await db["xdr_canonical_evidence"].update_one(
            {"event_id": evt_id}, {"$set": canonical}, upsert=True)
        await db["workspace_cases"].update_one(
            {"id": inc_id}, {"$set": incident}, upsert=True)
    _run(loop, _seed())
    return inc_id


# ── Owner-locked invariants ─────────────────────────────────────────

def test_cockpit_tab_order_locked():
    """RecordTabs MUST list the 12 canonical tabs in the exact order
    the R44 audit walked.  Any drift shows up as a diff here first."""
    fp = os.path.join(APP_ROOT, "apps/nivxray-xdr/src/xdr/pages",
                            "incidents/record/RecordTabs.jsx")
    src = open(fp, encoding="utf-8").read()
    order = re.findall(r'key:\s*"([^"]+)"', src)
    assert order == [
        "executive", "technical", "evidence", "auto_investigation",
        "mitre", "attack_story", "attack_graph", "report",
        "notes", "timeline", "related", "closure",
    ], f"cockpit tab order drifted: {order}"


def test_attack_graph_three_view_projection_locked(loop, db, incident_id):
    """Attack Graph must remain a three-view surface:
       ├── mitre_chain     (governed projection)
       ├── process_tree    (owner-locked)
       └── activity_graph  (owner-locked)"""
    g = _run(loop, AttackGraphService.compose(db, incident_id))
    for k in ("mitre_chain", "process_tree", "activity_graph"):
        assert k in (g.get("views") or {}), (
            f"Attack Graph view {k!r} missing — three-view projection "
            f"broken."
        )


def test_activity_graph_still_excludes_capability_and_finding(loop, db, incident_id):
    """R39 · Step 4 invariant · findings live as annotations only."""
    g = _run(loop, AttackGraphService.compose(db, incident_id))
    kinds = {n["kind"] for n in g["views"]["activity_graph"]["nodes"]}
    for forbidden in ("capability", "finding"):
        assert forbidden not in kinds, (
            f"Activity Graph canvas leaked {forbidden!r} kind — R39-Step4 "
            f"regression."
        )


def test_shared_inspector_still_resolves_all_governed_kinds(loop, db, incident_id):
    """The shared EvidenceInspector must still resolve every governed
    kind the cockpit deep-links to.  Missing kinds return MISSING
    honestly."""
    for kind, refId in (("event", "evt_r44_" + hashlib.sha256(b"r44-evt")
                                                       .hexdigest()[:12]),
                             ("host",  "WKS-R44"),
                             ("user",  "jane@nivxray.local"),
                             ("technique", "T1059.001"),
                             ("incident", incident_id)):
        env = _run(loop, inspector_resolve(db, incident_id, kind, refId))
        assert env.get("state") != "MISSING", (
            f"shared inspector cannot resolve {kind}={refId!r}: {env}"
        )
    # And an unknown ref must return an honest MISSING.
    env = _run(loop, inspector_resolve(db, incident_id, "event",
                                                   "does-not-exist"))
    assert env.get("state") == "MISSING"


def test_attack_evidence_ssot_shape_locked(loop, db, incident_id):
    """`AttackTechniqueEvidence` remains the SSOT for the MITRE tab
    and Attack Story projections.  The compose call MUST return the
    documented shape."""
    env = _run(loop, compose_attack_evidence(db, incident_id))
    for k in ("incident_id", "techniques"):
        assert k in env, f"attack_evidence envelope missing {k!r}: {env}"
    assert isinstance(env["techniques"], list)


def test_report_contract_shape_locked(loop, db, incident_id):
    """Report contract must retain the four owner-locked sections
    exactly.  No fifth section, no rename."""
    r = _run(loop, report_svc.compose(db, incident_id))
    assert set(r.get("sections", {}).keys()) == {
        "executive_summary", "technical_summary",
        "supporting_evidence", "recommendations",
    }, f"report section set drifted: {list(r['sections'])}"


def test_report_pdf_renderer_signature_backwards_compatible(loop, db, incident_id):
    """R43 · default `render_pdf(report)` remains cover-on so
    Step-5 callers get the R43 presentation automatically."""
    import inspect
    sig = inspect.signature(report_svc.render_pdf)
    p = sig.parameters.get("cover")
    assert p is not None, "render_pdf lost the cover kwarg"
    assert p.default is True, f"render_pdf(cover) default drifted: {p.default}"


def test_no_second_report_engine_symbol():
    """R39 + R43 invariant · single report composer / renderer."""
    forbidden = {"compose_v2", "render_pdf_v2", "compose_cover",
                    "render_cover", "cover_pdf", "compose_pdf",
                    "compose_report_pdf"}
    leaked = forbidden & set(dir(report_svc))
    assert not leaked, f"report_svc leaked engine symbols: {sorted(leaked)}"


def test_no_second_evidence_model_on_graph(loop, db, incident_id):
    """R42 invariant · deep-links must remain a client-side navigation
    enhancement, not a backend model expansion."""
    g = _run(loop, AttackGraphService.compose(db, incident_id))
    forbidden = {"evidence_details", "edge_evidence", "deep_link",
                    "evidence_index", "edge_inspector",
                    "replay", "timeline_v2", "playback",
                    "attack_timeline"}
    leaked = forbidden & set(g.keys())
    assert not leaked, (
        f"attack graph envelope leaked forbidden keys: {sorted(leaked)}"
    )


def test_dead_imports_removed_from_incident_detail_page():
    """R44 audit fix · `RecommendationsTab` / `RecommendationsTabV2`
    were dead imports (never rendered).  Both are now removed."""
    fp = os.path.join(APP_ROOT, "apps/nivxray-xdr/src/xdr/pages",
                            "XdrIncidentDetailPage.jsx")
    src = open(fp, encoding="utf-8").read()
    assert "RecommendationsTab " not in src, (
        "dead import RecommendationsTab returned"
    )
    assert "RecommendationsTabV2" not in src, (
        "dead import RecommendationsTabV2 returned"
    )


def test_cross_case_surfaces_stay_deferred():
    """Global nav must NOT expose the Phase-5 cross-case surfaces
    while the cockpit is locked."""
    fp = os.path.join(APP_ROOT, "apps/nivxray-xdr/src/xdr/XdrShell.jsx")
    src = open(fp, encoding="utf-8").read()
    # These labels must not appear as active nav entries (they may
    # appear in comments / disabled: true configs — that's fine).
    forbidden_labels = [
        '"Investigation Workspace"',
        '"Evidence Explorer"',
        '"Entity Search"',
        '"Attack Story Rollup"',
    ]
    for lbl in forbidden_labels:
        if lbl in src:
            # If the label exists, it must be gated as hidden/disabled.
            # Simplest heuristic: it must not appear on a line with an
            # active `to:` route.
            for line in src.splitlines():
                if lbl in line:
                    assert "to:" not in line, (
                        f"Phase-5 label {lbl} appears on an active "
                        f"nav route: {line.strip()}"
                    )


def test_intelligence_planes_remain_honestly_disabled():
    """R43-adjacent fix · Threat/IOC/Command/Malware Intelligence
    stay `disabled: true`, not clickable placeholder pages."""
    fp = os.path.join(APP_ROOT, "apps/nivxray-xdr/src/xdr/XdrShell.jsx")
    src = open(fp, encoding="utf-8").read()
    for label in ('"Threat Intelligence"', '"IOC Intelligence"',
                       '"Command Intelligence"', '"Malware Intelligence"'):
        # Locate the item block containing the label; the block must
        # carry `disabled: true` (not `reserved:` — reserved routed
        # to the broken placeholder page).
        idx = src.find(label)
        assert idx >= 0, f"label {label} missing from XdrShell.jsx"
        window = src[idx:idx + 400]
        assert "disabled: true" in window, (
            f"{label} must remain disabled:true (found: {window[:120]!r}…)"
        )
        assert "reserved:" not in window, (
            f"{label} regressed to `reserved:` routing"
        )
