"""Round 45 · Inspector Consolidation — regression.

Round 44 audit finding H-1: MitreTab previously shipped its own
inline governed-object detail widget (`EvidenceRow` + `EvidenceDetail`)
that fetched `/admin/content-supply-chain/evidence/{ref}` and rendered
it in-place.  R45 replaces that path with the shared
`<EvidenceInspector/>` (Round 38.3 · single governed detail surface).

This suite pins:

  1. The shared inspector resolver still opens governed evidence
     for every event id the MitreTab surfaces.
  2. MISSING refs remain honest (no fabrication).
  3. The MitreTab source file no longer contains an inline
     `EvidenceDetail` renderer or a direct call to the
     `/admin/content-supply-chain/evidence/` traversal endpoint.
  4. `MitreTab.jsx` imports the shared `EvidenceInspector`.
  5. No second governed-object detail component has been introduced
     anywhere else in the cockpit.
  6. Attack-chain composer output shape (SSOT projection) unchanged.
"""
from __future__ import annotations
import asyncio, hashlib, os, re
from datetime import datetime, timezone
import pytest
from dotenv import load_dotenv

from services.evidence_inspector import resolve as inspector_resolve
from detection_content.xdr_attack_chain_graph import compose as compose_attack_chain


APP_ROOT = "/app"
MITRE_TAB = os.path.join(APP_ROOT, "apps/nivxray-xdr/src/xdr/pages",
                                    "incidents/record/tabs/MitreTab.jsx")
COCKPIT_TABS_DIR = os.path.join(APP_ROOT, "apps/nivxray-xdr/src/xdr/pages",
                                              "incidents/record/tabs")


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
    inc_id = "inc_r45_" + hashlib.sha256(b"r45").hexdigest()[:12]
    evt_id = "evt_r45_" + hashlib.sha256(b"r45-evt").hexdigest()[:12]
    now = datetime.now(timezone.utc).isoformat()
    canonical = {
        "event_id": evt_id, "timestamp": now,
        "dsm": {"id": "sysmon"},
        "host": {"name": "WKS-R45"},
        "user": {"name": "kai@nivxray.local"},
        "process": {"name": "powershell.exe",
                        "parent": {"name": "winword.exe"},
                        "commandline": "powershell.exe -nop -w hidden -enc AAAA"},
        "security": {"signature": {"id": 45, "name": "PS"}, "severity": 2},
    }
    incident = {
        "id": inc_id, "tenant_id": "default",
        "created_at": now, "updated_at": now,
        "title": "R45 inspector consolidation fixture",
        "user_email": "admin@nivxray.com",
        "incident_state": "in_progress", "incident_priority": "P2",
        "verdict_card": {"verdict": "suspicious", "engine": "sigma"},
        "mitre": [{"technique_id": "T1059.001", "tactic_id": "TA0002",
                        "name": "PowerShell"}],
        "xdr_pipeline": {"canonical_event_id": evt_id, "ice_matches": [],
                              "detection_rule_id": "rule-r45",
                              "trace_id": "r45"},
    }
    async def _seed():
        await db["xdr_canonical_evidence"].update_one(
            {"event_id": evt_id}, {"$set": canonical}, upsert=True)
        await db["workspace_cases"].update_one(
            {"id": inc_id}, {"$set": incident}, upsert=True)
    _run(loop, _seed())
    return inc_id


# ── Acceptance gates ────────────────────────────────────────────────

def test_shared_inspector_resolves_mitre_evidence_ref(loop, db, incident_id):
    """The shared inspector must still open the canonical event that
    MitreTab surfaces as an evidence pill."""
    g = _run(loop, compose_attack_chain(db, incident_id))
    assert g.get("state") == "READY", g
    refs = []
    for n in g.get("nodes") or []:
        refs.extend(n.get("evidence_ids") or [])
    assert refs, "fixture must yield MitreTab evidence refs"
    ref = refs[0].replace("canonical:", "")
    env = _run(loop, inspector_resolve(db, incident_id, "event", ref))
    assert env.get("state") != "MISSING", env
    assert env["kind"] == "event"
    assert env["evidence"], "shared inspector must return governed evidence"


def test_shared_inspector_missing_ref_still_honest(loop, db, incident_id):
    env = _run(loop, inspector_resolve(db, incident_id, "event",
                                                    "definitely-not-a-real-event"))
    assert env.get("state") == "MISSING", env


def test_mitre_tab_no_longer_ships_inline_evidencedetail():
    """The `EvidenceDetail` in-place renderer + its `KV` helper have
    been removed from MitreTab (owner rule §11: single governed
    detail surface)."""
    src = open(MITRE_TAB, encoding="utf-8").read()
    assert "function EvidenceDetail" not in src, (
        "MitreTab still declares an inline `EvidenceDetail` — R45 "
        "consolidation regressed."
    )
    assert "function KV(" not in src, (
        "MitreTab still ships the `KV` helper used only by the "
        "removed inline detail — R45 consolidation regressed."
    )
    # The evidence-detail render used to test-id "evidence-detail-*".
    assert 'data-testid={`evidence-detail-' not in src, (
        "MitreTab still emits the inline `evidence-detail-*` testid."
    )


def test_mitre_tab_no_longer_calls_traversal_endpoint_directly():
    """MitreTab must NOT call
    `/admin/content-supply-chain/evidence/…` any more — the shared
    inspector service is the resolver."""
    src = open(MITRE_TAB, encoding="utf-8").read()
    assert "/admin/content-supply-chain/evidence/" not in src, (
        "MitreTab still calls the legacy evidence traversal "
        "endpoint directly."
    )


def test_mitre_tab_imports_shared_evidence_inspector():
    """MitreTab must import the shared `<EvidenceInspector>`."""
    src = open(MITRE_TAB, encoding="utf-8").read()
    assert re.search(r'import\s+EvidenceInspector\s+from\s+"@/xdr/components/EvidenceInspector"',
                             src), (
        "MitreTab does not import the shared EvidenceInspector."
    )


def test_no_second_evidencedetail_in_cockpit():
    """The audit invariant: only the shared inspector renders
    governed-object detail.  No other cockpit tab may declare its
    own `EvidenceDetail` / `KV` inline widget."""
    for fname in os.listdir(COCKPIT_TABS_DIR):
        if not fname.endswith(".jsx"):
            continue
        path = os.path.join(COCKPIT_TABS_DIR, fname)
        src = open(path, encoding="utf-8").read()
        assert "function EvidenceDetail" not in src, (
            f"{fname} declares an inline `EvidenceDetail` widget — "
            f"only the shared inspector may render governed detail."
        )


def test_no_second_evidence_inspector_component_added():
    """The shared inspector remains the ONE component."""
    comp_dir = os.path.join(APP_ROOT, "apps/nivxray-xdr/src/xdr/components")
    inspector_files = [f for f in os.listdir(comp_dir)
                              if "Inspector" in f
                                 and f.endswith((".jsx", ".tsx"))]
    assert inspector_files == ["EvidenceInspector.jsx"], (
        f"expected only EvidenceInspector.jsx in components/, got "
        f"{inspector_files!r}"
    )


def test_attack_chain_composer_shape_unchanged(loop, db, incident_id):
    """R45 must not touch the SSOT composer that feeds MitreTab.
    Envelope shape assertion.
    """
    g = _run(loop, compose_attack_chain(db, incident_id))
    for k in ("state", "nodes", "edges", "counts", "honesty_note"):
        assert k in g, f"attack chain envelope missing {k!r}: {list(g)}"


def test_mitre_tab_uses_context_provider():
    """R45 threading pattern: EvidenceRow opens the shared inspector
    via a tab-local React Context, not by prop-drilling."""
    src = open(MITRE_TAB, encoding="utf-8").read()
    assert "MitreInspectorCtx" in src, (
        "R45 context provider missing from MitreTab."
    )
    assert "useMitreInspector" in src, (
        "R45 context consumer helper missing from MitreTab."
    )


def test_deeplink_bar_test_ids_present():
    """The deep-link bar exposes back-navigation with a testid so
    the audit locking suite can pin the interaction contract."""
    src = open(MITRE_TAB, encoding="utf-8").read()
    for tid in ('data-testid="xdr-mitre-inspector"',
                    'data-testid="xdr-mitre-deeplink-bar"',
                    'data-testid="xdr-mitre-deeplink-back"'):
        assert tid in src, f"MitreTab missing testid: {tid}"
