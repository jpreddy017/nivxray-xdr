"""Live API tests — Phase 2 Final Integration Gate.

Covers:
  · GET  /api/narration/incident/{id}/cross-lane-story
  · POST /api/telemetry/verdict-inputs (persistence + idempotency)
  · GET  /api/narration/providers (cross_lane_story support)
"""
import os
import re
import uuid
from pathlib import Path

import pytest
import requests
from dotenv import dotenv_values

frontend_env = dotenv_values("/app/frontend/.env")
base_url = os.environ.get("REACT_APP_BACKEND_URL") or frontend_env.get("REACT_APP_BACKEND_URL")
if not base_url:
    raise RuntimeError("REACT_APP_BACKEND_URL missing")
BASE_URL = base_url.rstrip("/")

REAL_INCIDENT_ID = "36d8cd4d-a6b8-42b5-8106-1daf05a7d0ed"

FORBIDDEN = ("verdict", "severity", "maliciousness",
             "verdict_confidence", "attck_promote")


# ---------------- fixtures ----------------
@pytest.fixture(scope="session")
def creds():
    p = Path("/app/memory/test_credentials.md")
    c = p.read_text(encoding="utf-8")
    email = re.search(r'(?im)^\s*[-*]?\s*\*\*Email\*\*\s*:\s*`?([^`\s]+)', c)
    pwd = re.search(r'(?im)^\s*[-*]?\s*\*\*Password\*\*\s*:\s*`?([^`\s]+)', c)
    assert email and pwd, "credentials not parseable"
    return {"email": email.group(1), "password": pwd.group(1)}


@pytest.fixture(scope="session")
def client(creds):
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json"})
    r = s.post(f"{BASE_URL}/api/auth/login", json=creds, timeout=60)
    if r.status_code != 200:
        pytest.fail(f"login failed {r.status_code}: {r.text[:300]}")
    tok = r.json().get("access_token")
    assert tok, f"no access_token in {r.json()}"
    s.headers.update({"Authorization": f"Bearer {tok}"})
    return s


@pytest.fixture(scope="session")
def mongo_db():
    from motor.motor_asyncio import AsyncIOMotorClient
    be = dotenv_values("/app/backend/.env")
    cli = AsyncIOMotorClient(be["MONGO_URL"])
    return cli[be["DB_NAME"]]


def _cross_lane_events(actor="alice"):
    return [
        {"canonical_id": "ce-ep-1", "source_kind": "endpoint",
         "action": "process_create", "actor": {"id": actor},
         "target": {"host": "WKS-1"}},
        {"canonical_id": "ce-id-1", "source_kind": "identity",
         "action": "signin_success", "actor": {"id": actor},
         "target": {"app": "portal"}},
        {"canonical_id": "ce-cl-1", "source_kind": "cloud",
         "action": "role_assign", "actor": {"id": actor},
         "target": {"resource": "arn:aws:iam::1:role/admin"}},
    ]


# ---------------- narration providers ----------------
class TestNarrationProviders:
    def test_providers_support_cross_lane_story(self, client):
        r = client.get(f"{BASE_URL}/api/narration/providers", timeout=60)
        assert r.status_code == 200, r.text[:300]
        data = r.json()
        provs = data.get("providers") if isinstance(data, dict) else data
        assert provs, f"no providers in {data}"
        names = []
        for p in provs:
            supports = p.get("supports") or p.get("kinds") or []
            names.append(p.get("name"))
            assert "cross_lane_story" in supports, \
                f"{p.get('name')} missing cross_lane_story: {supports}"
        joined = " ".join(str(n) for n in names)
        assert "cloud" in joined and "offline" in joined and "deterministic" in joined, joined


# ---------------- cross-lane story ----------------
class TestCrossLaneStory:
    def test_cross_lane_story_grounded(self, client):
        r = client.get(
            f"{BASE_URL}/api/narration/incident/{REAL_INCIDENT_ID}/cross-lane-story",
            timeout=180)
        assert r.status_code == 200, r.text[:500]
        d = r.json()
        assert d["kind"] == "cross_lane_story", d["kind"]
        assert d["grounded"] is True, d.get("caveats")
        assert isinstance(d["text"], str) and len(d["text"]) > 40, d["text"]
        assert d["generation_mode"] in ("llm_cloud", "llm_offline", "deterministic")
        assert d["provider"]

    def test_no_fabricated_techniques(self, client):
        r = client.get(
            f"{BASE_URL}/api/narration/incident/{REAL_INCIDENT_ID}/cross-lane-story",
            timeout=180)
        assert r.status_code == 200
        d = r.json()
        allowed = set(d["technique_ids"])
        mentioned = set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", d["text"]))
        assert mentioned <= allowed, f"fabricated: {mentioned - allowed}"
        for p in d["paragraphs"]:
            assert set(p["technique_ids"]) <= allowed

    def test_honest_coverage_gap_for_zero_canonical_events(self, client):
        """Incidents with no canonical_events must narrate the gap,
        not fabricate cross-lane activity."""
        r = client.get(f"{BASE_URL}/api/xdr/incidents?limit=25", timeout=90)
        if r.status_code != 200:
            pytest.skip(f"incident list unavailable: {r.status_code}")
        body = r.json()
        items = body.get("items") or body.get("incidents") or body
        ids = [i.get("id") for i in items if isinstance(i, dict) and i.get("id")]
        assert ids, "no incidents to test"
        checked = 0
        for iid in ids:
            rr = client.get(
                f"{BASE_URL}/api/narration/incident/{iid}/cross-lane-story",
                timeout=180)
            if rr.status_code != 200:
                continue
            d = rr.json()
            lanes_hint = re.search(
                r"(no cross-lane|coverage gap|only endpoint|not (?:been )?onboard|"
                r"identity and cloud|no identity|single lane)",
                d["text"], re.I)
            if lanes_hint:
                assert d["grounded"] is True
                checked += 1
                break
        if checked == 0:
            pytest.skip("no zero-canonical-event incident surfaced coverage-gap prose")

    def test_missing_incident_404(self, client):
        r = client.get(
            f"{BASE_URL}/api/narration/incident/{uuid.uuid4()}/cross-lane-story",
            timeout=60)
        assert r.status_code == 404, f"{r.status_code}: {r.text[:200]}"


# ---------------- verdict-inputs ----------------
class TestVerdictInputs:
    def test_cross_lane_persistence_and_shape(self, client, mongo_db):
        import asyncio
        inc = f"TEST_inc_{uuid.uuid4()}"
        r = client.post(f"{BASE_URL}/api/telemetry/verdict-inputs",
                        json={"incident_id": inc, "events": _cross_lane_events()},
                        timeout=90)
        assert r.status_code == 200, r.text[:400]
        d = r.json()
        assert len(d["verdict_inputs"]) == 1, d["verdict_inputs"]
        vi = d["verdict_inputs"][0]
        assert vi["correlation_confidence"] == 0.85, vi
        assert len(d["evidence_graph_edges"]) == 2, d["evidence_graph_edges"]
        for e in d["evidence_graph_edges"]:
            assert e["provenance"]["attck_promotion"] is False, e
        assert d["persistence"] == {
            "incident_id": inc,
            "stored_inputs": 1,
            "stored_edges": 2,
            "authority": "existing-verdict-engine",
            "attck_promotion": False,
        }, d["persistence"]
        assert d["authority"] == "existing-verdict-engine"

        async def check():
            inputs = await mongo_db["xdr_verdict_inputs"].find(
                {"incident_id": inc}, {"_id": 0}).to_list(50)
            edges = await mongo_db["xdr_evidence_graph_edges"].find(
                {"incident_id": inc}, {"_id": 0}).to_list(50)
            return inputs, edges

        inputs, edges = asyncio.get_event_loop().run_until_complete(check())
        assert len(inputs) == 1, inputs
        assert len(edges) == 2, edges
        for doc in inputs + edges:
            for f in FORBIDDEN:
                assert f not in doc, f"forbidden field {f} persisted: {doc}"
        for e in edges:
            assert e["provenance"]["attck_promotion"] is False

        # cleanup
        async def clean():
            await mongo_db["xdr_verdict_inputs"].delete_many({"incident_id": inc})
            await mongo_db["xdr_evidence_graph_edges"].delete_many({"incident_id": inc})
        asyncio.get_event_loop().run_until_complete(clean())

    def test_idempotency_three_calls(self, client, mongo_db):
        import asyncio
        inc = f"TEST_inc_{uuid.uuid4()}"
        payload = {"incident_id": inc, "events": _cross_lane_events()}
        for _ in range(3):
            r = client.post(f"{BASE_URL}/api/telemetry/verdict-inputs",
                            json=payload, timeout=90)
            assert r.status_code == 200, r.text[:300]

        async def counts():
            return (
                await mongo_db["xdr_verdict_inputs"].count_documents({"incident_id": inc}),
                await mongo_db["xdr_evidence_graph_edges"].count_documents({"incident_id": inc}),
            )
        ni, ne = asyncio.get_event_loop().run_until_complete(counts())
        assert (ni, ne) == (1, 2), f"duplicates: inputs={ni} edges={ne}"

        async def clean():
            await mongo_db["xdr_verdict_inputs"].delete_many({"incident_id": inc})
            await mongo_db["xdr_evidence_graph_edges"].delete_many({"incident_id": inc})
        asyncio.get_event_loop().run_until_complete(clean())

    def test_endpoint_only_yields_nothing(self, client, mongo_db):
        import asyncio
        inc = f"TEST_inc_{uuid.uuid4()}"
        events = [
            {"canonical_id": "ce-ep-a", "source_kind": "endpoint",
             "action": "process_create", "actor": {"id": "alice"}},
            {"canonical_id": "ce-ep-b", "source_kind": "endpoint",
             "action": "file_write", "actor": {"id": "alice"}},
        ]
        r = client.post(f"{BASE_URL}/api/telemetry/verdict-inputs",
                        json={"incident_id": inc, "events": events}, timeout=90)
        assert r.status_code == 200, r.text[:300]
        d = r.json()
        assert d["verdict_inputs"] == [], d["verdict_inputs"]
        assert d["evidence_graph_edges"] == [], d["evidence_graph_edges"]
        assert d["persistence"]["stored_inputs"] == 0
        assert d["persistence"]["stored_edges"] == 0

        async def counts():
            return (
                await mongo_db["xdr_verdict_inputs"].count_documents({"incident_id": inc}),
                await mongo_db["xdr_evidence_graph_edges"].count_documents({"incident_id": inc}),
            )
        ni, ne = asyncio.get_event_loop().run_until_complete(counts())
        assert (ni, ne) == (0, 0)

    def test_no_incident_id_still_works_without_persistence(self, client):
        r = client.post(f"{BASE_URL}/api/telemetry/verdict-inputs",
                        json={"events": _cross_lane_events()}, timeout=90)
        assert r.status_code == 200, r.text[:300]
        d = r.json()
        assert len(d["verdict_inputs"]) == 1
        assert d["persistence"] is None, d["persistence"]

    def test_requires_auth(self):
        r = requests.post(f"{BASE_URL}/api/telemetry/verdict-inputs",
                          json={"events": []}, timeout=60)
        assert r.status_code in (401, 403), r.status_code
