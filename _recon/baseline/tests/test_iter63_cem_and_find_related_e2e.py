"""
Iter-63 · Phase 4 P1 Completion · E2E tests against preview URL
- POST /api/correlations/find-related
- GET  /api/correlations/cem/{case_id}
- Post-record hook (cem + pending_correlations backfill)
- Regression on existing /api/correlations/* and /api/history
"""
import os, time, base64, pytest, requests

BASE = os.environ.get("REACT_APP_BACKEND_URL", "https://greeting-app-5782.preview.emergentagent.com").rstrip("/")
ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PW    = "uulVDp5cCSB3Hva99s7UUAwK"

SEED_CID    = "6a72169b3d98eb14810c9506"
SEED_CASE_A = "6a71df55de61c45467e3a650"   # PE, in the seeded investigation
SEED_CASE_B = "6a7208be7b3dd2412874045f"   # ELF, in the seeded investigation


@pytest.fixture(scope="module")
def token():
    r = requests.post(f"{BASE}/api/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PW}, timeout=90)
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def H(token):
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


# ---------- CEM ----------
def test_cem_returns_shape(H):
    r = requests.get(f"{BASE}/api/correlations/cem/{SEED_CASE_A}", headers=H, timeout=30)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["case_id"] == SEED_CASE_A
    cem = body["cem"]
    for key in ("cem_version", "artifact_id", "convergence", "canonical_artifacts", "events", "indicators", "mitre", "traces", "child_artifacts", "verdict"):
        assert key in cem, f"missing CEM field: {key}"
    assert isinstance(cem["events"], list)
    for e in cem["events"]:
        assert "provenance" in e, "every CEM event must carry provenance"


def test_cem_is_deterministic(H):
    r1 = requests.get(f"{BASE}/api/correlations/cem/{SEED_CASE_A}", headers=H, timeout=30).json()
    r2 = requests.get(f"{BASE}/api/correlations/cem/{SEED_CASE_A}", headers=H, timeout=30).json()
    assert r1["cem"]["cem_version"] == r2["cem"]["cem_version"]
    ev1 = [(e.get("type"), e.get("hash") or e.get("id")) for e in r1["cem"]["events"]]
    ev2 = [(e.get("type"), e.get("hash") or e.get("id")) for e in r2["cem"]["events"]]
    assert ev1 == ev2
    assert r1["cem"]["indicators"] == r2["cem"]["indicators"]


def test_cem_case_not_found(H):
    r = requests.get(f"{BASE}/api/correlations/cem/000000000000000000000000", headers=H, timeout=30)
    assert r.status_code == 404


# ---------- find-related ----------
def test_find_related_existing_investigation(H):
    r = requests.post(f"{BASE}/api/correlations/find-related",
                      headers=H, json={"case_id": SEED_CASE_A}, timeout=45)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["case_id"] == SEED_CASE_A
    assert body["existing_investigation"] is not None
    assert body["existing_investigation"]["id"] == SEED_CID
    assert "suggestions" in body and isinstance(body["suggestions"], list)
    assert body["source"] in ("cache", "live")
    assert isinstance(body["min_score"], int)


def test_find_related_refresh_forces_live(H):
    r = requests.post(f"{BASE}/api/correlations/find-related",
                      headers=H, json={"case_id": SEED_CASE_A, "refresh": True}, timeout=60)
    assert r.status_code == 200, r.text
    assert r.json()["source"] == "live"


def test_find_related_case_not_found(H):
    r = requests.post(f"{BASE}/api/correlations/find-related",
                      headers=H, json={"case_id": "000000000000000000000000"}, timeout=30)
    assert r.status_code == 404


# ---------- post-record hook: cem + pending_correlations backfilled ----------
def test_record_then_hook_backfills_cem(H):
    # Recording happens internally when /api/decode/smart runs with source_name
    marker = f"TEST_iter63_{int(time.time())} nivxray unique payload"
    r = requests.post(f"{BASE}/api/decode/smart", headers=H,
                      json={"input": marker, "source_name": "iter63_hook_test"}, timeout=60)
    assert r.status_code == 200, r.text

    # Poll history for a match containing our marker in input_text
    case_id = None
    seen_cem = False
    seen_pending = False
    def _extract_items(js):
        if isinstance(js, list): return js
        if isinstance(js, dict): return js.get("items") or js.get("history") or []
        return []
    for _ in range(15):
        time.sleep(0.7)
        rr = requests.get(f"{BASE}/api/history?limit=50", headers=H, timeout=60)
        if rr.status_code != 200: continue
        items = _extract_items(rr.json())
        match = next((i for i in items if marker[:24] in (i.get("input_preview") or i.get("input_text") or "")), None)
        if not match:
            continue
        case_id = match.get("id") or match.get("_id")
        if match.get("cem"): seen_cem = True
        if "pending_correlations" in match: seen_pending = True
        if seen_cem and seen_pending:
            break
    # cleanup
    if case_id:
        try:
            requests.delete(f"{BASE}/api/history/{case_id}", headers=H, timeout=15)
        except Exception:
            pass
    assert case_id, "case never appeared in /api/history after decode/smart"
    assert seen_cem,     "post-record hook did not backfill `cem` within ~10s"
    assert seen_pending, "post-record hook did not backfill `pending_correlations` within ~10s"


# ---------- regression: /api/correlations/* still work ----------
def test_correlations_list_and_seed_endpoints(H):
    r = requests.get(f"{BASE}/api/correlations", headers=H, timeout=30)
    assert r.status_code == 200
    for suffix in ("chain", "graph", "timeline", "summary", "suggestions"):
        rr = requests.get(f"{BASE}/api/correlations/{SEED_CID}/{suffix}", headers=H, timeout=30)
        assert rr.status_code == 200, f"{suffix} failed: {rr.status_code} {rr.text[:200]}"


# ---------- regression: decode/smart still returns 200 ----------
def test_decode_smart_text_regression(H):
    r = requests.post(f"{BASE}/api/decode/smart",
                      headers=H, json={"input": "powershell -enc SGVsbG8="}, timeout=60)
    assert r.status_code == 200, r.text
    body = r.json()
    assert "verdict_card" in body
    assert "iedde_terminal_state" in body


# ---------- regression: artifacts/analyze routing unchanged ----------
def test_artifacts_capabilities(H):
    r = requests.get(f"{BASE}/api/artifacts/capabilities", headers=H, timeout=30)
    assert r.status_code == 200
    caps = r.json()
    # 4 analyzers still declared
    assert any(k in str(caps).lower() for k in ("pe", "elf", "pdf", "office"))
