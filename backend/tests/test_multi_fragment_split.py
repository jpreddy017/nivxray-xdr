"""Feb 2026 v1.3.1 · multi-fragment auto-split for /api/decode/smart.

Analysts frequently paste Splunk / Kibana / Sentinel log dumps where
multiple payloads are joined by `<br>` HTML line breaks. Previously we
decoded only the first fragment; now every `-Enc` block and every
LOLBAS command line surfaces independently in the output.
"""
import os
import subprocess

import pytest
import requests

API = os.environ.get("REACT_APP_BACKEND_URL") or subprocess.check_output(
    "grep REACT_APP_BACKEND_URL /app/frontend/.env | cut -d= -f2",
    shell=True,
).decode().strip()
EMAIL, PW = "admin@nivxray.com", "uulVDp5cCSB3Hva99s7UUAwK"


@pytest.fixture(scope="module")
def h():
    tok = requests.post(f"{API}/api/auth/login",
                        json={"email": EMAIL, "password": PW},
                        timeout=10).json()["access_token"]
    return {"Authorization": f"Bearer {tok}"}


# 4 identical `-Enc` blocks (same rundll32/comsvcs.dll LSASS-dump command line
# with different drop-file names) + 2 CMD lines, all joined by `<br>`.
_ENC = (
    "cgB1AG4AZABsAGwAMwAyAC4AZQB4AGUAIABDADoAXABXAGkAbgBkAG8AdwBzAFwAUwB5AHMA"
    "dABlAG0AMwAyAFwAYwBvAG0AcwB2AGMAcwAuAGQAbABsACwAIABgACMAKwAwADAAMAAwADIA"
    "NAAgACgARwBlAHQALQBQAHIAbwBjAGUAcwBzACAAbABzAGEAcwBzACkALgBJAGQAIABcAFcA"
    "aQBuAGQAbwB3AHMAXABUAGUAbQBwAFwATgA0AFAATQAuAGQAbwBjAHgAIABmAHUAbABsAA=="
)
_BR_PAYLOAD = (
    "-Embedding<br>"
    f"-NoP -Enc {_ENC}<br>"
    f"-NoP -Enc {_ENC}<br>"
    f"-NoP -Enc {_ENC}<br>"
    f"-NoP -Enc {_ENC}<br>"
    "CmD.exe /Q /c for /f \"tokens=1,2 delims= \" ^%A in ("
    "'\"tasklist /fi \"Imagename eq lsass.exe\" | find \"lsass\"\"') "
    "do rundll32.exe C:\\windows\\System32\\comsvcs.dll, #+0000^24 "
    "^%B \\Windows\\Temp\\lZP6n.dll full"
)


def test_br_delimited_multi_enc_splits(h):
    r = requests.post(f"{API}/api/decode/smart", headers=h,
                      json={"input": _BR_PAYLOAD}, timeout=60)
    assert r.status_code == 200
    d = r.json()

    # Multi-fragment engine kicked in
    assert d.get("engine") == "multi-fragment", d.get("engine")
    assert d.get("fragment_count", 0) >= 5

    # Every `-Enc` block decoded to the comsvcs.dll LSASS-dump command
    frags = d.get("fragments") or []
    enc_frags = [f for f in frags if "extract-payload" in (f.get("chain_ids") or []) or "base64-decode" in (f.get("chain_ids") or [])]
    assert len(enc_frags) >= 4, f"only {len(enc_frags)} -Enc blocks decoded"
    for f in enc_frags:
        assert "rundll32" in (f.get("output") or "")
        assert "comsvcs.dll" in (f.get("output") or "")
        assert "lsass" in (f.get("output") or "").lower()

    # MITRE union surfaces LSASS credential access + rundll32 abuse
    mitre_ids = {(m.get("id") if isinstance(m, dict) else m) for m in (d.get("mitre") or [])}
    assert "T1003.001" in mitre_ids, mitre_ids  # OS Credential Dumping: LSASS
    assert "T1218.011" in mitre_ids, mitre_ids  # rundll32

    # LOLBIN union
    lolbins = {(l.get("binary") if isinstance(l, dict) else l) for l in (d.get("lolbas") or [])}
    assert any("rundll32" in (b or "").lower() for b in lolbins), lolbins
    assert any("comsvcs" in (b or "").lower() for b in lolbins), lolbins

    # Response shape (regression parity with /decode/smart consumers)
    assert isinstance(d.get("chain_ids"), list)
    assert isinstance(d.get("score"), int)
    risk = d.get("risk") or {}
    assert risk.get("verdict") and risk.get("level")


def test_single_payload_does_not_go_multi_fragment(h):
    """A single -Enc paste (no <br>) must NOT trigger multi-fragment mode."""
    r = requests.post(f"{API}/api/decode/smart", headers=h,
                      json={"input": f"-NoP -Enc {_ENC}"}, timeout=30)
    d = r.json()
    assert d.get("engine") != "multi-fragment", d.get("engine")


def test_two_encs_on_separate_lines_splits(h):
    """Two `-Enc` blocks on newline-separated lines also trigger split."""
    payload = f"-NoP -Enc {_ENC}\n\n-NoP -Enc {_ENC}"
    r = requests.post(f"{API}/api/decode/smart", headers=h,
                      json={"input": payload}, timeout=45)
    d = r.json()
    assert d.get("engine") == "multi-fragment", d.get("engine")
    assert d.get("fragment_count", 0) == 2
