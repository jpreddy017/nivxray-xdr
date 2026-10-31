"""Feb 2026 v1.3.2 · Six MITRE-heuristic gap-fixes from daily regression.

Every payload here was returning `mitre_count=0` in the nightly regression
before this release. Each maps to a canonical ATT&CK ID via `mitre_map()`.
"""
from operations import mitre_map


def _ids(text: str):
    return {m.get("id") if isinstance(m, dict) else None
            for m in (mitre_map(text) or [])}


# A4 — AMSI reflection short-form
def test_a4_amsi_reflection_short():
    payload = ("[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
               ".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)")
    assert "T1562.001" in _ids(payload)


# B8 — PowerShell char-code assembly
def test_b8_ps_char_code_assembly():
    payload = "-join(([char[]](116,101,115,116)))"
    assert "T1027" in _ids(payload)


# B8 variant — hex char-code
def test_b8_ps_char_code_hex():
    payload = "[char[]](0x74,0x65,0x73,0x74) -join ''"
    assert "T1027" in _ids(payload)


# D3 — Linux background execution via nohup
def test_d3_linux_nohup_background():
    payload = "nohup /tmp/x >/dev/null 2>&1 &"
    assert "T1059.004" in _ids(payload)


# D3 variant — setsid / disown / trailing `&`
def test_d3_linux_background_setsid():
    assert "T1059.004" in _ids("setsid bash /tmp/loader.sh")


# E6 — MSBuild inline task
def test_e6_msbuild_inline_task():
    payload = "msbuild.exe C:\\Users\\Public\\evil.csproj"
    assert "T1127.001" in _ids(payload)


# E6 variant — UsingTask XML
def test_e6_msbuild_usingtask_xml():
    payload = '<UsingTask TaskName="Evil" AssemblyFile="x.dll">'
    assert "T1127.001" in _ids(payload)


# G1 — GCP service-account JWT / key file
def test_g1_gcp_service_account_jwt():
    # After JWT decoding the plaintext body surfaces `iam.gserviceaccount.com`
    # — mirror the pipeline behaviour (input + decoded output combined).
    raw = ("eyJhbGciOiJSUzI1NiJ9."
           "eyJpc3MiOiJzdmMtYWNjb3VudEBteS1wcm9qZWN0LmlhbS5nc2VydmljZWFjY291bnQuY29tIn0."
           "SIG")
    decoded = '{"iss":"svc-account@my-project.iam.gserviceaccount.com"}'
    assert "T1552.004" in _ids(raw + "\n" + decoded)


# G1 variant — JSON key file structure
def test_g1_gcp_key_json():
    assert "T1552.004" in _ids('{"type": "service_account", "private_key_id": "abc123def456' + "0" * 34 + '"}')


# G2 — AWS Cognito ID token (canonical body prefix)
def test_g2_aws_cognito_id_token():
    payload = ("eyJraWQiOiJmZDU3IiwiYWxnIjoiUlMyNTYifQ."
               "eyJjb2duaXRvOnVzZXJuYW1lIjoidmljdGltQHRhcmdldC5jb20iLCJhdWQiOiIxMjNhYmMifQ."
               "SIG")
    assert "T1528" in _ids(payload)


# G2 variant — plaintext issuer URL
def test_g2_cognito_issuer_url():
    assert "T1528" in _ids("cognito-idp.eu-central-1.amazonaws.com/eu-central-1_eXAmple")
