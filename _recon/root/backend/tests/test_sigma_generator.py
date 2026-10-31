"""Sigma rule generator regression — Feb 2026."""
from __future__ import annotations
import os, sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from sigma_generator import emit_sigma


def test_emit_sigma_basic_shape():
    y = emit_sigma(
        payload="powershell Enable-PSRemoting -Force",
        output="Enable-PSRemoting -Force",
        mitre=[{"id":"T1021.006"}, {"id":"T1562.004"}],
        lolbas=["powershell.exe"],
        iocs={"ips":["49.75.27.62"]},
        verdict={"verdict":"Malicious","confidence":92,"summary":"WinRM enabler"},
    )
    for k in ("title:", "id:", "logsource:", "detection:", "condition:",
              "level:", "tags:", "attack.t1021.006", "attack.t1562.004",
              "attack.lateral_movement", "attack.defense_evasion",
              "powershell.exe", "49.75.27.62"):
        assert k in y, f"missing {k!r} in emitted Sigma"


def test_emit_sigma_no_iocs_still_valid():
    y = emit_sigma(payload="whoami", output="whoami", mitre=[], lolbas=[], iocs={})
    assert "condition: selection_image" in y
    assert "level: medium" in y  # default confidence=70


def test_emit_sigma_high_confidence_high_level():
    y = emit_sigma(payload="x", output="x", mitre=[], lolbas=[], iocs={},
                   verdict={"confidence": 95})
    assert "\nlevel: high\n" in y


def test_emit_sigma_low_confidence_low_level():
    y = emit_sigma(payload="x", output="x", mitre=[], lolbas=[], iocs={},
                   verdict={"confidence": 40})
    assert "\nlevel: low\n" in y


def test_emit_sigma_deterministic_id():
    """Same input twice → same rule id (stable across re-generations)."""
    a = emit_sigma(payload="abc", output="def", mitre=[], lolbas=[], iocs={})
    b = emit_sigma(payload="abc", output="def", mitre=[], lolbas=[], iocs={})
    # Extract the id line from both
    id_a = [l for l in a.split("\n") if l.startswith("id:")][0]
    id_b = [l for l in b.split("\n") if l.startswith("id:")][0]
    assert id_a == id_b
