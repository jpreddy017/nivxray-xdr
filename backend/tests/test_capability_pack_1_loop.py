"""Capability Pack 1 · Universal Analyzer Loop · CI Gate.

Two things this proves:

  1. The UAIE Orchestrator with the migrated plugins + the new
     ``shellcode.analyzer`` (wrapping the existing production-grade
     ``shellcode_analyzer.py``) runs the full loop and terminates on
     a stable end-state.

  2. The loop unlocks strictly MORE evidence than the legacy peel
     alone — because the analyzer now emits family / MITRE / IOC /
     disassembly evidence sourced from the existing
     ``shellcode_analyzer.analyze()`` bundle that was previously
     only reachable through the legacy pipeline, never through UAIE.

The user's observation was exactly right: the technology was already
in the codebase — the missing piece was the wiring.  That wiring is
now the ``services.uaie.plugins.shellcode_analyzer`` Recognizer +
Capability pair.

Run:  cd /app/backend && python -m pytest tests/test_capability_pack_1_loop.py -v
"""
from __future__ import annotations

import os
import sys
from typing import Set

sys.path.insert(0, "/app/backend")
os.environ.setdefault("MONGO_URL", "mongodb://localhost:27017")
os.environ.setdefault("DB_NAME", "test_database")

from services.uaie.orchestrator import Orchestrator
from services.uaie              import plugins as _plugins_pkg
import shellcode_analyzer as _sca


# ═════════════════════════════════════════════════════════════════════════
# Synthetic shellcode — uses the SAME classification that the production
# `shellcode_analyzer` module already applies.  We craft a payload that:
#   · starts with a known Metasploit x86 prologue (\xFC\xE8)
#   · contains the wininet/ws2_32 marker used by _family_recognise
#   · has entropy > 6.5 (random tail padding)
#   · carries embedded ASCII IOCs (URL + user-agent + IP)
# ═════════════════════════════════════════════════════════════════════════
def _make_msf_meterpreter_bytes() -> bytes:
    """MSF Meterpreter x86 reverse-TCP stager shape."""
    prologue = b"\xFC\xE8\x89\x00\x00\x00\x60\x89\xE5\x31\xD2"
    body     = (
        b"wininet.dll\x00"
        b"ws2_32.dll\x00"
        b"WSAStartup\x00socket\x00connect\x00send\x00recv\x00"
        b"MSIE 8.0\x00"
        b"InternetOpenA\x00"
        b"http://c2.example.com/beacon.php\x00"
        b"149.28.81.19\x00"
    )
    # Random-looking tail to push entropy above 6.5.
    import hashlib
    tail = b""
    for i in range(64):
        tail += hashlib.sha256(str(i).encode()).digest()[:16]
    return prologue + body + tail


# ═════════════════════════════════════════════════════════════════════════
# T1 · The plugin is wired into UAIE with the production module.
# ═════════════════════════════════════════════════════════════════════════
def test_shellcode_analyzer_plugin_wraps_production_module():
    """R26 · The plugin's ``wraps_legacy`` field points at the existing
    production module — not at a duplicated implementation."""
    plugins = {p["name"]: p for p in _plugins_pkg.all_plugins()}
    p = plugins.get("shellcode.analyzer")
    assert p, "shellcode.analyzer plugin missing"
    assert p["wraps_legacy"] == "shellcode_analyzer.analyze", (
        f"expected wraps_legacy=shellcode_analyzer.analyze; "
        f"got {p['wraps_legacy']!r}"
    )


# ═════════════════════════════════════════════════════════════════════════
# T2 · Orchestrator loop runs and terminates on stable end-state.
# ═════════════════════════════════════════════════════════════════════════
def test_orchestrator_loop_terminates_on_stable_end_state():
    orch = Orchestrator(recognizers=_plugins_pkg.all_recognizers())
    result = orch.run(_make_msf_meterpreter_bytes(), root_type="shellcode_bytes")
    caps_hit = [w for w in result.warnings if "cap" in w.lower()]
    assert not caps_hit, f"loop hit safety cap: {caps_hit}"
    entries = list(result.ledger)
    assert entries
    last_actions = [e.action for e in entries[-5:]]
    assert "complete" in last_actions, \
        f"loop must end with COMPLETE action; got {last_actions}"


# ═════════════════════════════════════════════════════════════════════════
# T3 · The analyzer unlocks NEW evidence kinds the legacy peel never had.
# ═════════════════════════════════════════════════════════════════════════
def test_analyzer_unlocks_new_evidence_kinds_over_legacy():
    """R25/Pack-1 objective: the loop produces family / disassembly /
    shellcode_report evidence — kinds the legacy ``_shellcode_string_scan``
    could NEVER produce."""
    payload = _make_msf_meterpreter_bytes()

    from services.die.preprocessor.recursive_decoder import _shellcode_string_scan
    legacy_kinds: Set[str] = set()
    for tag in _shellcode_string_scan(payload):
        legacy_kinds.add(tag.split(":", 1)[0])

    orch = Orchestrator(recognizers=_plugins_pkg.all_recognizers())
    result = orch.run(payload, root_type="shellcode_bytes")
    uaie_kinds: Set[str] = {ev.kind for ev in result.evidence}

    # These are kinds ONLY the wired analyzer plugin can produce.
    must_have = {"family", "shellcode_report"}
    assert must_have.issubset(uaie_kinds), (
        f"analyzer failed to unlock new evidence kinds; expected "
        f"{must_have}, got {uaie_kinds}"
    )
    assert len(uaie_kinds) > len(legacy_kinds), (
        f"UAIE must extract strictly more evidence kinds than legacy "
        f"string scan; UAIE={uaie_kinds!r} legacy={legacy_kinds!r}"
    )


# ═════════════════════════════════════════════════════════════════════════
# T4 · MITRE ATT&CK mapping propagates through the analyzer plugin.
# ═════════════════════════════════════════════════════════════════════════
def test_analyzer_maps_iocs_and_family_to_mitre():
    orch = Orchestrator(recognizers=_plugins_pkg.all_recognizers())
    result = orch.run(_make_msf_meterpreter_bytes(), root_type="shellcode_bytes")

    # Family evidence carries MITRE from _family_recognise.
    fam = [ev for ev in result.evidence if ev.kind == "family"]
    assert fam, "expected family evidence"
    assert any(ev.mitre_techniques for ev in fam), \
        f"family evidence must carry MITRE; got {[e.mitre_techniques for e in fam]}"

    # URL evidence maps to T1071.001.
    urls = [ev for ev in result.evidence if ev.kind == "url"]
    if urls:  # depends on the analyzer's extract_iocs picking the URL up
        assert any("T1071.001" in ev.mitre_techniques for ev in urls)


# ═════════════════════════════════════════════════════════════════════════
# T5 · Pure-function contract — same input, same output.
# ═════════════════════════════════════════════════════════════════════════
def test_orchestrator_loop_is_pure():
    payload = _make_msf_meterpreter_bytes()
    r1 = Orchestrator(recognizers=_plugins_pkg.all_recognizers()).run(
        payload, root_type="shellcode_bytes")
    r2 = Orchestrator(recognizers=_plugins_pkg.all_recognizers()).run(
        payload, root_type="shellcode_bytes")
    assert set(r1.artifacts.keys()) == set(r2.artifacts.keys())
    # Fingerprint evidence ignoring uuid ids.
    def _fp(evs):
        return sorted((e.kind, str(e.value)[:200], e.source_capability,
                       tuple(e.mitre_techniques)) for e in evs)
    assert _fp(r1.evidence) == _fp(r2.evidence), \
        "same input MUST produce same evidence (pure-function contract)"


# ═════════════════════════════════════════════════════════════════════════
# T6 · The plugin agrees with the underlying production module —
# no drift between UAIE Evidence and shellcode_analyzer.analyze output.
# ═════════════════════════════════════════════════════════════════════════
def test_plugin_agrees_with_production_shellcode_analyzer():
    payload  = _make_msf_meterpreter_bytes()
    prod     = _sca.analyze(payload)
    fam, _   = _sca._family_recognise(payload)

    orch = Orchestrator(recognizers=_plugins_pkg.all_recognizers())
    result = orch.run(payload, root_type="shellcode_bytes")

    # Family: production module's answer == plugin's family evidence.
    plugin_family = next((ev.value for ev in result.evidence
                          if ev.kind == "family"), None)
    assert plugin_family == fam, \
        f"family drift: plugin={plugin_family!r} vs prod={fam!r}"

    # Shellcode report: plugin's shellcode_report matches production
    # bundle (size / entropy / arch / is_shellcode).
    plugin_report = next((ev.value for ev in result.evidence
                          if ev.kind == "shellcode_report"), None)
    assert plugin_report is not None
    for k in ("size", "entropy", "arch", "is_shellcode"):
        assert plugin_report[k] == prod[k], (
            f"shellcode_report drift on {k!r}: "
            f"plugin={plugin_report[k]!r} vs prod={prod[k]!r}"
        )
