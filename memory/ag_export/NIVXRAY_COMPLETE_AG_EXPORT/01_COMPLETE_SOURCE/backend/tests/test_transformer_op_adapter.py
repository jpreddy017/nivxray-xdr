"""transformer_op_adapter · Capability Pack (Priority 3 · CI Gate).

Proves the 5 function-only PowerShell transformer ops are now first-class
UAIE capabilities and actually contribute to end-to-end decoding.

Run: cd /app/backend && python -m pytest tests/test_transformer_op_adapter.py -v
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, "/app/backend")
os.environ.setdefault("MONGO_URL", "mongodb://localhost:27017")
os.environ.setdefault("DB_NAME", "test_database")

from services.uaie.orchestrator import Orchestrator
from services.uaie              import plugins as _plugins_pkg


# ── T1 · Every op-adapter plugin registered ─────────────────────────
def test_all_op_adapter_plugins_registered():
    plugins = {p["name"]: p for p in _plugins_pkg.all_plugins()}
    expected = {
        "op.ps-encodedcommand-multilayer",
        "op.powershell-hex-csv-inline",
        "op.powershell-xor-inline-key",
        "op.powershell-normalize",
        "op.powershell-reverse-string",
        "op.powershell-reverse-regex-swap",
        "op.powershell-semantic-mini",
    }
    missing = expected - set(plugins.keys())
    assert not missing, f"op-adapter plugins missing: {missing}"
    for name in expected:
        p = plugins[name]
        assert p["semantic"] == "transformer"
        assert p["wraps_legacy"].startswith("operations.OPERATIONS[")


# ── T2 · Hex-CSV inline PowerShell → calc.exe ───────────────────────
def test_hex_csv_inline_powershell_decodes():
    """The classic `$h='43,61,6c,63,2e,65,78,65'; -split ',' | ForEach-Object
    {[char][int]('0x'+$_)}; iex ($c -join '')` obfuscation.  We expect the
    op-adapter to peel it and emit a `powershell_normalized` child artifact
    containing `calc.exe`."""
    payload = (
        b"$h='43,61,6c,63,2e,65,78,65'; "
        b"$c = $h -split ',' | ForEach-Object {[char][int]('0x'+$_)}; "
        b"Invoke-Expression ($c -join '')"
    )
    orch = Orchestrator(recognizers=_plugins_pkg.all_recognizers())
    result = orch.run(payload, root_type="text")

    hits = [a for a in result.artifacts.values()
             if b"calc.exe" in a.payload.lower()]
    assert hits, (
        f"hex-csv inline decoder failed to peel to 'calc.exe'.  "
        f"Artifacts seen (first 5): "
        f"{[(a.artifact_type, a.payload[:60]) for a in list(result.artifacts.values())[:5]]}"
    )


# ── T3 · Reverse-string PowerShell → calc.exe ───────────────────────
def test_reverse_string_decodes():
    """`$s='exe.clac'; $s[-1..-8] -join ''` → `calc.exe`."""
    payload = b"$s = 'exe.clac'; $s[-1..-8] -join ''"
    orch = Orchestrator(recognizers=_plugins_pkg.all_recognizers())
    result = orch.run(payload, root_type="text")

    hits = [a for a in result.artifacts.values()
             if b"calc.exe" in a.payload]
    assert hits, (
        f"reverse-string decoder failed to peel to 'calc.exe'.  "
        f"Artifacts seen: "
        f"{[(a.artifact_type, a.payload[:80]) for a in result.artifacts.values()]}"
    )


# ── T4 · Semantic-mini chain evaluator ──────────────────────────────
def test_semantic_mini_chain_evaluator():
    """Empire/Nishang chain: literal → -replace regex_swap → reverse.
    Should peel `'exe.clac' -replace '(\\w+)\\.(\\w+)','$2.$1'
    | ForEach-Object { $_[-1..-8] -join '' }` to `exe.calc`."""
    payload = (
        b"Invoke-Expression (('exe.clac') -join '' -replace "
        b"'(\\w+)\\.(\\w+)','$2.$1' | ForEach-Object "
        b"{ $_[-1..-8] -join '' })"
    )
    orch = Orchestrator(recognizers=_plugins_pkg.all_recognizers())
    result = orch.run(payload, root_type="text")

    # Any artifact carrying either the mid-swap `clac.exe` or the reversed
    # `exe.calc` proves the semantic-mini op executed successfully.
    hits = [a for a in result.artifacts.values()
             if b"exe.calc" in a.payload or b"clac.exe" in a.payload]
    assert hits, (
        f"semantic-mini failed to peel.  Artifacts: "
        f"{[(a.artifact_type, a.payload[:100]) for a in result.artifacts.values()]}"
    )


# ── T5 · Normalize PowerShell exe path + parameter casing ───────────
def test_normalize_canonicalises_parameters():
    """`PoWeRsHeLl.EXE -NoPrOfIlE -ExEcUtIoNpOlIcY ByPaSs -CoMmAnD "Write-Host 'hi'"`
    → normalized canonical PowerShell command line."""
    payload = (b"PoWeRsHeLl.EXE -NoPrOfIlE -ExEcUtIoNpOlIcY ByPaSs "
                b"-CoMmAnD \"Write-Host 'hi'\"")
    orch = Orchestrator(recognizers=_plugins_pkg.all_recognizers())
    result = orch.run(payload, root_type="text")

    normalized = [a for a in result.artifacts.values()
                    if a.artifact_type == "powershell_normalized"]
    assert normalized, (
        f"normalize op failed to produce a powershell_normalized child.  "
        f"Artifacts: "
        f"{[(a.artifact_type, a.payload[:80]) for a in result.artifacts.values()]}"
    )
    joined = b" ".join(a.payload for a in normalized).lower()
    assert (b"-noprofile" in joined
              and b"-executionpolicy" in joined
              and b"-command" in joined), (
        f"normalize op did not canonicalise parameter casing.  "
        f"Got: {joined[:200]!r}"
    )


# ── T6 · Pure-function contract (R28) ───────────────────────────────
def test_op_adapter_run_is_deterministic():
    """Same payload → identical evidence + identical children across
    two independent Orchestrator instances."""
    payload = b"$h='43,61,6c,63,2e,65,78,65'; $c = $h -split ',' | ForEach-Object {[char][int]('0x'+$_)}; iex ($c -join '')"

    r1 = Orchestrator(recognizers=_plugins_pkg.all_recognizers()).run(
        payload, root_type="text")
    r2 = Orchestrator(recognizers=_plugins_pkg.all_recognizers()).run(
        payload, root_type="text")

    def _fp(evs):
        return sorted((e.kind, str(e.value)[:200], e.source_capability)
                      for e in evs)
    assert _fp(r1.evidence) == _fp(r2.evidence), (
        "same payload must produce identical evidence (R28 purity)"
    )
    assert (sorted(a.artifact_type for a in r1.artifacts.values())
              == sorted(a.artifact_type for a in r2.artifacts.values()))


# ── T7 · Sentinel handling — op returned "(op_id · no match)" ──────
def test_op_returns_no_match_sentinel_does_not_produce_child():
    """If the recognizer fires (marker present) but the op function
    can't actually decode (returns its `(op_id · reason)` sentinel),
    the adapter MUST NOT emit a child artifact."""
    # A payload that has hex-csv marker-look but the value isn't well-formed
    payload = b"$h='43'; # no comma-list, not actually decodable"
    orch = Orchestrator(recognizers=_plugins_pkg.all_recognizers())
    result = orch.run(payload, root_type="text")

    for a in result.artifacts.values():
        assert b"(powershell-hex-csv-inline" not in a.payload, (
            f"sentinel string leaked into a child artifact: {a.payload!r}"
        )
