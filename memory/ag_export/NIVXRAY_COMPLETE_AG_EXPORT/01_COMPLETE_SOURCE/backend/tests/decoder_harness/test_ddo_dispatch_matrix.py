"""Gate 2D-B3.2-A · DDO dispatch matrix invariant test.

Owner directive completion: ALL 7 migrated Plane-A codec families
MUST be reachable through the DDO signature-dispatch table.

This test freezes that architectural invariant so any future
regression (accidental removal of a signature, function rename,
etc.) fails a fast, cheap test rather than a full parity re-run.

It is NOT a behavioural test — it only asserts that the DDO
dispatch surface exposes the 7 required entries with the correct
adapter callable identity.  The adapter delegates to the
authoritative implementation at services.decoder.base.*.
"""
from __future__ import annotations

import pytest

from services.decoder.orchestrator import _SIGNATURES, _DECODER_FNS, INVARIANTS
from services.decoder.base import _ddo_adapter as ADAPT


# The 7 migrated families that MUST appear in DDO dispatch.
REQUIRED_MIGRATED = {
    "base.gzip":                 ADAPT.ddo_gzip,
    "base.zlib":                 ADAPT.ddo_zlib,
    "base.byte_array_xor_loop":  ADAPT.ddo_byte_array_xor_loop,
    "base.xor_brute":            ADAPT.ddo_xor_brute,
    "base.rc4":                  ADAPT.ddo_rc4,
    "base.aes_cbc":              ADAPT.ddo_aes_cbc,
    "base.ps_encodedcommand":    ADAPT.ddo_ps_encoded_command,
}


def test_ddo_signature_table_contains_all_7_migrated_families():
    """Every migrated family MUST have a signature entry."""
    sig_names = {name for name, _pat in _SIGNATURES}
    missing = set(REQUIRED_MIGRATED.keys()) - sig_names
    assert not missing, (
        f"DDO signature table missing migrated families: {sorted(missing)}. "
        f"Present base.* entries: "
        f"{sorted(n for n in sig_names if n.startswith('base.'))}."
    )


def test_ddo_dispatch_fns_wired_to_authoritative_adapter():
    """Every migrated family's dispatch fn MUST be the exact
    adapter object.  Identity check (`is`) prevents someone from
    re-routing the entry back through a legacy path."""
    for name, expected_fn in REQUIRED_MIGRATED.items():
        got = _DECODER_FNS.get(name)
        assert got is expected_fn, (
            f"DDO dispatch mismatch for {name!r}: "
            f"expected {expected_fn!r}, got {got!r}."
        )


def test_ddo_invariants_intact():
    """Structural invariants must remain enforced."""
    assert INVARIANTS["static_only"]         is True
    assert INVARIANTS["execution"]           is False
    assert INVARIANTS["network_access"]      is False
    assert INVARIANTS["attck_promotion"]     is False
    assert INVARIANTS["bounded_depth"]       is True
    assert INVARIANTS["deterministic_order"] is True
    assert INVARIANTS["provenance_required"] is True
    assert INVARIANTS["MAX_DEPTH"]           == 6


@pytest.mark.parametrize("name,fn", list(REQUIRED_MIGRATED.items()))
def test_adapter_never_fires_on_benign_ascii(name: str, fn):
    """No migrated-codec adapter may fire on plain English text.

    This is the false-reconstruction guard the DDO applies at the
    signature layer.  It ensures adding these adapters did not
    introduce any speculative decoding of benign inputs.
    """
    for benign in (
        "The quick brown fox jumps over the lazy dog.",
        "Get-Service | Where-Object Status -eq Running",
        "SELECT id FROM users WHERE tenant_id = 42;",
        "",
    ):
        out = fn(benign)
        assert out is None or out == benign, (
            f"{name} fired on benign text: {benign!r} -> {out!r}"
        )
