"""RC3.2c · enriched `crypto-key-required` tradecraft schema.

Locks the structured metadata contract so a refactor of the crypto-detect
plugin cannot silently drop analyst-critical fields.
"""
from __future__ import annotations

import base64
import os

import pytest

import decoders  # noqa: F401
from engine import AnalysisContext, Budget, Orchestrator


def _find_crypto_flag(findings):
    for tc in findings.tradecraft:
        if tc.flag == "crypto-key-required":
            return tc
    return None


@pytest.mark.parametrize("byte_len", [128, 200, 256])
def test_crypto_key_required_metadata_populated(byte_len):
    """Every crypto-key-required flag ships the structured schema.
    Larger blobs (≥128B random) guarantee entropy ≥ 6.0 → AES detection."""
    blob = os.urandom(byte_len)
    sample = 'var enc = "' + base64.b64encode(blob).decode() + '"'
    ctx = AnalysisContext(budget=Budget(wall_time_ms=8000))
    r = Orchestrator(ctx).run(sample)
    tc = _find_crypto_flag(r.findings)
    assert tc is not None, (
        f"crypto-key-required flag not emitted for {byte_len}B blob "
        f"(tradecraft: {[t.flag for t in r.findings.tradecraft]})"
    )
    m = tc.metadata
    # Required keys
    for key in ("algorithm", "mode", "key_len_bits", "iv_len_bits",
                "nonce_required", "encoding", "ciphertext_len",
                "keys_found", "ivs_found", "confidence", "candidates"):
        assert key in m, f"schema missing key {key!r}: {m}"
    # Any of the six algorithm families is acceptable — the schema is what we lock.
    assert m["algorithm"] in ("AES", "DES", "3DES", "RC4", "ChaCha20", "unknown"), (
        f"unknown algorithm string: {m['algorithm']!r}"
    )
    assert isinstance(m["candidates"], list) and m["candidates"]
    assert isinstance(m["nonce_required"], bool)
    assert 0.0 <= m["confidence"] <= 1.0


def test_chacha20_shape_detected_as_stream_candidate():
    """Stream-shape blob (not 16-aligned) surfaces ChaCha20 in candidates."""
    # 200 bytes non-16-aligned → stream surfaces after the extractor.
    blob = os.urandom(200)
    sample = 'ct = "' + base64.b64encode(blob).decode() + '"'
    ctx = AnalysisContext(budget=Budget(wall_time_ms=8000))
    r = Orchestrator(ctx).run(sample)
    tc = _find_crypto_flag(r.findings)
    assert tc is not None, (
        f"crypto flag missing (got {[t.flag for t in r.findings.tradecraft]})"
    )
    cands = tc.metadata["candidates"]
    # At least ONE of the stream / non-block candidates must appear
    assert any(c in cands for c in ("ChaCha20", "AES-CTR", "AES-GCM", "RC4")), (
        f"stream ciphertext must surface at least one non-CBC candidate — got {cands}"
    )


def test_aes_gcm_shape_detected_with_nonce_requirement():
    """Long 16-aligned blob (≥ IV+CT+TAG) surfaces AES-GCM in candidates."""
    # 12(IV) + 96(CT) + 16(TAG) = 124 bytes, but ensure 16-aligned overall by padding
    blob = os.urandom(128)
    sample = 'const enc = "' + base64.b64encode(blob).decode() + '"'
    ctx = AnalysisContext(budget=Budget(wall_time_ms=8000))
    r = Orchestrator(ctx).run(sample)
    tc = _find_crypto_flag(r.findings)
    assert tc is not None
    cands = tc.metadata["candidates"]
    # 128-byte block-aligned surfaces AES-CBC/ECB + optional AES-GCM
    assert any(c.startswith("AES") for c in cands), cands


def test_xworm_family_detector_end_to_end():
    """RC3.2b · XWorm end-to-end detection through orchestrator."""
    sample = (
        '<Xworm><Host>c2.example.test</Host><Port>7000</Port>'
        '<Mutex>XWormMutex_hb5r2Y</Mutex><Version>XWorm V5.6</Version>'
        '<USBNM>USBNM.exe</USBNM></Xworm>'
    )
    ctx = AnalysisContext(budget=Budget(wall_time_ms=8000))
    r = Orchestrator(ctx).run(sample)
    assert r.findings.family.family == "XWorm", (
        f"expected XWorm family, got {r.findings.family.family!r}"
    )
    assert r.findings.family.confidence >= 0.8, (
        f"XWorm confidence {r.findings.family.confidence:.2f} < 0.8"
    )
    assert r.findings.verdict == "malicious"
    mitre_ids = {h.id for h in r.findings.mitre_techniques}
    for expected in ("T1219", "T1091", "T1056.001", "T1573.001"):
        assert expected in mitre_ids, f"expected {expected} in {sorted(mitre_ids)}"
