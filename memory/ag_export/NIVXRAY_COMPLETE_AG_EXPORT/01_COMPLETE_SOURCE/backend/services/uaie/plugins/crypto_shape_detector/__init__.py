"""Plugin · Ciphertext Shape Detector · via ADAPTER (Priority 5).

Wraps the existing production ``CryptoDetectDecoder`` from
``decoders.crypto_symmetric`` — structural detector that flags encrypted
blobs (AES/RC4/ChaCha20/DES) and emits ``crypto-key-required`` tradecraft
+ MITRE T1027.013 when no inline key is found.

Semantic: analyzer (signal-only) — no data transform, no child artefact.
"""
from ...capability_adapter import adapt_and_register
from decoders.crypto_symmetric import CryptoDetectDecoder

adapt_and_register(
    legacy=CryptoDetectDecoder,
    semantic="analyzer",
    child_artifact_type=None,  # signal-only — never emits child artefact
    artifact_types=[
        "text", "powershell", "powershell_normalized",
        "base64_decoded", "gzip_decoded", "zlib_decoded", "xor_decoded",
        "unknown",
    ],
    profiles=["crypto", "malware", "enterprise", "universal"],
    name_override="crypto.shape_detector",
    # CryptoDetectDecoder is signal-only and returns conf 0.30 by design
    # (documented: "fire at LOW confidence because we don't actually
    # decode anything").  Override the adapter's default 0.4 gate.
    min_detect_confidence=0.25,
)
