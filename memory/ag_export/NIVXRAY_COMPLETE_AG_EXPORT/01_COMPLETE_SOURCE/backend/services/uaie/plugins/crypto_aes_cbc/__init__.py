"""Plugin · AES-CBC Symmetric Decoder · via ADAPTER (Priority 5).

Wraps the existing production ``AesCbcDecoder`` from
``decoders.crypto_symmetric`` — AES key/IV/ciphertext triple recovery,
PKCS7 unpad, printable-ratio validation.

Semantic: decoder → emits ``crypto_decoded`` child artefact.
"""
from ...capability_adapter import adapt_and_register
from decoders.crypto_symmetric import AesCbcDecoder

adapt_and_register(
    legacy=AesCbcDecoder,
    semantic="decoder",
    child_artifact_type="crypto_decoded",
    artifact_types=[
        "text", "powershell", "powershell_normalized",
        "base64_decoded", "gzip_decoded", "zlib_decoded",
        "unknown",
    ],
    profiles=["crypto", "malware", "loader", "enterprise", "universal"],
    name_override="crypto.aes_cbc",
)
