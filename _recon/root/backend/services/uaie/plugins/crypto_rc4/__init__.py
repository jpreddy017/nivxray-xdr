"""Plugin · RC4 Symmetric Decoder · via ADAPTER (Priority 5).

Wraps the existing production ``Rc4Decoder`` (~100 LOC) from
``decoders.crypto_symmetric`` — inline RC4 key extraction plus
Bang-for-buck brute force with printable-ratio validation.

Semantic: decoder → emits ``crypto_decoded`` child artefact.
"""
from ...capability_adapter import adapt_and_register
from decoders.crypto_symmetric import Rc4Decoder

adapt_and_register(
    legacy=Rc4Decoder,
    semantic="decoder",
    child_artifact_type="crypto_decoded",
    artifact_types=[
        "text", "powershell", "powershell_normalized",
        "base64_decoded", "gzip_decoded", "zlib_decoded", "xor_decoded",
        "unknown",
    ],
    profiles=["crypto", "malware", "loader", "enterprise", "universal"],
    name_override="crypto.rc4",
)
