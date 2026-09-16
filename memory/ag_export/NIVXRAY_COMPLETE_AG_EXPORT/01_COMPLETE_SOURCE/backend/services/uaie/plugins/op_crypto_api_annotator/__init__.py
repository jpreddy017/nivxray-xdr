"""Plugin · Crypto API Annotator (op adapter · Priority 5).

Wraps the ``crypto-api-annotator`` @op transformer that scans for
cryptographic API signatures (AES, RC4, ChaCha20, RijndaelManaged,
DES/3DES, DPAPI, OpenSSL, GPG, MachineGuid-derived, C2-fetched keys).

Semantic: annotator — emits evidence only, does NOT produce a child
artifact (setting ``child_artifact_type=None`` in the adapter prevents
downstream loop pollution).
"""
import re
from ...transformer_op_adapter import adapt_op_and_register

adapt_op_and_register(
    op_id="crypto-api-annotator",
    markers=(
        re.compile(
            r"""\b(?:AES|RC4|ChaCha20|Rijndael(?:Managed)?|"""
            r"""3?DES|DPAPI|CryptProtectData|CryptUnprotectData|"""
            r"""OpenSSL|MachineGuid)\b""",
            re.IGNORECASE),
    ),
    artifact_types=[
        "text", "powershell", "powershell_normalized",
        "base64_decoded", "gzip_decoded", "zlib_decoded", "crypto_decoded",
        "unknown",
    ],
    child_artifact_type=None,      # annotator only — no child artefact
    profiles=["crypto", "malware", "enterprise", "universal"],
    min_len=8,
)
