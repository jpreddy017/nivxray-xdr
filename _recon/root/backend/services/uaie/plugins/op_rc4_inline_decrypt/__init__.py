"""Plugin · RC4 inline-decrypt (op adapter · Priority 5).

Wraps the ``rc4-inline-decrypt`` @op transformer that deterministically
decrypts a PowerShell RC4 loader when both the ASCII key literal and
the base64 ciphertext are inline.  Runs standard KSA+PRGA in Python
without executing PowerShell.
"""
import re
from ...transformer_op_adapter import adapt_op_and_register

adapt_op_and_register(
    op_id="rc4-inline-decrypt",
    markers=(
        re.compile(r"0\s*\.\.\s*255"),
        re.compile(r"-bxor", re.IGNORECASE),
        re.compile(r"""\[Convert\]::FromBase64String""", re.IGNORECASE),
    ),
    artifact_types=[
        "text", "powershell", "powershell_normalized",
        "base64_decoded", "gzip_decoded", "zlib_decoded",
    ],
    child_artifact_type="crypto_decoded",
    profiles=["crypto", "powershell", "malware", "loader", "universal"],
    min_len=64,
)
