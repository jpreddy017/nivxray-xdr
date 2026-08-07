"""Plugin · PowerShell XOR inline-key (op adapter · Priority 3).

Wraps the ``powershell-xor-inline-key`` @op transformer that recovers
``[byte[]](N,N,…); -bxor <key>`` XOR loops with hardcoded ASCII keys.
"""
import re
from ...transformer_op_adapter import adapt_op_and_register

adapt_op_and_register(
    op_id="powershell-xor-inline-key",
    markers=(
        re.compile(r"""\[byte\[\]\]\s*\(\s*(?:\d{1,3}\s*,\s*){2,}\d""",
                    re.IGNORECASE),
        re.compile(r"""-bxor\b""", re.IGNORECASE),
    ),
    artifact_types=["text", "powershell", "powershell_normalized"],
    child_artifact_type="powershell_normalized",
    profiles=["powershell", "malware", "enterprise", "universal"],
    min_len=16,
)
