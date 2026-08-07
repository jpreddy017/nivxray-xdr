"""Plugin · PowerShell -EncodedCommand Multi-Layer (op adapter · Priority 3).

Wraps the ``ps-encodedcommand-multilayer`` @op transformer that peels
``powershell.exe -e <base64>`` payloads across multiple obfuscation
layers.  Function-only legacy — bridged via ``transformer_op_adapter``.
"""
import re
from ...transformer_op_adapter import adapt_op_and_register

adapt_op_and_register(
    op_id="ps-encodedcommand-multilayer",
    markers=(
        re.compile(r"powershell(?:\.exe)?\s+[-/](?:e|ec|encodedcommand)\b",
                    re.IGNORECASE),
        re.compile(r"[A-Za-z0-9+/=]{40,}"),
    ),
    artifact_types=["text", "powershell", "powershell_normalized"],
    child_artifact_type="powershell_normalized",
    profiles=["powershell", "malware", "enterprise", "universal"],
    min_len=32,
)
