"""Plugin · PowerShell hex-CSV inline (op adapter · Priority 3).

Wraps the ``powershell-hex-csv-inline`` @op transformer:
    $h='43,61,6c,63,2e,65,78,65'; $c = $h -split ',' | ForEach-Object
        {[char][int]('0x'+$_)}; Invoke-Expression ($c -join '')
→ decodes to `calc.exe`.
"""
import re
from ...transformer_op_adapter import adapt_op_and_register

adapt_op_and_register(
    op_id="powershell-hex-csv-inline",
    markers=(
        re.compile(r"""\$\w+\s*=\s*['"](?:[0-9a-fA-F]{1,2}\s*,\s*){4,}""",
                    re.IGNORECASE),
        re.compile(r"""ForEach-Object\s*\{\s*\[char\]\[int\]""",
                    re.IGNORECASE),
    ),
    artifact_types=["text", "powershell"],
    child_artifact_type="powershell_normalized",
    profiles=["powershell", "malware", "enterprise", "universal"],
    min_len=16,
)
