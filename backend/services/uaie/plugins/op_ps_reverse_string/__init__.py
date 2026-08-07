"""Plugin · PowerShell reverse-string (op adapter · Priority 3).

Wraps the ``powershell-reverse-string`` @op transformer that peels
``$s='exe.clac'; $s[-1..-8] -join ''`` → `calc.exe`.
"""
import re
from ...transformer_op_adapter import adapt_op_and_register

adapt_op_and_register(
    op_id="powershell-reverse-string",
    markers=(
        re.compile(r"""\$\w+\s*=\s*['"][^'"\r\n]{2,256}['"]""",
                    re.IGNORECASE),
        re.compile(r"""\$\w+\s*\[\s*-1\s*\.\.\s*-""", re.IGNORECASE),
    ),
    artifact_types=["text", "powershell", "powershell_normalized"],
    child_artifact_type="powershell_normalized",
    profiles=["powershell", "malware", "universal"],
    min_len=8,
)
