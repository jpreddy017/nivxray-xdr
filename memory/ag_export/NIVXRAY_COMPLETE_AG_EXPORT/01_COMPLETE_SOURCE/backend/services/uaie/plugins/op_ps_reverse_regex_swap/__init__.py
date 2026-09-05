"""Plugin · PowerShell reverse+regex swap (op adapter · Priority 3).

Wraps the ``powershell-reverse-regex-swap`` @op transformer that
peels ``'calc.exe' -replace '(\\w+)\\.(\\w+)','$2.$1'`` → `exe.calc`.
"""
import re
from ...transformer_op_adapter import adapt_op_and_register

adapt_op_and_register(
    op_id="powershell-reverse-regex-swap",
    markers=(
        re.compile(r"""-replace\s*['"]\([^)]+\)\\\.\([^)]+\)['"]\s*,\s*['"]\$2\.\$1['"]""",
                    re.IGNORECASE),
    ),
    artifact_types=["text", "powershell"],
    child_artifact_type="powershell_normalized",
    profiles=["powershell", "malware", "universal"],
    min_len=8,
)
