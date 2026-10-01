"""Plugin · PowerShell semantic mini-evaluator (op adapter · Priority 3).

Wraps the ``powershell-semantic-mini`` @op transformer that
deterministically evaluates the Empire/Nishang chain:
    (literal) -replace regex_swap | ForEach-Object
        { $_[-1..-N] -join '' }
"""
import re
from ...transformer_op_adapter import adapt_op_and_register

adapt_op_and_register(
    op_id="powershell-semantic-mini",
    markers=(
        re.compile(r"""-replace\s*['"]\([^)]+\)\\\.\([^)]+\)['"]""",
                    re.IGNORECASE),
        re.compile(r"""ForEach-Object\s*\{\s*\$_\[\s*-1\s*\.\.\s*-\d+""",
                    re.IGNORECASE),
    ),
    artifact_types=["text", "powershell"],
    child_artifact_type="powershell_normalized",
    profiles=["powershell", "malware", "universal"],
    min_len=8,
)
