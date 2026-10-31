"""Plugin · PowerShell Normalize (op adapter · Priority 3).

Wraps the ``powershell-normalize`` @op transformer that canonicalises
casing / parameter names / exe path / quoted payloads and simulates
safe built-ins (Write-Host, Echo, etc.).  Never emulates
Invoke-Expression, external binaries, or side effects.
"""
import re
from ...transformer_op_adapter import adapt_op_and_register

adapt_op_and_register(
    op_id="powershell-normalize",
    markers=(
        re.compile(r"""\b(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\b""",
                    re.IGNORECASE),
        re.compile(r"""\s-(?:NoProfile|NonInteractive|NoLogo|NoExit|ExecutionPolicy|Command|EncodedCommand|Enc|WindowStyle|File|Version|Sta|Mta)\b""",
                    re.IGNORECASE),
    ),
    artifact_types=["text", "powershell"],
    child_artifact_type="powershell_normalized",
    profiles=["powershell", "malware", "enterprise", "universal"],
    min_len=8,
)
