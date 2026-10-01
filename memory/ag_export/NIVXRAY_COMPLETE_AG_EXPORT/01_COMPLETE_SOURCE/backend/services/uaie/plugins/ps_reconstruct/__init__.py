"""Plugin · PowerShell Reconstruct · via ADAPTER (Priority 2).

Wraps the existing production ``PowerShellReconstructDecoder`` which
handles concatenation / string-split / -replace / -join / char-array
rebuilding — a critical transformer for real-world PowerShell loaders.
"""
from ...capability_adapter import adapt_and_register
from decoders.ps_reconstruct import PowerShellReconstructDecoder

adapt_and_register(
    legacy=PowerShellReconstructDecoder,
    semantic="decoder",
    child_artifact_type="powershell_normalized",
    artifact_types=["text", "powershell"],
    profiles=["powershell", "malware", "enterprise", "universal"],
    name_override="powershell.reconstruct",
)
