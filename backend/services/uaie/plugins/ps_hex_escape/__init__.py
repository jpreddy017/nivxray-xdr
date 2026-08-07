"""Plugin · PowerShell Hex-Escape Decoder · via ADAPTER (Priority 2)."""
from ...capability_adapter import adapt_and_register
from decoders.ps_hex_escape import PsHexEscapeDecoder

adapt_and_register(
    legacy=PsHexEscapeDecoder,
    semantic="decoder",
    child_artifact_type="powershell_normalized",
    artifact_types=["text", "powershell"],
    profiles=["powershell", "malware", "enterprise", "universal"],
    name_override="powershell.hex_escape",
)
