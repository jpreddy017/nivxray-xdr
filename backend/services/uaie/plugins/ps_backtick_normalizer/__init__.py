"""Plugin · PowerShell Backtick Normalizer · via ADAPTER (Priority 2)."""
from ...capability_adapter import adapt_and_register
from decoders.ps_backtick_normalizer import PSBacktickNormalizerDecoder

adapt_and_register(
    legacy=PSBacktickNormalizerDecoder,
    semantic="decoder",
    child_artifact_type="powershell_normalized",
    artifact_types=["text", "powershell"],
    profiles=["powershell", "malware", "enterprise", "universal"],
    name_override="powershell.backtick_normalizer",
)
