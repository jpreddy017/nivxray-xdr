"""Plugin · PowerShell Alias Normalizer · via ADAPTER (Priority 2)."""
from ...capability_adapter import adapt_and_register
from decoders.ps_alias_normalizer import PSAliasNormalizerDecoder

adapt_and_register(
    legacy=PSAliasNormalizerDecoder,
    semantic="decoder",
    child_artifact_type="powershell_normalized",
    artifact_types=["text", "powershell", "powershell_normalized"],
    profiles=["powershell", "malware", "enterprise", "universal"],
    name_override="powershell.alias_normalizer",
)
