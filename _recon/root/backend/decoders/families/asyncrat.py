"""AsyncRAT — deterministic family plugin (RC2.1a)."""
from __future__ import annotations

from engine.models import MitreHint
from engine.registry import DecoderRegistry

from ._base import FamilyPlugin, Signature


class AsyncRatFamily(FamilyPlugin):
    id = "family-asyncrat"
    name = "AsyncRAT"
    family_name = "AsyncRAT"
    aka = ("AsyncRAT.NET", "AsyncClient")

    signatures = (
        # Distinctive .NET config strings from AsyncRAT client
        Signature(r"AsyncClient\.Settings", 0.55, "string",
                  "AsyncClient.Settings config namespace"),
        Signature(r"AsyncClient", 0.30, "string", "AsyncClient class"),
        Signature(r"<AsyncRAT", 0.55, "string", "AsyncRAT XML config marker"),
        Signature(r"AsyncMutex_[a-zA-Z0-9_]{6,}", 0.60, "regex",
                  "AsyncMutex_* singleton mutex pattern"),
        Signature(r"Aes256", 0.15, "string", "Aes256 crypto reference"),
        Signature(r"Anti_Analysis|SendPassword|InstallStartup", 0.35, "regex",
                  "AsyncRAT feature-flag names"),
        Signature(r"Base_Settings|Ports_Settings|Version_Settings", 0.35,
                  "regex", "AsyncRAT config keys"),
        # Server-side handshake tag
        Signature(r"CLIENTINFO|Msg_[a-zA-Z]{3,10}", 0.25, "regex",
                  "AsyncRAT wire protocol tags"),
        # Common obfuscator prefix
        Signature(r"Reactor\.NET|Confuser\.NET", 0.15, "regex",
                  ".NET obfuscator markers common with AsyncRAT"),
    )
    calibration = 0.85

    mitre = (
        MitreHint(id="T1219", technique="Remote Access Software",
                  tactic="Command and Control",
                  evidence="AsyncRAT is a commodity remote-access tool",
                  source="family"),
        MitreHint(id="T1055", technique="Process Injection",
                  tactic="Defense Evasion",
                  evidence="AsyncRAT hollowing/reflection loader",
                  source="family"),
        MitreHint(id="T1547.001", technique="Registry Run Keys / Startup Folder",
                  tactic="Persistence",
                  evidence="AsyncRAT InstallStartup persistence",
                  source="family"),
        MitreHint(id="T1573.001", technique="Encrypted Channel: Symmetric Cryptography",
                  tactic="Command and Control",
                  evidence="AsyncRAT AES-256 C2 encryption",
                  source="family"),
    )
    yara_seed_name = "MAL_AsyncRAT_Client"
    atomic_red = "T1219"


DecoderRegistry.register(AsyncRatFamily())
