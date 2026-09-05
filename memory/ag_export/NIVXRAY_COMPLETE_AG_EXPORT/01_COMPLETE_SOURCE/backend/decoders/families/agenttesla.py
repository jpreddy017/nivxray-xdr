"""AgentTesla — deterministic family plugin (RC2.1a)."""
from __future__ import annotations

from engine.models import MitreHint
from engine.registry import DecoderRegistry

from ._base import FamilyPlugin, Signature


class AgentTeslaFamily(FamilyPlugin):
    id = "family-agenttesla"
    name = "AgentTesla"
    family_name = "AgentTesla"
    aka = ("AgentTesla Stealer", "Origin Logger",
           "Agent Tesla Keylogger", "AGENT_TESLA")

    signatures = (
        # .NET class + namespace fingerprints
        Signature(r"AgentTesla|Agent[_ ]?Tesla", 0.55, "regex",
                  "AgentTesla product string"),
        Signature(r"OriginLogger", 0.55, "string",
                  "OriginLogger rebrand"),
        # SMTP-exfil templates unique to AgentTesla
        Signature(r"SMTPServer\s*=|SMTPPort\s*=|SMTPUsername\s*=", 0.35, "regex",
                  "SMTP-exfil config template"),
        Signature(r"Screen\s+Resolution:|Time:|User\s+Name:|Computer\s+Name:", 0.25,
                  "regex", "AgentTesla report-body template lines"),
        # Keylog line format markers
        Signature(r"\[<[A-Z_]+>\]", 0.30, "regex",
                  "Keylog special-key markers [<CTRL>], [<ALT>]"),
        Signature(r"pw_string_", 0.35, "string",
                  "AgentTesla credential field prefix"),
        # Feature flags in decoded config
        Signature(r"IsScreenshotEnabled|IsKeylogEnabled|IsClipperEnabled", 0.35,
                  "regex", "AgentTesla feature-flag config keys"),
        # Panel path (Origin Logger)
        Signature(r"/Panel/(login|process)\.php", 0.20, "regex",
                  "AgentTesla operator panel path"),
        # Common obfuscator + packer traits (ConfuserEx heavily used)
        Signature(r"koi\.[a-zA-Z]{2,20}", 0.15, "regex",
                  "ConfuserEx-style obfuscated names"),
    )
    calibration = 0.85

    mitre = (
        MitreHint(id="T1056.001", technique="Keylogging",
                  tactic="Collection",
                  evidence="AgentTesla is a full-featured keylogger",
                  source="family"),
        MitreHint(id="T1555.003", technique="Credentials from Web Browsers",
                  tactic="Credential Access",
                  evidence="AgentTesla scrapes browser saved passwords",
                  source="family"),
        MitreHint(id="T1114.001", technique="Local Email Collection",
                  tactic="Collection",
                  evidence="AgentTesla parses Outlook profile",
                  source="family"),
        MitreHint(id="T1048.003", technique="Exfiltration Over Unencrypted Protocol",
                  tactic="Exfiltration",
                  evidence="SMTP / FTP / Telegram exfil",
                  source="family"),
        MitreHint(id="T1113", technique="Screen Capture",
                  tactic="Collection",
                  evidence="AgentTesla screenshot module",
                  source="family"),
    )
    yara_seed_name = "MAL_AgentTesla_Stealer"
    atomic_red = "T1056.001"


DecoderRegistry.register(AgentTeslaFamily())
