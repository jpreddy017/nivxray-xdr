"""Snake Keylogger — deterministic family plugin (RC2.1a)."""
from __future__ import annotations

from engine.models import MitreHint
from engine.registry import DecoderRegistry

from ._base import FamilyPlugin, Signature


class SnakeKeyloggerFamily(FamilyPlugin):
    id = "family-snake-keylogger"
    name = "Snake Keylogger"
    family_name = "Snake Keylogger"
    aka = ("Snake", "404 Keylogger", "Snake KL")

    signatures = (
        # Product / brand strings
        Signature(r"Snake[-_ ]?Keylogger", 0.55, "regex",
                  "Snake-Keylogger product string"),
        Signature(r"404[-_ ]?keylogger", 0.55, "regex",
                  "404 Keylogger (alt brand)"),
        # SMTP-exfil templates (Snake reuses AgentTesla's format but adds its own)
        Signature(r"Snake\s+Passwords|Snake\s+Keystrokes", 0.55, "regex",
                  "Snake report headers"),
        Signature(r"SMTPServer=|SMTPPort=|SMTPPass=", 0.35, "regex",
                  "SMTP-exfil config template"),
        # Class/namespace fingerprints in decoded .NET stager
        Signature(r"Snake\.(Client|Common|Config)", 0.55, "regex",
                  "Snake.* .NET namespace"),
        # Credential-scrape helper prefixes
        Signature(r"PW-[A-Za-z]+|KEYLOG-[A-Za-z]+", 0.30, "regex",
                  "PW-/KEYLOG- exfil field prefixes"),
        # Screenshot / clipboard flags
        Signature(r"IsScreenshot|IsClipboard|IsKeylog", 0.30, "regex",
                  "Snake feature flags"),
        # Panel path
        Signature(r"/Snake/Panel/", 0.35, "regex", "Snake operator-panel path"),
        # Telegram exfil bot token URL pattern (Snake supports Telegram exfil)
        Signature(r"api\.telegram\.org/bot[0-9]{6,}:[a-zA-Z0-9_-]{30,}", 0.35,
                  "regex", "Telegram bot exfil URL"),
    )
    calibration = 0.90

    mitre = (
        MitreHint(id="T1056.001", technique="Keylogging",
                  tactic="Collection",
                  evidence="Snake is a keylogger + credential stealer",
                  source="family"),
        MitreHint(id="T1555.003", technique="Credentials from Web Browsers",
                  tactic="Credential Access",
                  evidence="Snake scrapes browser saved passwords",
                  source="family"),
        MitreHint(id="T1114.001", technique="Local Email Collection",
                  tactic="Collection",
                  evidence="Snake parses Outlook credentials",
                  source="family"),
        MitreHint(id="T1048.003",
                  technique="Exfiltration Over Unencrypted Protocol",
                  tactic="Exfiltration",
                  evidence="Snake exfils via SMTP / Telegram / FTP",
                  source="family"),
        MitreHint(id="T1113", technique="Screen Capture",
                  tactic="Collection",
                  evidence="Snake screenshot module",
                  source="family"),
    )
    yara_seed_name = "MAL_Snake_Keylogger"
    atomic_red = "T1056.001"


DecoderRegistry.register(SnakeKeyloggerFamily())
