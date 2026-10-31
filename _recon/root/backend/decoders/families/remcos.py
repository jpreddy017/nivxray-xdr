"""Remcos RAT — deterministic family plugin (RC2.1a)."""
from __future__ import annotations

from engine.models import MitreHint
from engine.registry import DecoderRegistry

from ._base import FamilyPlugin, Signature


class RemcosFamily(FamilyPlugin):
    id = "family-remcos"
    name = "Remcos RAT"
    family_name = "Remcos RAT"
    aka = ("Remcos", "Remcos Pro", "BreakingSecurity Remcos")

    signatures = (
        Signature(r"Remcos[-_ ]?RAT", 0.55, "regex", "Remcos-RAT product string"),
        Signature(r"Remcos", 0.20, "string", "Remcos brand marker"),
        # Well-known mutex prefix
        Signature(r"Remcos_MUTEX_[A-Z0-9]{6,}", 0.60, "regex",
                  "Remcos_MUTEX_* singleton mutex"),
        # RC4 config-block signature (Remcos wraps config in RC4)
        Signature(r"\x1c[\x00-\xff]{2,4}SETTINGS", 0.45, "regex",
                  "Remcos RC4 config-block SETTINGS section"),
        Signature(r"BreakingSecurity", 0.30, "string",
                  "BreakingSecurity vendor string"),
        # Config keys observed in decoded settings blocks
        Signature(r"KEYL(_STATE|_LOG)?\||CAMS\||SCRN\|", 0.30, "regex",
                  "Remcos module toggle keys"),
        # Screenshot & keylog handler tags
        Signature(r"OFFLINEKEYLOG|Screenshot=1", 0.30, "regex",
                  "Remcos data-collection flags"),
        # Panel path
        Signature(r"/panel/login\.php\?url=", 0.20, "regex",
                  "Remcos operator-panel path"),
    )
    calibration = 0.90

    mitre = (
        MitreHint(id="T1219", technique="Remote Access Software",
                  tactic="Command and Control",
                  evidence="Remcos is a commercial RAT",
                  source="family"),
        MitreHint(id="T1056.001", technique="Keylogging",
                  tactic="Collection",
                  evidence="Remcos ships with a keylogger module",
                  source="family"),
        MitreHint(id="T1113", technique="Screen Capture",
                  tactic="Collection",
                  evidence="Remcos screen-capture module",
                  source="family"),
        MitreHint(id="T1547.001", technique="Registry Run Keys / Startup Folder",
                  tactic="Persistence",
                  evidence="Remcos autorun persistence",
                  source="family"),
    )
    yara_seed_name = "MAL_Remcos_RAT_Config"
    atomic_red = "T1219"


DecoderRegistry.register(RemcosFamily())
