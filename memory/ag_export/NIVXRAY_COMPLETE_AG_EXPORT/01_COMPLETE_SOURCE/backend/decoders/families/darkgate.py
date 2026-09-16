"""DarkGate — deterministic family plugin (RC2.1a)."""
from __future__ import annotations

from engine.models import MitreHint
from engine.registry import DecoderRegistry

from ._base import FamilyPlugin, Signature


class DarkGateFamily(FamilyPlugin):
    id = "family-darkgate"
    name = "DarkGate Loader"
    family_name = "DarkGate"
    aka = ("DarkGate Loader", "MehCrypter")

    signatures = (
        # DarkGate signature markers in decoded AutoIt / MSI stagers
        Signature(r"%STAT%", 0.60, "string", "DarkGate %STAT% variable marker"),
        Signature(r"%B64%", 0.45, "string", "DarkGate %B64% variable marker"),
        Signature(r"DGSNM", 0.55, "string", "DGSNM DarkGate module tag"),
        # AutoIt-compiled dropper indicators (DarkGate loves AutoIt)
        Signature(r"AutoIt[3]?ExecuteLine|AutoIt3\.exe", 0.30, "regex",
                  "AutoIt runtime marker"),
        # DarkGate mutex + config-block patterns
        Signature(r"NIM\d{2,}", 0.35, "regex", "DarkGate 'NIM##' mutex pattern"),
        Signature(r"Piece_[0-9]+", 0.30, "regex",
                  "DarkGate config-block piece marker"),
        # C2 URL scheme observed in campaigns
        Signature(r"/(cdn|adload|ledger)/(index|main)\.php", 0.25, "regex",
                  "DarkGate common C2 CGI"),
        # DarkGate obfuscated key strings
        Signature(r"cQHNb", 0.20, "string", "DarkGate custom obfuscation prefix"),
    )
    calibration = 0.90

    mitre = (
        MitreHint(id="T1204.002", technique="User Execution: Malicious File",
                  tactic="Execution",
                  evidence="DarkGate dropped via malicious PDF/MSI/HTA",
                  source="family"),
        MitreHint(id="T1055", technique="Process Injection",
                  tactic="Defense Evasion",
                  evidence="DarkGate hollow-injects into MicrosoftEdge/OneDrive",
                  source="family"),
        MitreHint(id="T1547.001", technique="Registry Run Keys / Startup Folder",
                  tactic="Persistence",
                  evidence="DarkGate Run key persistence",
                  source="family"),
        MitreHint(id="T1140", technique="Deobfuscate/Decode Files or Information",
                  tactic="Defense Evasion",
                  evidence="DarkGate custom base64 alphabet + XOR",
                  source="family"),
    )
    yara_seed_name = "MAL_DarkGate_Loader"
    atomic_red = "T1204.002"


DecoderRegistry.register(DarkGateFamily())
