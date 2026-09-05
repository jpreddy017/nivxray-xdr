"""QuasarRAT — deterministic family plugin (RC2.1a)."""
from __future__ import annotations

from engine.models import MitreHint
from engine.registry import DecoderRegistry

from ._base import FamilyPlugin, Signature


class QuasarRatFamily(FamilyPlugin):
    id = "family-quasarrat"
    name = "QuasarRAT"
    family_name = "QuasarRAT"
    aka = ("Quasar", "Quasar RAT", "xRAT")

    signatures = (
        # .NET class + namespace + protobuf types
        Signature(r"Quasar\.Common", 0.55, "string",
                  "Quasar.Common namespace"),
        Signature(r"Quasar\.Client", 0.55, "string",
                  "Quasar.Client namespace"),
        Signature(r"QuasarRAT|Quasar[- ]?Rat", 0.45, "regex", "Quasar product string"),
        # Config properties
        Signature(r"SETTINGS[\x00-\xff]{4,32}(HOSTS|VERSION|SUBDIRECTORY)", 0.45,
                  "regex", "Quasar decoded-config header"),
        # AES key derivation constant (Rfc2898/PBKDF2 salt used by Quasar)
        Signature(r"BSF3lLtvGT3\+dSagRhTG", 0.60, "string",
                  "Quasar default AES-key salt fragment"),
        # Certificate CN pattern
        Signature(r"CN=Quasar Server CA|Quasar Server CA", 0.55, "regex",
                  "Quasar built-in TLS server-CA CN"),
        # File-system tokens
        Signature(r"SubDirectory=|InstallSub=|InstallName=", 0.30, "regex",
                  "Quasar install-config keys"),
        # Message-type enum names (protobuf)
        Signature(r"GetProcesses|GetSystemInfo|DoDownloadFile|DoUploadFile", 0.25,
                  "regex", "Quasar command-message types"),
    )
    calibration = 0.90

    mitre = (
        MitreHint(id="T1219", technique="Remote Access Software",
                  tactic="Command and Control",
                  evidence="Quasar is an open-source RAT",
                  source="family"),
        MitreHint(id="T1573.002", technique="Encrypted Channel: Asymmetric Cryptography",
                  tactic="Command and Control",
                  evidence="Quasar TLS-pinned C2",
                  source="family"),
        MitreHint(id="T1547.001", technique="Registry Run Keys / Startup Folder",
                  tactic="Persistence",
                  evidence="Quasar autorun persistence",
                  source="family"),
        MitreHint(id="T1113", technique="Screen Capture",
                  tactic="Collection",
                  evidence="Quasar remote desktop module",
                  source="family"),
    )
    yara_seed_name = "MAL_QuasarRAT_Client"
    atomic_red = "T1219"


DecoderRegistry.register(QuasarRatFamily())
