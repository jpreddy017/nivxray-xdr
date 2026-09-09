"""NjRAT (Bladabindi) · deterministic family plugin (RC3.4 · Feb-2026).

NjRAT is a Delphi/.NET remote-access tool that has dominated the
Middle-East / North-Africa threat landscape since 2013 and remains one
of the most-observed commodity RATs in 2024-2025. It's the RAT-of-choice
for regional cybercrime crews and lives in APT reports as "Bladabindi".

Fingerprints (post-extract, cleartext):
    * Class markers                 njrat, njRat, ll (config splitter)
    * Splitter char                 "\\x11n\\x00j\\x00R\\x00a\\x00t"
    * Persistence path              Software\\Microsoft\\Windows\\CurrentVersion\\Run
    * Wire commands                 nd, kl, get, rn, up, pl, un
    * Version banner                njrat0.7d / 0.7.NC / v0.7.3
    * Base64 config prefix          "|'|'|"
    * Mutex string                  "..." (Delphi-generated GUIDs)
    * Registry runkey name          "SystemDrive" or "TrayNotify"
"""
from __future__ import annotations

from engine.models import MitreHint
from engine.registry import DecoderRegistry

from ._base import FamilyPlugin, Signature


class NjRatFamily(FamilyPlugin):
    id = "family-njrat"
    name = "njRAT"
    family_name = "njRAT"
    aka = ("Bladabindi", "njrat", "njRat")

    signatures = (
        Signature(r"\bnjRat\b|\bnj[Rr]at\b|Bladabindi", 0.65, "regex",
                  "njRAT / Bladabindi branding"),
        Signature(r"njrat\s*0\.7\w?|njrat\s*v\s*0\.\d+", 0.55, "regex",
                  "njRAT version banner (0.7 family)"),
        Signature(r"\|'\|'\|", 0.60, "regex",
                  "njRAT config-splitter literal '|\\'|\\'|'"),
        # These wire opcodes come out of the C2 dispatcher table
        Signature(r"^(nd|kl|get|rn|up|pl|un|inv|rs)\|", 0.35, "regex",
                  "njRAT wire opcode dispatcher tokens"),
        Signature(r"CurrentVersion\\Run.{0,50}(SystemDrive|TrayNotify)",
                  0.20, "regex",
                  "njRAT registry Run-key persistence naming"),
        Signature(r"netsh\s+firewall\s+add\s+allowedprogram", 0.20, "regex",
                  "njRAT netsh firewall self-allowlist"),
        Signature(r"vbs_startup\.vbs|njrat\.vbs", 0.20, "regex",
                  "njRAT VBS staging file"),
        Signature(r"Base64String|Environment\.NewLine.*Convert\.FromBase64",
                  0.10, "regex", ".NET base64 config decode helpers (weak)"),
    )
    calibration = 1.25

    mitre = (
        MitreHint(id="T1219", technique="Remote Access Software",
                  tactic="Command and Control",
                  evidence="njRAT / Bladabindi commodity RAT",
                  source="family"),
        MitreHint(id="T1547.001",
                  technique="Registry Run Keys / Startup Folder",
                  tactic="Persistence",
                  evidence="njRAT SystemDrive / TrayNotify Run-key persistence",
                  source="family"),
        MitreHint(id="T1562.004",
                  technique="Impair Defenses: Disable or Modify System Firewall",
                  tactic="Defense Evasion",
                  evidence="njRAT netsh firewall add allowedprogram",
                  source="family"),
        MitreHint(id="T1059.005", technique="Visual Basic",
                  tactic="Execution",
                  evidence="njRAT VBS staging file / launcher",
                  source="family"),
        MitreHint(id="T1056.001", technique="Input Capture: Keylogging",
                  tactic="Collection",
                  evidence="njRAT kl (keylog) wire command",
                  source="family"),
        MitreHint(id="T1113", technique="Screen Capture",
                  tactic="Collection",
                  evidence="njRAT get (screen-capture) wire command",
                  source="family"),
        MitreHint(id="T1105", technique="Ingress Tool Transfer",
                  tactic="Command and Control",
                  evidence="njRAT up (upload) / pl (plugin) wire commands",
                  source="family"),
    )
    yara_seed_name = "MAL_NjRAT_Bladabindi"
    atomic_red = "T1219"


DecoderRegistry.register(NjRatFamily())
