"""Emotet · deterministic family plugin (RC3.4 · Feb-2026).

Emotet is the archetypal modular banking-trojan-turned-loader. Originally
Feodo/Heodo (2014), it evolved into a MaaS botnet that dropped IcedID,
QakBot, Trickbot, and ransomware for ~5 years. Taken down by Operation
LadyBird (Jan 2021), it returned Nov 2021 and remained active through
2024-2025 waves (SOC.OS / RedCanary / SANS ISC threat feeds).

Deterministic fingerprints (post-extract):
    * PowerShell chain marker       Get-Content|IEX|Add-MpPreference
    * Doc-macro naming              document_open|Auto_Open|Workbook_Open
    * XL4 formula pattern           =SET.NAME("...",...)
    * URL retry list                Chunks of 5+ candidate URLs
                                    separated by @ / | delimiters
    * Payload dropper name          y1.exe|y2.exe|A0.exe|POM.exe
    * COM object abuse              CreateObject("MSXML2.XMLHTTP")
                                    CreateObject("ADODB.Stream")
    * Config decrypt                RC4Init/RC4Crypt classic loops
    * Registry persistence          HKCU\Software\Microsoft\Windows\CurrentVersion\Run
                                    with random dword-name value
"""
from __future__ import annotations

from engine.models import MitreHint
from engine.registry import DecoderRegistry

from ._base import FamilyPlugin, Signature


class EmotetFamily(FamilyPlugin):
    id = "family-emotet"
    name = "Emotet"
    family_name = "Emotet"
    aka = ("Heodo", "Feodo", "Geodo", "MummySpider")

    signatures = (
        Signature(r"\bEmotet\b|\bHeodo\b|\bMummySpider\b", 0.65, "regex",
                  "Emotet / Heodo / MummySpider branding"),
        # Emotet's canonical XL4 / VBA macro pattern
        Signature(r"document_open|Auto_Open|Workbook_Open", 0.20, "regex",
                  "Office auto-execute macro entrypoint"),
        Signature(r'=SET\.NAME\(|=CALL\(|=EXEC\(', 0.30, "regex",
                  "Excel 4.0 (XLM) macro formulas"),
        # Emotet PS downloader chunk with @-delimited fallback URL list
        Signature(r"(?:https?://[a-z0-9.-]+/[a-zA-Z0-9./?=&_-]+@){3,}",
                  0.50, "regex",
                  "5+ URL @-delimited fallback list (Emotet trademark)"),
        Signature(r"\by[12]\.exe\b|\bA0\.exe\b|\bPOM\.exe\b", 0.30, "regex",
                  "Emotet dropper artefact filenames"),
        Signature(r"MSXML2\.(?:XMLHTTP|ServerXMLHTTP)|ADODB\.Stream",
                  0.20, "regex",
                  "Emotet COM-object downloader stack"),
        Signature(r"Add-MpPreference|Set-MpPreference|Windows Defender bypass",
                  0.25, "regex", "Emotet Defender-bypass tradecraft"),
        Signature(r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                  0.15, "regex", "Emotet Run-key persistence path (weak)"),
        Signature(r"RC4Init|RC4Crypt|RC4_setKey", 0.20, "regex",
                  "Emotet RC4 config decrypt helpers"),
        Signature(r"IEX\s*\(\s*New-Object", 0.15, "regex",
                  "PS IEX downloader — weak correlator"),
    )
    calibration = 1.30

    mitre = (
        MitreHint(id="T1059.001", technique="PowerShell",
                  tactic="Execution",
                  evidence="Emotet PowerShell loader stage",
                  source="family"),
        MitreHint(id="T1059.005", technique="Visual Basic",
                  tactic="Execution",
                  evidence="Emotet Word/Excel VBA macro entrypoint",
                  source="family"),
        MitreHint(id="T1059.007", technique="JavaScript",
                  tactic="Execution",
                  evidence="Emotet JS dropper variant",
                  source="family"),
        MitreHint(id="T1204.002", technique="Malicious File",
                  tactic="Execution",
                  evidence="Emotet Word/Excel document lure",
                  source="family"),
        MitreHint(id="T1547.001",
                  technique="Registry Run Keys / Startup Folder",
                  tactic="Persistence",
                  evidence="Emotet HKCU Run-key persistence",
                  source="family"),
        MitreHint(id="T1105", technique="Ingress Tool Transfer",
                  tactic="Command and Control",
                  evidence="Emotet @-delimited fallback URL loader",
                  source="family"),
        MitreHint(id="T1071.001",
                  technique="Application Layer Protocol: Web Protocols",
                  tactic="Command and Control",
                  evidence="Emotet HTTP/HTTPS beacons",
                  source="family"),
        MitreHint(id="T1573.001",
                  technique="Encrypted Channel: Symmetric Cryptography",
                  tactic="Command and Control",
                  evidence="Emotet RC4-encrypted config + beacon body",
                  source="family"),
        MitreHint(id="T1562.001",
                  technique="Impair Defenses: Disable or Modify Tools",
                  tactic="Defense Evasion",
                  evidence="Emotet Add-MpPreference / Defender exclusion",
                  source="family"),
        MitreHint(id="T1027",
                  technique="Obfuscated Files or Information",
                  tactic="Defense Evasion",
                  evidence="Emotet macro / PowerShell obfuscation layers",
                  source="family"),
    )
    yara_seed_name = "MAL_Emotet_Loader"
    atomic_red = "T1204.002"


DecoderRegistry.register(EmotetFamily())
