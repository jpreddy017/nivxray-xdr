"""Cobalt Strike Beacon — deterministic family plugin (RC2.1a)."""
from __future__ import annotations

from engine.models import MitreHint
from engine.registry import DecoderRegistry

from ._base import FamilyPlugin, Signature


class CobaltStrikeFamily(FamilyPlugin):
    id = "family-cobaltstrike"
    name = "Cobalt Strike Beacon"
    family_name = "Cobalt Strike Beacon"
    aka = ("CobaltStrike", "CS Beacon", "beacon.dll")

    signatures = (
        # x86 beacon shellcode prologue (well-known CS stager)
        Signature(r"\xfc\xe8\x8f\x00\x00\x00", 0.60, "opcode",
                  "Cobalt-Strike Beacon shellcode prologue"),
        Signature(r"beacon\.(x64\.)?(dll|exe)", 0.45, "regex",
                  "beacon.dll payload name"),
        Signature(r"beacon", 0.15, "string", "beacon marker"),
        # Malleable-C2 markers
        Signature(r"Malleable-C2|malleable-c2\.profile", 0.55, "regex",
                  "Malleable-C2 profile marker"),
        # Default C2 URIs
        Signature(r"/updates\.rss|/ptj|/submit\.php\?id=", 0.40, "regex",
                  "Cobalt-Strike default C2 URIs"),
        # DNS staging
        Signature(r"cdn\.[a-z]{3,20}\.(com|net)\.[0-9]{2,}", 0.15, "regex",
                  "DNS-beacon staging pattern"),
        # Jitter/sleep-mask constants
        Signature(r"\xbe\xef\xbe\xef", 0.30, "opcode",
                  "0xBEEF jitter constant"),
        Signature(r"i_am_key_statement", 0.55, "string",
                  "CS sleep_mask.bin key statement"),
        # Beacon config-block v3/v4 tags
        Signature(r"\x00\x01\x00\x01\x00\x02", 0.35, "opcode",
                  "Beacon config-block type/length header"),
        # HTTP fields common in Beacon
        Signature(r"__cfduid=|SESSIONID=|jsessionid=", 0.10, "regex",
                  "Beacon HTTP profile cookies (default profile)"),
    )
    calibration = 1.00

    mitre = (
        MitreHint(id="T1071.001",
                  technique="Application Layer Protocol: Web Protocols",
                  tactic="Command and Control",
                  evidence="Cobalt-Strike HTTP(S) beacon C2",
                  source="family"),
        MitreHint(id="T1055", technique="Process Injection",
                  tactic="Defense Evasion",
                  evidence="Cobalt-Strike beacon inject/spawn commands",
                  source="family"),
        MitreHint(id="T1027", technique="Obfuscated Files or Information",
                  tactic="Defense Evasion",
                  evidence="Cobalt-Strike sleep-mask + Malleable-C2 obfuscation",
                  source="family"),
        MitreHint(id="T1573.002",
                  technique="Encrypted Channel: Asymmetric Cryptography",
                  tactic="Command and Control",
                  evidence="Beacon RSA-encrypted metadata",
                  source="family"),
        MitreHint(id="T1090.001", technique="Internal Proxy",
                  tactic="Command and Control",
                  evidence="Cobalt-Strike SMB/TCP pivot beacons",
                  source="family"),
    )
    yara_seed_name = "APT_CobaltStrike_Beacon"
    atomic_red = "T1071.001"


DecoderRegistry.register(CobaltStrikeFamily())
