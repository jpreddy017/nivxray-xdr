"""Meterpreter / MSFvenom stager — deterministic family plugin (RC2.1a)."""
from __future__ import annotations

from engine.models import MitreHint
from engine.registry import DecoderRegistry

from ._base import FamilyPlugin, Signature


class MeterpreterFamily(FamilyPlugin):
    id = "family-meterpreter"
    name = "Meterpreter / MSFvenom Stager"
    family_name = "Meterpreter/MSFvenom stager"
    aka = ("Metasploit stager", "MSFvenom", "meterpreter/reverse_tcp",
           "meterpreter/reverse_https")

    signatures = (
        # x86 shellcode prologues (Metasploit block_api template)
        Signature(r"\xfc\xe8[\x82\x89\x8b\x8c\x8f]\x00\x00\x00", 0.55,
                  "opcode", "MSFvenom x86 stager prologue"),
        Signature(r"\xfc\xeb[\x00-\xff]{1,4}\xe8", 0.45,
                  "opcode", "MSFvenom x86 stager (jmp variant)"),
        # x64 shellcode prologue
        Signature(r"\xfc\x48\x83\xe4\xf0", 0.55,
                  "opcode", "MSFvenom x64 stager prologue"),
        # WinSock loading (typical meterpreter stager)
        Signature(r"ws2_32", 0.20, "string", "ws2_32 import string"),
        Signature(r"WSAStartup", 0.20, "string", "WSAStartup ref"),
        Signature(r"WSASocket", 0.20, "string", "WSASocket ref"),
        # Block API hash constants (Metasploit's classic hash-based API resolution)
        Signature(r"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28", 0.55,
                  "opcode", "MSF block_api PEB walk"),
        Signature(r"\x60\x89\xe5\x31\xc0", 0.35,
                  "opcode", "MSF block_api entry (32-bit)"),
        # DLL & command strings observed in decoded stagers
        Signature(r"metsrv\.dll", 0.60, "string", "metsrv.dll payload name"),
        Signature(r"stdapi", 0.30, "string", "stdapi extension"),
        Signature(r"reverse_(tcp|https|http)", 0.35,
                  "string", "reverse-connect handler ref"),
        # Encoder markers
        Signature(r"\xd9[\x74\xee]\x24\xf4", 0.30,
                  "opcode", "shikata_ga_nai FPU trick"),
    )
    calibration = 1.10   # ~2 strong sig matches → conf ~1.0

    mitre = (
        MitreHint(id="T1055.012", technique="Process Hollowing",
                  tactic="Defense Evasion",
                  evidence="Meterpreter shellcode injection",
                  source="family"),
        MitreHint(id="T1059.001", technique="PowerShell",
                  tactic="Execution",
                  evidence="PowerShell stager for Meterpreter payload",
                  source="family"),
        MitreHint(id="T1027", technique="Obfuscated Files or Information",
                  tactic="Defense Evasion",
                  evidence="XOR/base64-encoded shellcode",
                  source="family"),
        MitreHint(id="T1071.001", technique="Application Layer Protocol: Web Protocols",
                  tactic="Command and Control",
                  evidence="reverse_http(s) meterpreter C2",
                  source="family"),
    )
    yara_seed_name = "APT_Meterpreter_MSFvenom_Stager"
    atomic_red = "T1055.012#T1055.012-1"


DecoderRegistry.register(MeterpreterFamily())
