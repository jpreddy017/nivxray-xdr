"""XWorm · deterministic family plugin (RC3.2b · Feb-2026).

XWorm is a .NET-based commodity remote-access tool sold on cybercrime
forums since 2022. It surged into the top-5 delivered malware families
by 2024-2025 (unit42, malpedia, checkpoint IR reports) and has become the
default loader-of-choice for phishing operations that previously used
AsyncRAT / Remcos.

Reference indicators (deterministic — no LLM lookups):
    * Client class name              XClient
    * Mutex prefix                   XWormMutex_
    * Config XML root                <XWorm> / <XwormSettings>
    * Feature enums                  XPlugin, XChat, XKeyLog, XHVNC
    * Wire tags                      pong, host, plugin, save_Plugin, offline_Get
    * String obf marker              XNormal.
    * Default C2 port token          "Port : "
    * Persistence / evasion feature  USB_Spread, StartUP
    * Version banner                 "XWorm V" (e.g. "XWorm V5.6")
    * Aes cipher class               EncryptionKey, Algorithm.Aes

Sources:
    * Malpedia Xworm/xworm entry (fingerprints scraped 2025-Q4)
    * Unit42 "XWorm V5 config extractor" 2025-06 IOC dump
    * Elastic "XWorm hunt-package" (elastic/detection-rules)
    * SentinelOne "XWorm phishing wave — Nov-2025" report
"""
from __future__ import annotations

from engine.models import MitreHint
from engine.registry import DecoderRegistry

from ._base import FamilyPlugin, Signature


class XWormFamily(FamilyPlugin):
    id = "family-xworm"
    name = "XWorm"
    family_name = "XWorm"
    aka = ("XWorm.NET", "XClient", "Xworm")

    signatures = (
        # ── Class / namespace fingerprints ────────────────────────────
        Signature(r"XClient\.Settings", 0.60, "string",
                  "XClient.Settings config namespace"),
        Signature(r"class\s+XClient\b", 0.55, "regex",
                  "XClient class declaration"),
        Signature(r"XNormal\.", 0.35, "string",
                  "XNormal.* string-obfuscation helper"),

        # ── Version banner ────────────────────────────────────────────
        Signature(r"XWorm\s*V\s*\d+(\.\d+)?", 0.65, "regex",
                  "XWorm version banner (e.g. 'XWorm V5.6')"),
        Signature(r"<XWorm(\s[^>]*)?>|<XwormSettings", 0.55, "regex",
                  "XWorm config XML root"),

        # ── Mutex prefix (highly distinctive) ────────────────────────
        Signature(r"XWormMutex_[a-zA-Z0-9_]{4,}", 0.65, "regex",
                  "XWormMutex_* singleton mutex pattern"),

        # ── Feature / plugin enum names ──────────────────────────────
        Signature(r"XPlugin|XChat|XKeyLog|XHVNC|XClipper|XFileMgr|XLogger",
                  0.45, "regex",
                  "XWorm feature-module class names"),
        Signature(r"USB_Spread|StartUP|Anti_Analysis|InstallStartUp",
                  0.30, "regex",
                  "XWorm feature-flag toggles"),

        # ── Wire-protocol tags ───────────────────────────────────────
        Signature(r"\b(pong|save_Plugin|offline_Get|plugin|Xchat)\b",
                  0.30, "regex",
                  "XWorm C2 wire-protocol verbs"),
        Signature(r"CLIENTINFO|Ping|hostname", 0.15, "regex",
                  "generic .NET RAT wire tags (weak, correlator only)"),

        # ── Config keys ──────────────────────────────────────────────
        Signature(r"\bHost\s*:\s*|\bPort\s*:\s*|\bMutex\s*:\s*", 0.20, "regex",
                  "XWorm human-readable config lines"),
        Signature(r"USBNM\.exe|USB\.exe", 0.30, "regex",
                  "XWorm USB-spread dropper artifact"),

        # ── Crypto refs ──────────────────────────────────────────────
        Signature(r"EncryptionKey|Algorithm\.Aes|Aes256", 0.15, "regex",
                  "AES-256 config-decrypt reference (shared with AsyncRAT — low weight)"),
    )
    # calibration: 4-5 strong hits (mutex + version + XClient + plugin enum)
    # should saturate to confidence 1.0. sum ≈ 2.35 without weak correlators.
    calibration = 2.10

    mitre = (
        MitreHint(id="T1219", technique="Remote Access Software",
                  tactic="Command and Control",
                  evidence="XWorm is a commodity remote-access tool",
                  source="family"),
        MitreHint(id="T1055", technique="Process Injection",
                  tactic="Defense Evasion",
                  evidence="XWorm process-hollowing loader",
                  source="family"),
        MitreHint(id="T1547.001", technique="Registry Run Keys / Startup Folder",
                  tactic="Persistence",
                  evidence="XWorm StartUP / InstallStartUp persistence",
                  source="family"),
        MitreHint(id="T1091", technique="Replication Through Removable Media",
                  tactic="Lateral Movement",
                  evidence="XWorm USB_Spread module drops USBNM.exe onto removable media",
                  source="family"),
        MitreHint(id="T1573.001",
                  technique="Encrypted Channel: Symmetric Cryptography",
                  tactic="Command and Control",
                  evidence="XWorm AES-256 config + C2 encryption",
                  source="family"),
        MitreHint(id="T1056.001", technique="Input Capture: Keylogging",
                  tactic="Collection",
                  evidence="XKeyLog module",
                  source="family"),
        MitreHint(id="T1113", technique="Screen Capture",
                  tactic="Collection",
                  evidence="XHVNC / XChat screen-share module",
                  source="family"),
    )
    yara_seed_name = "MAL_XWorm_Client"
    atomic_red = "T1219"


DecoderRegistry.register(XWormFamily())
