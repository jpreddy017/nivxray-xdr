"""RedLine Stealer · deterministic family plugin (RC3.3 · Feb-2026).

RedLine has been the #1 credential + browser-data stealer since 2020
(malpedia, red canary, sekoia, group-ib reports) and is the dominant
infostealer sold through the MaaS "RedLine Panel" on Russian-speaking
forums. It's a .NET (Framework 4.x) client that talks NetTcpBinding /
SOAP-over-TCP to its C2 panel.

Deterministic fingerprints (no LLM):
    * Panel namespace              RedLine.Client / RedLine.Loader
    * Config class                 Arguments (with IP / Key / Type fields)
    * SOAP endpoints               IRemoteEndpoint, DownloadAndExecute,
                                   SendSettings, GetCommands
    * ScanRules markers            ScanBrowsers, ScanWallets, ScanTelegram,
                                   ScanDiscord, ScanSteam, ScanFTP, ScanFiles
    * Wallets                      Zcash / Armory / Bytecoin / Jaxx / Exodus
    * Persistence                  StartupHelper / TaskScheduler.NET
    * Version banner               RedLine V(20|21|22|23)
    * Rijndael references          Rijndael, TripleDES helpers
"""
from __future__ import annotations

from engine.models import MitreHint
from engine.registry import DecoderRegistry

from ._base import FamilyPlugin, Signature


class RedLineFamily(FamilyPlugin):
    id = "family-redline"
    name = "RedLine Stealer"
    family_name = "RedLine"
    aka = ("RedLine.Stealer", "RedLineStealer")

    signatures = (
        Signature(r"RedLine\.(Client|Loader|Config|Panel)", 0.65, "regex",
                  "RedLine.* namespace"),
        Signature(r"class\s+Arguments\b.{0,120}(IP|Key|Type)", 0.35, "regex",
                  "Arguments config class"),
        Signature(r"IRemoteEndpoint|DownloadAndExecute|SendSettings|GetCommands",
                  0.55, "regex", "SOAP endpoint contract"),
        Signature(r"ScanBrowsers|ScanWallets|ScanTelegram|ScanDiscord|"
                  r"ScanSteam|ScanFTP|ScanFiles", 0.60, "regex",
                  "RedLine ScanRules feature flags"),
        Signature(r"Zcash|Armory|Bytecoin|Jaxx|Exodus", 0.30, "regex",
                  "Wallet targeting list (weak — needs correlator)"),
        Signature(r"NetTcpBinding|BasicHttpBinding|WSHttpBinding", 0.20, "regex",
                  "WCF binding types (.NET framework hint)"),
        Signature(r"RedLine\s*V\s*2[0-3]", 0.60, "regex",
                  "RedLine version banner V20-V23"),
        Signature(r"StartupHelper|TaskScheduler\.NET", 0.25, "regex",
                  "Persistence helper class"),
        Signature(r"Rijndael|TripleDESCryptoServiceProvider", 0.15, "regex",
                  "Rijndael / 3DES config-decrypt reference"),
        Signature(r"api\.ip\.sb|iplogger\.org|myexternalip", 0.15, "regex",
                  "IP-check services commonly used by RedLine at startup"),
    )
    # Two strong hits (namespace + ScanRules) should saturate to ~0.85+.
    calibration = 1.60

    mitre = (
        MitreHint(id="T1555.003", technique="Credentials from Web Browsers",
                  tactic="Credential Access",
                  evidence="RedLine ScanBrowsers module extracts saved credentials",
                  source="family"),
        MitreHint(id="T1005", technique="Data from Local System",
                  tactic="Collection",
                  evidence="RedLine ScanFiles + ScanWallets modules",
                  source="family"),
        MitreHint(id="T1113", technique="Screen Capture",
                  tactic="Collection",
                  evidence="RedLine screenshot module",
                  source="family"),
        MitreHint(id="T1082", technique="System Information Discovery",
                  tactic="Discovery",
                  evidence="RedLine profiles host on first checkin",
                  source="family"),
        MitreHint(id="T1071.001", technique="Application Layer Protocol: Web Protocols",
                  tactic="Command and Control",
                  evidence="RedLine SOAP-over-HTTP / NetTcpBinding C2",
                  source="family"),
        MitreHint(id="T1573.001",
                  technique="Encrypted Channel: Symmetric Cryptography",
                  tactic="Command and Control",
                  evidence="RedLine Rijndael / 3DES C2 encryption",
                  source="family"),
        MitreHint(id="T1547.001",
                  technique="Registry Run Keys / Startup Folder",
                  tactic="Persistence",
                  evidence="RedLine StartupHelper persistence",
                  source="family"),
        MitreHint(id="T1041", technique="Exfiltration Over C2 Channel",
                  tactic="Exfiltration",
                  evidence="RedLine SendSettings ships stolen creds to panel",
                  source="family"),
    )
    yara_seed_name = "MAL_RedLine_Stealer"
    atomic_red = "T1555.003"


DecoderRegistry.register(RedLineFamily())
