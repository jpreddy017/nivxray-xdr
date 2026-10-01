"""FormBook · deterministic family plugin (RC3.4 · Feb-2026).

FormBook is a C-based commodity info-stealer + form-grabber that has been
active since 2016 and re-emerged in 2022+ as XLoader (its rebranded macOS
sibling). It's known for extensive anti-analysis (hollow-process injection,
API hashing, xor-encoded strings) and hides its C2 URLs inside a decoy
list. Fingerprints below capture the deterministic surface after string
extraction / config decrypt.

Sources:
    * Malpedia formbook + xloader entries
    * FR3D / CheckPoint "XLoader / FormBook Config Extractor" 2023-2025 IOC
      dumps
    * FireEye "FormBook Decoding Malicious Injection Server Traffic"
"""
from __future__ import annotations

from engine.models import MitreHint
from engine.registry import DecoderRegistry

from ._base import FamilyPlugin, Signature


class FormBookFamily(FamilyPlugin):
    id = "family-formbook"
    name = "FormBook"
    family_name = "FormBook"
    aka = ("XLoader", "FormBook-XLoader")

    signatures = (
        Signature(r"FormBook|Form[Bb]ook", 0.50, "regex", "FormBook branding string"),
        Signature(r"XLoader", 0.55, "regex", "XLoader (rebranded FormBook) marker"),
        Signature(r"\.mozilla|Chromium|Chrome\\User Data|Mozilla\\Firefox\\Profiles",
                  0.20, "regex", "FormBook browser-path harvest list"),
        # Distinctive: FormBook fakes a decoy list of ~15-20 URLs and the
        # real C2 is at a hard-coded slot (usually index 6 or 12).
        Signature(r"(?:https?://[a-z0-9.-]+/[a-zA-Z0-9./?=&_-]+[\s,|@]*){12,}", 0.35, "regex",
                  "≥12 URL decoy-list pattern (FormBook signature layout)"),
        Signature(r"CommandCode|CommandID|command_line|InstalledPrograms",
                  0.15, "regex", "FormBook command dispatch verbs"),
        Signature(r"HOLLOW|process_hollow|_HollowInject_", 0.20, "regex",
                  "Hollow-process injection helper"),
        # ntdll ordinal + hash-based API resolver (common FormBook obfuscation)
        Signature(r"ZwCreateSection|NtMapViewOfSection|ZwUnmapViewOfSection",
                  0.20, "regex", "Native syscall imports (hollow-injection)"),
        Signature(r"\[HKEY_CURRENT_USER\\Software\\Microsoft\\[A-Z0-9]{6,}\]",
                  0.20, "regex", "FormBook persistence registry path shape"),
        Signature(r"api\.ip\.sb|checkip\.dyndns\.org|ip-api\.com",
                  0.10, "regex", "IP-check services (correlator)"),
    )
    calibration = 1.20

    mitre = (
        MitreHint(id="T1055.012", technique="Process Hollowing",
                  tactic="Defense Evasion",
                  evidence="FormBook hollow-process injection into svchost/wininit",
                  source="family"),
        MitreHint(id="T1056.001", technique="Input Capture: Keylogging",
                  tactic="Collection",
                  evidence="FormBook keystroke capture module",
                  source="family"),
        MitreHint(id="T1056.004",
                  technique="Input Capture: Credential API Hooking",
                  tactic="Collection",
                  evidence="FormBook form-grabber hooks browser API",
                  source="family"),
        MitreHint(id="T1555.003",
                  technique="Credentials from Web Browsers",
                  tactic="Credential Access",
                  evidence="FormBook browser-credential harvest",
                  source="family"),
        MitreHint(id="T1113", technique="Screen Capture",
                  tactic="Collection",
                  evidence="FormBook screenshot on-demand",
                  source="family"),
        MitreHint(id="T1082", technique="System Information Discovery",
                  tactic="Discovery",
                  evidence="FormBook host profile on checkin",
                  source="family"),
        MitreHint(id="T1071.001",
                  technique="Application Layer Protocol: Web Protocols",
                  tactic="Command and Control",
                  evidence="FormBook HTTP POST beacon w/ decoy-URL list",
                  source="family"),
        MitreHint(id="T1027.007",
                  technique="Dynamic API Resolution",
                  tactic="Defense Evasion",
                  evidence="FormBook hash-based API resolver",
                  source="family"),
    )
    yara_seed_name = "MAL_FormBook_XLoader"
    atomic_red = "T1055.012"


DecoderRegistry.register(FormBookFamily())
