"""Lumma Stealer — deterministic family plugin (RC2.1a)."""
from __future__ import annotations

from engine.models import MitreHint
from engine.registry import DecoderRegistry

from ._base import FamilyPlugin, Signature


class LummaFamily(FamilyPlugin):
    id = "family-lumma"
    name = "Lumma Stealer"
    family_name = "Lumma Stealer"
    aka = ("LummaC2", "Lumma", "Lumma-C2-Stealer")

    signatures = (
        # C2 endpoint pattern (Lumma panels commonly expose /api/steal, /api/conf)
        Signature(r"/api/(steal|conf|log|get|task)", 0.45, "regex",
                  "Lumma C2 API path"),
        Signature(r"lumma[-_ ]?shop", 0.55, "regex",
                  "'lumma-shop' operator branding"),
        Signature(r"Lumma", 0.20, "string", "Lumma product string"),
        # Exfil-config JSON dictionary keys (very Lumma-specific)
        Signature(r'"crypto":\s*\[', 0.30, "regex", "Lumma exfil: crypto list"),
        Signature(r'"browsers":\s*\[', 0.25, "regex", "Lumma exfil: browsers list"),
        Signature(r'"wallets":\s*\[', 0.30, "regex", "Lumma exfil: wallets list"),
        Signature(r'"files":\s*\[', 0.15, "regex", "Lumma exfil: files list"),
        Signature(r'"software":\s*\[', 0.15, "regex", "Lumma exfil: software list"),
        # User-agent + build ID
        Signature(r"TeslaBrowser/[0-9.]+", 0.55, "regex",
                  "Lumma custom User-Agent 'TeslaBrowser'"),
        Signature(r"build_?id=[a-zA-Z0-9]{5,}", 0.20, "regex",
                  "Lumma build_id URL param"),
        # Sample dropper strings observed in unpacked payloads
        Signature(r"HWID_[A-F0-9]{8,}", 0.20, "regex",
                  "Lumma hardware-id token"),
    )
    calibration = 0.90

    mitre = (
        MitreHint(id="T1005", technique="Data from Local System",
                  tactic="Collection",
                  evidence="Lumma harvests local browser data",
                  source="family"),
        MitreHint(id="T1555.003", technique="Credentials from Web Browsers",
                  tactic="Credential Access",
                  evidence="Lumma steals stored browser passwords",
                  source="family"),
        MitreHint(id="T1552.001", technique="Credentials In Files",
                  tactic="Credential Access",
                  evidence="Lumma scrapes wallet keys, config files",
                  source="family"),
        MitreHint(id="T1041", technique="Exfiltration Over C2 Channel",
                  tactic="Exfiltration",
                  evidence="Lumma exfil bundle via /api/steal",
                  source="family"),
    )
    yara_seed_name = "MAL_Lumma_Stealer_C2"
    atomic_red = "T1555.003"


DecoderRegistry.register(LummaFamily())
