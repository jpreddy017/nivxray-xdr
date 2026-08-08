"""Case Context · read-only projection of a decode result / SSOT
document into the 12 evidence dimensions the engine reasons over.

Never mutates the input — pure projection.  Every accessor returns
``()`` / ``{}`` / ``None`` on absence so rule predicates can be
written without defensive ``.get(...) or []`` boilerplate.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing      import Any, Dict, FrozenSet, List, Optional, Set, Tuple


# ── Vocabulary — canonical strings so rules and projections share ─
BEHAVIOUR_TAGS = frozenset({
    "execution", "persistence", "c2", "credential_access",
    "discovery", "lateral_movement", "impact", "collection",
    "defense_evasion", "exfiltration", "recon",
})

DETECTION_TYPES = frozenset({
    "signature", "heuristic", "behavioural", "anomaly",
    "pattern", "correlation",
})

IMPACT_TAGS = frozenset({
    "data_encrypted", "data_destroyed", "credential_exposed",
    "data_theft", "service_disruption", "in_memory_execution",
    "recovery_inhibited", "system_shutdown",
})


@dataclass(frozen=True)
class CaseContext:
    """The immutable view a rule sees when it evaluates a case."""
    # 1 · Observed Evidence
    processes:      Tuple[str, ...] = ()
    commands:       Tuple[str, ...] = ()
    files:          Tuple[str, ...] = ()
    registry_keys:  Tuple[str, ...] = ()
    users:          Tuple[str, ...] = ()
    hosts:          Tuple[str, ...] = ()
    artifacts:      Tuple[str, ...] = ()
    output_text:    str = ""

    # 2 · Detection Types
    detection_types: FrozenSet[str] = field(default_factory=frozenset)

    # 3 · Behavior Tags (Cyber Kill Chain aligned)
    behaviors:       FrozenSet[str] = field(default_factory=frozenset)

    # 4 · MITRE ATT&CK
    mitre_techniques: FrozenSet[str] = field(default_factory=frozenset)

    # 5 · Malware Intelligence
    malware_family:   Optional[str] = None
    malware_capabilities: FrozenSet[str] = field(default_factory=frozenset)

    # 6 · APT / Threat-Actor Intelligence
    apt_group:        Optional[str] = None
    apt_confidence:   str = ""              # ("", "low", "medium", "high")

    # 7 · LOLBAS / Tool Intelligence
    lolbas_hits:      Tuple[str, ...] = ()

    # 8 · IOC / Infrastructure
    ips:              Tuple[str, ...] = ()
    domains:          Tuple[str, ...] = ()
    urls:             Tuple[str, ...] = ()
    hashes:           Tuple[str, ...] = ()

    # 9 · Attack Pattern / Correlation
    obfuscation_layers: int = 0
    kill_chain_phases:  FrozenSet[str] = field(default_factory=frozenset)

    # 10 · Impact
    impacts:          FrozenSet[str] = field(default_factory=frozenset)
    reached_shellcode: bool = False

    # 11 · Scope & Criticality
    affected_hosts:   int = 0
    privileged_users_affected: int = 0
    critical_assets_affected: int = 0

    # 12 · Confidence
    detection_confidence: str = "low"       # "low" | "medium" | "high" | "confirmed"
    false_positive_indicators: Tuple[str, ...] = ()

    def has_any_behavior(self, *tags: str) -> bool:
        return any(t in self.behaviors for t in tags)

    def has_any_impact(self, *tags: str) -> bool:
        return any(t in self.impacts for t in tags)

    def has_any_mitre(self, *techniques: str) -> bool:
        return any(t in self.mitre_techniques for t in techniques)


# ══════════════════════════════════════════════════════════════════
# Projection · decode_result / SSOT dict → CaseContext
# ══════════════════════════════════════════════════════════════════
def project_from_decode_result(res: Dict[str, Any]) -> CaseContext:
    """Project the analysis_core deterministic_best_decode dict.

    Fully deterministic — no LLM, no external service calls.
    Missing signals map to empty / False / "" so downstream rules
    can rely on the returned object being total.
    """
    if not res:
        return CaseContext()

    output_text = str(res.get("output") or "")
    iocs        = res.get("iocs") or {}
    ips     = tuple(iocs.get("ip")     or iocs.get("ips")     or ())
    domains = tuple(iocs.get("domain") or iocs.get("domains") or ())
    urls    = tuple(iocs.get("url")    or iocs.get("urls")    or ())
    hashes  = tuple((iocs.get("sha256") or ())
                    + (iocs.get("sha1")   or ())
                    + (iocs.get("md5")    or ()))
    recipe_ops = _recipe_ops(res)

    detection_types: Set[str] = set()
    if recipe_ops:
        detection_types.add("pattern")
    if any("decoder" in op or "peel" in op for op in recipe_ops):
        detection_types.add("behavioural")
    if any(fam_ua in output_text for fam_ua in _KNOWN_UA):
        detection_types.add("signature")

    behaviors: Set[str] = set()
    ops_joined = " ".join(op.lower() for op in recipe_ops)
    if "encoded_command" in ops_joined or "encodedcommand" in ops_joined \
            or "from_base64" in ops_joined:
        behaviors.add("defense_evasion")
        behaviors.add("execution")
    if bool(res.get("reached_shellcode")):
        behaviors.add("execution")
        behaviors.add("defense_evasion")
    if ips or urls or domains:
        behaviors.add("c2")
    if any(m in output_text.lower()
             for m in ("lsass", "mimikatz", "sekurlsa", "hashdump",
                        "invoke-mimikatz")):
        behaviors.add("credential_access")
    if any(m in output_text
             for m in ("New-Service", "Set-Service", "schtasks",
                        "Register-ScheduledTask",
                        "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")):
        behaviors.add("persistence")
    if any(m in output_text
             for m in ("Invoke-WMIMethod", "PSSession", "WinRM",
                        "PSExec", "Enter-PSSession")):
        behaviors.add("lateral_movement")
    if any(m in output_text
             for m in ("Cipher", ".locked", ".encrypted", "vssadmin",
                        "wbadmin", "bcdedit /set")):
        behaviors.add("impact")
    if any(m in output_text
             for m in ("Get-ADUser", "Get-ADComputer", "net view",
                        "net user /domain", "whoami /priv")):
        behaviors.add("discovery")

    obfuscation_layers = _count_obfuscation(recipe_ops)

    mitre = _derive_mitre_from_evidence(recipe_ops, output_text,
                                          bool(res.get("reached_shellcode")))

    family, apt = _fingerprint_family_and_apt(output_text)

    lolbas = _detect_lolbas(output_text, res)

    impacts: Set[str] = set()
    if bool(res.get("reached_shellcode")):
        impacts.add("in_memory_execution")
    if "credential_access" in behaviors:
        impacts.add("credential_exposed")
    if any(m in output_text
             for m in ("vssadmin delete", "wbadmin delete",
                        "bcdedit /set", ".locked", ".encrypted",
                        "cipher /w")):
        impacts.add("data_encrypted")
        impacts.add("recovery_inhibited")

    kill_chain: Set[str] = set()
    if obfuscation_layers >= 1:                       kill_chain.add("delivery")
    if "execution" in behaviors:                       kill_chain.add("exploitation")
    if bool(res.get("reached_shellcode")):             kill_chain.add("installation")
    if "c2" in behaviors:                              kill_chain.add("command_and_control")
    if impacts:                                        kill_chain.add("actions_on_objectives")

    # Confidence — high when family fingerprint hits, else driven by
    # obfuscation depth + shellcode + IOC promotion count.
    if family or apt:
        confidence = "confirmed" if family else "high"
    elif bool(res.get("reached_shellcode")) and obfuscation_layers >= 2:
        confidence = "high"
    elif obfuscation_layers >= 2 or ips or urls:
        confidence = "medium"
    else:
        confidence = "low"

    return CaseContext(
        processes     = ("powershell.exe",) if "powershell" in output_text.lower() else (),
        commands      = tuple(recipe_ops),
        files         = (),
        registry_keys = (),
        users         = (),
        hosts         = (),
        artifacts     = tuple(res.get("artifacts", ()) or ()),
        output_text   = output_text,

        detection_types  = frozenset(detection_types),
        behaviors        = frozenset(behaviors),
        mitre_techniques = frozenset(mitre),
        malware_family   = family,
        malware_capabilities = frozenset(),
        apt_group        = apt,
        apt_confidence   = "medium" if apt else "",
        lolbas_hits      = tuple(lolbas),
        ips              = ips,
        domains          = domains,
        urls             = urls,
        hashes           = hashes,
        obfuscation_layers = obfuscation_layers,
        kill_chain_phases  = frozenset(kill_chain),
        impacts            = frozenset(impacts),
        reached_shellcode  = bool(res.get("reached_shellcode")),
        affected_hosts     = 1 if bool(res.get("reached_shellcode")) else 0,
        detection_confidence = confidence,
    )


# ── helpers ────────────────────────────────────────────────────────
def _recipe_ops(res: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for r in (res.get("recipe") or []):
        op = (r or {}).get("op")
        if op: out.append(str(op))
    if not out:
        for s in (res.get("steps") or []):
            op = (s or {}).get("op")
            if op: out.append(str(op))
    return out


def _count_obfuscation(recipe_ops: List[str]) -> int:
    joined = " ".join(op.lower() for op in recipe_ops)
    n = 0
    if "encoded_command" in joined or "encodedcommand" in joined:
        n += 1
    if "from_base64" in joined or "decoder-from-base64-string" in joined \
            or "bare_base64" in joined:
        n += 1
    if "gzip" in joined or "zlib" in joined or "compression" in joined:
        n += 1
    if "xor" in joined and "loop" in joined:
        n += 1
    return n


_KNOWN_UA: Dict[str, str] = {
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; BOIE9;PTBR)":
        "cobalt_strike",
    "Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko":
        "cobalt_strike",
    "Mozilla/4.0 (compatible; MSIE 8.0":  "empire",
}


def _fingerprint_family_and_apt(output_text: str) -> Tuple[Optional[str],
                                                             Optional[str]]:
    for ua, fam in _KNOWN_UA.items():
        if ua in output_text:
            return fam, None
    return None, None


def _derive_mitre_from_evidence(recipe_ops: List[str],
                                  output_text: str,
                                  reached_sc: bool) -> Set[str]:
    """Derive MITRE technique IDs from actual evidence — NOT from
    template libraries.  Each addition below is justified by a
    concrete signal in the case."""
    techs: Set[str] = set()
    joined = " ".join(op.lower() for op in recipe_ops)
    if "encoded_command" in joined or "encodedcommand" in joined:
        techs.add("T1059.001")     # PowerShell
        techs.add("T1027")         # Obfuscated Files or Information
    if "from_base64" in joined or "bare_base64" in joined:
        techs.add("T1140")         # Deobfuscate/Decode Files or Information
    if "gzip" in joined or "zlib" in joined:
        techs.add("T1140")
    if "xor" in joined and "loop" in joined:
        techs.add("T1027")
        techs.add("T1140")
    if reached_sc:
        techs.add("T1055")         # Process Injection
        techs.add("T1620")         # Reflective Code Loading
    lc = output_text.lower()
    if "downloadstring" in lc or "downloadfile" in lc or "webclient" in lc:
        techs.add("T1105")         # Ingress Tool Transfer
    if any(m in lc for m in ("lsass", "mimikatz", "sekurlsa")):
        techs.add("T1003")         # OS Credential Dumping
    if "invoke-expression" in lc or "iex " in lc:
        techs.add("T1059.001")
    return techs


_LOLBAS_BINS = (
    "certutil.exe", "bitsadmin.exe", "mshta.exe", "regsvr32.exe",
    "rundll32.exe", "installutil.exe", "cscript.exe", "wscript.exe",
    "wmic.exe",     "powershell.exe", "msbuild.exe",
)


def _detect_lolbas(output_text: str, res: Dict[str, Any]) -> Set[str]:
    hits: Set[str] = set()
    lc = output_text.lower()
    for b in _LOLBAS_BINS:
        if b in lc:
            hits.add(b)
    return hits


__all__ = [
    "CaseContext", "project_from_decode_result",
    "project_from_investigation_outcome",
    "BEHAVIOUR_TAGS", "DETECTION_TYPES", "IMPACT_TAGS",
]


# ══════════════════════════════════════════════════════════════════
# Projection · InvestigationOutcome dict → CaseContext
# ══════════════════════════════════════════════════════════════════
def project_from_investigation_outcome(outcome: Dict[str, Any]
                                          ) -> CaseContext:
    """Project the Workspace-produced structured outcome.

    Per user directive: the engine consumes what the Workspace
    ALREADY DISCOVERED — no re-analysis, no string-matching, no
    payload re-parsing.  This projector is the canonical entry
    point going forward; ``project_from_decode_result`` remains
    for the single legacy caller that still needs on-the-fly
    analysis of a raw paste (compare endpoint).
    """
    o = outcome or {}
    _S = lambda v, d=(): tuple(v) if isinstance(v, (list, tuple)) else d
    _FS = lambda v: frozenset(v) if isinstance(v, (list, tuple, set,
                                                     frozenset)) else frozenset()

    malware = o.get("malware") or {}
    apt      = o.get("apt")     or {}
    iocs     = o.get("iocs")    or {}
    attack   = o.get("attack_pattern") or {}
    scope    = o.get("scope")   or {}

    return CaseContext(
        processes     = _S(o.get("processes")),
        commands      = _S(o.get("commands")),
        files         = _S(o.get("files")),
        registry_keys = _S(o.get("registry_keys")),
        users         = _S(o.get("users")),
        hosts         = _S(o.get("hosts")),
        artifacts     = _S(o.get("artifacts")),
        output_text   = str(o.get("output_text") or ""),

        detection_types  = _FS(o.get("detection_types")),
        behaviors        = _FS(o.get("behaviors")),
        mitre_techniques = _FS(o.get("mitre_techniques")),

        malware_family   = malware.get("family"),
        malware_capabilities = _FS(malware.get("capabilities")),

        apt_group        = apt.get("group"),
        apt_confidence   = str(apt.get("confidence") or ""),

        lolbas_hits      = _S(o.get("lolbas_hits")),

        ips              = _S(iocs.get("ips") or iocs.get("ip")),
        domains          = _S(iocs.get("domains") or iocs.get("domain")),
        urls             = _S(iocs.get("urls") or iocs.get("url")),
        hashes           = _S(iocs.get("hashes")),

        obfuscation_layers = int(attack.get("obfuscation_layers") or 0),
        kill_chain_phases  = _FS(attack.get("kill_chain_phases")),

        impacts            = _FS(o.get("impacts")),
        reached_shellcode  = bool(o.get("reached_shellcode")),

        affected_hosts             = int(scope.get("affected_hosts") or 0),
        privileged_users_affected  = int(scope.get("privileged_users_affected") or 0),
        critical_assets_affected   = int(scope.get("critical_assets_affected") or 0),

        detection_confidence       = str(o.get("detection_confidence") or "low"),
        false_positive_indicators  = _S(o.get("false_positive_indicators")),
    )
