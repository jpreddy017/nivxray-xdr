"""Initial evidence-driven rule library.

Each rule is a small, auditable statement of the form:

    IF <evidence-predicate>  THEN <analyst-facing action>

The predicate is the LOAD-BEARING part.  If the predicate returns
False for a case, the rule emits nothing — no static template, no
default recommendation.

Rule authors: every new rule you add here MUST also add a matching
test in ``tests/test_evidence_driven_engine.py`` demonstrating both
a case where it fires and a case where it does NOT.
"""
from __future__ import annotations

from typing import List

from .rules        import RecommendationRule
from .case_context import CaseContext


# ── Predicate helpers (kept local so rule bodies stay readable) ───
def _has_shellcode(c: CaseContext) -> bool:
    return c.reached_shellcode and c.detection_confidence in ("high", "confirmed")


def _has_c2(c: CaseContext) -> bool:
    return bool(c.ips or c.urls or c.domains) and "c2" in c.behaviors


def _has_credential_access(c: CaseContext) -> bool:
    return "credential_access" in c.behaviors


def _is_ransomware(c: CaseContext) -> bool:
    return ("impact" in c.behaviors
            and c.has_any_impact("data_encrypted", "recovery_inhibited"))


def _has_family_attribution(c: CaseContext) -> bool:
    return bool(c.malware_family) and c.detection_confidence in ("high", "confirmed")


# ══════════════════════════════════════════════════════════════════
# Category 1 · INVESTIGATE — analyst enrichment, never destructive
# ══════════════════════════════════════════════════════════════════
INVESTIGATE_RULES: List[RecommendationRule] = [
    RecommendationRule(
        id       = "inv.analyze_ps_chain",
        trigger  = lambda c: ("execution" in c.behaviors and
                                 ("T1059.001" in c.mitre_techniques
                                    or "powershell.exe" in c.processes)),
        action   = "Analyze the PowerShell process chain — parent/child, "
                    "command line, script block content, spawn depth.",
        reason   = "PowerShell execution is confirmed in this case; the "
                    "process tree reveals origin (email macro, browser, "
                    "scheduled task, RDP) and downstream spawns.",
        category = "investigate",
        mitre    = ("T1059.001",),
        priority = "high",
    ),
    RecommendationRule(
        id       = "inv.investigate_download",
        trigger  = lambda c: ("T1105" in c.mitre_techniques
                                 or "downloadstring" in c.output_text.lower()
                                 or "downloadfile" in c.output_text.lower()),
        action   = "Investigate the downloaded payload — capture the file, "
                    "compute hashes, submit to sandbox, correlate with the "
                    "endpoint's proxy/DNS logs.",
        reason   = "Download-and-execute pattern detected in the decoded "
                    "content — the fetched payload is the next stage.",
        category = "investigate",
        mitre    = ("T1105",),
        priority = "high",
    ),
    RecommendationRule(
        id       = "inv.check_persistence",
        trigger  = lambda c: "persistence" in c.behaviors,
        action   = "Enumerate persistence mechanisms — Run keys, scheduled "
                    "tasks, services, WMI subscriptions, startup folders.",
        reason   = "Persistence-related APIs / commands observed in the "
                    "decoded content.",
        category = "investigate",
        mitre    = ("T1547", "T1053"),
        priority = "medium",
    ),
    RecommendationRule(
        id       = "inv.check_credential_theft",
        trigger  = _has_credential_access,
        action   = "Examine whether credentials were harvested — Security "
                    "log 4624/4672, LSASS access, Mimikatz artifacts.",
        reason   = "Credential-access tooling markers observed in the "
                    "decoded content.",
        category = "investigate",
        mitre    = ("T1003",),
        priority = "critical",
    ),
]


# ══════════════════════════════════════════════════════════════════
# Category 2 · HUNT — search across the fleet for the same pattern
# ══════════════════════════════════════════════════════════════════
HUNT_RULES: List[RecommendationRule] = [
    RecommendationRule(
        id       = "hunt.encoded_powershell",
        trigger  = lambda c: "T1027" in c.mitre_techniques
                              and "T1059.001" in c.mitre_techniques,
        action   = 'Hunt: process_name:"powershell.exe" AND '
                    '(command_line:"-EncodedCommand" OR command_line:"-enc")',
        reason   = "This case ran PowerShell with an encoded command — "
                    "hunt for other endpoints executing the same pattern.",
        category = "hunt",
        mitre    = ("T1059.001", "T1027"),
        priority = "high",
    ),
    RecommendationRule(
        id       = "hunt.b64_gzip_loader",
        trigger  = lambda c: c.obfuscation_layers >= 2
                              and "T1140" in c.mitre_techniques,
        action   = 'Hunt: process_name:"powershell.exe" AND '
                    'command_line:"FromBase64String" AND '
                    'command_line:"GzipStream"',
        reason   = "Base64 + GZip in-memory loader idiom detected — a "
                    "canonical stager pattern used by multiple frameworks.",
        category = "hunt",
        mitre    = ("T1140",),
        priority = "high",
    ),
    RecommendationRule(
        id       = "hunt.byte_array_xor",
        trigger  = lambda c: ("T1055" in c.mitre_techniques
                                 or "T1620" in c.mitre_techniques)
                              and c.obfuscation_layers >= 3,
        action   = 'Hunt: process_name:"powershell.exe" AND '
                    'command_line:"-bxor" AND command_line:"[Byte[]]"',
        reason   = "Byte-array XOR loop is the signature idiom of "
                    "in-memory shellcode stagers.",
        category = "hunt",
        mitre    = ("T1055", "T1620"),
        priority = "high",
    ),
]


def _ip_block_rules(ips) -> List[RecommendationRule]:
    """Concrete IP-block rules — one per promoted IP.  Generated at
    engine-eval time, not at import time, so scope-string is bound."""
    out = []
    for ip in ips:
        out.append(RecommendationRule(
            id       = f"contain.block_ip:{ip}",
            trigger  = lambda c, _ip=ip: _ip in c.ips and _has_c2(c),
            action   = f"Block outbound traffic to {ip} at the perimeter "
                        "firewall + add to DNS sinkhole.",
            reason   = f"IP {ip} was promoted from the decoded payload as "
                        "a C2 endpoint.",
            category = "contain",
            scope    = (f"ip:{ip}",),
            mitre    = ("T1071",),
            priority = "critical",
            requires_confirmation = False,
        ))
    return out


def _url_block_rules(urls) -> List[RecommendationRule]:
    out = []
    for u in urls:
        out.append(RecommendationRule(
            id       = f"contain.block_url:{u}",
            trigger  = lambda c, _u=u: _u in c.urls and _has_c2(c),
            action   = f"Block URL {u} at the proxy / web-gateway.",
            reason   = f"URL {u} was promoted from the decoded payload.",
            category = "contain",
            scope    = (f"url:{u}",),
            mitre    = ("T1071",),
            priority = "critical",
        ))
    return out


def _domain_sinkhole_rules(domains) -> List[RecommendationRule]:
    out = []
    for d in domains:
        out.append(RecommendationRule(
            id       = f"contain.sinkhole_domain:{d}",
            trigger  = lambda c, _d=d: _d in c.domains and _has_c2(c),
            action   = f"Sinkhole domain {d} in the resolver + block at "
                        "the firewall.",
            reason   = f"Domain {d} was resolved from the decoded payload.",
            category = "contain",
            scope    = (f"domain:{d}",),
            mitre    = ("T1071.001",),
            priority = "critical",
        ))
    return out


# ══════════════════════════════════════════════════════════════════
# Category 3 · CONTAIN — evidence-supported isolation actions
# ══════════════════════════════════════════════════════════════════
CONTAIN_RULES: List[RecommendationRule] = [
    RecommendationRule(
        id       = "contain.isolate_host",
        trigger  = _has_shellcode,
        action   = "Isolate the affected host via EDR network containment "
                    "OR VLAN quarantine.",
        reason   = "Shellcode terminal payload reached — treat as active "
                    "compromise; prevent lateral movement.",
        category = "contain",
        mitre    = ("T1055", "T1620"),
        scope    = ("host:affected",),
        priority = "critical",
        requires_confirmation = True,
    ),
    RecommendationRule(
        id       = "contain.kill_powershell",
        trigger  = lambda c: (_has_shellcode(c)
                                 and "powershell.exe" in c.processes),
        action   = "Kill running powershell.exe / pwsh.exe on the affected "
                    "host (procdump before termination if triage-worthy).",
        reason   = "In-memory shellcode reached via PowerShell — stopping "
                    "the process halts the beacon before persistence "
                    "is established.",
        category = "contain",
        mitre    = ("T1059.001",),
        scope    = ("process:powershell.exe",),
        priority = "critical",
        requires_confirmation = True,
    ),
    RecommendationRule(
        id       = "contain.preserve_memory",
        trigger  = _has_shellcode,
        action   = "Collect a full memory image (winpmem / DumpIt) BEFORE "
                    "any reboot.",
        reason   = "Volatile memory holds the unpacked shellcode and "
                    "beacon config — lost on reboot.",
        category = "contain",
        priority = "high",
        prerequisites = ("Host isolated first — do not collect over the "
                          "network from a still-connected compromised host.",),
    ),
]


# ══════════════════════════════════════════════════════════════════
# Category 4 · ERADICATE — actions that require evidence of impact
# ══════════════════════════════════════════════════════════════════
ERADICATE_RULES: List[RecommendationRule] = [
    RecommendationRule(
        id       = "erad.rotate_credentials",
        trigger  = _has_credential_access,
        action   = "Reset every credential that authenticated to the "
                    "affected host in the last 72 hours (including "
                    "service accounts).",
        reason   = "Credential-access markers observed — credentials on "
                    "the host may already be compromised.",
        category = "eradicate",
        mitre    = ("T1003",),
        scope    = ("credential:affected-users",),
        priority = "critical",
        requires_confirmation = True,
        prerequisites = ("Verify the account list from Windows Security "
                          "log EIDs 4624 / 4672 before mass reset.",),
    ),
    RecommendationRule(
        id       = "erad.reimage_ransomware",
        trigger  = _is_ransomware,
        action   = "Re-image affected hosts from a known-good baseline.",
        reason   = "Ransomware behaviour observed — file integrity on the "
                    "host cannot be trusted.",
        category = "eradicate",
        priority = "critical",
        requires_confirmation = True,
        prerequisites = (
            "Confirm the host list from encryption artifacts before "
            "starting.",
            "Restore only after full containment.",
        ),
    ),
]


# ══════════════════════════════════════════════════════════════════
# Category 5 · RECOVER — evidence of impact required
# ══════════════════════════════════════════════════════════════════
RECOVER_RULES: List[RecommendationRule] = [
    RecommendationRule(
        id       = "rec.restore_backups",
        trigger  = _is_ransomware,
        action   = "Restore affected data from offline / immutable backups "
                    "after eradication is complete.",
        reason   = "Data-encryption impact observed — recovery requires "
                    "clean backups.",
        category = "recover",
        mitre    = ("T1490",),
        priority = "high",
        prerequisites = ("Eradication complete on the affected hosts.",),
    ),
]


# ══════════════════════════════════════════════════════════════════
# Category 6 · HARDEN — always-applicable prevention (bounded, small)
# The user directive: hardening MUST also be evidence-relevant — the
# engine only adds hardening when the underlying weakness was
# demonstrated by the case, never as a generic checklist.
# ══════════════════════════════════════════════════════════════════
HARDEN_RULES: List[RecommendationRule] = [
    RecommendationRule(
        id       = "harden.ps_script_block_logging",
        trigger  = lambda c: "T1059.001" in c.mitre_techniques,
        action   = "Enable PowerShell Script Block Logging (EID 4104) "
                    "and Module Logging (EID 4103) fleet-wide via GPO / "
                    "Intune.",
        reason   = "This case's decoded payload would have been captured "
                    "in the Windows event log at execution time if these "
                    "were enabled.",
        category = "harden",
        mitre    = ("T1059.001",),
        priority = "high",
    ),
    RecommendationRule(
        id       = "harden.egress_restrict_ps",
        trigger  = lambda c: ("T1105" in c.mitre_techniques
                                 and "c2" in c.behaviors),
        action   = "Restrict outbound network access from powershell.exe "
                    "at the endpoint firewall.",
        reason   = "Download-and-execute + C2 pattern demonstrated in "
                    "this case — legitimate PS workflows rarely need "
                    "direct internet access.",
        category = "harden",
        mitre    = ("T1105", "T1071"),
        priority = "medium",
    ),
    RecommendationRule(
        id       = "harden.lolbas_allowlist",
        trigger  = lambda c: bool(c.lolbas_hits),
        action   = ("Restrict execution of the following LOLBAS binaries "
                     "via WDAC / AppLocker: "
                     + ", ".join(sorted({b for b in [] if b}))
                     + " — see scope."),
        reason   = "This case abused a legitimate Windows binary that "
                    "is commonly whitelisted.  Constrain it.",
        category = "harden",
        priority = "medium",
    ),
]


# ══════════════════════════════════════════════════════════════════
# Public entry — assemble the full rule set for a case
# ══════════════════════════════════════════════════════════════════
def rules_for(ctx: CaseContext) -> List[RecommendationRule]:
    """Return every static rule + the IOC-scoped rules generated
    from the case's promoted IPs / URLs / domains."""
    rules: List[RecommendationRule] = []
    rules.extend(INVESTIGATE_RULES)
    rules.extend(HUNT_RULES)
    rules.extend(CONTAIN_RULES)
    rules.extend(ERADICATE_RULES)
    rules.extend(RECOVER_RULES)
    rules.extend(HARDEN_RULES)
    rules.extend(_ip_block_rules(ctx.ips))
    rules.extend(_url_block_rules(ctx.urls))
    rules.extend(_domain_sinkhole_rules(ctx.domains))
    return rules


__all__ = ["rules_for"]
