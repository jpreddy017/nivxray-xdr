"""Deterministic Behavior Extractor + Kill-Chain / MITRE mapper.

Fixes the P1 gap where every PowerShell command lands in the
``Execution`` swim-lane.  Each command may exhibit MULTIPLE behaviors;
each behavior maps to at LEAST one MITRE technique and Kill-Chain
stage.  Deduplication (P1.5) then folds identical behaviors from
multiple evidence items into a single node.

The mapping table is intentionally small and deterministic — no NLP,
no LLM.  Growing the table is O(1) per new behavior; the extractor
never invents a mapping.

Shape returned to the caller:

    Behavior(
        id                = "download_cradle",
        title             = "Remote Payload Retrieval",
        kill_chain        = ["Delivery"],
        mitre_techniques  = ["T1105"],
        mitre_tactics=["Command and Control"],
        confidence        = 0.98,
        evidence          = [BehaviorEvidence(text="System.Net.WebClient", location="cmd.5")],
        description       = "Uses WebClient / DownloadString / IWR to retrieve payloads.",
    )

Downstream (Phase 6 Reasoning Engine) consumes these to render swim
lanes, attack story, and recommendations.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from services.normalization.powershell_folding import fold_text


# ─── Base-64 recursive-decode helpers (P0.c) ──────────────────────────
# When the outer text contains a base64 blob (either as an
# ``-EncodedCommand`` argument or a ``FromBase64String('...')`` literal),
# we decode it as BOTH utf-8 and utf-16-le and expose the resulting text
# to the behavior scanner.  This is what lets us surface behaviors
# like WMI / service enumeration that live inside the payload.

import base64

_B64_RE = re.compile(
    r"""
    (?:
      -[eE](?:nc|ncodedcommand)\b\s+       # -enc <blob>
      (?P<enc>[A-Za-z0-9+/=]{20,})
    )
    |
    (?:
      FromBase64String\s*\(\s*             # FromBase64String('<blob>')
      ['"](?P<fbs>[A-Za-z0-9+/=]{20,})['"]
    )
    """,
    re.VERBOSE,
)


def _decode_embedded_base64(text: str) -> List[str]:
    """Return every plausible decoded payload found in ``text``.

    Tries UTF-8 and UTF-16-LE — the two encodings PowerShell actually
    uses.  Silently drops blobs that don't decode cleanly.
    """
    out: List[str] = []
    for m in _B64_RE.finditer(text):
        blob = m.group("enc") or m.group("fbs")
        if not blob:
            continue
        # Pad to a multiple of 4.
        padded = blob + "=" * ((4 - len(blob) % 4) % 4)
        try:
            raw = base64.b64decode(padded, validate=False)
        except Exception:
            continue
        for encoding in ("utf-16-le", "utf-8"):
            try:
                decoded = raw.decode(encoding, errors="strict")
            except Exception:
                continue
            # Require SOME printable ratio to avoid random-byte noise.
            printable = sum(1 for c in decoded if 32 <= ord(c) < 127 or c in "\n\r\t")
            if printable >= max(4, len(decoded) // 2):
                out.append(decoded)
                break
    return out


# ─── Data model ───────────────────────────────────────────────────────
@dataclass
class BehaviorEvidence:
    text:     str                 # exact substring that fired the rule
    location: Optional[str] = None  # e.g. "cmd.3", "line.42", "block.2"


@dataclass
class Behavior:
    id:                str
    title:             str
    kill_chain:        List[str]
    mitre_techniques:  List[str]
    mitre_tactics:     List[str]        # PLURAL — R8 canonical: one behavior may span multiple tactics
    confidence:        float
    description:       str
    severity:          str = "medium"   # "low" | "medium" | "high" | "critical" — deterministic tier
    order:             int = 0          # deterministic chronology for timelines / story
    evidence:          List[BehaviorEvidence] = field(default_factory=list)

    # ── Backwards-compat shim (existing callers used .mitre_tactic) ──
    @property
    def mitre_tactic(self) -> str:
        """Deprecated singular alias — returns the primary tactic (first element).

        New code MUST use ``mitre_tactics`` (plural) so a single behavior
        can legitimately appear in multiple ATT&CK swim lanes per the
        canonical model (R8).
        """
        return self.mitre_tactics[0] if self.mitre_tactics else ""

    def merge(self, other: "Behavior") -> None:
        """Merge another Behavior's evidence into this one (P1.5)."""
        seen = {(e.text, e.location) for e in self.evidence}
        for e in other.evidence:
            key = (e.text, e.location)
            if key not in seen:
                self.evidence.append(e)
                seen.add(key)
        # Confidence rises with evidence — capped at 0.99.
        self.confidence = min(0.99, self.confidence + 0.03 * (len(other.evidence) or 1))


# ─── Behavior rules (deterministic — patterns are case-insensitive) ───
# Each rule is:
#   id, title, kill_chain[], mitre_techniques[], mitre_tactic,
#   base_confidence, description, patterns[]
#
# ``patterns`` is a list of compiled regexes; ANY match fires the rule.
_RULES: List[Dict[str, Any]] = [
    dict(
        id="execution_policy_bypass",
        title="Execution Policy Bypass",
        kill_chain=["Defense Evasion"],
        mitre_techniques=["T1562.001"],
        mitre_tactics=["Defense Evasion"],
        base_confidence=0.95,
        description="PowerShell execution policy is bypassed, disabling script signing enforcement.",
        patterns=[
            r"-ExecutionPolicy\s+Bypass\b",
            r"-EP\s+Bypass\b",
            r"-ExecutionBypass\b",
        ],
    ),
    dict(
        id="hidden_window",
        title="Hidden PowerShell Window",
        kill_chain=["Defense Evasion"],
        mitre_techniques=["T1564.003"],
        mitre_tactics=["Defense Evasion"],
        base_confidence=0.9,
        description="Runs PowerShell with a hidden window — reduces user-visible signals.",
        patterns=[
            r"-w(?:indow)?style?\s+hidden\b",
            r"-w\s+hidden\b",
        ],
    ),
    dict(
        id="encoded_command",
        title="Encoded Command (Base64 / UTF-16)",
        kill_chain=["Defense Evasion", "Execution"],
        mitre_techniques=["T1027", "T1059.001"],
        mitre_tactics=["Defense Evasion"],
        base_confidence=0.95,
        description="Uses -EncodedCommand or FromBase64String to hide the payload from static scanners.",
        patterns=[
            r"-e(?:nc|ncodedcommand)\b",
            r"FromBase64String\s*\(",
        ],
    ),
    dict(
        id="in_memory_execution",
        title="In-Memory Execution (IEX / Invoke-Expression)",
        kill_chain=["Execution"],
        mitre_techniques=["T1059.001"],
        mitre_tactics=["Execution"],
        base_confidence=0.98,
        description="Executes decoded / downloaded PowerShell directly in memory.",
        patterns=[
            r"\bIEX\b",
            r"\bInvoke-Expression\b",
            r"\|\s*iex\b",
        ],
    ),
    dict(
        id="download_cradle",
        title="Remote Payload Retrieval (Download Cradle)",
        kill_chain=["Delivery", "Command and Control"],
        mitre_techniques=["T1105"],
        mitre_tactics=["Command and Control"],
        base_confidence=0.97,
        description="Uses System.Net.WebClient / DownloadString / Invoke-WebRequest to fetch remote content.",
        patterns=[
            r"System\.Net\.WebClient\b",
            r"\bNet\.WebClient\b",
            r"\.DownloadString\s*\(",
            r"\.DownloadFile\s*\(",
            r"\.DownloadData\s*\(",
            r"Invoke-WebRequest\b",
            r"\biwr\b",
        ],
    ),
    dict(
        id="wmi_process_creation",
        title="WMI Process Creation",
        kill_chain=["Execution", "Lateral Movement"],
        mitre_techniques=["T1047"],
        mitre_tactics=["Execution"],
        base_confidence=0.95,
        description="Creates a process via WMI (Win32_Process Create) — common for stealthy execution or lateral movement.",
        patterns=[
            r"Invoke-WmiMethod\b",
            r"Win32_Process\b",
            r"WMI(Object)?\b.{0,60}?Create\b",
        ],
    ),
    dict(
        id="service_enumeration",
        title="Service Enumeration",
        kill_chain=["Reconnaissance"],
        mitre_techniques=["T1007"],
        mitre_tactics=["Discovery"],
        base_confidence=0.9,
        description="Enumerates services — common host-reconnaissance step.",
        patterns=[
            r"\bGet-Service\b",
            r"\bsc\.exe\b\s+query",
        ],
    ),
    dict(
        id="proxy_credential_theft",
        title="Ambient Credential Reuse via System Proxy",
        kill_chain=["Defense Evasion", "Credential Access"],
        mitre_techniques=["T1090", "T1550"],
        mitre_tactics=["Defense Evasion"],
        base_confidence=0.88,
        description="Reuses the current user's cached proxy credentials to blend in with legitimate traffic.",
        patterns=[
            r"\[Net\.CredentialCache\]::DefaultCredentials\b",
            r"GetSystemWebProxy\b",
        ],
    ),
    dict(
        id="string_concat_obfuscation",
        title="String-Concatenation Obfuscation",
        kill_chain=["Defense Evasion"],
        mitre_techniques=["T1027"],
        mitre_tactics=["Defense Evasion"],
        base_confidence=0.92,
        description="Splits identifiers across '+'-joined literals to evade static string matching.",
        patterns=[
            # 3+ adjacent 1-6 char quoted literals joined by +
            r"(?:'[^']{1,6}'\s*\+\s*){2,}'[^']{1,6}'",
            r"(?:\"[^\"]{1,6}\"\s*\+\s*){2,}\"[^\"]{1,6}\"",
        ],
    ),
    dict(
        id="variable_alias_hiding",
        title="Variable-Alias Hiding",
        kill_chain=["Defense Evasion"],
        mitre_techniques=["T1027"],
        mitre_tactics=["Defense Evasion"],
        base_confidence=0.86,
        description="Assigns a namespace/class to a variable so subsequent references bypass name-based detection.",
        patterns=[
            # Set-Item / Set-Variable   <name-or-quoted-name>  ( [Type]  or  [Type]::
            # Handles the folded form (`Set-Item 'Variable:OB' ([Type](...))`)
            # AND the raw form (`Set-Variable OB ([Type](...))`).
            r"Set-(?:Item|Variable)\s+"
            r"(?:'[^']*'|\"[^\"]*\"|(?:Variable:)?[A-Za-z_][A-Za-z0-9_]*)"
            r"\s+\(?\[Type\]",
        ],
    ),
]

# Compile once
for _r in _RULES:
    _r["_compiled"] = [re.compile(p, re.IGNORECASE) for p in _r["patterns"]]


# ─── Extraction ───────────────────────────────────────────────────────
def extract_behaviors(text: str,
                       *, location_prefix: Optional[str] = None,
                       auto_fold: bool = True,
                       recurse_decode: bool = True) -> List[Behavior]:
    """Scan ``text`` and return a de-duplicated list of behaviors.

    ``location_prefix`` is stamped into every evidence entry so
    downstream code can trace back to the source (e.g. ``"cmd.3"``).

    ``auto_fold`` runs the PowerShell constant folder first so folded
    forms (``System.Net.WebClient``) become detectable.  The evidence
    entries always cite the FOLDED form for readability.

    ``recurse_decode`` (P0.c) also scans decoded base64 payloads found
    inside the text — this surfaces behaviors like WMI / service
    enumeration that live INSIDE the -EncodedCommand blob.
    """
    if not isinstance(text, str) or not text:
        return []
    scanned = fold_text(text) if auto_fold else text
    # Concatenate decoded payloads so a SINGLE scan picks up behaviors
    # from both the outer command AND the inner payload.  Cite the
    # decoded frame in evidence via ``location_prefix + ".decoded"``.
    if recurse_decode:
        decoded_parts = _decode_embedded_base64(scanned)
        for dp in decoded_parts:
            # Fold the decoded payload too — malware often layers folds.
            scanned = scanned + "\n" + fold_text(dp)
    matches: Dict[str, Behavior] = {}
    for rule in _RULES:
        rid = rule["id"]
        rule_matches: List[BehaviorEvidence] = []
        for pat in rule["_compiled"]:
            for m in pat.finditer(scanned):
                rule_matches.append(BehaviorEvidence(
                    text=m.group(0),
                    location=location_prefix,
                ))
        if not rule_matches:
            continue
        # Confidence rises with evidence count — capped at 0.99.
        conf = min(0.99, rule["base_confidence"] + 0.02 * (len(rule_matches) - 1))
        # Severity — deterministic tier from base confidence + evidence corroboration.
        if   conf >= 0.97: sev = "critical"
        elif conf >= 0.90: sev = "high"
        elif conf >= 0.75: sev = "medium"
        else:              sev = "low"
        matches[rid] = Behavior(
            id=rid,
            title=rule["title"],
            kill_chain=list(rule["kill_chain"]),
            mitre_techniques=list(rule["mitre_techniques"]),
            mitre_tactics=list(rule["mitre_tactics"]),
            confidence=round(conf, 3),
            description=rule["description"],
            severity=sev,
            order=len(matches),       # deterministic insertion order
            evidence=rule_matches,
        )
    return list(matches.values())


def correlate_behaviors(behavior_lists: List[List[Behavior]]) -> List[Behavior]:
    """P1.5 · Merge identical behaviors from multiple evidence sources.

    Two behaviors with the same ``id`` collapse into one node whose
    ``evidence`` is the union of the two evidence lists.  Confidence
    rises with corroboration (capped at 0.99).
    """
    merged: Dict[str, Behavior] = {}
    for lst in behavior_lists:
        for b in lst:
            if b.id in merged:
                merged[b.id].merge(b)
            else:
                # Copy to avoid mutating the caller's Behavior
                merged[b.id] = Behavior(
                    id=b.id, title=b.title,
                    kill_chain=list(b.kill_chain),
                    mitre_techniques=list(b.mitre_techniques),
                    mitre_tactics=list(b.mitre_tactics),
                    confidence=b.confidence,
                    description=b.description,
                    severity=b.severity,
                    order=b.order,
                    evidence=list(b.evidence),
                )
    # Deterministic ordering — by kill-chain phase, then behavior id.
    _PHASE_ORDER = {
        "Reconnaissance": 0, "Delivery": 1, "Execution": 2,
        "Defense Evasion": 3, "Credential Access": 4, "Discovery": 5,
        "Lateral Movement": 6, "Command and Control": 7,
        "Actions on Objectives": 8, "Impact": 9,
    }
    def _sort_key(b: Behavior) -> Tuple[int, str]:
        first_phase = b.kill_chain[0] if b.kill_chain else "zzz"
        return (_PHASE_ORDER.get(first_phase, 99), b.id)
    return sorted(merged.values(), key=_sort_key)


# ─── Convenience projections ──────────────────────────────────────────
def to_lane_map(behaviors: List[Behavior]) -> Dict[str, List[Behavior]]:
    """Group behaviors by their primary kill-chain lane — used by the
    Attack Lifecycle diagram.  A behavior with multiple lanes appears
    in EACH of them."""
    lanes: Dict[str, List[Behavior]] = {}
    for b in behaviors:
        for phase in (b.kill_chain or ["Uncategorised"]):
            lanes.setdefault(phase, []).append(b)
    return lanes


def to_mitre_techniques(behaviors: List[Behavior]) -> List[Dict[str, Any]]:
    """Return a de-duplicated list of MITRE technique dicts, each
    citing the behaviors + evidence that fired it."""
    tech: Dict[str, Dict[str, Any]] = {}
    for b in behaviors:
        for tid in b.mitre_techniques:
            row = tech.setdefault(tid, {"id": tid, "behaviors": [], "evidence_count": 0})
            row["behaviors"].append(b.id)
            row["evidence_count"] += len(b.evidence)
    # Deterministic order
    return sorted(tech.values(), key=lambda r: r["id"])
