"""Semantic Alias Registry — v1 (curated foundational).

A governed architectural asset that maps *field-name surface forms*
observed in security telemetry to *canonical concepts*
(Host, User, Process, Command, File, Hash, IP, Domain, URL, Email,
Registry, Service, ScheduledTask, Certificate, NetworkConnection,
Port, Protocol, NamedPipe, Mutex, Detection, Alert, MITRE, …).

Governance rules (see NIVXRAY_ARCHITECTURE_VISION.md §Semantic Alias
Registry):

  1. **Canonical Concepts First.** Aliases map to CONCEPTS, never to
     vendors. This registry contains zero vendor knowledge.
  2. **Versioned.** Every registry release carries a version
     (``SEMANTIC_ALIAS_REGISTRY_VERSION``). Downstream stages record
     the version they read for provenance.
  3. **Confidence is intrinsic.** Every alias declares a confidence
     score. Ambiguous surface forms are OMITTED rather than added
     with low confidence — ambiguity is resolved by the Semantic
     Field Mapper (Stage 3) using contextual evidence.
  4. **Curated, not exhaustive.** v1 covers the foundational security
     concepts with their highest-confidence aliases only. Expansion
     is incremental, backed by real telemetry and regression tests.
  5. **Graceful degradation.** ``lookup`` returns an empty list for
     unknown fields — an unknown field is a supported state, never
     an error.

This module is intentionally read-only: no downstream code mutates it.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple

SEMANTIC_ALIAS_REGISTRY_VERSION = "semantic_alias_registry_v1"


CONCEPTS: Tuple[str, ...] = (
    "Host",
    "User",
    "Process",
    "Command",
    "File",
    "Directory",
    "Hash",
    "IP",
    "Domain",
    "URL",
    "Email",
    "Registry",
    "Service",
    "ScheduledTask",
    "Certificate",
    "NetworkConnection",
    "Port",
    "Protocol",
    "NamedPipe",
    "Mutex",
    "Detection",
    "Alert",
    "MITRE",
)


@dataclass(frozen=True)
class Alias:
    """A single declared alias in the registry."""
    surface: str        # normalized form (lowercase, separators stripped)
    concept: str        # canonical concept name (from CONCEPTS)
    confidence: float   # 0.0 .. 1.0 — declared strength of this alias


@dataclass(frozen=True)
class AliasMatch:
    """A resolved lookup result."""
    surface_input: str  # the raw field name as observed
    surface_normalized: str
    concept: str
    confidence: float
    registry_version: str


# ── Foundational aliases ────────────────────────────────────────────
#
# Each row is (normalized_surface, confidence). All normalized surfaces
# are: lowercase, with `_`, `-`, `.`, and whitespace removed.
#
# CONSERVATIVE curation:
#   • 1.00 — unambiguous, universally used across schemas
#   • 0.90 — strong signal with occasional cross-domain overlap
#   • 0.80 — contextually reliable but not stand-alone determinative
#
# Ambiguous surface forms (e.g. bare "path", bare "target", bare
# "name") are deliberately EXCLUDED.  Context-driven resolution is
# the Semantic Field Mapper's responsibility (Stage 3).

_FOUNDATIONAL_ALIASES: Dict[str, List[Tuple[str, float]]] = {
    "Host": [
        ("host", 1.00),
        ("hostname", 1.00),
        ("computer", 1.00),
        ("computername", 1.00),
        ("device", 1.00),
        ("devicename", 1.00),
        ("machine", 1.00),
        ("machinename", 1.00),
        ("hostfqdn", 1.00),
        ("endpoint", 0.90),
        ("asset", 0.80),
    ],
    "User": [
        ("user", 1.00),
        ("username", 1.00),
        ("useraccount", 1.00),
        ("accountname", 0.95),
        ("account", 0.90),
        ("subjectuser", 0.95),
        ("targetuser", 0.95),
        ("principal", 0.85),
        ("login", 0.85),
        ("actor", 0.80),
    ],
    "Process": [
        ("process", 1.00),
        ("processname", 1.00),
        ("image", 0.95),
        ("imagename", 0.95),
        ("imagepath", 0.95),
        ("executable", 0.95),
        ("proc", 0.90),
        ("processid", 0.95),
        ("pid", 0.95),
        ("parentprocessname", 1.00),
        ("parentimage", 0.95),
        ("parentpid", 0.95),
        ("ppid", 0.95),
    ],
    "Command": [
        ("commandline", 1.00),
        ("processcommandline", 1.00),
        ("cmdline", 1.00),
        ("command", 0.90),
        ("arguments", 0.90),
        ("args", 0.85),
    ],
    "File": [
        ("filename", 1.00),
        ("filepath", 1.00),
        ("filefullpath", 1.00),
        ("targetfilename", 1.00),
        ("file", 0.90),
    ],
    "Directory": [
        ("directory", 1.00),
        ("folder", 0.95),
        ("cwd", 1.00),
        ("workingdirectory", 1.00),
        ("currentdirectory", 1.00),
        ("currentworkingdirectory", 1.00),
    ],
    "Hash": [
        ("hash", 0.90),
        ("md5", 1.00),
        ("md5hash", 1.00),
        ("sha1", 1.00),
        ("sha1hash", 1.00),
        ("sha256", 1.00),
        ("sha256hash", 1.00),
        ("sha512", 1.00),
        ("imphash", 1.00),
        ("filehash", 0.95),
        ("hashvalue", 0.90),
    ],
    "IP": [
        ("ip", 0.95),
        ("ipaddress", 1.00),
        ("ipaddr", 1.00),
        ("sourceip", 1.00),
        ("srcip", 1.00),
        ("sourceipaddress", 1.00),
        ("destinationip", 1.00),
        ("dstip", 1.00),
        ("destinationipaddress", 1.00),
        ("remoteip", 0.95),
        ("localip", 0.95),
        ("clientip", 0.95),
        ("serverip", 0.95),
    ],
    "Domain": [
        ("domain", 0.95),
        ("domainname", 1.00),
        ("fqdn", 1.00),
        ("dnsname", 1.00),
        ("dnsquery", 1.00),
        ("requesteddomain", 1.00),
        ("registereddomain", 1.00),
        ("tld", 0.90),
    ],
    "URL": [
        ("url", 1.00),
        ("uri", 0.95),
        ("requesturl", 1.00),
        ("requesturi", 1.00),
        ("targeturl", 1.00),
        ("weburl", 0.95),
        ("referrer", 0.90),
        ("referer", 0.90),
    ],
    "Email": [
        ("email", 0.95),
        ("emailaddress", 1.00),
        ("senderemail", 1.00),
        ("recipientemail", 1.00),
        ("mailfrom", 0.95),
        ("mailto", 0.95),
    ],
    "Registry": [
        ("registrykey", 1.00),
        ("registryvalue", 1.00),
        ("registrypath", 1.00),
        ("regkey", 0.95),
        ("regvalue", 0.95),
        ("registryvaluename", 1.00),
        ("registryvaluedata", 1.00),
    ],
    "Service": [
        ("service", 0.90),
        ("servicename", 1.00),
        ("servicedisplayname", 1.00),
        ("svc", 0.85),
    ],
    "ScheduledTask": [
        ("scheduledtask", 1.00),
        ("taskname", 0.95),
        ("schedtask", 0.95),
    ],
    "Certificate": [
        ("certificate", 0.95),
        ("cert", 0.90),
        ("certname", 0.95),
        ("thumbprint", 1.00),
        ("certificatethumbprint", 1.00),
        ("certificateissuer", 1.00),
        ("certificatesubject", 1.00),
    ],
    "NetworkConnection": [
        ("connection", 0.90),
        ("networkconnection", 1.00),
        ("netflow", 0.95),
        ("flow", 0.85),
        ("conn", 0.85),
    ],
    "Port": [
        ("port", 0.95),
        ("sourceport", 1.00),
        ("srcport", 1.00),
        ("destinationport", 1.00),
        ("dstport", 1.00),
        ("remoteport", 0.95),
        ("localport", 0.95),
    ],
    "Protocol": [
        ("protocol", 1.00),
        ("proto", 0.95),
        ("networkprotocol", 1.00),
        ("transportprotocol", 1.00),
        ("l4protocol", 1.00),
    ],
    "NamedPipe": [
        ("namedpipe", 1.00),
        ("pipe", 0.85),
        ("pipename", 1.00),
    ],
    "Mutex": [
        ("mutex", 1.00),
        ("mutant", 0.95),
        ("mutexname", 1.00),
    ],
    "Detection": [
        ("detection", 0.95),
        ("detectionname", 1.00),
        ("detectiontype", 1.00),
        ("verdict", 0.85),
        ("disposition", 0.85),
    ],
    "Alert": [
        ("alert", 0.90),
        ("alertname", 1.00),
        ("alertid", 1.00),
        ("alertseverity", 1.00),
        ("incident", 0.90),
        ("incidenttype", 1.00),
        ("ruleid", 0.95),
        ("rulename", 0.95),
        ("signature", 0.90),
        ("signatureid", 0.95),
        ("signaturename", 0.95),
    ],
    "MITRE": [
        ("mitreattack", 1.00),
        ("mitreid", 1.00),
        ("techniqueid", 1.00),
        ("tactic", 0.95),
        ("technique", 0.95),
        ("subtechnique", 1.00),
        ("attackid", 0.95),
        ("attacktactic", 1.00),
        ("attacktechnique", 1.00),
    ],
}


# ── Normalization ────────────────────────────────────────────────────

def _normalize(surface: str) -> str:
    """Deterministic normalization of a surface field name.

    Lowercase and strip the four common separator characters used
    across telemetry schemas: underscore, hyphen, dot, whitespace.
    No suffix stripping — governance rule 3 forbids implicit fuzz.
    """
    if surface is None:
        return ""
    out = []
    for ch in str(surface).lower():
        if ch in ("_", "-", ".", " ", "\t"):
            continue
        out.append(ch)
    return "".join(out)


# ── Compiled lookup index (built once at import) ────────────────────

def _build_index() -> Dict[str, Tuple[str, float]]:
    idx: Dict[str, Tuple[str, float]] = {}
    for concept, rows in _FOUNDATIONAL_ALIASES.items():
        if concept not in CONCEPTS:
            raise RuntimeError(
                f"registry integrity: concept {concept!r} not declared "
                f"in CONCEPTS tuple"
            )
        for surface, confidence in rows:
            if surface != _normalize(surface):
                raise RuntimeError(
                    f"registry integrity: alias {surface!r} for "
                    f"concept {concept!r} is not pre-normalized"
                )
            if not 0.0 <= confidence <= 1.0:
                raise RuntimeError(
                    f"registry integrity: confidence {confidence} out "
                    f"of range for {surface!r}"
                )
            if surface in idx:
                prev_concept, _ = idx[surface]
                raise RuntimeError(
                    f"registry integrity: ambiguous alias {surface!r} "
                    f"maps to both {prev_concept!r} and {concept!r}; "
                    f"registry must not create ambiguity"
                )
            idx[surface] = (concept, confidence)
    return idx


_INDEX: Dict[str, Tuple[str, float]] = _build_index()


# ── Public API ──────────────────────────────────────────────────────

def lookup(surface: str) -> List[AliasMatch]:
    """Resolve a raw field-name surface to canonical concept matches.

    Returns an empty list when the field is unknown to the registry —
    an unknown field is a supported state.

    v1 returns at most one match per surface (registry is ambiguity-
    free by construction). List return shape is preserved for forward
    compatibility with future context-driven multi-match variants.
    """
    if not surface:
        return []
    norm = _normalize(surface)
    hit = _INDEX.get(norm)
    if hit is None:
        return []
    concept, confidence = hit
    return [AliasMatch(
        surface_input=surface,
        surface_normalized=norm,
        concept=concept,
        confidence=confidence,
        registry_version=SEMANTIC_ALIAS_REGISTRY_VERSION,
    )]


def concepts() -> Tuple[str, ...]:
    """Return the canonical concept tuple."""
    return CONCEPTS


def aliases_for(concept: str) -> List[Alias]:
    """Return every declared alias for a concept."""
    if concept not in _FOUNDATIONAL_ALIASES:
        return []
    return [Alias(surface=s, concept=concept, confidence=c)
            for s, c in _FOUNDATIONAL_ALIASES[concept]]


def registry_snapshot() -> Dict[str, List[Alias]]:
    """Full registry as a plain dict — useful for provenance dumps."""
    return {c: aliases_for(c) for c in CONCEPTS}


__all__ = [
    "SEMANTIC_ALIAS_REGISTRY_VERSION",
    "CONCEPTS",
    "Alias",
    "AliasMatch",
    "lookup",
    "concepts",
    "aliases_for",
    "registry_snapshot",
]
