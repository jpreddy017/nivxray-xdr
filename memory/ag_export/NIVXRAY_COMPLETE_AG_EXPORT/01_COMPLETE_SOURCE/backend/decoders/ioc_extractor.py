"""Generic IOC extractor — intelligence plugin.

Scans any textual payload for common Indicators of Compromise:
    * URLs (http/https/ftp/file)
    * IPv4 addresses (with light private/RFC1918 filtering surfaced as tradecraft)
    * Domains (dotted, with TLD sanity)
    * Email addresses
    * File hashes (MD5, SHA1, SHA256)
    * Bitcoin addresses (legacy + bech32)
    * Windows/Unix file paths
    * PowerShell / CMD tell-tales

Design
------
* category="intelligence" — the orchestrator runs it in the post-decode pass
  over every trace layer's preview AND the final payload, so IOCs are captured
  even if a downstream decoder mangles them.
* Non-destructive: `output` is left empty (intelligence plugins don't transform).
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Set

from engine.decoder_base import BaseDecoder
from engine.entity_classifier import (
    classify_token,
    _slice_context,
    KIND_IPV4,
    KIND_WINDOWS_BUILD,
    KIND_SOFTWARE_VERSION,
    KIND_GENERIC_DOTTED_QUAD,
)
from engine.models import (
    AnalysisContext,
    DetectResult,
    Fingerprint,
    MitreHint,
    PluginResult,
    TradecraftFlag,
)
from engine.registry import DecoderRegistry


_RX_URL = re.compile(
    r"""(?i)\b(?:https?|ftp|file)://[^\s"'<>{}|\\^`]+""",
)
_RX_IPV4 = re.compile(
    r"""\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}\b""",
)
_RX_DOMAIN = re.compile(
    r"""(?i)\b(?=[a-z0-9-]{1,63}\.)(?!-)(?:[a-z0-9-]{1,63}\.)+"""
    r"""(?:com|net|org|io|dev|xyz|top|info|biz|cn|ru|us|uk|de|fr|jp|in|br|ca|"""
    r"""au|nl|it|es|se|no|fi|dk|pl|cz|gr|be|ch|at|tv|cc|me|co|ws|pw|club|"""
    r"""online|site|store|space|website|link|live|host|tech|ai|app|cloud)\b"""
)
_RX_EMAIL = re.compile(
    r"""(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,24}\b"""
)
_RX_MD5 = re.compile(r"""(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])""")
_RX_SHA1 = re.compile(r"""(?<![0-9a-fA-F])[0-9a-fA-F]{40}(?![0-9a-fA-F])""")
_RX_SHA256 = re.compile(r"""(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])""")
_RX_BTC = re.compile(
    r"""\b(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{25,90})\b"""
)
_RX_WIN_PATH = re.compile(
    r"""(?:[A-Za-z]:\\[^\s<>"'|?*\r\n]{1,256}|\\\\[^\s<>"'|?*\r\n]{2,256})""",
)
_RX_UNIX_PATH = re.compile(
    r"""(?<![A-Za-z0-9])/(?:etc|var|usr|opt|tmp|home|root|bin|sbin|dev)/[^\s"'<>|;&`\r\n]{1,256}""",
)


def _extract_all(text: str) -> Dict[str, List[str]]:
    if not text:
        return {}
    out: Dict[str, Set[str]] = {
        "urls": set(),
        "ips": set(),
        "domains": set(),
        "emails": set(),
        "md5": set(),
        "sha1": set(),
        "sha256": set(),
        "bitcoin_addresses": set(),
        "file_paths": set(),
        "windows_builds": set(),
        "software_versions": set(),
        "generic_dotted_quads": set(),
    }
    # Track entity-classifier decisions per token so callers (evidence
    # graph, API responses, UI) can inspect exactly *why* a dotted-quad
    # was routed to a given bucket.
    classifications: List[dict] = []
    for m in _RX_URL.findall(text):
        out["urls"].add(m.rstrip(".,;:)]"))
    # ── URL-segment mask ────────────────────────────────────────
    # Hash regexes match ANY 32/40/64-char hex sequence — including
    # URL path segments (GitHub Gist IDs, S3 keys, blob paths, etc.).
    # Mask URL substrings so the hash regexes cannot fire inside a URL
    # path. Without this the analyst sees false-positive MD5 / SHA1
    # IOCs derived from URL segments (e.g. a GitHub Gist ID becomes a
    # "malware MD5") — a P0 correctness bug that erodes analyst trust.
    # Also strip reversed-URL substrings (ops.py reverses layers to
    # catch dEsRevER-style obfuscation — but a reversed URL still
    # contains the same hex path chars that would look like a hash).
    hash_scan_text = _RX_URL.sub(lambda m: " " * (m.end() - m.start()), text)
    hash_scan_text = re.sub(r"[^\s\"'<>\)|&;`]{3,}//:s?ptth",
                             lambda m: " " * (m.end() - m.start()),
                             hash_scan_text, flags=re.IGNORECASE)
    for m in _RX_IPV4.finditer(text):
        token = m.group(0)
        ctx = _slice_context(text, m.start(), m.end())
        result = classify_token(token, ctx)
        classifications.append(result.to_dict())
        if result.kind == KIND_IPV4:
            out["ips"].add(token)
        elif result.kind == KIND_WINDOWS_BUILD:
            out["windows_builds"].add(token)
        elif result.kind == KIND_SOFTWARE_VERSION:
            out["software_versions"].add(token)
        elif result.kind == KIND_GENERIC_DOTTED_QUAD:
            out["generic_dotted_quads"].add(token)
    # Domains — but skip anything already inside an extracted URL host.
    covered = " ".join(out["urls"])
    for m in _RX_DOMAIN.findall(text):
        if m.lower() in covered.lower():
            continue
        out["domains"].add(m)
    for m in _RX_EMAIL.findall(text):
        out["emails"].add(m)
    for m in _RX_SHA256.findall(hash_scan_text):
        out["sha256"].add(m.lower())
    for m in _RX_SHA1.findall(hash_scan_text):
        # SHA1 length collides with nothing but MD5+extra; SHA256 was already
        # stripped by the negative-lookbehind logic upstream.
        out["sha1"].add(m.lower())
    for m in _RX_MD5.findall(hash_scan_text):
        # MD5 sequences that also appear inside a SHA1/SHA256 hit are already
        # consumed by the longer patterns via non-overlapping findall.
        # De-dupe against sha1/sha256 to keep the analyst report tidy.
        if any(m.lower() in s for s in out["sha1"] | out["sha256"]):
            continue
        out["md5"].add(m.lower())
    for m in _RX_BTC.findall(text):
        out["bitcoin_addresses"].add(m)
    for m in _RX_WIN_PATH.findall(text):
        out["file_paths"].add(m)
    for m in _RX_UNIX_PATH.findall(text):
        out["file_paths"].add(m)
    result_map = {k: sorted(v)[:25] for k, v in out.items() if v}
    if classifications:
        result_map["_entity_classifications"] = classifications[:64]
    return result_map


class IocExtractor(BaseDecoder):
    id = "ioc-extractor"
    name = "Generic IOC Extractor"
    category = "intelligence"
    cost = 1
    tags = ("ioc", "url", "ip", "domain", "hash", "email", "bitcoin", "file-path")
    schema_version = "1.0"

    def detect(self, payload: str, fp: Fingerprint, ctx: AnalysisContext) -> DetectResult:
        if not payload or len(payload) < 4:
            return DetectResult(confidence=0.0, why="Empty / too short")
        # Cheap probe: does anything look like a URL / IP / hash?
        if not any(rx.search(payload) for rx in (_RX_URL, _RX_IPV4, _RX_EMAIL,
                                                  _RX_MD5, _RX_BTC, _RX_WIN_PATH,
                                                  _RX_UNIX_PATH)):
            # domain probe (slightly slower)
            if not _RX_DOMAIN.search(payload):
                return DetectResult(confidence=0.0, why="No IOC-shaped substrings")
        return DetectResult(confidence=0.6, why="Candidate IOC patterns present")

    def decode(self, payload: str, args: Dict[str, Any], ctx: AnalysisContext) -> PluginResult:
        iocs = _extract_all(payload)
        if not iocs:
            return PluginResult(output="", notes=["ioc-extractor: nothing extracted"])
        mitre: List[MitreHint] = []
        tradecraft: List[TradecraftFlag] = []
        if iocs.get("urls") or iocs.get("domains") or iocs.get("ips"):
            mitre.append(MitreHint(
                id="T1071", technique="Application Layer Protocol",
                tactic="Command and Control",
                evidence="Network IOCs surfaced by IOC extractor",
                source="heuristic",
            ))
        if iocs.get("bitcoin_addresses"):
            mitre.append(MitreHint(
                id="T1657", technique="Financial Theft",
                tactic="Impact",
                evidence="Bitcoin address in payload",
                source="heuristic",
            ))
            tradecraft.append(TradecraftFlag(
                flag="crypto-wallet-hit", severity="high",
                evidence=f"{len(iocs['bitcoin_addresses'])} bitcoin address(es) found",
            ))
        return PluginResult(
            output="",                          # intelligence plugin — no transform
            iocs=iocs,
            mitre_hints=mitre,
            tradecraft=tradecraft,
            notes=[f"Extracted IOCs across {len(iocs)} categor(y|ies)"],
            explanation=(
                "Scanned payload for standard IOC shapes and surfaced the hits."
            ),
        )


DecoderRegistry.register(IocExtractor())
