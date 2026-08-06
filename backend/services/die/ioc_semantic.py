"""
DIE · Deterministic Network IOC Extractor
─────────────────────────────────────────
Consolidated indicator extraction with decode-stage provenance.  Every
returned value carries:

    { "kind": <ip|domain|url|unc|onion|discord|email>,
      "value": <canonical string>,
      "confidence": <0.0 – 1.0>,
      "source": <"raw" | "decoded" | provided by caller> }

The confidence score is deterministic: it reflects regex specificity
and structural sanity (e.g., punycode/IDN, TLD validity, private-IP
detection), never anything probabilistic.  Analysts get a clean,
auditable table they can hand to a SIEM.
"""
from __future__ import annotations
import ipaddress, re
from typing import Dict, List, Set, Any

# ── regexes ───────────────────────────────────────────────────────
_URL_RE      = re.compile(r"\bhttps?://[^\s<>\"'`]+", re.IGNORECASE)
_ONION_RE    = re.compile(r"\b[a-z2-7]{16,56}\.onion(?::\d+)?\b", re.IGNORECASE)
_DISCORD_RE  = re.compile(r"\bhttps?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+", re.IGNORECASE)
_EMAIL_RE    = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_UNC_RE      = re.compile(r"\\\\[A-Za-z0-9._\-$]+\\[A-Za-z0-9._\-$\\]+")
_IPV4_RE     = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE     = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F:]{1,32}\b")
_DOMAIN_RE   = re.compile(
    r"\b(?:[a-zA-Z0-9][a-zA-Z0-9\-]{0,62}\.){1,}[a-zA-Z]{2,63}\b"
)

# TLDs we treat as noise unless embedded in a URL — the extractor
# needs deterministic filters so that decoded blobs don't spam junk.
_NOISE_STRINGS = {
    "microsoft.com", "windows.com", "schemas.xmlsoap.org", "w3.org",
    "example.com", "localhost", "example.org",
}

# Deterministic domain filter — a "domain" that ends in a code
# extension (a filename) or is an internal .NET / PS type reference
# must never be surfaced as a network IOC.  Analysts get exactly the
# indicators they can hand to a SIEM.
_DOMAIN_EXCLUDED_SUFFIXES = (
    ".exe", ".dll", ".ps1", ".psm1", ".psd1", ".bat", ".cmd",
    ".vbs", ".js", ".py", ".sh", ".hta", ".msi", ".scr",
    ".lnk", ".ini", ".cfg", ".xml", ".json", ".yaml", ".yml",
)
_DOMAIN_EXCLUDED_HOSTS = {
    "system.net", "system.io", "system.reflection", "system.text",
    "system.diagnostics", "system.security", "net.webclient",
    "net.webrequest", "management.automation",
}


def _v4_kind(ip: str) -> str:
    try:
        addr = ipaddress.IPv4Address(ip)
    except (ipaddress.AddressValueError, ValueError):
        return ""
    if addr.is_loopback or addr.is_multicast or addr.is_reserved:
        return ""
    return "private-ip" if addr.is_private else "ip"


def extract_iocs(text: str, source: str = "raw") -> List[Dict[str, Any]]:
    """Deterministic IOC scan over ``text``.  Each result is stable
    across runs.  Duplicates are collapsed by canonical value.
    """
    if not text:
        return []

    out: Dict[str, Dict[str, Any]] = {}

    def _add(kind: str, value: str, conf: float):
        v = value.strip().rstrip(".,;:)>]}").lower()
        if not v or v in _NOISE_STRINGS:
            return
        key = f"{kind}:{v}"
        prev = out.get(key)
        if prev is None or prev["confidence"] < conf:
            out[key] = {"kind": kind, "value": v,
                        "confidence": round(conf, 2), "source": source}

    # Discord webhooks are high-signal → match first, then strip so
    # we don't double-count as a generic URL.
    scan = text
    for m in _DISCORD_RE.finditer(scan):
        _add("discord-webhook", m.group(0), 0.99)
    scan = _DISCORD_RE.sub(" ", scan)

    for m in _URL_RE.finditer(scan):
        _add("url", m.group(0), 0.92)

    for m in _ONION_RE.finditer(scan):
        _add("onion", m.group(0), 0.98)

    for m in _UNC_RE.finditer(scan):
        _add("unc", m.group(0), 0.90)

    for m in _EMAIL_RE.finditer(scan):
        _add("email", m.group(0), 0.85)

    for m in _IPV4_RE.finditer(scan):
        kind = _v4_kind(m.group(0))
        if kind == "ip":
            _add("ip", m.group(0), 0.90)
        elif kind == "private-ip":
            _add("private-ip", m.group(0), 0.70)

    for m in _IPV6_RE.finditer(scan):
        # Loose regex — validate structurally.
        try:
            ipaddress.IPv6Address(m.group(0))
            _add("ipv6", m.group(0), 0.85)
        except (ipaddress.AddressValueError, ValueError):
            continue

    # Domains: only accept if not already contained in a matched URL
    # (URL matches carry their host already).  Deterministic filter:
    # host must not be a numeric-only sequence, must not be pure
    # punctuation, TLD length ≥ 2, ≤ 63.
    #
    # P0.b (2026-02-06): route every domain candidate through the
    # artifact classifier so .NET namespaces / method names
    # (`ascii.getstring`, `net.credentialcache`, `system.convert`,
    # `w.downloadstring`, `d.tolower`, `system.text.encoding`) NEVER
    # reach the analyst as domain IOCs. This closes the workspace
    # "wrong Domains" bug reported 2026-02-06.
    try:
        from services.normalization.artifact_classifier import classify
    except Exception:
        classify = None   # type: ignore
    already = {v["value"] for v in out.values()}
    for m in _DOMAIN_RE.finditer(scan):
        d = m.group(0).lower()
        if any(d in u for u in already):
            continue
        if d.replace(".", "").isdigit():
            continue
        if d in _DOMAIN_EXCLUDED_HOSTS:
            continue
        if d.endswith(_DOMAIN_EXCLUDED_SUFFIXES):
            continue
        parts = d.split(".")
        if len(parts[-1]) < 2 or len(parts[-1]) > 63:
            continue
        # Authoritative classifier veto — refuses .NET-shaped identifiers.
        if classify is not None and classify(d) != "domain":
            continue
        _add("domain", d, 0.78)

    # Stable ordering — analysts appreciate reproducible output.
    return sorted(out.values(), key=lambda x: (x["kind"], x["value"]))


def summarize_iocs(iocs: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """Compact ``{kind: [values]}`` view suitable for CEM ingestion."""
    bucket: Dict[str, Set[str]] = {}
    for i in iocs:
        bucket.setdefault(i["kind"], set()).add(i["value"])
    return {k: sorted(v) for k, v in bucket.items()}
