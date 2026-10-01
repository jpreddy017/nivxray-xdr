"""ADR-0014 · Phase 2 · IOC Classifier (§1.1.16).

Every extracted URL / domain / IP is classified into one of six
categories. Only `external_ioc` and `malicious_ioc` may drive
verdicts, severity, or recommendations. `vendor_infrastructure` and
`certificate_infrastructure` are stripped from the primary IOC set
so vendor CRL URLs and AMP console URLs can never dominate an
investigation.

Deterministic — no network calls, no AI. Curated infra lists live in
this file (§1.1.16 governance).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional
from urllib.parse import urlparse


IOCCategory = Literal[
    "vendor_infrastructure",       # Cisco AMP console, XDR endpoints, Defender API, etc.
    "certificate_infrastructure",  # Verisign / DigiCert / Sectigo / Let's Encrypt CRLs & OCSPs
    "internal_asset",              # RFC1918 / RFC4193 / .local / .lan / .corp
    "external_ioc",                # anything else — investigation lead
    "malicious_ioc",               # TI-provider confirmed malicious (set by upstream)
    "unknown",                     # unparseable
]


@dataclass(frozen=True)
class ClassificationResult:
    category: IOCCategory
    reason: str
    weight: int  # 0..10 — see evidence_priority.WEIGHTS


# ── Curated infra lists ─────────────────────────────────────────────
#
# Only exact-match or suffix-match on the host label. NEVER substring
# — we do not want `verisign.attacker.com` classified as CA infra.

_CERTIFICATE_INFRA_SUFFIXES: frozenset[str] = frozenset({
    "verisign.com",
    "thawte.com",
    "digicert.com",
    "sectigo.com",
    "geotrust.com",
    "letsencrypt.org",
    "globalsign.com",
    "entrust.net",
    "godaddy.com",           # certificate issuance
    "identrust.com",
    "usertrust.com",
    "comodoca.com",
    "quovadisglobal.com",
    "starfieldtech.com",
    "trustwave.com",
    "gtsr1.crl.pki.goog",    # Google trust services
    "pki.goog",
})

_VENDOR_INFRA_SUFFIXES: frozenset[str] = frozenset({
    # Cisco Secure Endpoint / AMP / XDR / Talos
    "amp.cisco.com",
    "console.amp.cisco.com",
    "private.intel.amp.cisco.com",
    "xdr.us.security.cisco.com",
    "xdr.eu.security.cisco.com",
    "security.cisco.com",
    "talosintelligence.com",
    # Microsoft Defender / Sentinel / Windows telemetry
    "microsoft.com",
    "windowsupdate.microsoft.com",
    "windows.com",
    "securitycenter.microsoft.com",
    "securitycenter.windows.com",
    "portal.azure.com",
    "graph.microsoft.com",
    # CrowdStrike Falcon
    "crowdstrike.com",
    "falcon.crowdstrike.com",
    # SentinelOne
    "sentinelone.com",
    # QRadar / IBM
    "qradar.ibmcloud.com",
    "ibm.com",
    # Splunk
    "splunk.com",
    "splunkcloud.com",
    # Trend / Symantec / etc.
    "trendmicro.com",
    "symantec.com",
    "broadcom.com",
    "sophos.com",
})


def _extract_host(value: str) -> Optional[str]:
    if not value:
        return None
    v = value.strip()
    if not v:
        return None
    # If it's a URL, parse it.
    if "://" in v:
        try:
            parsed = urlparse(v)
            return (parsed.hostname or "").lower() or None
        except Exception:
            return None
    # Otherwise treat as bare host / IP.
    # Strip trailing / and path fragments.
    v = v.split("/", 1)[0].strip().lower()
    return v or None


def _is_rfc1918(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return False
    if any(o < 0 or o > 255 for o in octets):
        return False
    if octets[0] == 10:
        return True
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    if octets[0] == 192 and octets[1] == 168:
        return True
    if octets[0] == 127:
        return True
    return False


def _is_ipv4_literal(host: str) -> bool:
    parts = host.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _suffix_matches(host: str, suffix_set: frozenset[str]) -> Optional[str]:
    for suffix in suffix_set:
        if host == suffix or host.endswith("." + suffix):
            return suffix
    return None


def classify(
    value: str,
    *,
    ioc_kind: str = "",
    ti_labelled_malicious: bool = False,
) -> ClassificationResult:
    """Classify a single IOC value.

    Parameters
    ----------
    value : the raw IOC string (URL, domain, or IP).
    ioc_kind : optional hint ("url" | "domain" | "ip" | "hash" | ...).
               `hash` and `email` short-circuit to `external_ioc`.
    ti_labelled_malicious : if a TI provider has already labelled this
                            value as malicious, bypass the infra check.
    """
    if ti_labelled_malicious:
        return ClassificationResult("malicious_ioc",
                                    "threat-intel-labelled", weight=10)

    kind = (ioc_kind or "").lower()
    if kind in ("hash", "md5", "sha1", "sha256", "email"):
        return ClassificationResult("external_ioc",
                                    f"{kind}-lead", weight=8)

    host = _extract_host(value)
    if not host:
        return ClassificationResult("unknown", "unparseable", weight=0)

    # IPv4?
    if _is_ipv4_literal(host):
        if _is_rfc1918(host):
            return ClassificationResult("internal_asset",
                                        "rfc1918-ipv4", weight=1)
        return ClassificationResult("external_ioc",
                                    "external-ipv4", weight=8)

    # `.local` / `.lan` / `.corp` / `.internal`?
    if host.endswith((".local", ".lan", ".corp", ".internal")):
        return ClassificationResult("internal_asset",
                                    "internal-suffix", weight=1)

    # Certificate infrastructure?
    hit = _suffix_matches(host, _CERTIFICATE_INFRA_SUFFIXES)
    if hit:
        return ClassificationResult("certificate_infrastructure",
                                    f"ca:{hit}", weight=0)

    # Vendor infrastructure?
    hit = _suffix_matches(host, _VENDOR_INFRA_SUFFIXES)
    if hit:
        return ClassificationResult("vendor_infrastructure",
                                    f"vendor:{hit}", weight=0)

    # Fall-through: external IOC (investigation lead).
    return ClassificationResult("external_ioc",
                                "external-domain", weight=7)


__all__ = ["classify", "ClassificationResult", "IOCCategory"]
