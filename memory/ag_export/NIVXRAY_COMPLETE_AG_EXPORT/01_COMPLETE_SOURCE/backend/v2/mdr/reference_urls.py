"""NivXRay MDR — Reference URL classifier.

Distinguishes attacker infrastructure from vendor / documentation /
enrichment URLs that legitimately appear inside XDR incidents.

A Tier-2 analyst NEVER treats `https://umbrella.cisco.com/...`,
`https://www.virustotal.com/gui/...`, `https://docs.microsoft.com/...`,
`https://attack.mitre.org/...` etc. as attacker infrastructure.
NivXRay used to flag them as IOCs — that produced the noise the user
called out.

Classification:
  reference  → vendor / documentation / enrichment (NEVER an IOC)
  benign     → RFC1918 / loopback / .local (surrounding infra)
  suspect    → matches a known-bad TI corpus row
  attacker   → external + downloadable payload verbs nearby
  unknown    → external + no context

The classification is deterministic and evidence-driven.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

# Suffix table. All entries match ANY subdomain via endswith().
_REFERENCE_HOSTS = {
    # Cisco family
    "cisco.com", "amp.cisco.com", "umbrella.com", "talosintelligence.com",
    "talos-intelligence.com", "opendns.com", "openvuln.cisco.com",
    "webexcontent.com",
    # Microsoft
    "microsoft.com", "windows.com", "microsoftonline.com", "office.com",
    "azure.com", "azurewebsites.net", "msftconnecttest.com", "windowsupdate.com",
    "live.com", "outlook.com", "sharepoint.com",
    # Threat intel & enrichment
    "virustotal.com", "abuseipdb.com", "otx.alienvault.com",
    "threatcrowd.org", "threatminer.org", "urlhaus.abuse.ch",
    "malwarebazaar.abuse.ch", "shodan.io", "greynoise.io", "censys.io",
    # MITRE / community references
    "mitre.org", "attack.mitre.org", "cisa.gov", "us-cert.gov",
    "cert.org",
    # Vendor knowledge bases
    "crowdstrike.com", "sentinelone.com", "carbonblack.com",
    "paloaltonetworks.com", "unit42.paloaltonetworks.com",
    "fireeye.com", "trellix.com", "mandiant.com", "kaspersky.com",
    "trendmicro.com", "sophos.com", "symantec.com", "broadcom.com",
    "bitdefender.com", "eset.com", "welivesecurity.com",
    # Developer / repo mirrors that show up in RSS / advisories
    "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org",
    "pypi.org", "npmjs.com", "docker.com", "hub.docker.com",
    "stackexchange.com", "stackoverflow.com",
    # Common enrichment portals
    "any.run", "hybrid-analysis.com", "joesecurity.org",
    "hatching.io", "tria.ge", "malware-traffic-analysis.net",
}

# Verbs that suggest DOWNLOAD or EXECUTION happened AT the URL.
# When one appears within 80 chars of an external URL, we upgrade the
# classification to `attacker`.
_ATTACK_VERBS = re.compile(
    r"\b(?:downloaded\s+from|fetched\s+from|c2|command\s*&\s*control|"
    r"beacon|posting\s+to|exfiltrated\s+to|reached\s+out\s+to|"
    r"connected\s+to|downloadstring|downloadfile|invoke-webrequest|"
    r"curl|wget|certutil\s+-urlcache)\b",
    re.I,
)


def is_reference_host(host: str) -> bool:
    if not host:
        return False
    h = host.lower().strip().strip(".")
    return any(h == r or h.endswith("." + r) for r in _REFERENCE_HOSTS)


def is_private_host(host: str) -> bool:
    import ipaddress
    if not host:
        return True
    h = host.lower().strip(".")
    if h in ("localhost", "::1") or h.endswith(".local") or h.endswith(".internal") or h.endswith(".lan"):
        return True
    try:
        ip = ipaddress.ip_address(h)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        return False


def classify_url(url: str, surrounding_text: str = "",
                 ti_hits: set[str] | None = None) -> dict:
    """Return `{classification, host, port, reason}`.

    classification ∈ {reference, benign, suspect, attacker, unknown}
    """
    try:
        p = urlparse(url)
    except Exception:
        return {"classification": "unknown", "host": "", "port": None,
                "reason": "URL parse failed"}
    host = p.hostname or ""
    port = p.port
    if is_reference_host(host):
        return {"classification": "reference", "host": host, "port": port,
                "reason": f"`{host}` is a known vendor / documentation host."}
    if is_private_host(host):
        return {"classification": "benign", "host": host, "port": port,
                "reason": f"`{host}` resolves to private / loopback space."}
    if ti_hits and url in ti_hits:
        return {"classification": "suspect", "host": host, "port": port,
                "reason": "URL matched local threat-intel corpus."}
    if ti_hits and host in ti_hits:
        return {"classification": "suspect", "host": host, "port": port,
                "reason": f"Host `{host}` matched local threat-intel corpus."}
    # Look for attack verbs in the surrounding context.
    if surrounding_text:
        try:
            idx = surrounding_text.index(url)
            window = surrounding_text[max(0, idx - 80): idx + len(url) + 80]
        except ValueError:
            window = surrounding_text
        if _ATTACK_VERBS.search(window):
            return {"classification": "attacker", "host": host, "port": port,
                    "reason": ("External URL appearing near an attack verb "
                               "(download / C2 / beacon / exfil).")}
    return {"classification": "unknown", "host": host, "port": port,
            "reason": "External URL — no supporting context for attacker attribution."}


def classify_all(urls: list[str], surrounding_text: str = "",
                 ti_hits: set[str] | None = None) -> dict[str, list[dict]]:
    """Group every URL into its classification bucket."""
    buckets: dict[str, list[dict]] = {"reference": [], "benign": [], "suspect": [],
                                       "attacker": [], "unknown": []}
    for u in dict.fromkeys(urls):
        info = classify_url(u, surrounding_text, ti_hits)
        buckets[info["classification"]].append({"url": u, **info})
    return buckets
