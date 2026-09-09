"""
IDA · URL Intent Classifier (Slice 1.6)
───────────────────────────────────────
Frozen 2026-03-01 · P0.

The URL Intent Classifier answers the question the legacy pipeline
never asked:

    "A URL is a resource, not an IOC.  What KIND of resource?"

Every URL gets one of the following intents:

    threat_report   — vendor blog / advisory / campaign write-up
                       (esentire, talos, mandiant, crowdstrike,
                        microsoft, unit42, sentinelone, welivesecurity,
                        eset, kaspersky, trellix, elastic, huntress,
                        rapid7, redcanary, chainalysis, s2w, dfir,
                        cisa, ic3, ncsc, cert-*)
    ioc_portal      — reputation / IOC database
                       (virustotal, urlhaus, abuse.ch, alienvault-otx,
                        talos-intelligence lookups, greynoise, shodan,
                        censys, cisco-talos ip/domain endpoints)
    repository      — source-hosting site (github repos, gitlab,
                       bitbucket, sourceforge)
    code_snippet    — code / paste hosting
                       (pastebin, gist, hastebin, ghostbin, rentry,
                        justpaste.it, dpaste)
    file_resource   — direct download / file share
                       (dropbox, google drive, mega.nz, mediafire,
                        anonfiles, s3 bucket links, direct .exe/.dll/.zip)
    atomic_ioc      — everything else: a URL that is itself just an
                       IOC, no acquisition possible / valuable
                       (bare shortener, dynamic C2, IP-only URL)

Each intent carries an `acquirable` flag so the pipeline knows
whether to route to IDA-3 (fetch) or to the IOC/reputation lane.

The classifier is 100% deterministic — no LLM, no network.  It
inspects host, tld, path suffix, and a curated vendor knowledge
pack.  Every new vendor / paste site plugs into `_VENDORS` and
`_PASTE_HOSTS` — no consumer touches.
"""
from __future__ import annotations
import re
from typing import Any, Dict, Optional, Tuple


# ══════════════════════════════════════════════════════════════════
# 1. Vendor knowledge pack (threat_report intent)
# ══════════════════════════════════════════════════════════════════
# host-suffix → vendor label.  Longest-suffix match wins.  Adding a
# new vendor is one line; no other code changes.
_VENDORS: Tuple[Tuple[str, str], ...] = (
    ("esentire.com",           "eSentire"),
    ("talosintelligence.com",  "Cisco Talos"),
    ("blog.talosintelligence.com", "Cisco Talos"),
    ("mandiant.com",           "Mandiant"),
    ("cloud.google.com",       "Google Cloud (Mandiant)"),
    ("crowdstrike.com",        "CrowdStrike"),
    ("microsoft.com",          "Microsoft Threat Intel"),
    ("techcommunity.microsoft.com", "Microsoft"),
    ("unit42.paloaltonetworks.com", "Unit 42 · Palo Alto"),
    ("paloaltonetworks.com",   "Palo Alto Networks"),
    ("sentinelone.com",        "SentinelOne"),
    ("welivesecurity.com",     "ESET WeLiveSecurity"),
    ("eset.com",               "ESET"),
    ("securelist.com",         "Kaspersky Securelist"),
    ("kaspersky.com",          "Kaspersky"),
    ("trellix.com",            "Trellix"),
    ("elastic.co",             "Elastic Security Labs"),
    ("huntress.com",           "Huntress"),
    ("rapid7.com",             "Rapid7"),
    ("redcanary.com",          "Red Canary"),
    ("chainalysis.com",        "Chainalysis"),
    ("s2w.inc",                "S2W"),
    ("thedfirreport.com",      "The DFIR Report"),
    ("cisa.gov",               "CISA"),
    ("ic3.gov",                "IC3 / FBI"),
    ("ncsc.gov.uk",            "UK NCSC"),
    ("cert.gov",               "CERT"),
    ("cert-eu.eu",             "CERT-EU"),
    ("bleepingcomputer.com",   "BleepingComputer"),
    ("thehackernews.com",      "The Hacker News"),
    ("krebsonsecurity.com",    "Krebs on Security"),
    ("darkreading.com",        "Dark Reading"),
    ("securityaffairs.com",    "Security Affairs"),
    ("proofpoint.com",         "Proofpoint"),
    ("blog.proofpoint.com",    "Proofpoint"),
    ("intezer.com",            "Intezer"),
    ("checkpoint.com",         "Check Point Research"),
    ("research.checkpoint.com", "Check Point Research"),
    ("sekoia.io",              "Sekoia.io"),
    ("blog.sekoia.io",         "Sekoia.io"),
    ("volexity.com",           "Volexity"),
    ("attack.mitre.org",       "MITRE ATT&CK"),
)

# IOC-portal hosts — a URL that lands here IS a lookup, not a report.
_IOC_PORTAL_HOSTS: Tuple[str, ...] = (
    "virustotal.com",
    "www.virustotal.com",
    "urlhaus.abuse.ch",
    "abuse.ch",
    "malshare.com",
    "any.run",
    "app.any.run",
    "otx.alienvault.com",
    "greynoise.io",
    "shodan.io",
    "censys.io",
    "search.censys.io",
    "hybrid-analysis.com",
    "malwarebazaar.abuse.ch",
    "threatfox.abuse.ch",
    "feodotracker.abuse.ch",
    "ipvoid.com",
    "urlvoid.com",
    "xforce.ibmcloud.com",
    "exchange.xforce.ibmcloud.com",
    "talosintelligence.com/reputation_center",
)

# Paste / snippet hosts
_PASTE_HOSTS: Tuple[str, ...] = (
    "pastebin.com",
    "gist.github.com",
    "hastebin.com",
    "ghostbin.com",
    "rentry.co",
    "justpaste.it",
    "dpaste.com",
    "dpaste.org",
    "controlc.com",
    "paste.ee",
    "termbin.com",
)

# Repository hosts
_REPO_HOSTS: Tuple[str, ...] = (
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "sourceforge.net",
    "code.google.com",
    "codeberg.org",
)

# File-share hosts
_FILE_HOSTS: Tuple[str, ...] = (
    "dropbox.com",
    "drive.google.com",
    "docs.google.com",
    "mega.nz",
    "mediafire.com",
    "anonfiles.com",
    "wetransfer.com",
    "1drv.ms",
    "onedrive.live.com",
    "sendspace.com",
    "workupload.com",
)

# Direct-file extensions that make ANY URL a file_resource
_FILE_EXTS: Tuple[str, ...] = (
    ".exe", ".dll", ".msi", ".ps1", ".bat", ".cmd", ".vbs", ".js",
    ".hta", ".scr", ".jar", ".apk", ".elf", ".sh", ".py", ".pl",
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".iso",
    ".cab", ".img", ".doc", ".docm", ".docx", ".xls", ".xlsm",
    ".xlsx", ".ppt", ".pptx", ".pdf", ".lnk", ".xll",
)

# URL-shorteners → treat as atomic IOC (acquiring would follow the
# redirect blindly; that's an IDA-3.1 slice, not now).
_SHORTENERS: Tuple[str, ...] = (
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "shorte.st", "adf.ly", "rebrand.ly",
    "s.id", "lnkd.in",
)


# ══════════════════════════════════════════════════════════════════
# 2. Public API
# ══════════════════════════════════════════════════════════════════
_URL_RE = re.compile(r"^\s*(https?|ftp|ftps|smb|s3)://([^/\s]+)(/[^\s]*)?", re.I)


def classify_url_intent(url: str) -> Dict[str, Any]:
    """Return the URL's investigative intent.

    Result shape::

        {
          "intent":     one of threat_report / ioc_portal / repository /
                        code_snippet / file_resource / atomic_ioc,
          "acquirable": bool,               # True → route to IDA-3
          "vendor":     str | None,          # e.g. "eSentire" · "Cisco Talos"
          "host":       str,                 # normalised host
          "scheme":     str,                 # https / http / …
          "reasoning":  list[str],           # analyst-visible bullets
        }
    """
    m = _URL_RE.match(url or "")
    if not m:
        return _fallback("Input is not a well-formed URL.")
    scheme = m.group(1).lower()
    host   = m.group(2).lower().rstrip(".")
    path   = (m.group(3) or "").lower()

    # Strip userinfo / port
    if "@" in host:
        host = host.split("@", 1)[1]
    if ":" in host:
        host = host.split(":", 1)[0]

    reasoning: list[str] = [f"URL scheme `{scheme}`, host `{host}`."]

    # 1. IP-only host → atomic IOC (never acquire)
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        reasoning.append("Host is a bare IPv4 address — treated as an atomic IOC.")
        return {
            "intent":     "atomic_ioc",
            "acquirable": False,
            "vendor":     None,
            "host":       host,
            "scheme":     scheme,
            "reasoning":  reasoning,
        }

    # 2. URL shortener → atomic IOC for now (redirect-follow is IDA-3.1)
    if host in _SHORTENERS:
        reasoning.append(f"Host `{host}` is a URL shortener — atomic IOC lane until IDA-3.1 (redirect follow) lands.")
        return {
            "intent":     "atomic_ioc",
            "acquirable": False,
            "vendor":     None,
            "host":       host,
            "scheme":     scheme,
            "reasoning":  reasoning,
        }

    # 3. IOC portal
    for suffix in _IOC_PORTAL_HOSTS:
        if host == suffix or host.endswith("." + suffix) or (suffix in host and "/" in suffix):
            reasoning.append(f"Host matches IOC-portal knowledge pack (`{suffix}`) — this is a lookup, not a report.")
            return {
                "intent":     "ioc_portal",
                "acquirable": False,      # lookups are IOC-lane, not IDA-3
                "vendor":     None,
                "host":       host,
                "scheme":     scheme,
                "reasoning":  reasoning,
            }

    # 4. Paste / snippet
    for suffix in _PASTE_HOSTS:
        if host == suffix or host.endswith("." + suffix):
            reasoning.append(f"Host `{host}` is a code-snippet / paste site.")
            return {
                "intent":     "code_snippet",
                "acquirable": True,
                "vendor":     None,
                "host":       host,
                "scheme":     scheme,
                "reasoning":  reasoning,
            }

    # 5. Repository
    for suffix in _REPO_HOSTS:
        if host == suffix or host.endswith("." + suffix):
            reasoning.append(f"Host `{host}` is a source-repository host.")
            return {
                "intent":     "repository",
                "acquirable": True,
                "vendor":     None,
                "host":       host,
                "scheme":     scheme,
                "reasoning":  reasoning,
            }

    # 6. File-share host
    for suffix in _FILE_HOSTS:
        if host == suffix or host.endswith("." + suffix):
            reasoning.append(f"Host `{host}` is a file-share / cloud-drive.")
            return {
                "intent":     "file_resource",
                "acquirable": True,
                "vendor":     None,
                "host":       host,
                "scheme":     scheme,
                "reasoning":  reasoning,
            }

    # 7. Direct-file URL (any host, but path ends in an executable /
    # archive / office extension)
    for ext in _FILE_EXTS:
        if path.endswith(ext):
            reasoning.append(f"Path ends in `{ext}` — direct file download.")
            return {
                "intent":     "file_resource",
                "acquirable": True,          # IDA-3 will honour safe-download rules
                "vendor":     None,
                "host":       host,
                "scheme":     scheme,
                "reasoning":  reasoning,
            }

    # 8. Vendor knowledge pack → threat_report
    #    Longest-suffix wins so `blog.talosintelligence.com` maps to
    #    Talos, not to a generic hit.
    best_vendor: Optional[Tuple[str, str]] = None
    for suffix, label in _VENDORS:
        if host == suffix or host.endswith("." + suffix):
            if best_vendor is None or len(suffix) > len(best_vendor[0]):
                best_vendor = (suffix, label)
    if best_vendor is not None:
        suffix, label = best_vendor
        reasoning.append(
            f"Host `{host}` matches vendor knowledge pack (`{suffix}` → **{label}**) "
            f"— treat as a threat-intelligence report."
        )
        return {
            "intent":     "threat_report",
            "acquirable": True,
            "vendor":     label,
            "host":       host,
            "scheme":     scheme,
            "reasoning":  reasoning,
        }

    # 9. Generic HTTPS URL with a substantive path (`/blog/…`,
    # `/advisory/…`, `/research/…`, `/report/…`) — likely a report.
    if any(seg in path for seg in ("/blog/", "/advisory/", "/advisories/",
                                    "/research/", "/report/", "/reports/",
                                    "/campaign/", "/threat/", "/malware/")):
        reasoning.append(
            f"Path `{path}` suggests a threat-report layout even though the vendor is unknown."
        )
        return {
            "intent":     "threat_report",
            "acquirable": True,
            "vendor":     None,
            "host":       host,
            "scheme":     scheme,
            "reasoning":  reasoning,
        }

    # 10. Fallback — unknown host, unknown path.  Not fetchable
    # confidently — treat as atomic IOC and let the IOC lane handle it.
    reasoning.append(
        "Host / path did not match any acquirable category — falling back to atomic IOC."
    )
    return {
        "intent":     "atomic_ioc",
        "acquirable": False,
        "vendor":     None,
        "host":       host,
        "scheme":     scheme,
        "reasoning":  reasoning,
    }


# ══════════════════════════════════════════════════════════════════
# 3. Helpers
# ══════════════════════════════════════════════════════════════════
def _fallback(reason: str) -> Dict[str, Any]:
    return {
        "intent":     "atomic_ioc",
        "acquirable": False,
        "vendor":     None,
        "host":       "",
        "scheme":     "",
        "reasoning":  [reason],
    }
