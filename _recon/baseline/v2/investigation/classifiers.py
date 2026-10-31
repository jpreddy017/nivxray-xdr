"""NivXRay Investigation — Evidence Classifiers.

Every artefact surfaced by AUTO INVESTIGATE MUST be classified with a
provenance tag before it is presented. Classification is deterministic
and evidence-driven — no LLM, no heuristics on the report body itself.

Provenance vocabulary (mirrors the spec):

    Observed              — surfaced directly in the incident telemetry
    Decoded               — recovered from a decoder chain
    ThreatIntelligence    — matched a TI corpus (VirusTotal / OTX / etc.)
    Console               — vendor console/portal URL (Cisco XDR, Talos …)
    Documentation         — vendor documentation / knowledge-base URL
    Historical            — pivot on host/user/hash/process from prior events
    Internal              — RFC1918 / .local / hostname / internal DNS
    Loopback              — 127.0.0.1 / ::1 / localhost
    Derived               — computed / synthesised (e.g. reconstructed chain)

Only artefacts with provenance ∈ {Observed, Decoded} AND classified as
attacker-controlled infrastructure may be presented as IOCs.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

# ── Provenance constants ─────────────────────────────────────────
PROV_OBSERVED       = "Observed"
PROV_DECODED        = "Decoded"
PROV_TI             = "ThreatIntelligence"
PROV_CONSOLE        = "Console"
PROV_DOCUMENTATION  = "Documentation"
PROV_HISTORICAL     = "Historical"
PROV_INTERNAL       = "Internal"
PROV_LOOPBACK       = "Loopback"
PROV_DERIVED        = "Derived"

# Never IOCs
_NON_IOC_PROVENANCE = {PROV_CONSOLE, PROV_DOCUMENTATION, PROV_INTERNAL, PROV_LOOPBACK}


# ── Reference vendor host classifier ─────────────────────────────
# The absolute-mandatory noise filter. Cisco/Umbrella/VirusTotal/etc URLs
# that appear inside an XDR case are ALWAYS analyst references, never
# attacker infrastructure.
_CONSOLE_HOSTS = {
    # Cisco family
    "cisco.com", "secureboard.cisco.com", "amp.cisco.com", "sse.cisco.com",
    "umbrella.com", "opendns.com", "openvuln.cisco.com",
    "talosintelligence.com", "talos-intelligence.com", "webexcontent.com",
    "secureboard.cisco.com",
    # Microsoft security consoles
    "security.microsoft.com", "portal.azure.com", "admin.microsoft.com",
    "securitycenter.microsoft.com", "compliance.microsoft.com",
    "endpoint.microsoft.com", "protection.office.com",
    # Other vendor consoles
    "falcon.crowdstrike.com", "us-2.crowdstrike.com", "us-1.crowdstrike.com",
    "eu-1.crowdstrike.com", "management.sentinelone.net",
    "workbench.trellix.com", "portal.sophos.com",
}
_DOC_HOSTS = {
    # Documentation
    "docs.microsoft.com", "learn.microsoft.com", "support.microsoft.com",
    "developer.microsoft.com", "techcommunity.microsoft.com",
    "mitre.org", "attack.mitre.org", "capec.mitre.org", "cve.mitre.org",
    "cisa.gov", "us-cert.gov", "cert.org", "nist.gov",
    # Threat-intel/enrichment portals (analyst references, not IOCs)
    "virustotal.com", "abuseipdb.com", "otx.alienvault.com",
    "urlhaus.abuse.ch", "malwarebazaar.abuse.ch", "shodan.io",
    "greynoise.io", "censys.io", "hybrid-analysis.com", "any.run",
    "joesecurity.org", "hatching.io", "tria.ge",
    # CDN / SSL infra
    "digicert.com", "letsencrypt.org", "akamai.com", "akamaihd.net",
    "akamaitechnologies.com", "cloudflare.com", "cloudflare-dns.com",
    # Vendor knowledge bases
    "welivesecurity.com", "unit42.paloaltonetworks.com", "mandiant.com",
    "fireeye.com", "trellix.com", "kaspersky.com", "trendmicro.com",
    "sophos.com", "symantec.com", "broadcom.com", "bitdefender.com",
    "eset.com", "cybereason.com",
    # Public code / dev
    "github.com", "githubusercontent.com", "gitlab.com", "bitbucket.org",
    "pypi.org", "npmjs.com", "stackoverflow.com", "stackexchange.com",
    # SIEM / vendor consoles missing from earlier passes
    "splunk.com", "splunkcloud.com", "ibm.com", "qradar.ibm.com",
    "logrhythm.com", "exabeam.com", "arcsight.com",
}
_INTERNAL_TLDS = (".local", ".internal", ".lan", ".corp", ".intra", ".arpa")


def _host_matches(host: str, suffixes: set[str]) -> bool:
    h = (host or "").lower().strip().strip(".")
    return any(h == s or h.endswith("." + s) for s in suffixes)


def is_loopback_host(host: str) -> bool:
    h = (host or "").lower().strip(".")
    if h in ("localhost", "::1", "0.0.0.0", ""):
        return h != ""
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def is_internal_host(host: str) -> bool:
    h = (host or "").lower().strip(".")
    if any(h.endswith(sfx) for sfx in _INTERNAL_TLDS):
        return True
    # bare hostnames (no dots) are internal by definition
    if h and "." not in h and not h.replace(":", "").isdigit():
        return True
    try:
        ip = ipaddress.ip_address(h)
        return ip.is_private or ip.is_link_local or ip.is_reserved
    except ValueError:
        return False


def classify_url(url: str) -> dict:
    """Return `{value, kind, provenance, host, port, is_ioc, reason}`."""
    try:
        p = urlparse(url)
    except Exception:
        return {"value": url, "kind": "url", "provenance": PROV_OBSERVED,
                "host": "", "port": None, "is_ioc": False,
                "reason": "unparseable URL"}
    host = (p.hostname or "").lower()
    port = p.port

    if is_loopback_host(host):
        return {"value": url, "kind": "url", "provenance": PROV_LOOPBACK,
                "host": host, "port": port, "is_ioc": False,
                "reason": "loopback / localhost — cannot be attacker infrastructure"}
    if _host_matches(host, _CONSOLE_HOSTS):
        return {"value": url, "kind": "url", "provenance": PROV_CONSOLE,
                "host": host, "port": port, "is_ioc": False,
                "reason": f"`{host}` is a vendor security console — analyst reference only"}
    if _host_matches(host, _DOC_HOSTS):
        return {"value": url, "kind": "url", "provenance": PROV_DOCUMENTATION,
                "host": host, "port": port, "is_ioc": False,
                "reason": f"`{host}` is a documentation / enrichment portal — analyst reference only"}
    if is_internal_host(host):
        return {"value": url, "kind": "url", "provenance": PROV_INTERNAL,
                "host": host, "port": port, "is_ioc": False,
                "reason": f"`{host}` resolves to internal / private space"}
    # External + not a reference host → candidate IOC (attacker-controlled)
    return {"value": url, "kind": "url", "provenance": PROV_OBSERVED,
            "host": host, "port": port, "is_ioc": True,
            "reason": "external URL — no reference-host match → treat as attacker-controlled"}


def classify_domain(domain: str) -> dict:
    if not domain:
        return {"value": domain, "kind": "domain", "provenance": PROV_OBSERVED,
                "is_ioc": False, "reason": "empty"}
    h = domain.lower().strip(".")
    if _host_matches(h, _CONSOLE_HOSTS):
        return {"value": domain, "kind": "domain", "provenance": PROV_CONSOLE,
                "is_ioc": False,
                "reason": f"`{h}` is a vendor console host — reference only"}
    if _host_matches(h, _DOC_HOSTS):
        return {"value": domain, "kind": "domain", "provenance": PROV_DOCUMENTATION,
                "is_ioc": False,
                "reason": f"`{h}` is a documentation portal — reference only"}
    if is_internal_host(h):
        return {"value": domain, "kind": "domain", "provenance": PROV_INTERNAL,
                "is_ioc": False, "reason": "internal / private domain"}
    return {"value": domain, "kind": "domain", "provenance": PROV_OBSERVED,
            "is_ioc": True,
            "reason": "external domain — no reference-host match"}


def classify_ip(ip: str) -> dict:
    try:
        addr = ipaddress.ip_address(ip)
    except Exception:
        return {"value": ip, "kind": "ip", "provenance": PROV_OBSERVED,
                "is_ioc": False, "reason": "invalid IP"}
    if addr.is_loopback:
        return {"value": ip, "kind": "ip", "provenance": PROV_LOOPBACK,
                "is_ioc": False, "reason": "loopback"}
    if addr.is_private or addr.is_link_local or addr.is_reserved:
        return {"value": ip, "kind": "ip", "provenance": PROV_INTERNAL,
                "is_ioc": False, "reason": "RFC1918 / link-local / reserved"}
    return {"value": ip, "kind": "ip", "provenance": PROV_OBSERVED,
            "is_ioc": True, "reason": "external / public IP"}


# ── File behaviour classifier ────────────────────────────────────
# Every file surfaced by the pipeline must be classified by the LATEST
# action observed on it, not merely listed.

_LOLBIN_NAMES = {
    "rundll32.exe", "regsvr32.exe", "certutil.exe", "mshta.exe",
    "bitsadmin.exe", "wmic.exe", "installutil.exe", "regasm.exe",
    "regsvcs.exe", "msbuild.exe", "csc.exe", "wscript.exe", "cscript.exe",
    "hh.exe", "at.exe", "schtasks.exe", "sc.exe", "reg.exe", "netsh.exe",
    "psexec.exe", "wmiprvse.exe", "wsmprovhost.exe", "cmstp.exe",
    "curl.exe", "wget.exe", "forfiles.exe", "msdt.exe", "control.exe",
    "extexport.exe", "presentationhost.exe", "installer.exe",
}
_TRUSTED_SYSTEM = {
    "svchost.exe", "explorer.exe", "lsass.exe", "services.exe",
    "winlogon.exe", "csrss.exe", "wininit.exe", "smss.exe", "spoolsv.exe",
    "taskhostw.exe", "sihost.exe", "runtimebroker.exe", "conhost.exe",
    "system", "idle", "audiodg.exe",
}
_KNOWN_MALWARE = {
    "sh.exe", "mimikatz.exe", "sharphound.exe", "cobaltstrike.exe",
    "beacon.exe", "keylog.exe", "sekurlsa.exe",
}


def _basename(path: str) -> str:
    if not path:
        return ""
    return path.replace("\\", "/").rstrip("/").split("/")[-1].lower()


def classify_file(f: dict) -> dict:
    """Return the file event decorated with `{classification, provenance,
    is_ioc, reason}`."""
    action = (f.get("action") or "").lower()
    path   = f.get("path") or ""
    name   = _basename(path)
    sha    = f.get("sha256") or ""

    # Classification order matters — most specific first.
    if action == "quarantined":
        cls, reason = "Quarantined", "Endpoint quarantined the file"
    elif action == "blocked":
        cls, reason = "Blocked", "Endpoint blocked the file"
    elif action in ("deleted", "removed"):
        cls, reason = "Deleted", f"File was {action}"
    elif action in ("moved", "renamed"):
        cls, reason = "Moved", f"File was {action}"
    elif action == "executed":
        cls, reason = "Executed", "Execution telemetry present"
    elif action == "downloaded":
        cls, reason = "Downloaded", "Download telemetry present"
    elif action == "created":
        cls, reason = "Created", "File creation telemetry present"
    elif action == "modified":
        cls, reason = "Modified", "File modification telemetry present"
    else:
        cls, reason = "Observed", "File referenced but no action telemetry"

    # Reputation layer — LOLBIN / trusted / known-malware
    reputation = None
    if name in _KNOWN_MALWARE:
        reputation = "Malware"
    elif name in _LOLBIN_NAMES:
        reputation = "LOLBIN"
    elif name in _TRUSTED_SYSTEM:
        reputation = "Trusted"

    is_ioc = bool(sha) and cls not in ("Trusted",)
    return {
        **f,
        "name":           name,
        "classification": cls,
        "reputation":     reputation,
        "provenance":     PROV_OBSERVED,
        "is_ioc":         is_ioc,
        "reason":         reason,
    }


# ── Process chain classifier ─────────────────────────────────────
# Rebuilds parent → child chains and marks each row's ROLE.
def classify_processes(processes: list[dict]) -> list[dict]:
    """Deduplicate, annotate role (parent/child/leaf) and reputation."""
    if not processes:
        return []
    # Deduplicate on (parent, process, command_line) — keep the first
    # occurrence's timestamp/host/user.
    seen: dict[tuple[str, str, str], dict] = {}
    for p in processes:
        key = (p.get("parent") or "", p.get("process") or "", p.get("command_line") or "")
        if key not in seen:
            seen[key] = dict(p)
    rows = list(seen.values())

    # Roles: any process observed as another row's parent is a "parent";
    # any process referenced as a child is "child".
    parents = {r.get("process") for r in rows if r.get("process")}
    children = {r.get("child") for r in rows if r.get("child")}
    all_parents = {r.get("parent") for r in rows if r.get("parent")}

    for r in rows:
        proc = r.get("process") or ""
        role = "process"
        if proc in all_parents:
            role = "parent"
        if proc in children and proc not in all_parents:
            role = "child"
        name = _basename(proc)
        rep = None
        if name in _KNOWN_MALWARE:
            rep = "Malware"
        elif name in _LOLBIN_NAMES:
            rep = "LOLBIN"
        elif name in _TRUSTED_SYSTEM:
            rep = "Trusted"
        r["role"] = role
        r["reputation"] = rep
        r["provenance"] = PROV_OBSERVED
    return rows


# ── Aggregate classifier over the whole entity block ─────────────
def classify_entities(entities: dict) -> dict:
    """Return `{urls, domains, ips, files, processes}` — each item
    decorated with provenance + is_ioc.

    Buckets are ALWAYS returned; empty lists are preserved so the UI
    can render "no attacker-controlled URLs — {n} references filtered"
    style empty states.
    """
    urls    = [classify_url(u)    for u in (entities.get("urls")    or [])]
    domains = [classify_domain(d) for d in (entities.get("domains") or [])]
    ips     = [classify_ip(i)     for i in (entities.get("ips")     or [])]

    return {
        "urls":     urls,
        "domains":  domains,
        "ips":      ips,
        "iocs": {
            "urls":    [u for u in urls    if u["is_ioc"]],
            "domains": [d for d in domains if d["is_ioc"]],
            "ips":     [i for i in ips     if i["is_ioc"]],
        },
        "references": {
            "urls":    [u for u in urls    if u["provenance"] in _NON_IOC_PROVENANCE],
            "domains": [d for d in domains if d["provenance"] in _NON_IOC_PROVENANCE],
            "ips":     [i for i in ips     if i["provenance"] in _NON_IOC_PROVENANCE],
        },
        "counts": {
            "urls_total":       len(urls),
            "urls_ioc":         sum(1 for u in urls if u["is_ioc"]),
            "urls_reference":   sum(1 for u in urls if u["provenance"] in _NON_IOC_PROVENANCE),
            "domains_total":    len(domains),
            "domains_ioc":      sum(1 for d in domains if d["is_ioc"]),
            "ips_total":        len(ips),
            "ips_ioc":          sum(1 for i in ips if i["is_ioc"]),
        },
    }
