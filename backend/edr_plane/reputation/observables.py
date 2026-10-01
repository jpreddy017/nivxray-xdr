"""B4 · OBSERVABLE EXTRACTION — canonical evidence → observables.

Extraction is a READ. It never writes evidence, never derives a value
that the source did not state, and never moves a value between subjects:
a process-image SHA-256 stays `PROCESS_IMAGE`, a written file's SHA-256
stays `FILE_CONTENT`, and a DNS question is not a contacted peer.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Optional

from .contract import (OBS_DOMAIN, OBS_IP, OBS_MD5, OBS_SHA1, OBS_SHA256,
                       OBS_URL, SUBJECT_DNS_QUESTION, SUBJECT_FILE_CONTENT,
                       SUBJECT_NETWORK_PEER, SUBJECT_PROCESS_IMAGE,
                       SUBJECT_URL, Observable)

_HASH_LEN = {64: OBS_SHA256, 40: OBS_SHA1, 32: OBS_MD5}
_HEX = re.compile(r"^[0-9a-f]+$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9])?\.)+"
                     r"[a-z]{2,63}$")


def _s(v: Any) -> str:
    return "" if v is None else str(v).strip()


def _hash_type(value: str) -> Optional[str]:
    v = value.lower()
    if not _HEX.match(v):
        return None
    return _HASH_LEN.get(len(v))


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def extract(canonical: dict[str, Any], *, tenant_id: str = "",
            endpoint_id: str = "",
            evidence_ref: str = "") -> list[Observable]:
    """Every observable this ONE canonical event genuinely carries."""
    out: list[Observable] = []
    extra = canonical.get("additional_fields") or {}
    tenant = _s(tenant_id or canonical.get("tenant_id"))
    endpoint = _s(endpoint_id or extra.get("endpoint_id")
                  or (canonical.get("host") or {}).get("host_id"))
    ref = _s(evidence_ref or canonical.get("event_id"))
    refs = (ref,) if ref else ()

    def add(otype: str, value: str, subject: str, source_field: str,
            provenance: str = "") -> None:
        if not value:
            return
        out.append(Observable(type=otype, value=value, subject=subject,
                              source_field=source_field, evidence_refs=refs,
                              tenant_id=tenant, endpoint_id=endpoint,
                              provenance=provenance))

    proc = canonical.get("process") or {}
    proc_prov = proc.get("field_provenance") or {}
    for algo, digest in (proc.get("hashes") or {}).items():
        value = _s(digest).lower()
        otype = _hash_type(value)
        if not otype:
            continue
        add(otype, value, SUBJECT_PROCESS_IMAGE,
            f"process.hashes.{algo.lower()}",
            _s(proc_prov.get(f"hashes.{algo.lower()}")))

    fil = canonical.get("file") or {}
    file_prov = fil.get("field_provenance") or {}
    for algo, digest in (fil.get("hashes") or {}).items():
        value = _s(digest).lower()
        otype = _hash_type(value)
        if not otype:
            continue
        add(otype, value, SUBJECT_FILE_CONTENT,
            f"file.hashes.{algo.lower()}",
            _s(file_prov.get(f"hashes.{algo.lower()}")))

    net = canonical.get("network") or {}
    net_prov = net.get("field_provenance") or {}
    for key, field_name in (("dest_ip", "network.dest_ip"),
                            ("src_ip", "network.src_ip")):
        value = _s(net.get(key))
        if value and _valid_ip(value):
            add(OBS_IP, value, SUBJECT_NETWORK_PEER, field_name,
                _s(net_prov.get(key)))

    dns = canonical.get("dns") or {}
    query = _s(net.get("dns_query")) or _s(dns.get("query_name"))
    if query and _DOMAIN.match(query.lower()):
        add(OBS_DOMAIN, query.lower(), SUBJECT_DNS_QUESTION,
            "network.dns_query", _s(net_prov.get("dns_query")))
    for answer in (net.get("dns_response_ips") or dns.get("answers") or ()):
        value = _s(answer)
        if value and _valid_ip(value):
            add(OBS_IP, value, SUBJECT_DNS_QUESTION,
                "network.dns_response_ips", _s(net_prov.get(
                    "dns_response_ips")))

    url = _s(net.get("url")) or _s(extra.get("url"))
    if url:
        add(OBS_URL, url, SUBJECT_URL, "network.url")

    return _dedupe(out)


def _dedupe(items: list[Observable]) -> list[Observable]:
    """One observable per (type, value, subject). Evidence refs merge."""
    seen: dict[tuple[str, str, str], Observable] = {}
    for item in items:
        k = (item.type, item.value, item.subject)
        prior = seen.get(k)
        if prior is None:
            seen[k] = item
            continue
        merged = tuple(dict.fromkeys(prior.evidence_refs
                                     + item.evidence_refs))
        seen[k] = Observable(
            type=prior.type, value=prior.value, subject=prior.subject,
            source_field=prior.source_field, evidence_refs=merged,
            tenant_id=prior.tenant_id, endpoint_id=prior.endpoint_id,
            provenance=prior.provenance)
    return list(seen.values())
