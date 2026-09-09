"""Semantic CEM Builder — additive path (Stage 4 preview).

Additive-only implementation of the future CEM assembly path:
    SchemaFingerprint + SemanticMappingResult  →  CanonicalEventModel

This module DOES NOT replace the existing vendor normalizers. It runs
alongside them so the Parity Comparator (``cem_parity.py``) can measure
divergence over the golden corpus before any cut-over.

Contract:
  · Consumes ParsedInput + SemanticMappingResult (no re-parsing, no
    re-detection).
  · Emits CanonicalEventModel with entities populated from mapped
    fields only.
  · Vendor identity, if known, attaches as ``vendor`` provenance
    metadata — never routes behaviour.
  · Event kind is inferred from *concept co-occurrence*, never from
    vendor-specific EventID lookup. Unknown kind → ``generic``.
  · Never raises. Missing / unmapped fields degrade gracefully.

The output is intentionally minimal compared to vendor-normalizer
output; the parity report will surface the gap, which is exactly
the evidence the owner requires before cutting over.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from nivxforge.investigation.cem import (
    CanonicalEvent,
    CanonicalEventModel,
    Dns,
    EventKind,
    FileEntity,
    Host,
    Network,
    Process,
    Provenance,
    Registry,
    SeverityLevel,
    User,
)
from .parser import ParsedInput
from .semantic_field_mapper import (
    FieldMapping,
    SemanticMappingResult,
)


# ── Entry point ──────────────────────────────────────────────────

def build_semantic_cem(parsed: ParsedInput,
                       mapping: SemanticMappingResult,
                       *,
                       vendor_metadata: Optional[Dict[str, Any]] = None,
                       ) -> CanonicalEventModel:
    """Build a CEM from semantic mapping output.

    ``vendor_metadata`` is optional — if provided, it attaches as
    provenance decoration on the root but never influences event
    construction.
    """
    events: List[CanonicalEvent] = []
    records = list(parsed.records or ())

    concept_by_surface = {m.surface_field: m for m in mapping.mappings}

    for idx, rec in enumerate(records):
        evt = _build_event(idx, rec, concept_by_surface, mapping)
        if evt is not None:
            events.append(evt)

    return CanonicalEventModel(
        vendor=(vendor_metadata or {}).get("vendor"),
        vendor_route=(vendor_metadata or {}).get("route",
                                                  "semantic_cem_v0"),
        events=events,
        provenance=Provenance(
            source="semantic_cem_builder",
            vendor=(vendor_metadata or {}).get("vendor"),
            confidence=mapping.semantic_confidence,
            evidence_refs=[f"semantic_mapping@{mapping.registry_version}"],
        ),
    )


# ── Event construction ───────────────────────────────────────────

def _build_event(record_idx: int,
                 rec: Any,
                 mappings_by_surface: Dict[str, FieldMapping],
                 mapping: SemanticMappingResult,
                 ) -> Optional[CanonicalEvent]:
    if not isinstance(rec, dict):
        return None

    # Group values by concept: {concept: [(surface, value, confidence)]}
    # Values that are themselves containers (dict / list) are demoted
    # so scalar values win when multiple surfaces map to the same
    # concept (e.g. Cisco maps both "computer" and "computer.hostname"
    # to Host — the string leaf is the analyst-defensible answer).
    grouped: Dict[str, List[Tuple[str, Any, float]]] = {}
    container_grouped: Dict[str, List[Tuple[str, Any, float]]] = {}
    for surface, fm in mappings_by_surface.items():
        val = _resolve_value(rec, surface)
        if val is None or val == "":
            continue
        if isinstance(val, (dict, list)):
            container_grouped.setdefault(fm.concept, []).append(
                (surface, val, fm.confidence))
            continue
        grouped.setdefault(fm.concept, []).append(
            (surface, val, fm.confidence))
    # If a concept has ONLY container-typed values, fall back to those.
    for concept, rows in container_grouped.items():
        grouped.setdefault(concept, rows)

    # Prefer more-specific (deeper-dotted) surfaces when multiple map
    # to the same concept. This makes enriched sibling fields (e.g.
    # ``User.username`` from the identity parser) win over the raw
    # origin (``User = "CORP\\alice"``).
    for concept, rows in grouped.items():
        rows.sort(key=lambda r: (-r[0].count("."), -r[2]))

    prov = Provenance(
        source="semantic_cem_builder",
        confidence=mapping.semantic_confidence,
        evidence_refs=[f"record[{record_idx}]"],
    )

    host = _first_host(grouped, prov)
    user = _first_user(grouped, prov)
    process = _build_process(grouped, prov)
    file_entity = _build_file(grouped, prov)
    network = _build_network(grouped, prov)
    dns = _build_dns(grouped, prov)
    registry = _build_registry(grouped, prov)

    kind = _infer_event_kind(grouped)

    # Skip fully-empty events — nothing semantic to record.
    if not any([host, user, process, file_entity, network, dns, registry]):
        return None

    return CanonicalEvent(
        event_id=str(uuid.uuid4()),
        kind=kind,
        timestamp=None,   # temporal reasoning is Timeline's job (Stage 10)
        host=host,
        user=user,
        process=process,
        file=file_entity,
        registry=registry,
        network=network,
        dns=dns,
        detection=None,
        raw=rec,
        provenance=prov,
    )


def _infer_event_kind(grouped: Dict[str, list]) -> EventKind:
    """Infer event kind from concept co-occurrence only.

    Vendor-neutral. Order matters — more specific patterns first.
    """
    has = grouped.__contains__
    if has("Process") and has("Command"):
        return EventKind.process_create
    if has("Domain") and not has("Process"):
        return EventKind.dns_query
    if has("IP") and has("Port"):
        return EventKind.network_connect
    if has("Registry"):
        return EventKind.registry_write
    if has("File") and has("Hash"):
        return EventKind.file_create
    if has("Detection") or has("Alert"):
        return EventKind.detection
    return EventKind.generic


# ── Entity builders ─────────────────────────────────────────────

def _first_host(grouped: Dict[str, list],
                prov: Provenance) -> Optional[Host]:
    entries = grouped.get("Host")
    if not entries:
        return None
    _s, name, _c = entries[0]
    ip_entries = grouped.get("IP") or []
    ip_value = ip_entries[0][1] if ip_entries else None
    return Host(name=str(name), ip=(str(ip_value) if ip_value else None),
                provenance=prov)


def _first_user(grouped: Dict[str, list],
                prov: Provenance) -> Optional[User]:
    entries = grouped.get("User")
    if not entries:
        return None
    _s, name, _c = entries[0]
    return User(name=str(name), provenance=prov)


def _build_process(grouped: Dict[str, list],
                   prov: Provenance) -> Optional[Process]:
    proc = grouped.get("Process") or []
    cmd = grouped.get("Command") or []
    hashes = grouped.get("Hash") or []
    if not proc and not cmd:
        return None
    image = str(proc[0][1]) if proc else None
    command_line = str(cmd[0][1]) if cmd else None
    sha256 = None
    for _s, v, _c in hashes:
        if isinstance(v, str) and len(v) == 64:
            sha256 = v
            break
    return Process(image=image, command_line=command_line,
                   hash_sha256=sha256, provenance=prov)


def _build_file(grouped: Dict[str, list],
                prov: Provenance) -> Optional[FileEntity]:
    files = grouped.get("File") or []
    hashes = grouped.get("Hash") or []
    if not files and not hashes:
        return None
    path = None
    name = None
    for surface, val, _ in files:
        if isinstance(val, str) and ("\\" in val or "/" in val):
            path = val
        else:
            name = str(val) if val is not None else None
    md5 = sha1 = sha256 = None
    for _s, v, _c in hashes:
        if not isinstance(v, str):
            continue
        if len(v) == 32:
            md5 = v
        elif len(v) == 40:
            sha1 = v
        elif len(v) == 64:
            sha256 = v
    return FileEntity(path=path, name=name,
                      hash_md5=md5, hash_sha1=sha1, hash_sha256=sha256,
                      provenance=prov)


def _build_network(grouped: Dict[str, list],
                   prov: Provenance) -> Optional[Network]:
    ips = grouped.get("IP") or []
    ports = grouped.get("Port") or []
    proto = grouped.get("Protocol") or []
    urls = grouped.get("URL") or []
    domains = grouped.get("Domain") or []

    if not (ips or ports or urls or domains):
        return None

    # Split IPs / Ports into src / dst based on surface hints.
    src_ip = dst_ip = None
    src_port = dst_port = None
    for surface, val, _ in ips:
        norm = surface.lower()
        if any(k in norm for k in ("dst", "dest", "remote", "target")):
            dst_ip = str(val)
        elif any(k in norm for k in ("src", "source", "local", "client")):
            src_ip = str(val)
        else:
            src_ip = src_ip or str(val)
    for surface, val, _ in ports:
        norm = surface.lower()
        try:
            n = int(val)
        except (TypeError, ValueError):
            continue
        if any(k in norm for k in ("dst", "dest", "remote", "target")):
            dst_port = n
        elif any(k in norm for k in ("src", "source", "local", "client")):
            src_port = n
        else:
            src_port = src_port or n

    protocol = str(proto[0][1]) if proto else None
    url = str(urls[0][1]) if urls else None
    domain = str(domains[0][1]) if domains else None
    return Network(src_ip=src_ip, src_port=src_port,
                   dst_ip=dst_ip, dst_port=dst_port,
                   protocol=protocol, url=url, domain=domain,
                   provenance=prov)


def _build_dns(grouped: Dict[str, list],
               prov: Provenance) -> Optional[Dns]:
    domains = grouped.get("Domain") or []
    # Only produce a DNS event object when Domain is present WITHOUT
    # network coordinates — else the Network builder covers it.
    if not domains:
        return None
    if grouped.get("IP") and grouped.get("Port"):
        return None
    return Dns(query=str(domains[0][1]), provenance=prov)


def _build_registry(grouped: Dict[str, list],
                    prov: Provenance) -> Optional[Registry]:
    reg = grouped.get("Registry") or []
    if not reg:
        return None
    return Registry(key=str(reg[0][1]), provenance=prov)


# ── Value resolution over dotted paths ───────────────────────────

def _resolve_value(rec: Dict[str, Any], surface: str) -> Any:
    if surface in rec:
        return rec[surface]
    if "." not in surface:
        return None
    cur: Any = rec
    for part in surface.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


__all__ = ["build_semantic_cem"]
