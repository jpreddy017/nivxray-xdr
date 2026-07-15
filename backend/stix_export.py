"""NivX Forge — STIX 2.1 bundle exporter (SOC/CTI-ready, TIP/SIEM compatible).

Produces a fully STIX 2.1 compliant bundle that imports cleanly into
OpenCTI, MISP, Microsoft Sentinel, Splunk ES, QRadar, ThreatConnect, Anomali,
ThreatQuotient, and other TIP/SIEM platforms.

Bundle contents (default full set):
  • Identity        — NivX Forge (producer, organization) + analyst (individual)
  • Marking         — TLP:AMBER (SOC-safe default; overridable)
  • Attack Pattern  — one per MITRE ATT&CK technique, with kill-chain phase
  • Malware         — when aggregate.family is identified (family label + labels)
  • Indicator       — one per IOC (url, ipv4, ipv6, domain, md5, sha1, sha256, email, file)
  • Observed Data   — SCO-only mirror of each indicator (for TIPs that consume SCOs)
  • Note            — decode chain narrative + analyst_notes
  • Relationship    — Indicator→Malware (indicates), Malware→AttackPattern (uses),
                      AttackPattern→Malware (delivers) for chain records
  • Report          — top-level container linking every object above
  • External Refs   — MITRE ATT&CK, VirusTotal (per hash), AbuseIPDB (per IP) etc

Chain investigations (kind == "chain") get per-stage kill-chain-phase objects
derived from the persisted `aggregate.kill_chain` array; the Report emits one
row per stage under `x_nivxforge_stages` for downstream analyst review.

Refs:
  OASIS STIX 2.1 spec — https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
  MITRE ATT&CK STIX  — https://github.com/mitre-attack/attack-stix-data
"""
from __future__ import annotations
import hashlib
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# --------------------------------------------------------------------------- #
# STIX identifier helpers
# --------------------------------------------------------------------------- #

# NivX Forge namespace — arbitrary but stable so re-exports of the same
# investigation produce identical UUIDs (idempotent import into TIPs).
_NVX_NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")  # NAMESPACE_DNS


def _uid(kind: str, seed: str) -> str:
    """Deterministic UUIDv5 based on kind + seed for stable STIX ids."""
    return f"{kind}--{uuid.uuid5(_NVX_NAMESPACE, f'nivxforge/{kind}/{seed}')}"


def _iso(dt: Optional[datetime] = None) -> str:
    """STIX 2.1 timestamp: RFC-3339 UTC with millisecond precision + Z."""
    d = dt or datetime.now(timezone.utc)
    return d.strftime("%Y-%m-%dT%H:%M:%S.") + f"{int(d.microsecond / 1000):03d}Z"


# --------------------------------------------------------------------------- #
# Static producer identity & marking
# --------------------------------------------------------------------------- #
_PRODUCER_NAME = "NivX Forge"
_PRODUCER_ID   = _uid("identity", "producer:nivxforge")

# TLP:AMBER — OASIS-published marking definition (constant UUID, well-known).
_TLP_AMBER_ID  = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
_TLP_MARKINGS  = {
    "WHITE":  "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "GREEN":  "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "AMBER":  "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "RED":    "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}


def _producer_identity(ts: str) -> Dict[str, Any]:
    return {
        "type": "identity",
        "spec_version": "2.1",
        "id": _PRODUCER_ID,
        "created": ts, "modified": ts,
        "name": _PRODUCER_NAME,
        "description": (
            "NivX Forge — hybrid deterministic/AI payload decoder & threat analysis "
            "platform. Automated IOC extraction, MITRE ATT&CK mapping, and multi-stage "
            "chain investigation for SOC/CTI teams."
        ),
        "identity_class": "organization",
        "sectors": ["technology"],
        "contact_information": "https://nivxray.nivxforge.com",
    }


def _analyst_identity(analyst_email: str, ts: str) -> Dict[str, Any]:
    return {
        "type": "identity",
        "spec_version": "2.1",
        "id": _uid("identity", f"analyst:{analyst_email}"),
        "created": ts, "modified": ts,
        "created_by_ref": _PRODUCER_ID,
        "name": analyst_email or "unknown-analyst",
        "identity_class": "individual",
        "contact_information": analyst_email or "",
    }


# --------------------------------------------------------------------------- #
# IOC → STIX Indicator pattern helpers
# --------------------------------------------------------------------------- #
_IPV6_RX = re.compile(r"^[0-9a-f:]+$", re.IGNORECASE)


def _ip_kind(value: str) -> str:
    return "ipv6-addr" if ":" in value and _IPV6_RX.match(value) else "ipv4-addr"


def _escape_stix_str(v: str) -> str:
    return v.replace("\\", "\\\\").replace("'", "\\'")


def _ioc_patterns(iocs: Dict[str, Any]) -> List[Tuple[str, str, str, str, str]]:
    """Return list of tuples: (bucket, ioc_value, sco_type, stix_pattern, label).

    Emits STIX-compliant patterns per SCO type. Hash patterns use RFC-compliant
    hash names (`MD5`, `SHA-1`, `SHA-256`, `SHA-512`). URL/domain/ip use their
    respective SCO namespaces. Email uses `email-addr:value`.
    """
    out: List[Tuple[str, str, str, str, str]] = []

    for bucket, sco_type, label in [
        ("urls",    "url",         "URL"),
        ("domains", "domain-name", "Domain"),
        ("emails",  "email-addr",  "Email Address"),
    ]:
        for v in iocs.get(bucket) or []:
            v = str(v).strip()
            if not v: continue
            out.append((bucket, v, sco_type,
                        f"[{sco_type}:value = '{_escape_stix_str(v)}']", label))

    for v in iocs.get("ips") or []:
        v = str(v).strip()
        if not v: continue
        kind = _ip_kind(v)
        out.append(("ips", v, kind, f"[{kind}:value = '{_escape_stix_str(v)}']", "IP Address"))

    _hash_map = [
        ("md5",    "MD5"),
        ("sha1",   "SHA-1"),
        ("sha256", "SHA-256"),
        ("sha512", "SHA-512"),
    ]
    for bucket, hash_name in _hash_map:
        for v in iocs.get(bucket) or []:
            v = str(v).strip()
            if not v: continue
            out.append((bucket, v, "file",
                        f"[file:hashes.'{hash_name}' = '{_escape_stix_str(v)}']",
                        f"File ({hash_name})"))

    # File name IOCs (dropped payloads) → file:name pattern
    for v in iocs.get("files") or []:
        v = str(v).strip()
        if not v: continue
        out.append(("files", v, "file",
                    f"[file:name = '{_escape_stix_str(v)}']", "File Name"))

    return out


def _sco_object(sco_type: str, value: str, bucket: str) -> Dict[str, Any]:
    """Build a STIX Cyber Observable (SCO) matching the indicator's pattern."""
    sid = _uid(sco_type, f"{sco_type}:{value}")
    base = {"type": sco_type, "spec_version": "2.1", "id": sid}
    if sco_type in ("url", "domain-name", "ipv4-addr", "ipv6-addr", "email-addr"):
        base["value"] = value
    elif sco_type == "file":
        if bucket == "files":
            base["name"] = value
        else:
            hash_key = {"md5": "MD5", "sha1": "SHA-1",
                        "sha256": "SHA-256", "sha512": "SHA-512"}.get(bucket, bucket.upper())
            base["hashes"] = {hash_key: value}
    return base


# --------------------------------------------------------------------------- #
# External references (OSINT + MITRE)
# --------------------------------------------------------------------------- #
def _ioc_external_refs(bucket: str, value: str) -> List[Dict[str, Any]]:
    """Deep-links to common CTI/OSINT enrichment platforms per IOC type."""
    refs: List[Dict[str, Any]] = []
    if bucket in ("md5", "sha1", "sha256", "sha512"):
        refs.append({"source_name": "VirusTotal",
                     "url": f"https://www.virustotal.com/gui/file/{value}"})
        refs.append({"source_name": "MalwareBazaar",
                     "url": f"https://bazaar.abuse.ch/browse.php?search=sha256%3A{value}"
                     if bucket == "sha256" else
                     f"https://bazaar.abuse.ch/browse.php?search={bucket}%3A{value}"})
    elif bucket == "ips":
        refs.append({"source_name": "AbuseIPDB",
                     "url": f"https://www.abuseipdb.com/check/{value}"})
        refs.append({"source_name": "VirusTotal",
                     "url": f"https://www.virustotal.com/gui/ip-address/{value}"})
        refs.append({"source_name": "Shodan",
                     "url": f"https://www.shodan.io/host/{value}"})
    elif bucket == "domains":
        refs.append({"source_name": "VirusTotal",
                     "url": f"https://www.virustotal.com/gui/domain/{value}"})
        refs.append({"source_name": "URLhaus",
                     "url": f"https://urlhaus.abuse.ch/browse.php?search={value}"})
        refs.append({"source_name": "Whois",
                     "url": f"https://who.is/whois/{value}"})
    elif bucket == "urls":
        refs.append({"source_name": "VirusTotal",
                     "url": f"https://www.virustotal.com/gui/search/{value}"})
        refs.append({"source_name": "URLhaus",
                     "url": f"https://urlhaus.abuse.ch/browse.php?search={value}"})
    return refs


# --------------------------------------------------------------------------- #
# Malware object (family recognition)
# --------------------------------------------------------------------------- #
def _malware_object(family: str, confidence_pct: int, ts: str) -> Dict[str, Any]:
    """Build a STIX Malware SDO for a recognised family."""
    return {
        "type": "malware",
        "spec_version": "2.1",
        "id": _uid("malware", f"family:{family.lower()}"),
        "created": ts, "modified": ts,
        "created_by_ref": _PRODUCER_ID,
        "name": family,
        "description": f"{family} family recognised by NivX Forge deterministic pipeline "
                       f"(confidence: {confidence_pct}%).",
        "malware_types": ["trojan"],   # generic label; refined by post-processing hooks
        "is_family": True,
        "labels": ["nivxforge-detected", family.lower()],
        "confidence": confidence_pct,
    }


# --------------------------------------------------------------------------- #
# Attack Pattern (MITRE technique) — with kill_chain_phases + external refs
# --------------------------------------------------------------------------- #
def _attack_pattern(mitre_entry: Dict[str, Any], ts: str, stage: Optional[int] = None) -> Dict[str, Any]:
    tid = str(mitre_entry.get("id") or "").strip()
    tactic = str(mitre_entry.get("tactic") or "").strip()
    tech = mitre_entry.get("technique") or tid
    ap: Dict[str, Any] = {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": _uid("attack-pattern", f"mitre:{tid}"),
        "created": ts, "modified": ts,
        "created_by_ref": _PRODUCER_ID,
        "name": tech,
        "description": mitre_entry.get("evidence") or f"MITRE ATT&CK {tid} — {tech}",
        "external_references": [{
            "source_name": "mitre-attack",
            "external_id": tid,
            "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
        }],
    }
    if tactic:
        ap["kill_chain_phases"] = [{
            "kill_chain_name": "mitre-attack",
            "phase_name": tactic.lower().replace(" ", "-"),
        }]
    if stage is not None:
        ap["x_nivxforge_stage_index"] = stage
    return ap


# --------------------------------------------------------------------------- #
# Bundle builder — single or chain investigation
# --------------------------------------------------------------------------- #
def build_investigation_bundle(
    *,
    analyst_email: str,
    input_preview: str,
    output_preview: str,
    engine: Optional[str],
    confidence: Optional[int],
    trace: List[Dict[str, Any]],
    iocs: Dict[str, Any],
    mitre: List[Dict[str, Any]],
    verdict: Optional[Dict[str, Any]],
    # Extended (chain-aware) fields — optional for backward compatibility
    kind: str = "single",
    stages: Optional[List[Dict[str, Any]]] = None,
    aggregate: Optional[Dict[str, Any]] = None,
    analyst_notes: str = "",
    tlp: str = "AMBER",
    osint: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Return a fully-populated STIX 2.1 bundle dict ready to json.dumps().

    Backward compatible with the pre-Feb-2026 minimal exporter (adds optional
    kwargs). When `kind == "chain"` and `stages` is provided, the bundle
    includes per-stage kill-chain ordering + a Report row per stage.
    """
    ts = _iso()
    objects: List[Dict[str, Any]] = []
    marking_ref = _TLP_MARKINGS.get(tlp.upper(), _TLP_AMBER_ID)
    confidence = confidence if confidence is not None else 75
    aggregate = aggregate or {}
    stages = stages or []
    osint = osint or {}

    # ─── Identities ──────────────────────────────────────────────────────
    producer = _producer_identity(ts)
    analyst = _analyst_identity(analyst_email, ts)
    objects.extend([producer, analyst])

    # Track all object ids for the top-level Report.object_refs
    obj_refs: List[str] = [producer["id"], analyst["id"]]

    # ─── Malware SDO (if aggregate.family recognised) ────────────────────
    malware_obj: Optional[Dict[str, Any]] = None
    family = (aggregate.get("family") or {}).get("family") if isinstance(aggregate.get("family"), dict) else None
    fam_conf = (aggregate.get("family") or {}).get("confidence") if isinstance(aggregate.get("family"), dict) else None
    if family:
        malware_obj = _malware_object(family, int(fam_conf or confidence), ts)
        malware_obj["object_marking_refs"] = [marking_ref]
        objects.append(malware_obj)
        obj_refs.append(malware_obj["id"])

    # ─── Attack Patterns from MITRE ──────────────────────────────────────
    ap_ids: List[str] = []
    for m in (mitre or []):
        if not (m or {}).get("id"): continue
        ap = _attack_pattern(m, ts)
        ap["object_marking_refs"] = [marking_ref]
        # If chain: attach stage number when this MITRE tid appears in aggregate.kill_chain
        kc = aggregate.get("kill_chain") or []
        for k in kc:
            if k.get("id") == m.get("id") and k.get("stage") is not None:
                ap["x_nivxforge_stage_index"] = k["stage"]
                break
        objects.append(ap)
        ap_ids.append(ap["id"])
        obj_refs.append(ap["id"])

    # ─── Indicators + SCO Observed Data ──────────────────────────────────
    indicator_ids: List[str] = []
    sco_ids: List[str] = []
    for bucket, value, sco_type, pattern, label in _ioc_patterns(iocs or {}):
        ext_refs = _ioc_external_refs(bucket, value)
        # OSINT enrichment refs (e.g. VirusTotal detection ratios) if available
        for src, hit in (osint.get(value) or {}).items():
            if isinstance(hit, dict) and hit.get("url"):
                ext_refs.append({"source_name": src, "url": hit["url"]})

        ind = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": _uid("indicator", f"{sco_type}:{value}"),
            "created": ts, "modified": ts,
            "created_by_ref": _PRODUCER_ID,
            "object_marking_refs": [marking_ref],
            "name": f"{label}: {value}",
            "description": f"Extracted from NivX Forge decoded payload "
                           f"(engine={engine or 'deterministic'}).",
            "pattern": pattern,
            "pattern_type": "stix",
            "pattern_version": "2.1",
            "valid_from": ts,
            "indicator_types": ["malicious-activity"],
            "labels": ["nivxforge-decoded", bucket],
            "confidence": confidence,
        }
        if ext_refs:
            ind["external_references"] = ext_refs
        objects.append(ind)
        indicator_ids.append(ind["id"])
        obj_refs.append(ind["id"])

        # Companion SCO (raw observable) — many TIPs (OpenCTI, MISP) prefer SCOs
        sco = _sco_object(sco_type, value, bucket)
        objects.append(sco)
        sco_ids.append(sco["id"])
        obj_refs.append(sco["id"])

        # Observed Data envelope grouping the SCO
        obs = {
            "type": "observed-data",
            "spec_version": "2.1",
            "id": _uid("observed-data", f"{sco_type}:{value}"),
            "created": ts, "modified": ts,
            "created_by_ref": _PRODUCER_ID,
            "object_marking_refs": [marking_ref],
            "first_observed": ts,
            "last_observed": ts,
            "number_observed": 1,
            "object_refs": [sco["id"]],
        }
        objects.append(obs)
        obj_refs.append(obs["id"])

    # ─── Relationships ────────────────────────────────────────────────────
    def _rel(rel_type: str, src: str, tgt: str) -> Dict[str, Any]:
        return {
            "type": "relationship",
            "spec_version": "2.1",
            "id": _uid("relationship", f"{rel_type}:{src}:{tgt}"),
            "created": ts, "modified": ts,
            "created_by_ref": _PRODUCER_ID,
            "object_marking_refs": [marking_ref],
            "relationship_type": rel_type,
            "source_ref": src,
            "target_ref": tgt,
        }

    # Indicator → indicates → Malware
    if malware_obj:
        for iid in indicator_ids:
            rel = _rel("indicates", iid, malware_obj["id"])
            objects.append(rel); obj_refs.append(rel["id"])
        # Malware → uses → each Attack Pattern
        for ap_id in ap_ids:
            rel = _rel("uses", malware_obj["id"], ap_id)
            objects.append(rel); obj_refs.append(rel["id"])
    # Indicator → indicates → Attack Pattern (fallback when no malware family)
    else:
        for iid in indicator_ids:
            for ap_id in ap_ids:
                rel = _rel("indicates", iid, ap_id)
                objects.append(rel); obj_refs.append(rel["id"])

    # ─── Note: decode chain narrative + analyst_notes ────────────────────
    chain_summary = " → ".join([t.get("op", "?") for t in (trace or [])])
    note_content = (
        f"Engine: {engine or 'unknown'}\n"
        f"Confidence: {confidence}%\n"
        f"Kind: {kind}\n"
        f"Chain: {chain_summary or '(no ops)'}\n\n"
        f"── Input preview ──\n{(input_preview or '')[:800]}\n\n"
        f"── Decoded output preview ──\n{(output_preview or '')[:800]}"
    )
    if analyst_notes:
        note_content += f"\n\n── Analyst notes ──\n{analyst_notes[:1500]}"

    note = {
        "type": "note",
        "spec_version": "2.1",
        "id": _uid("note", "chain:" + hashlib.sha1(
            (chain_summary + input_preview[:200]).encode("utf-8", errors="replace")
        ).hexdigest()),
        "created": ts, "modified": ts,
        "created_by_ref": _PRODUCER_ID,
        "object_marking_refs": [marking_ref],
        "abstract": (f"NivX Forge decode chain ({engine or 'deterministic'}) "
                     f"— {kind} · {chain_summary or 'plaintext'}")[:250],
        "content": note_content,
        "object_refs": obj_refs[:] or [producer["id"]],
    }
    objects.append(note); obj_refs.append(note["id"])

    # ─── Report — top-level container ────────────────────────────────────
    verdict_block = verdict or {}
    verdict_label = (verdict_block.get("verdict") or "Unverified")
    report_types = ["threat-report"]
    if malware_obj:
        report_types.append("malware")
    if ap_ids:
        report_types.append("attack-pattern")
    if indicator_ids:
        report_types.append("indicator")

    report: Dict[str, Any] = {
        "type": "report",
        "spec_version": "2.1",
        "id": _uid("report",
                   f"{analyst_email}:{ts}:{hashlib.sha1((input_preview or '').encode('utf-8', errors='replace')).hexdigest()[:12]}"),
        "created": ts, "modified": ts,
        "created_by_ref": _PRODUCER_ID,
        "object_marking_refs": [marking_ref],
        "name": (f"NivX Forge Investigation — {verdict_label} "
                 f"— {family or (chain_summary or 'plaintext')}")[:250],
        "description": (
            verdict_block.get("summary")
            or f"Automated decode + threat analysis via NivX Forge "
               f"({engine or 'deterministic'} engine). Confidence: {confidence}%."
        ),
        "published": ts,
        "report_types": report_types,
        "labels": ["nivxforge", verdict_label.lower(), kind],
        "confidence": confidence,
        "object_refs": obj_refs,
    }

    # Extension fields for chain investigations
    if kind == "chain" and stages:
        report["x_nivxforge_stages"] = [
            {
                "stage_index": s.get("stage_index"),
                "engine": s.get("engine"),
                "confidence": s.get("confidence"),
                "input_preview": (s.get("input_preview") or "")[:200],
                "output_preview": (s.get("output_preview") or (s.get("output") or ""))[:200],
                "reached_shellcode": bool(s.get("reached_shellcode")),
            }
            for s in stages
        ]
    if aggregate.get("kill_chain"):
        report["x_nivxforge_kill_chain"] = aggregate["kill_chain"]
    if verdict_block:
        report["x_nivxforge_verdict"] = verdict_block

    objects.append(report)

    # ─── Bundle envelope ─────────────────────────────────────────────────
    return {
        "type": "bundle",
        "id": _uid("bundle",
                   f"{analyst_email}:{ts}:{report['id'][-12:]}"),
        "objects": objects,
    }


# --------------------------------------------------------------------------- #
# Convenience: build from a persisted investigation history record
# --------------------------------------------------------------------------- #
def build_from_history_record(
    record: Dict[str, Any],
    *,
    analyst_notes: str = "",
    tlp: str = "AMBER",
) -> Dict[str, Any]:
    """Build a STIX 2.1 bundle from a saved investigation (single or chain).

    `record` is the `_serialize`d document returned by /api/history/{id}. The
    Report + Malware confidence, IOC set, MITRE map, verdict, and per-stage
    kill-chain phases are all pulled from the persisted schema.
    """
    return build_investigation_bundle(
        analyst_email=record.get("user_email") or "unknown@nivxforge",
        input_preview=record.get("input_preview") or "",
        output_preview=record.get("output_preview") or "",
        engine=record.get("engine"),
        confidence=int(record.get("confidence") or 0),
        trace=[{"op": op, "args": {}} for op in (record.get("chain") or [])],
        iocs=record.get("iocs") or {},
        mitre=record.get("mitre") or [],
        verdict=record.get("verdict"),
        kind=record.get("kind") or "single",
        stages=record.get("stages") or [],
        aggregate=record.get("aggregate") or {},
        analyst_notes=analyst_notes,
        tlp=tlp,
        osint=record.get("osint") or {},
    )
